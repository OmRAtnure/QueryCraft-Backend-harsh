import express from "express";
import axios from "axios";
import { Pool } from "pg";
import cors from "cors";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import authenticate from "./middleware/authMiddleware.js";
import bcrypt from "bcrypt";
import Groq from "groq-sdk";

dotenv.config();
const groq = new Groq({
  apiKey: process.env.GROQ_API_KEY
});

const app = express();
// app.use(express.static("public"));
app.use(express.json());
app.use(cors());

// PostgreSQL connection
dotenv.config();

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  ssl: {
    rejectUnauthorized: false
  }
});

// set schema immediately
await pool.query("SET search_path TO public");

const JWT_SECRET = process.env.JWT_SECRET;
const WORKSPACE_ROLES = ["owner", "editor", "viewer"];
const SLOW_QUERY_THRESHOLD_MS = 3000;

function normalizeWorkspaceRole(value) {
  const role = String(value || "").trim().toLowerCase();
  return WORKSPACE_ROLES.includes(role) ? role : "viewer";
}

function isMutatingSql(sql) {
  const text = String(sql || "").trim().toLowerCase();
  return /\b(insert|update|delete|create|drop|alter|truncate|grant|revoke)\b/.test(text);
}

function normalizeTags(tags) {
  if (!Array.isArray(tags)) return [];
  const cleaned = tags
    .map((tag) => String(tag || "").trim().toLowerCase())
    .filter((tag) => tag.length > 0)
    .slice(0, 10);
  return [...new Set(cleaned)];
}

async function ensureSavedQueriesTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS public.saved_queries (
      id BIGSERIAL PRIMARY KEY,
      user_id INT NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      query TEXT NOT NULL,
      description TEXT DEFAULT '',
      tags JSONB NOT NULL DEFAULT '[]'::jsonb,
      is_favorite BOOLEAN NOT NULL DEFAULT FALSE,
      last_run_at TIMESTAMP NULL,
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMP NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_saved_queries_user_updated
    ON public.saved_queries (user_id, updated_at DESC);
  `);
}

async function ensureWorkspacesTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS public.workspaces (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      schema_name TEXT NOT NULL UNIQUE,
      owner_user_id INT NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMP NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS public.workspace_members (
      workspace_id BIGINT NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
      user_id INT NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
      role TEXT NOT NULL CHECK (role IN ('owner', 'editor', 'viewer')),
      joined_at TIMESTAMP NOT NULL DEFAULT NOW(),
      PRIMARY KEY (workspace_id, user_id)
    );
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_workspace_members_user
    ON public.workspace_members (user_id, workspace_id);
  `);
}

async function ensurePersonalWorkspaceForUser(userId, username, schemaName) {
  const existing = await pool.query(
    `SELECT id FROM public.workspaces WHERE schema_name = $1 LIMIT 1`,
    [schemaName]
  );

  let workspaceId;

  if (existing.rows.length > 0) {
    workspaceId = existing.rows[0].id;
  } else {
    const created = await pool.query(
      `
        INSERT INTO public.workspaces (name, schema_name, owner_user_id)
        VALUES ($1, $2, $3)
        RETURNING id;
      `,
      [`${username}'s Workspace`, schemaName, userId]
    );
    workspaceId = created.rows[0].id;
  }

  await pool.query(
    `
      INSERT INTO public.workspace_members (workspace_id, user_id, role)
      VALUES ($1, $2, 'owner')
      ON CONFLICT (workspace_id, user_id)
      DO UPDATE SET role = 'owner';
    `,
    [workspaceId, userId]
  );
}

async function resolveWorkspaceContext(req, res) {
  const requestedWorkspaceId = Number(req.headers["x-workspace-id"]);
  const hasRequestedWorkspace = Number.isInteger(requestedWorkspaceId) && requestedWorkspaceId > 0;

  const query = hasRequestedWorkspace
    ? `
        SELECT w.id, w.name, w.schema_name, m.role, w.owner_user_id
        FROM public.workspaces w
        JOIN public.workspace_members m ON m.workspace_id = w.id
        WHERE w.id = $1 AND m.user_id = $2
        LIMIT 1;
      `
    : `
        SELECT w.id, w.name, w.schema_name, m.role, w.owner_user_id
        FROM public.workspaces w
        JOIN public.workspace_members m ON m.workspace_id = w.id
        WHERE w.schema_name = $1 AND m.user_id = $2
        LIMIT 1;
      `;

  const params = hasRequestedWorkspace
    ? [requestedWorkspaceId, req.user.user_id]
    : [req.user.schema, req.user.user_id];

  const result = await pool.query(query, params);

  if (result.rows.length > 0) {
    return result.rows[0];
  }

  if (!hasRequestedWorkspace) {
    await ensurePersonalWorkspaceForUser(req.user.user_id, req.user.username || "User", req.user.schema);

    const retry = await pool.query(
      `
        SELECT w.id, w.name, w.schema_name, m.role, w.owner_user_id
        FROM public.workspaces w
        JOIN public.workspace_members m ON m.workspace_id = w.id
        WHERE w.schema_name = $1 AND m.user_id = $2
        LIMIT 1;
      `,
      [req.user.schema, req.user.user_id]
    );

    if (retry.rows.length > 0) {
      return retry.rows[0];
    }
  }

  res.status(403).json({ error: "Workspace access denied" });
  return null;
}

async function ensureUserProfilesTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS public.user_profiles (
      user_id INT PRIMARY KEY REFERENCES public.users(id) ON DELETE CASCADE,
      display_name TEXT NOT NULL,
      email TEXT DEFAULT '',
      bio TEXT DEFAULT '',
      avatar_url TEXT DEFAULT '',
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMP NOT NULL DEFAULT NOW()
    );
  `);
}

function normalizeProfileText(value, maxLength = 255) {
  return String(value || "").trim().slice(0, maxLength);
}

function normalizeAvatarUrl(value) {
  const url = String(value || "").trim();
  if (!url) return "";
  if (url.startsWith("http://") || url.startsWith("https://")) {
    return url.slice(0, 500);
  }
  return "";
}

async function getDatabaseSchema(schemaName) {
  const result = await pool.query(`
    SELECT table_name, column_name, data_type
    FROM information_schema.columns
    WHERE table_schema = '${schemaName}'
    ORDER BY table_name, ordinal_position;
  `);

  const rows = result.rows;
  const grouped = {};

  rows.forEach(row => {
    if (!grouped[row.table_name]) {
      grouped[row.table_name] = [];
    }

    grouped[row.table_name].push(
      `${row.column_name} ${row.data_type}`
    );
  });

  let schemaString = "";

  for (const table in grouped) {
    schemaString += `${table}(${grouped[table].join(", ")})\n`;
  }

  return schemaString.trim();
}

async function generateSQL(userInput, schemaName) {
  const schema = await getDatabaseSchema(schemaName);
  console.log("Database Schema:\n", schema);

  const response = await groq.chat.completions.create({
    model: "llama-3.3-70b-versatile",
    temperature: 0,
    messages: [
      {
        role: "user",
        content: `
You are a PostgreSQL query engine.

Your job is to convert English instructions into VALID PostgreSQL SQL.

You MUST return ONLY valid JSON.
Do NOT return markdown.
Do NOT explain anything outside JSON.

-------------------------------------
DATABASE SCHEMA:
${schema}

-------------------------------------
ALLOWED OPERATIONS:
- CREATE TABLE
- INSERT INTO
- SELECT
- UPDATE
- DELETE
- DROP TABLE

-------------------------------------
STRICT RULES:

1. If the request is incomplete (e.g., CREATE TABLE without columns),
   return:

{
  "runnable": false,
  "message": "Explain what information is missing."
}

2. If columns are mentioned but no data types are provided,
   intelligently assign appropriate PostgreSQL data types:
   - id → INT
   - name → TEXT
   - marks → INT
   - date → DATE
   - price → NUMERIC

3. Do NOT invent columns that are not mentioned or not in schema.

4. Do NOT generate:
   - DROP DATABASE
   - ALTER SYSTEM
   - GRANT
   - REVOKE

5. If referencing an existing table, use only columns that exist in schema.

6. Always generate complete SQL statements ending with semicolon.

7.Interprate what doe user want do properly and genearte query acording to their intent.

8.Use proper key where every necessery as primary key while creating table and foreign key while referencing another table.

9.When generating column names for CREATE TABLE:
   - Correct spelling mistakes in column names.
   - Do NOT use spaces in column names.
   - Convert column names to lowercase.
   - Replace spaces with underscores (_).

-------------------------------------

If request is valid, return:

{
  "runnable": true,
  "sql": "VALID POSTGRESQL SQL HERE"
}

-------------------------------------

User Input:
${userInput}
`
      }
    ]
  });

  let raw = response.choices[0].message.content.trim();

  const firstBrace = raw.indexOf("{");
  const lastBrace = raw.lastIndexOf("}");

  if (firstBrace !== -1 && lastBrace !== -1) {
    raw = raw.substring(firstBrace, lastBrace + 1);
  }

  try {
    return JSON.parse(raw);
  } catch (err) {
    console.error("JSON Parse Error:", raw);
    return {
      runnable: false,
      message: "AI returned invalid JSON format."
    };
  }
}

app.post("/query", authenticate, async (req, res) => {
  try {
    const workspace = await resolveWorkspaceContext(req, res);
    if (!workspace) return;

    const { text } = req.body;
    console.log("Received query request:", text);

    const result = await generateSQL(text, workspace.schema_name);

    if (!result.runnable) {
      return res.json({
        message: result.message,
        schemaChanged: false
      });
    }

    const sql = result.sql;
    console.log("Generated SQL:", sql);

    if (workspace.role === "viewer" && isMutatingSql(sql)) {
      return res.status(403).json({
        error: "Viewer role can only run read-only queries in this workspace.",
        schemaChanged: false,
      });
    }

    const client = await pool.connect();

    try {
      await client.query(`SET search_path TO ${workspace.schema_name}`);
      const executionStart = process.hrtime.bigint();
      const dbResult = await client.query(sql);
      const executionMs = Number(process.hrtime.bigint() - executionStart) / 1_000_000;

      console.log("Executed SQL:", sql);

      const lowerSQL = sql.toLowerCase().trim();

      const schemaChanged =
        lowerSQL.startsWith("create table") ||
        lowerSQL.startsWith("drop table") ||
        lowerSQL.startsWith("alter table");

      return res.json({
        generatedSQL: sql,
        runnable: true,
        data: dbResult.rows || [],
        rowCount: dbResult.rowCount || (dbResult.rows || []).length || 0,
        executionMs: Math.round(executionMs),
        slowQuery: executionMs >= SLOW_QUERY_THRESHOLD_MS,
        message: "Query executed successfully",
        schemaChanged,
        workspace: {
          id: workspace.id,
          name: workspace.name,
          role: workspace.role,
        },
      });

    } finally {
      client.release();
    }

  } catch (err) {
    console.error("QUERY ERROR:", err);

    res.status(500).json({
      error: err.message || "Internal server error",
      schemaChanged: false
    });
  }
});

app.post("/execute", authenticate, async (req, res) => {
  const sql = req.body.query;
  console.log("Received execute request:", sql);

  try {
    const workspace = await resolveWorkspaceContext(req, res);
    if (!workspace) return;

    if (workspace.role === "viewer" && isMutatingSql(sql)) {
      return res.status(403).json({ error: "Viewer role can only run read-only queries in this workspace." });
    }

    const client = await pool.connect();

    try {
      await client.query(`SET search_path TO ${workspace.schema_name}`);
      const executionStart = process.hrtime.bigint();
      const result = await client.query(sql);
      const executionMs = Number(process.hrtime.bigint() - executionStart) / 1_000_000;

    const lowerSQL = sql.toLowerCase().trim();

    const schemaChanged =
      lowerSQL.startsWith("create table") ||
      lowerSQL.startsWith("drop table");

      res.json({
        data: result.rows || [],
        rowCount: result.rowCount || (result.rows || []).length || 0,
        executionMs: Math.round(executionMs),
        slowQuery: executionMs >= SLOW_QUERY_THRESHOLD_MS,
        message: "Query executed successfully",
        schemaChanged,
        workspace: {
          id: workspace.id,
          name: workspace.name,
          role: workspace.role,
        },
      });

    } catch (err) {
      console.error("Error executing SQL:", err);
      res.status(500).json({
        error: err.message
      });

    } finally {
      client.release();
    }
  } catch (err) {
    console.error("Workspace execution error:", err);
    res.status(500).json({ error: "Failed to resolve workspace" });
  }
});

app.get("/test-db", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM students;");
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send("DB error");
  }
});

app.get("/", (req, res) => {
  res.send("Server is working");
});

app.get("/schema", authenticate, async (req, res) => {
  console.log("Fetching schema for user:", req.user);

  const workspace = await resolveWorkspaceContext(req, res);
  if (!workspace) return;

  const client = await pool.connect();

  try {
    await client.query(`SET search_path TO ${workspace.schema_name}`);

    const result = await client.query(`
      SELECT table_name
      FROM information_schema.tables
      WHERE table_schema = '${workspace.schema_name}'
      ORDER BY table_name;
    `);

    console.log("Schema query result:", result.rows);

    res.json({
      tables: result.rows,
      workspace: {
        id: workspace.id,
        name: workspace.name,
        role: workspace.role,
      },
    });

  } catch (err) {
    console.error("Schema error:", err);
    res.status(500).json({ error: "Failed to fetch schema" });

  } finally {
    client.release();
  }
});

app.post("/register", async (req, res) => {
  await pool.query("SET search_path TO public");
  const { username, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      "INSERT INTO users (username, password, schema_name) VALUES ($1, $2, $3) RETURNING id",
      [username, hashedPassword, "temp"]
    );

    const userId = result.rows[0].id;
    const schemaName = `user_${userId}`;

    await pool.query(`CREATE SCHEMA ${schemaName}`);

    await pool.query(
      "UPDATE users SET schema_name = $1 WHERE id = $2",
      [schemaName, userId]
    );

    await ensurePersonalWorkspaceForUser(userId, username, schemaName);

    await pool.query(
      "INSERT INTO public.user_profiles (user_id, display_name) VALUES ($1, $2) ON CONFLICT (user_id) DO NOTHING",
      [userId, username]
    );

    const token = jwt.sign(
      {
        user_id: userId,
        username,
        schema: schemaName,
      },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({ token });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Registration failed" });
  }
});

app.get("/me", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `
        SELECT
          u.id AS user_id,
          u.username,
          u.schema_name AS schema,
          COALESCE(p.display_name, u.username) AS display_name,
          COALESCE(p.email, '') AS email,
          COALESCE(p.bio, '') AS bio,
          COALESCE(p.avatar_url, '') AS avatar_url,
          p.created_at,
          p.updated_at
        FROM public.users u
        LEFT JOIN public.user_profiles p ON p.user_id = u.id
        WHERE u.id = $1
        LIMIT 1;
      `,
      [req.user.user_id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error("Failed to fetch profile:", err);
    res.status(500).json({ error: "Failed to fetch profile" });
  }
});

app.put("/me", authenticate, async (req, res) => {
  const displayName = normalizeProfileText(req.body?.displayName, 80);
  const email = normalizeProfileText(req.body?.email, 200);
  const bio = normalizeProfileText(req.body?.bio, 500);
  const avatarUrl = normalizeAvatarUrl(req.body?.avatarUrl);

  if (!displayName) {
    return res.status(400).json({ error: "Display name is required" });
  }

  if (req.body?.avatarUrl && !avatarUrl) {
    return res.status(400).json({ error: "Avatar URL must start with http:// or https://" });
  }

  try {
    const result = await pool.query(
      `
        INSERT INTO public.user_profiles (user_id, display_name, email, bio, avatar_url)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (user_id)
        DO UPDATE SET
          display_name = EXCLUDED.display_name,
          email = EXCLUDED.email,
          bio = EXCLUDED.bio,
          avatar_url = EXCLUDED.avatar_url,
          updated_at = NOW()
        RETURNING user_id, display_name, email, bio, avatar_url, created_at, updated_at;
      `,
      [req.user.user_id, displayName, email, bio, avatarUrl]
    );

    res.json(result.rows[0]);
  } catch (err) {
    console.error("Failed to update profile:", err);
    res.status(500).json({ error: "Failed to update profile" });
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  await pool.query("SET search_path TO public");

  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE username = $1",
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ message: "User not found" });
    }

    const user = result.rows[0];

    await ensurePersonalWorkspaceForUser(user.id, username, user.schema_name);

    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      return res.status(400).json({ message: "Invalid password" });
    }

    const token = jwt.sign(
      {
        user_id: user.id,
        username,
        schema: user.schema_name,
      },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({ token });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Login failed" });
  }
});

app.get("/workspaces", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `
        SELECT
          w.id,
          w.name,
          w.schema_name,
          w.owner_user_id,
          m.role,
          w.created_at,
          w.updated_at
        FROM public.workspace_members m
        JOIN public.workspaces w ON w.id = m.workspace_id
        WHERE m.user_id = $1
        ORDER BY CASE WHEN m.role = 'owner' THEN 0 ELSE 1 END, w.updated_at DESC;
      `,
      [req.user.user_id]
    );

    res.json(result.rows);
  } catch (err) {
    console.error("Failed to fetch workspaces:", err);
    res.status(500).json({ error: "Failed to fetch workspaces" });
  }
});

app.post("/workspaces", authenticate, async (req, res) => {
  const name = String(req.body?.name || "").trim();
  if (!name) {
    return res.status(400).json({ error: "Workspace name is required" });
  }

  const workspaceName = name.slice(0, 120);
  const schemaSuffix = `${req.user.user_id}_${Date.now().toString(36)}`;
  const schemaName = `workspace_${schemaSuffix}`.replace(/[^a-zA-Z0-9_]/g, "_").toLowerCase();

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query(`CREATE SCHEMA ${schemaName}`);

    const workspaceResult = await client.query(
      `
        INSERT INTO public.workspaces (name, schema_name, owner_user_id)
        VALUES ($1, $2, $3)
        RETURNING id, name, schema_name, owner_user_id, created_at, updated_at;
      `,
      [workspaceName, schemaName, req.user.user_id]
    );

    const workspace = workspaceResult.rows[0];

    await client.query(
      `
        INSERT INTO public.workspace_members (workspace_id, user_id, role)
        VALUES ($1, $2, 'owner');
      `,
      [workspace.id, req.user.user_id]
    );

    await client.query("COMMIT");

    res.status(201).json({ ...workspace, role: "owner" });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Failed to create workspace:", err);
    res.status(500).json({ error: "Failed to create workspace" });
  } finally {
    client.release();
  }
});

app.get("/workspaces/:id/members", authenticate, async (req, res) => {
  const workspaceId = Number(req.params.id);
  if (!Number.isInteger(workspaceId) || workspaceId <= 0) {
    return res.status(400).json({ error: "Invalid workspace id" });
  }

  try {
    const membership = await pool.query(
      `SELECT role FROM public.workspace_members WHERE workspace_id = $1 AND user_id = $2 LIMIT 1`,
      [workspaceId, req.user.user_id]
    );

    if (membership.rows.length === 0) {
      return res.status(403).json({ error: "Workspace access denied" });
    }

    const result = await pool.query(
      `
        SELECT wm.user_id, u.username, wm.role, wm.joined_at
        FROM public.workspace_members wm
        JOIN public.users u ON u.id = wm.user_id
        WHERE wm.workspace_id = $1
        ORDER BY CASE wm.role WHEN 'owner' THEN 0 WHEN 'editor' THEN 1 ELSE 2 END, u.username;
      `,
      [workspaceId]
    );

    res.json(result.rows);
  } catch (err) {
    console.error("Failed to fetch workspace members:", err);
    res.status(500).json({ error: "Failed to fetch workspace members" });
  }
});

app.post("/workspaces/:id/members", authenticate, async (req, res) => {
  const workspaceId = Number(req.params.id);
  if (!Number.isInteger(workspaceId) || workspaceId <= 0) {
    return res.status(400).json({ error: "Invalid workspace id" });
  }

  const username = String(req.body?.username || "").trim();
  const role = normalizeWorkspaceRole(req.body?.role);

  if (!username) {
    return res.status(400).json({ error: "Username is required" });
  }

  if (role === "owner") {
    return res.status(400).json({ error: "Assign editor or viewer role for members" });
  }

  try {
    const requester = await pool.query(
      `SELECT role FROM public.workspace_members WHERE workspace_id = $1 AND user_id = $2 LIMIT 1`,
      [workspaceId, req.user.user_id]
    );

    if (requester.rows.length === 0) {
      return res.status(403).json({ error: "Workspace access denied" });
    }

    if (requester.rows[0].role !== "owner") {
      return res.status(403).json({ error: "Only workspace owner can manage members" });
    }

    const userResult = await pool.query(
      `SELECT id, username FROM public.users WHERE username = $1 LIMIT 1`,
      [username]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const target = userResult.rows[0];

    await pool.query(
      `
        INSERT INTO public.workspace_members (workspace_id, user_id, role)
        VALUES ($1, $2, $3)
        ON CONFLICT (workspace_id, user_id)
        DO UPDATE SET role = EXCLUDED.role;
      `,
      [workspaceId, target.id, role]
    );

    res.json({ message: "Member role updated", user_id: target.id, username: target.username, role });
  } catch (err) {
    console.error("Failed to add workspace member:", err);
    res.status(500).json({ error: "Failed to add workspace member" });
  }
});

app.get("/saved-queries", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `
        SELECT
          id,
          name,
          query,
          description,
          tags,
          is_favorite,
          last_run_at,
          created_at,
          updated_at
        FROM public.saved_queries
        WHERE user_id = $1
        ORDER BY is_favorite DESC, updated_at DESC;
      `,
      [req.user.user_id]
    );

    res.json(result.rows);
  } catch (err) {
    console.error("Failed to fetch saved queries:", err);
    res.status(500).json({ error: "Failed to fetch saved queries" });
  }
});

app.post("/saved-queries", authenticate, async (req, res) => {
  const name = String(req.body?.name || "").trim();
  const query = String(req.body?.query || "").trim();
  const description = String(req.body?.description || "").trim();
  const tags = normalizeTags(req.body?.tags);

  if (!name || !query) {
    return res.status(400).json({ error: "Name and query are required" });
  }

  if (name.length > 120) {
    return res.status(400).json({ error: "Name must be 120 characters or less" });
  }

  if (query.length > 10000) {
    return res.status(400).json({ error: "Query is too long" });
  }

  try {
    const result = await pool.query(
      `
        INSERT INTO public.saved_queries (user_id, name, query, description, tags)
        VALUES ($1, $2, $3, $4, $5::jsonb)
        RETURNING id, name, query, description, tags, is_favorite, last_run_at, created_at, updated_at;
      `,
      [req.user.user_id, name, query, description, JSON.stringify(tags)]
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error("Failed to save query:", err);
    res.status(500).json({ error: "Failed to save query" });
  }
});

app.put("/saved-queries/:id", authenticate, async (req, res) => {
  const queryId = Number(req.params.id);
  if (!Number.isInteger(queryId) || queryId <= 0) {
    return res.status(400).json({ error: "Invalid query id" });
  }

  const name = String(req.body?.name || "").trim();
  const query = String(req.body?.query || "").trim();
  const description = String(req.body?.description || "").trim();
  const tags = normalizeTags(req.body?.tags);
  const isFavorite = Boolean(req.body?.isFavorite);

  if (!name || !query) {
    return res.status(400).json({ error: "Name and query are required" });
  }

  if (name.length > 120) {
    return res.status(400).json({ error: "Name must be 120 characters or less" });
  }

  if (query.length > 10000) {
    return res.status(400).json({ error: "Query is too long" });
  }

  try {
    const result = await pool.query(
      `
        UPDATE public.saved_queries
        SET
          name = $1,
          query = $2,
          description = $3,
          tags = $4::jsonb,
          is_favorite = $5,
          updated_at = NOW()
        WHERE id = $6 AND user_id = $7
        RETURNING id, name, query, description, tags, is_favorite, last_run_at, created_at, updated_at;
      `,
      [name, query, description, JSON.stringify(tags), isFavorite, queryId, req.user.user_id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Saved query not found" });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error("Failed to update saved query:", err);
    res.status(500).json({ error: "Failed to update saved query" });
  }
});

app.delete("/saved-queries/:id", authenticate, async (req, res) => {
  const queryId = Number(req.params.id);
  if (!Number.isInteger(queryId) || queryId <= 0) {
    return res.status(400).json({ error: "Invalid query id" });
  }

  try {
    const result = await pool.query(
      `DELETE FROM public.saved_queries WHERE id = $1 AND user_id = $2 RETURNING id`,
      [queryId, req.user.user_id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Saved query not found" });
    }

    res.json({ message: "Saved query deleted" });
  } catch (err) {
    console.error("Failed to delete saved query:", err);
    res.status(500).json({ error: "Failed to delete saved query" });
  }
});

app.post("/saved-queries/:id/run", authenticate, async (req, res) => {
  const queryId = Number(req.params.id);
  if (!Number.isInteger(queryId) || queryId <= 0) {
    return res.status(400).json({ error: "Invalid query id" });
  }

  try {
    const result = await pool.query(
      `
        UPDATE public.saved_queries
        SET last_run_at = NOW(), updated_at = NOW()
        WHERE id = $1 AND user_id = $2
        RETURNING id, last_run_at;
      `,
      [queryId, req.user.user_id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Saved query not found" });
    }

    res.json({ message: "Saved query marked as used", lastRunAt: result.rows[0].last_run_at });
  } catch (err) {
    console.error("Failed to update saved query usage:", err);
    res.status(500).json({ error: "Failed to update saved query usage" });
  }
});

await ensureWorkspacesTables();
await ensureUserProfilesTable();
await ensureSavedQueriesTable();

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on ${PORT}`);
});
