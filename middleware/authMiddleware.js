// import jwt from "jsonwebtoken";

// function authenticate(req, res, next) {
//   const token = req.headers.authorization?.split(" ")[1];
    // //console.log("Authenticating request with token:", token);
//   if (!token) {
//     return res.status(401).json({ message: "No token provided" });
//   }

//   try {
//     const decoded = jwt.verify(token, process.env.JWT_SECRET);
//     req.user = decoded;
//     next();
//   } catch {
//     return res.status(403).json({ message: "Invalid token" });
//   }
// }

// export default authenticate;


import jwt from "jsonwebtoken";

function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "No token provided" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    req.user = decoded;   // { user_id, schema, iat, exp }
    next();

  } catch (error) {

    // Token expired
    if (error.name === "TokenExpiredError") {
      return res.status(401).json({ message: "Token expired" });
    }

    // Invalid token
    return res.status(401).json({ message: "Invalid token" });
  }
}

export default authenticate;