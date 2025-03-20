import jwt from "jsonwebtoken";

export async function createAccessToken(payload: any) {
  return new Promise((resolve, reject) => {
    jwt.sign(payload, process.env.TOKEN_SECRET || 'my-secret', { expiresIn: "1d" }, (err, token) => {
      if (err) reject(err);
      resolve(token);
    });
  });
}