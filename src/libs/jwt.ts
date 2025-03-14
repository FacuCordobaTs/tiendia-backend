import jwt from "jsonwebtoken";

const TOKEN_SECRET = 'my-token-secret';

export async function createAccessToken(payload: any) {
  return new Promise((resolve, reject) => {
    jwt.sign(payload, TOKEN_SECRET, { expiresIn: "1d" }, (err, token) => {
      if (err) reject(err);
      resolve(token);
    });
  });
}