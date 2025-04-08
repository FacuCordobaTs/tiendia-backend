import { getCookie } from 'hono/cookie';
import jwt from 'jsonwebtoken';
import { drizzle } from 'drizzle-orm/mysql2'; // Cambiamos a mysql2
import { pool } from '../db'; // Importamos el pool de MySQL
import { eq } from 'drizzle-orm';
import { users } from '../db/schema';


export const authMiddleware = async (c: any, next: Function) => {
  try {
    const token = getCookie(c, 'token');
    if (!token) {
      return c.json({ message: 'No hay token' }, 200);
    }

    const decoded = await new Promise((resolve, reject) => {
      jwt.verify(token, process.env.TOKEN_SECRET || 'my-secret', (error, decoded) => {
        if (error) reject(error);
        resolve(decoded);
      });
    });

    const db = drizzle(pool); // Usamos el pool de MySQL
    const user = await db.select().from(users)
      .where(eq(users.id, (decoded as jwt.JwtPayload).id))

    if (!user) {
      return c.json({ message: 'Usuario no encontrado' }, 400);
    }
    c.set('user', user);
    await next();
  } catch (error) {
    return c.json({ message: 'Invalid or expired token' }, 200);
  }
};