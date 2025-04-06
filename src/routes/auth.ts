import { Hono } from 'hono';
import { eq } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/mysql2';
import { pool } from '../db';
import { z } from "zod";
import { zValidator } from "@hono/zod-validator";
import {
    getCookie,
    setCookie,
    deleteCookie,
} from 'hono/cookie';
import jwt, { JwtPayload } from "jsonwebtoken";
import { users } from '../db/schema';
import bcrypt from "bcryptjs";
import { createAccessToken } from "../libs/jwt";
import UUID from 'uuid-js';
import { authMiddleware } from '../middlewares/auth.middleware';
import { writeFile, unlink } from "fs/promises";
import { join } from "path";

const UPLOAD_DIR = join(process.cwd(), 'public', 'uploads');

// Funciones de manejo de imágenes (sin cambios)
async function saveImage(base64String: string): Promise<string> {
    const base64Data = base64String.replace(/^data:image\/\w+;base64,/, "");
    const buffer = Buffer.from(base64Data, 'base64');
    const uuid = UUID.create().toString();
    const fileName = `${uuid}.png`;
    const filePath = join(UPLOAD_DIR, fileName);
    await writeFile(filePath, buffer);
    return `/uploads/${fileName}`;
}

async function updateImage(oldUrl: string, newBase64: string): Promise<string> {
    await deleteImage(oldUrl);
    return await saveImage(newBase64);
}

async function deleteImage(imageUrl: string): Promise<void> {
    try {
        const fileName = imageUrl.split("/").pop();
        if (!fileName) {
            console.warn("URL de imagen inválida:", imageUrl);
            return;
        }
        const filePath = join(UPLOAD_DIR, fileName);
        await unlink(filePath);
    } catch (error: any) {
        if (error.code === "ENOENT") {
            console.warn("Imagen no encontrada:", imageUrl);
        } else {
            console.error("Error al eliminar la imagen:", error);
        }
    }
}

// Esquemas de validación
const userSchema = z.object({
    email: z.string().min(3).max(255),
    password: z.string().min(6),
});

const signUpSchema = z.object({
    email: z.string().min(3).max(255),
    password: z.string().min(6),
    category: z.string(),
});

const updateSchema = z.object({
    category: z.string()
});

// Rutas
export const authRoute = new Hono()
    .post('/register', zValidator("json", signUpSchema), async (c) => {
        const { email, password, category } = c.req.valid("json");
        const db = drizzle(pool);

        try {
            const existingEmail = await db.select().from(users)
                .where(eq(users.email, email));

            if (existingEmail.length) {
                return c.json({ error: 'Email already used', existingEmail }, 409);
            }

            const passwordHash = await bcrypt.hash(password, 10);
            await db.insert(users).values({
                email,
                password: passwordHash,
                category,
                createdAt: new Date()
            });

            const newUser = await db.select().from(users)
                .where(eq(users.email, email))
                .limit(1);

            const token = await createAccessToken({ id: newUser[0].id });
            setCookie(c, 'token', token as string, {
                path: '/',
                sameSite: 'None',
                secure: true,
                maxAge: 7 * 24 * 60 * 60,
            });

            return c.json({ message: 'Usuario registrado correctamente', newUser }, 200);
        } catch (error: any) {
            return c.json({ message: 'Error al registrar el usuario: ' + error.message }, 400);
        }
    })
    .put('/update', zValidator("json", updateSchema), authMiddleware, async (c) => {
        try {
            const { category } = c.req.valid("json");
            const db = drizzle(pool);
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

            await db.update(users)
                .set({ category })
                .where(eq(users.id, (decoded as jwt.JwtPayload).id));

            return c.json({
                message: 'Usuario actualizado correctamente'
            }, 200);
        } catch (error: any) {
            return c.json({ message: error.message }, 500);
        }
    })
    // Rutas no modificadas (login, profile, logout, fcm-token) se mantienen igual
    .post('/login', zValidator("json", userSchema), async (c) => {
        const { email, password } = c.req.valid("json");
        const db = drizzle(pool);

        try {
            const user = await db.select().from(users)
                .where(eq(users.email, email));

            if (!user.length) {
                return c.json({ message: 'Usuario no encontrado' }, 400);
            }

            const isMatch = await bcrypt.compare(password, user[0].password);
            if (!isMatch) {
                return c.json({ message: 'Contraseña incorrecta' }, 400);
            }

            const token = await createAccessToken({ id: user[0].id });
            setCookie(c, 'token', token as string, {
                path: '/',
                sameSite: 'None',
                secure: true,
                maxAge: 7 * 24 * 60 * 60,
            });

            return c.json({ message: 'Inicio de sesión realizado con éxito', user }, 200);
        } catch (error) {
            return c.json({ error: 'Login failed' }, 500);
        }
    })
    .get('/profile', async (c) => {
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

        const db = drizzle(pool);
        const user = await db.select().from(users)
            .where(eq(users.id, (decoded as jwt.JwtPayload).id));

        if (!user.length) {
            return c.json({ message: 'Usuario no encontrado' }, 400);
        }
        return c.json({ user }, 200);
    })
    .delete('/logout', async (c) => {
        deleteCookie(c, 'token');
        return c.json({ message: 'Logout successful' }, 200);
    })