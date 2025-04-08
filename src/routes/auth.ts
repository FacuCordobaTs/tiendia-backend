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
import { writeFile, unlink } from "fs/promises";
import { join } from "path";
import { OAuth2Client } from 'google-auth-library';
import crypto from 'crypto';

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
const googleClient = new OAuth2Client(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_REDIRECT_URI
);

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
});

// Rutas
export const authRoute = new Hono()
.post('/register', zValidator("json", signUpSchema), async (c) => {
    const { email, password } = c.req.valid("json");
    const db = drizzle(pool);

    try {
        const existingEmail = await db.select().from(users)
            .where(eq(users.email, email));

        if (existingEmail.length) {
            return c.json({ error: 'Email ya utilizado', existingEmail }, 409);
        }

        const passwordHash = await bcrypt.hash(password, 10);
        await db.insert(users).values({
            email,
            password: passwordHash,
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
        return c.json({ message: 'Error al registrar el usuario'}, 400);
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

        if (!user[0].password) {
            return c.json({ message: 'Contraseña no válida' }, 400);
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

        const db = drizzle(pool);
        const user = await db.select().from(users)
            .where(eq(users.id, (decoded as jwt.JwtPayload).id));

        if (!user.length) {
            return c.json({ message: 'Usuario no encontrado' }, 400);
        }
        return c.json({ user }, 200);
    } catch (error) {
        return c.json({ message: 'Error al obtener el perfil del usuario'}, 400);
    }
})
.delete('/logout', async (c) => {
    deleteCookie(c, 'token');
    return c.json({ message: 'Logout successful' }, 200);
})  
.get('/google', async (c) => {
    const state = crypto.randomBytes(16).toString('hex');
    setCookie(c, 'oauth_state', state, {
        path: '/api/auth/google/callback',
        httpOnly: true,
        maxAge: 600,
        sameSite: 'None',
        secure: process.env.NODE_ENV === 'production',
    });

    const authUrl = googleClient.generateAuthUrl({
        access_type: 'offline',
        scope: [
            'https://www.googleapis.com/auth/userinfo.email',
            'https://www.googleapis.com/auth/userinfo.profile',
            'openid', 
        ],
        state: state,
    });
    return c.redirect(authUrl);
})

.get('/google/callback', async (c) => {
    const db = drizzle(pool);
    const code = c.req.query('code');
    
    deleteCookie(c, 'oauth_state', { path: '/api/auth/google/callback' });


    if (!code) {
        
            const error = c.req.query('error');
            console.error("Google OAuth Error:", error);
            return c.redirect(`https://tiendia.app/login?error=${error || 'unknown_google_error'}`);
    }

    try {
        
        const { tokens } = await googleClient.getToken(code);
        googleClient.setCredentials(tokens); 

        
        if (!tokens.id_token) {
            throw new Error("ID token not received from Google.");
        }
        const loginTicket = await googleClient.verifyIdToken({
            idToken: tokens.id_token,
            audience: process.env.GOOGLE_CLIENT_ID,
        });
        const payload = loginTicket.getPayload();
        if (!payload || !payload.sub || !payload.email) {
            throw new Error('Información de perfil de Google inválida.');
        }

        const googleId = payload.sub;
        const email = payload.email;

        
        let user: (typeof users.$inferSelect) | null = null;
        const existingUser = await db.select().from(users)
            .where(eq(users.email, email))
            .limit(1);

        if (existingUser.length) {
            
            user = existingUser[0];
            
            if (!user.googleId) {
                await db.update(users)
                .set({ googleId: googleId }) 
                .where(eq(users.id, user.id));
                user.googleId = googleId; 
            } else if (user.googleId !== googleId) {
                return c.redirect(`${process.env.FRONTEND_URL}/login?error=email_google_conflict`);
            }
            

        } else {
            const insertResult = await db.insert(users).values({
                email,
                googleId,
                createdAt: new Date(),
            });
            const userId = insertResult[0].insertId;
            const newUserResult = await db.select().from(users)
            .where(eq(users.id, userId))
            .limit(1);
            if (!newUserResult.length) {
                throw new Error("No se pudo encontrar el usuario de Google recién creado.");
            }
            user = newUserResult[0];

        }

        
        if (!user) { 
                throw new Error("No se pudo obtener o crear la información del usuario.");
        }
        const token = await createAccessToken({ id: user.id });

        setCookie(c, 'token', token as string, {
            path: '/',
            sameSite: 'None',
            secure: true,
            maxAge: 7 * 24 * 60 * 60,
        });
        
        return c.redirect(`${process.env.FRONTEND_URL}/dashboard`); 


    } catch (error: any) {
        console.error("Google Callback Error:", error);
        
        return c.redirect(`${process.env.FRONTEND_URL}/login?error=google_callback_failed`);
    }
});
