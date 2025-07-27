// src/routes/credits.ts
import { Hono } from 'hono';
import { users } from '../db/schema';
import { eq } from 'drizzle-orm';
import { getCookie } from 'hono/cookie';
import jwt, { JwtPayload } from "jsonwebtoken";
import { drizzle } from "drizzle-orm/mysql2";
import { pool } from "../db";
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';

const creditsRouter = new Hono();

const AUTO_CHARGE_AMOUNT = 500;

const addCreditsSchema = z.object({
    credits: z.number(),
});

creditsRouter
.post('/auto-charge', async (c) => {
    const token = getCookie(c, 'token');
    if (!token) return c.json({ error: 'Unauthorized' }, 401);
    const db = drizzle(pool);

    const decoded = await new Promise((resolve, reject) => {
        jwt.verify(token, process.env.TOKEN_SECRET || 'my-secret', (error, decoded) => {
            if (error) reject(error);
            resolve(decoded);
        });
    });

    try {
        // Obtener los créditos actuales del usuario
        const currentUser = await db.select({ credits: users.credits }).from(users).where(eq(users.id, (decoded as JwtPayload).id)).limit(1);

        if (!currentUser || currentUser.length === 0) {
            return c.json({ message: 'Usuario no encontrado' }, 404);
        }

        const currentCredits = currentUser[0].credits;

        if (currentCredits == null) {
            console.log("No se puede cargar automaticamente")
            return c.json({ message: 'No se puede cargar automaticamente' }, 404);
        }

        // Restar los créditos
        const updatedUser = await db.update(users)
            .set({ credits: currentCredits + AUTO_CHARGE_AMOUNT })
            .where(eq(users.id, (decoded as JwtPayload).id))

        return c.json({ 
            message: `Se han agregadp ${AUTO_CHARGE_AMOUNT} créditos exitosamente.`, 
            newCredits: currentCredits + AUTO_CHARGE_AMOUNT
        });

    } catch (error: any) {
        console.error('Error al descontar créditos:', error);
        return c.json({ message: 'Error interno del servidor al procesar el cargo automático', error: error.message }, 500);
    }
})
.post('/admin-add-credits', zValidator("json",addCreditsSchema), async (c) => {
    const { credits } = c.req.valid('json');
    const token = getCookie(c, 'token');
    if (!token) return c.json({ error: 'Unauthorized' }, 401);
    const db = drizzle(pool);

    const decoded = await new Promise((resolve, reject) => {
        jwt.verify(token, process.env.TOKEN_SECRET || 'my-secret', (error, decoded) => {
            if (error) reject(error);
            resolve(decoded);
        });
    });

    if ((decoded as JwtPayload).email !== 'review2025@tiendia.app') {
        return c.json({ error: 'Unauthorized' }, 401);
    }

    const currentUser = await db.select({ credits: users.credits }).from(users).where(eq(users.id, (decoded as JwtPayload).id)).limit(1);

    const currentCredits = currentUser[0].credits;

    if (currentCredits == null) {
        console.log("No se puede cargar automaticamente")
        return c.json({ message: 'No se puede cargar automaticamente' }, 404);
    }

    await db.update(users)
        .set({ credits: currentCredits + credits })
        .where(eq(users.id, (decoded as JwtPayload).id))

    return c.json({ message: `Se han agregado ${credits} créditos exitosamente.` });
})

export default creditsRouter;