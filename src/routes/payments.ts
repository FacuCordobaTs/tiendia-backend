import { zValidator } from "@hono/zod-validator";
import { Hono } from "hono";
import { z } from "zod";
import jwt, { JwtPayload } from "jsonwebtoken";
import { getCookie } from "hono/cookie";
import * as UUID from 'uuid';
import { users } from "../db/schema";
import { drizzle } from "drizzle-orm/mysql2";
import { pool } from "../db";
import { eq } from "drizzle-orm";

export type Env = {};

const paymentsRoute = new Hono<{ Bindings: Env }>();

const creditSchema = z.object({
    credits: z.number(),
});

paymentsRoute.post("/create-preference", zValidator("json",creditSchema), async (c) => {
    const { credits } = c.req.valid("json");
    const token = getCookie(c, 'token');
    if (!token) return c.json({ error: 'Unauthorized' }, 401);
    const db = drizzle(pool);

    const decoded = await new Promise((resolve, reject) => {
        jwt.verify(token, process.env.TOKEN_SECRET || 'my-secret', (error, decoded) => {
            if (error) reject(error);
            resolve(decoded);
        });
    });

    const response = await fetch('https://api.mercadopago.com/checkout/preferences', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + process.env.MP_ACCESS_TOKEN,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        items: [
          {
            id: UUID.v4(),
            title: `Carga de creditos`,
            unit_price: credits,
            quantity: 1,
            currency_id: "ARS"
          }
        ],
        back_urls: {
          success: `https://tiendia.app/home`,
        },
        notification_url: "https://api.tiendia.app/api/payments/webhook"
      }),
    });
    const preference = await response.json() as { id: string };

    if (preference && preference.id) {
      await db.update(users).set({
        lastPreferenceId: preference.id
      })
      .where(eq(users.id, (decoded as JwtPayload).id));
    }

    console.log("PREFERENCEID: ", preference.id)
    return c.json({ preference });
});

paymentsRoute.post('/webhook', async (c) => {
    try {
      const id = c.req.query('id');
    console.log("SOLICITUD RECIBIDA MP", id);

    if (!id) {
        return c.json({ error: 'Missing id parameter' }, 400);
    }
    const url = `https://api.mercadopago.com/merchant_orders/${id}`;
    const db = drizzle(pool);

    const response = await fetch(url,{
          headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer '+ process.env.MP_ACCESS_TOKEN 
          }
    })

    const data = await response.json() as { items: { id: string, title: string, unit_price: number, quantity: number }[], preference_id: string };
    console.log("Data: " ,data)

    const credits = data.items[0].unit_price;
    const preferenceId = data.preference_id;

    const user = await db.select().from(users)
        .where(eq(users.lastPreferenceId, preferenceId));

    console.log(user[0])

    if (user[0] && user[0].credits) {
        await db.update(users).set({
          credits: user[0].credits + credits
      }).where(eq(users.lastPreferenceId, preferenceId));
    }

    return c.json({ message: 'Webhook processed successfully' }, 200);
    } catch (error) {
        console.error("Error processing webhook:", error);
        return c.json({ error: 'Internal Server Error' }, 500);
    }
  });


export default paymentsRoute