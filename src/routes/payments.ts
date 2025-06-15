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
import { MercadoPagoConfig, PreApproval} from "mercadopago";
export type Env = {};

const paymentsRoute = new Hono<{ Bindings: Env }>();

const creditSchema = z.object({
    credits: z.number(),
});

export const mercadopago = new MercadoPagoConfig({
  accessToken: process.env.MP_ACCESS_TOKEN_TEST!,
});

paymentsRoute.post("/create-preapproval", async (c) => {
  const db = drizzle(pool);
  const token = getCookie(c, 'token');
  
  if (!token) return c.json({ error: 'Unauthorized' }, 401);
  const decoded = await new Promise((resolve, reject) => {
    jwt.verify(token, process.env.TOKEN_SECRET || 'my-secret', (error, decoded) => {
      if (error) reject(error);
      resolve(decoded);
    });
  });

  const user = await db.select().from(users).where(eq(users.id, (decoded as JwtPayload).id));

  const suscription = await new PreApproval(mercadopago).create({
    body: {
      back_url: "https://my.tiendia.app/home",
      reason: "Suscripción a tiendia.app",
      auto_recurring: {
        frequency: 1, 
        frequency_type: "months",
        transaction_amount: 3500,
        currency_id: "ARS",
      },
      payer_email: user[0].email,
      status: "pending"
    },
  });

  return c.json({ suscription });
});

paymentsRoute.post("/suscriptions-webhook", async (c) => {
  const db = drizzle(pool);
  const token = getCookie(c, 'token');
  if (!token) return c.json({ error: 'Unauthorized' }, 401);

  const decoded = await new Promise((resolve, reject) => {
    jwt.verify(token, process.env.TOKEN_SECRET || 'my-secret', (error, decoded) => {
      if (error) reject(error);
      resolve(decoded);
    });
  });

  const user = await db.select().from(users).where(eq(users.id, (decoded as JwtPayload).id));
  
  const body: {data: {id: string}; type: string} = await c.req.json();

  if (body.type === "subscription_preapproval") {
    const preapproval = await new PreApproval(mercadopago).get({id: body.data.id});
    console.log(preapproval);
    if (preapproval.status === "authorized") {
      await db.update(users).set({
        suscriptionId: body.data.id,
      }).where(eq(users.id, (decoded as JwtPayload).id));
    }
  }
})

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
          success: `https://my.tiendia.app/home`,
        },
        notification_url: "https://api.tiendia.app/api/payments/webhook"
      }),
    });
    const preference = await response.json() as { id: string };

    if (preference && preference.id) {
      await db.update(users).set({
        lastPreferenceId: preference.id,
        lastPreferencePaid: false,
      })
      .where(eq(users.id, (decoded as JwtPayload).id));
    }

    console.log("PREFERENCEID: ", preference.id)
    return c.json({ preference });
});

paymentsRoute.post('/webhook', async (c) => {
    try {
      const id = c.req.query('id');

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

    const data = await response.json() as { items: { id: string, title: string, unit_price: number, quantity: number }[], preference_id: string, status: string };

    const credits = data.items[0].unit_price;
    const preferenceId = data.preference_id;

    const user = await db.select().from(users)
        .where(eq(users.lastPreferenceId, preferenceId));

    if (user[0] && user[0].credits != null && !user[0].lastPreferencePaid && data?.status == "closed") {
      if (credits == 80) {
        await db.update(users).set({
          credits: user[0].credits + 50,
          lastPreferencePaid: true,
        }).where(eq(users.lastPreferenceId, preferenceId));
      } else if (credits == 800) {
        await db.update(users).set({
          credits: user[0].credits + 500,
          lastPreferencePaid: true,
        }).where(eq(users.lastPreferenceId, preferenceId));
      } else if (credits == 3500) {
        await db.update(users).set({
          credits: user[0].credits + 2500,
          lastPreferencePaid: true,
        }).where(eq(users.lastPreferenceId, preferenceId));
      } else if (credits == 6800) {
        await db.update(users).set({
          credits: user[0].credits + 5000,
          lastPreferencePaid: true,
        }).where(eq(users.lastPreferenceId, preferenceId));
      }
      
    }

    return c.json({ message: 'Webhook processed successfully' }, 200);
    } catch (error) {
        console.error("Error processing webhook:", error);
        return c.json({ error: 'Internal Server Error' }, 500);
    }
  });


export default paymentsRoute