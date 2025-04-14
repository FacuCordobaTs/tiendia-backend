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

    const decoded = jwt.verify(token, process.env.TOKEN_SECRET || '')

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
        metadata: {
          user_id: (decoded as JwtPayload).id,
          credits
        },
        back_urls: {
          success: `https://tiendia.app/successfullPayment`,
        },
        notification_url: "https://api.tiendia.app/api/payments/webhook"
      }),
    });
    const preference = await response.json();

    return c.json({ preference });
});

paymentsRoute.post('/webhook', async (c) => {
    // const id = await c.req.query('id');
    // const url = `https://api.mercadopago.com/merchant_orders/${id}`;
    // const db = drizzle(pool);

    // const response = await fetch(url,{
    //       headers: {
    //         'Content-Type': 'application/json',
    //         'Authorization': 'Bearer ACCES_TOKEN' 
    //       }
    // })

    // const data = await response.json() as { metadata: { user_id: number, credits: number } };
    // const userId = data.metadata.user_id
    // const credits = data.metadata.credits;

    // if (userId && credits)  {
    //     await db.update(users)
    //         .set({
    //             credits
    //         })
    //         .where(eq(users.id, userId));

    // }
  
    return c.status(200);
  });


export default paymentsRoute