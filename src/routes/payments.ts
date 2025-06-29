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
import paypal from "@paypal/checkout-server-sdk";

export type Env = {};

const paymentsRoute = new Hono<{ Bindings: Env }>();

const creditSchema = z.object({
    credits: z.number(),
});

const paypalSchema = z.object({
    price: z.number(),
}); 

export const mercadopago = new MercadoPagoConfig({
  accessToken: process.env.MP_ACCESS_TOKEN_TEST!,
});


const environment = new paypal.core.SandboxEnvironment(process.env.PAYPAL_CLIENT_ID_TEST!, process.env.PAYPAL_SECRET_TEST!);
const client = new paypal.core.PayPalHttpClient(environment);

paymentsRoute.post("/create-paypal-order", zValidator("json", paypalSchema), async (c) => {
  try {
    const { price } = c.req.valid("json");
    const token = getCookie(c, 'token');
    if (!token) return c.json({ error: 'Unauthorized' }, 401);
    const db = drizzle(pool);

    const decoded = await new Promise((resolve, reject) => {
        jwt.verify(token, process.env.TOKEN_SECRET || 'my-secret', (error, decoded) => {
            if (error) reject(error);
            resolve(decoded);
        });
    });

    const request = new paypal.orders.OrdersCreateRequest();
    
    console.log(request);
    
    request.requestBody({
        intent: "CAPTURE",
        purchase_units: [
            {
                amount: {
                    currency_code: "USD",
                    value: price.toString(),
                },
                description: "Carga de imágenes",
                
            }
        ]
    })
    
    const response = await client.execute(request);
    const orderId = response.result.id;
    return c.json({ orderId });
  } catch (error: any) {
    console.error("Error creating PayPal order:", error);
    return c.json({ error: error.message }, 500);
  }
    
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
            title: `Carga de imágenes`,
            unit_price: credits,
            quantity: 1,
            description: "Imagenes para generar con IA",
            currency_id: "ARS"
          }
        ],
        back_urls: {
          success: `https://my.tiendia.app/home`,
        },
        notification_url: "https://api.tiendia.app/api/payments/webhook",
        statement_descriptor: "Carga de imagen",
        external_reference: UUID.v4()
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
      if (credits == 150) {
        await db.update(users).set({
          credits: user[0].credits + 50,
          lastPreferencePaid: true,
        }).where(eq(users.lastPreferenceId, preferenceId));
      } else if (credits == 1500) {
        await db.update(users).set({
          credits: user[0].credits + 500,
          lastPreferencePaid: true,
        }).where(eq(users.lastPreferenceId, preferenceId));
      } else if (credits == 6600) {
        await db.update(users).set({
          credits: user[0].credits + 2500,
          lastPreferencePaid: true,
        }).where(eq(users.lastPreferenceId, preferenceId));
      } else if (credits == 12750) {
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