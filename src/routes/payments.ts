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
    const decodedPayload = decoded as JwtPayload;
    const userId = decodedPayload.id;

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
                description: "Carga de imágenes para generar con IA en tiendia.app",
                custom_id: userId,
                
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

  async function verifyPaypalWebhook(c: any): Promise<boolean> {
    const headers = c.req.header();
    const body = await c.req.text(); // Necesitamos el body en formato raw para la verificación

    const request = {
        auth_algo: headers['paypal-auth-algo'],
        cert_url: headers['paypal-cert-url'],
        transmission_id: headers['paypal-transmission-id'],
        transmission_sig: headers['paypal-transmission-sig'],
        transmission_time: headers['paypal-transmission-time'],
        webhook_id: process.env.PAYPAL_WEBHOOK_ID_TEST!, // Tu ID de webhook de PayPal
        webhook_event: body
    };

    try {
        const verificationResponse = await fetch('https://api.sandbox.paypal.com/v1/notifications/verify-webhook-signature', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${await getPaypalAccessToken()}` // Necesitamos un token de acceso
            },
            body: JSON.stringify(request)
        });

        const verificationData = await verificationResponse.json() as { verification_status: string };
        return verificationData.verification_status === 'SUCCESS';
    } catch (error) {
        console.error("Error verifying PayPal webhook:", error);
        return false;
    }
}

async function getPaypalAccessToken(): Promise<string> {
    const auth = Buffer.from(`${process.env.PAYPAL_CLIENT_ID_TEST!}:${process.env.PAYPAL_SECRET_TEST!}`).toString('base64');
    const response = await fetch('https://api.sandbox.paypal.com/v1/oauth2/token', {
        method: 'POST',
        headers: {
            'Authorization': `Basic ${auth}`,
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: 'grant_type=client_credentials'
    });
    const data = await response.json() as { access_token: string };
    return data.access_token;
}


// Nuevo endpoint para el webhook de PayPal
paymentsRoute.post('/paypal-webhook', async (c) => {
    const db = drizzle(pool);

    try {
        // 1. Verificar la autenticidad del Webhook
        const isVerified = await verifyPaypalWebhook(c);

        if (!isVerified) {
            console.error("PayPal webhook verification failed.");
            return c.json({ error: 'Webhook verification failed' }, 401);
        }

        // 2. Procesar el evento
        const event = await c.req.json();
        
        // Solo nos interesa el evento cuando la captura del pago se completa
        if (event.event_type === 'PAYMENT.CAPTURE.COMPLETED') {
            const capture = event.resource;
            const purchaseUnit = capture.purchase_units[0];
            const amountPaid = parseFloat(purchaseUnit.payments.captures[0].amount.value);
            const userId = purchaseUnit.custom_id; // <-- Recuperamos el ID de nuestro usuario

            if (!userId) {
                console.error("Webhook received without a custom_id (userId).");
                return c.json({ message: 'Processed, but no user ID found.' }, 200);
            }
            
            // 3. Buscar al usuario en la BD
            const userResult = await db.select().from(users).where(eq(users.id, userId));
            const user = userResult[0];

            if (!user || user.credits === null) {
                console.error(`User with ID ${userId} not found or has null credits.`);
                return c.json({ error: 'User not found' }, 404);
            }

            // 4. Asignar créditos basados en el monto pagado
            let creditsToAdd = 0;
            if (amountPaid === 4.50) {
                creditsToAdd = 2500;
            } else if (amountPaid === 8.30) {
                creditsToAdd = 5000;
            } else {
                console.warn(`Payment received for an unconfigured amount: ${amountPaid}`);
            }

            if (creditsToAdd > 0) {
                const newTotalCredits = (user.credits || 0) + creditsToAdd;
                await db.update(users)
                    .set({ credits: newTotalCredits })
                    .where(eq(users.id, userId));
                
                console.log(`Successfully added ${creditsToAdd} credits to user ${userId}. New balance: ${newTotalCredits}.`);
            }
        }

        // 5. Responder a PayPal con un 200 OK
        // Es crucial responder rápidamente para que PayPal no reintente enviar el webhook.
        return c.json({ message: 'Webhook processed successfully' }, 200);

    } catch (error: any) {
        console.error("Error processing PayPal webhook:", error.message);
        return c.json({ error: 'Internal Server Error' }, 500);
    }
});


export default paymentsRoute