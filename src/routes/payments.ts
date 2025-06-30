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
  async function verifyPaypalWebhook(headers: any, rawBody: string): Promise<boolean> {
    // 1. Añadimos un log para ver el rawBody que estamos recibiendo.
    console.log("--- RAW BODY RECEIVED ---");
    console.log(rawBody);
    console.log("-------------------------");

    // Validamos que el body no esté vacío
    if (!rawBody) {
        console.error("Webhook verification failed: Received empty body.");
        return false;
    }

    try {
        const accessToken = await getPaypalAccessToken();

        // Guard clause para asegurar que tenemos un token
        if (!accessToken) {
            console.error("Webhook verification failed: Could not retrieve PayPal access token.");
            return false;
        }

        const requestPayload = {
            auth_algo: headers['paypal-auth-algo'],
            cert_url: headers['paypal-cert-url'],
            transmission_id: headers['paypal-transmission-id'],
            transmission_sig: headers['paypal-transmission-sig'],
            transmission_time: headers['paypal-transmission-time'],
            webhook_id: process.env.PAYPAL_WEBHOOK_ID_TEST!,
            webhook_event: JSON.parse(rawBody) // Parseamos el body a un objeto JSON
        };

        // 2. Log CLAVE: Mostramos el objeto COMPLETO que vamos a enviar a PayPal.
        console.log("--- SENDING TO PAYPAL FOR VERIFICATION ---");
        console.log(JSON.stringify(requestPayload, null, 2)); // Usamos JSON.stringify para verlo bonito
        console.log("------------------------------------------");

        const verificationResponse = await fetch('https://api.sandbox.paypal.com/v1/notifications/verify-webhook-signature', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${accessToken}`
            },
            body: JSON.stringify(requestPayload) // Enviamos el payload stringificado
        });
        
        const verificationData = await verificationResponse.json() as { verification_status: string };

        if (verificationData.verification_status !== 'SUCCESS') {
            console.error('PayPal verification API responded with failure:', verificationData);
        }
        
        return verificationData.verification_status === 'SUCCESS';

    } catch (error) {
        console.error("CRITICAL: Error during webhook verification logic. Potentially malformed rawBody.", error);
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


// Endpoint para el webhook de PayPal con la lógica corregida
paymentsRoute.post('/paypal-webhook', async (c) => {
    const db = drizzle(pool);

    try {
        // --- CAMBIO CLAVE 1: Leer el body UNA SOLA VEZ ---
        const rawBody = await c.req.text();
        const headers = c.req.header();
        
        // 1. Verificar la autenticidad del Webhook
        const isVerified = await verifyPaypalWebhook(headers, rawBody);

        if (!isVerified) {
            console.error("PayPal webhook verification failed. Request rejected.");
            return c.json({ error: 'Webhook verification failed' }, 401);
        }

        // 2. Procesar el evento usando la variable que ya leímos
        const event = JSON.parse(rawBody);
        
        if (event.event_type === 'PAYMENT.CAPTURE.COMPLETED') {
            const resource = event.resource;

            // --- CAMBIO CLAVE 2: Adaptar a la estructura de datos de PayPal ---
            const amountPaid = parseFloat(resource.amount.value);
            const userId = resource.custom_id;

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
                creditsToAdd = 50; // Ajustado al plan original
            } else if (amountPaid === 8.30) {
                creditsToAdd = 100; // Ajustado al plan original
            } else {
                console.warn(`Payment received for an unconfigured amount: ${amountPaid}`);
            }

            if (creditsToAdd > 0) {
                const newTotalCredits = (user.credits || 0) + creditsToAdd;
                await db.update(users)
                    .set({ credits: newTotalCredits })
                    .where(eq(users.id, userId));
                
                console.log(`✅ Success: Added ${creditsToAdd} credits to user ${userId}. New balance: ${newTotalCredits}.`);
            }
        }

        // 5. Responder a PayPal con un 200 OK
        return c.json({ message: 'Webhook processed successfully' }, 200);

    } catch (error: any) {
        console.error("Error processing PayPal webhook:", error.message);
        return c.json({ error: 'Internal Server Error' }, 500);
    }
});


export default paymentsRoute