import { zValidator } from "@hono/zod-validator";
import { Hono } from "hono";
import { z } from "zod";
import jwt, { JwtPayload } from "jsonwebtoken";
import { getCookie } from "hono/cookie";
import * as UUID from 'uuid';
import { users, transactions } from "../db/schema";
import { drizzle } from "drizzle-orm/mysql2";
import { pool } from "../db";
import { eq } from "drizzle-orm";
import { createHmac } from 'crypto';

export type Env = {};

const paymentsRoute = new Hono<{ Bindings: Env }>();

const creditSchema = z.object({
    credits: z.number(),
    uri: z.string().optional(),
});

// Configuración de dLocal
const DLOCAL_SECRET_KEY = process.env.DLOCAL_SECRET_KEY!;
const DLOCAL_API_KEY = process.env.DLOCAL_API_KEY!;

function validateDLocalSignature(apiKey: string, payload: string, secretKey: string, receivedSignature: string): boolean {
  const message = apiKey + payload;
  const expectedSignature = createHmac('sha256', secretKey)
    .update(message)
    .digest('hex');
  
  return expectedSignature === receivedSignature;
} 


paymentsRoute.post("/create-preference", zValidator("json",creditSchema), async (c) => {
    const { credits, uri } = c.req.valid("json");
    let token = getCookie(c, 'token');
    if (!token) {
        // Buscar en el header Authorization
        const authHeader = c.req.header('Authorization');
        if (authHeader && authHeader.startsWith('Bearer ')) {
            token = authHeader.replace('Bearer ', '');
        }
    }
    if (!token) return c.json({ error: 'Unauthorized' }, 401);
    const db = drizzle(pool);

    const decoded = await new Promise((resolve, reject) => {
        jwt.verify(token, process.env.TOKEN_SECRET || 'my-secret', (error, decoded) => {
            if (error) reject(error);
            resolve(decoded);
        });
    });

    // Calculate credits to add based on payment amount
    let creditsToAdd = 0;
    if (credits == 120) {
        creditsToAdd = 50;
    } else if (credits == 1200) {
        creditsToAdd = 500;
    } else if (credits == 5280 || credits == 4200) {
        creditsToAdd = 2500;
    } else if (credits == 10000 || credits == 8400) {
        creditsToAdd = 5000;
    } else if (credits == 2000) {
        creditsToAdd = 1;
    }


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
          success: uri || `https://my.tiendia.app/home`,
        },
        notification_url: "https://api.tiendia.app/api/payments/webhook",
        statement_descriptor: "Carga de imagen",
      }),
    });
    const preference = await response.json() as { id: string };

    if (preference && preference.id) {
      // Store transaction with calculated credits
      await db.insert(transactions).values({
        userId: (decoded as JwtPayload).id,
        orderId: preference.id,
        amount: credits, // Convert to cents
        currency: "ARS",
        creditsToAdd: creditsToAdd,
        paymentProvider: "mercadopago",
        status: "pending"
      });

      // Update user's lastPreferenceId for backward compatibility
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

    const preferenceId = data.preference_id;

    // Find transaction by preference_id
    const transaction = await db.select().from(transactions)
        .where(eq(transactions.orderId, preferenceId));

    if (transaction[0] && !transaction[0].processed && data?.status == "closed") {
      const user = await db.select().from(users)
          .where(eq(users.id, transaction[0].userId));

      if (user[0] && user[0].credits != null && transaction[0].creditsToAdd > 0 && transaction[0].creditsToAdd != 1) {
        await db.update(users).set({
          credits: user[0].credits + transaction[0].creditsToAdd,
        }).where(eq(users.id, transaction[0].userId));

        await db.update(transactions).set({
          status: "completed",
          processed: true,
          processedAt: new Date()
        }).where(eq(transactions.id, transaction[0].id));

        console.log(`MercadoPago: Added ${transaction[0].creditsToAdd} credits to user ${user[0].id} for payment ${preferenceId}`);
      } else if (user[0] && transaction[0].creditsToAdd == 1) {
        await db.update(users).set({
          paidMiTienda: true,
          paidMiTiendaDate: new Date(),
        }).where(eq(users.id, transaction[0].userId));

        await db.update(transactions).set({
          status: "completed",
          processed: true,
          processedAt: new Date()
        }).where(eq(transactions.id, transaction[0].id));

        console.log(`MercadoPago MiTiendia: User ${user[0].id} paid for MiTiendia service`);
      }
    }

    return c.json({ message: 'Webhook processed successfully' }, 200);
    } catch (error) {
        console.error("Error processing webhook:", error);
        return c.json({ error: 'Internal Server Error' }, 500);
    }
  });


  paymentsRoute.post("/create-dlocal-payment", zValidator("json", creditSchema), async (c) => {
    const { credits, uri } = c.req.valid("json");
    let token = getCookie(c, 'token');
    if (!token) {
        // Buscar en el header Authorization
        const authHeader = c.req.header('Authorization');
        if (authHeader && authHeader.startsWith('Bearer ')) {
            token = authHeader.replace('Bearer ', '');
        }
    }
    if (!token) return c.json({ error: 'Unauthorized' }, 401);
    const db = drizzle(pool);
  
    try {
        const decoded = await new Promise<JwtPayload>((resolve, reject) => {
            jwt.verify(token, process.env.TOKEN_SECRET || 'my-secret', (error, decoded) => {
                if (error) reject(error);
                resolve(decoded as JwtPayload);
            });
        });

        const orderId = UUID.v4();

        // Calculate credits to add based on payment amount
        let creditsToAdd = 0;
        if (credits == 0.125) {
            creditsToAdd = 50;
        } else if (credits == 1.25) {
            creditsToAdd = 500;
        } else if (credits == 5.5 || credits == 4.4) {
            creditsToAdd = 2500;
        } else if (credits == 10.625 || credits == 8.8) {
            creditsToAdd = 5000;
        } else if (credits == 2) {
            creditsToAdd = 1;
        }
  
        // Crear pago en dLocal
        const dLocalPayment = {
            amount: credits,
            currency: "USD",
            order_id: orderId,
            "description": "Compra de imagenes en tiendia",
            "success_url": uri || "https://my.tiendia.app/home",
            "notification_url": "https://api.tiendia.app/api/payments/dlocal-webhook"
        };
  
        const response = await fetch(`https://api.dlocalgo.com/v1/payments`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${DLOCAL_API_KEY}:${DLOCAL_SECRET_KEY}`,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(dLocalPayment),
        });
  
        if (!response.ok) {
            throw new Error(`dLocal API error: ${response.status}`);
        }
  
        const paymentData = await response.json() as { order_id: string, redirect_url: string };
  
        // Store transaction with calculated credits
        await db.insert(transactions).values({
          userId: decoded.id,
          orderId: paymentData.order_id,
          amount: Math.round(credits * 1200), // Convert to cents
          currency: "USD",
          creditsToAdd: creditsToAdd,
          paymentProvider: "dlocal",
          status: "pending"
        });

        // Update user's lastPreferenceId for backward compatibility
        await db.update(users).set({
            lastPreferenceId: paymentData.order_id,
            lastPreferencePaid: false,
        })
        .where(eq(users.id, decoded.id));
  
        console.log("dLocal Payment ID: ", paymentData.order_id);
        
        return c.json({ 
            redirect_url: paymentData.redirect_url 
        });
  
    } catch (error) {
        console.error('Error creating dLocal payment:', error);
        return c.json({ error: 'Error creating payment' }, 500);
    }
  });
  
  // dLocal Webhook
  paymentsRoute.post('/dlocal-webhook', async (c) => {
    try {
        // Obtener la firma del header
        const authHeader = c.req.header('Authorization');
        if (!authHeader) {
            console.error('Missing Authorization header');
            return c.json({ error: 'Missing Authorization header' }, 400);
        }
  
        // Extraer la firma del header
        const signatureMatch = authHeader.match(/Signature:\s*([a-f0-9]+)/i);
        if (!signatureMatch) {
            console.error('Invalid Authorization header format');
            return c.json({ error: 'Invalid Authorization header format' }, 400);
        }
  
        const receivedSignature = signatureMatch[1];
        
        // Obtener el payload
        const payload = await c.req.text();
        console.log('dLocal notification payload:', payload);
  
        // Validar la firma
        if (!validateDLocalSignature(DLOCAL_API_KEY, payload, DLOCAL_SECRET_KEY, receivedSignature)) {
            console.error('Invalid dLocal signature');
            return c.json({ error: 'Invalid signature' }, 401);
        }
  
        // Parsear el JSON del payload
        let notificationData;
        try {
            notificationData = JSON.parse(payload);
        } catch (error) {
            console.error('Invalid JSON payload:', error);
            return c.json({ error: 'Invalid JSON payload' }, 400);
        }
  
        const { payment_id } = notificationData;
        
        if (!payment_id) {
            console.error('Missing payment_id in notification');
            return c.json({ error: 'Missing payment_id' }, 400);
        }
  
        console.log('Processing dLocal notification for payment:', payment_id);
  
        // Obtener el estado actualizado del pago desde dLocal
        const paymentResponse = await fetch(`https://api.dlocalgo.com/v1/payments/${payment_id}`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${DLOCAL_API_KEY}:${DLOCAL_SECRET_KEY}`,
                'Content-Type': 'application/json',
            },
        });
  
        if (!paymentResponse.ok) {
            throw new Error(`Error fetching dLocal payment: ${paymentResponse.status}`);
        }
  
        const paymentDetails = await paymentResponse.json() as { status: string, amount: number, order_id: string };
        const db = drizzle(pool);
        console.log(paymentDetails)
        
        // Find transaction by order_id
        const transaction = await db.select().from(transactions)
            .where(eq(transactions.orderId, paymentDetails.order_id));
        
        console.log('Transaction lookup result:', transaction);
        console.log('Looking for order_id:', paymentDetails.order_id);
        console.log('Transaction found:', transaction.length > 0);
        
        if (transaction[0] && !transaction[0].processed && paymentDetails.status === 'PAID') {
            const user = await db.select().from(users)
                .where(eq(users.id, transaction[0].userId));

            if (user[0] && user[0].credits != null) {
              
                if (transaction[0].creditsToAdd > 0 && transaction[0].creditsToAdd != 1) {
                  await db.update(users).set({
                      credits: user[0].credits + transaction[0].creditsToAdd,
                  }).where(eq(users.id, transaction[0].userId));

                  await db.update(transactions).set({
                    status: "completed",
                    processed: true,
                    processedAt: new Date()
                  }).where(eq(transactions.id, transaction[0].id));

                  console.log(`dLocal: Added ${transaction[0].creditsToAdd} credits to user ${user[0].id} for payment ${payment_id}`);
                } else if (user[0] && transaction[0].creditsToAdd == 1) {
                  await db.update(users).set({
                    paidMiTienda: true,
                    paidMiTiendaDate: new Date(),
                  }).where(eq(users.id, transaction[0].userId));

                  await db.update(transactions).set({
                    status: "completed",
                    processed: true,
                    processedAt: new Date()
                  }).where(eq(transactions.id, transaction[0].id));

                  console.log(`dLocal MiTiendia: User ${user[0].id} paid for MiTiendia service`);
                }
            }
        }
  
        // Responder con 200 OK para confirmar la recepción
        return c.json({ message: 'dLocal notification processed successfully' }, 200);
  
    } catch (error) {
        console.error('Error processing dLocal notification:', error);
        return c.json({ error: 'Internal server error' }, 500);
    }
  });

  paymentsRoute.get('/exchange-rates', async (c) => {
    try {
        const response = await fetch('https://api.dlocalgo.com/v1/currency-exchanges', {
            headers: {
                'Authorization': `Bearer ${DLOCAL_API_KEY}:${DLOCAL_SECRET_KEY}`,
            },
        });

        if (!response.ok) {
            console.error('dLocal API error fetching exchange rates:', response.status);
            throw new Error('Could not fetch exchange rates');
        }

        const rates = await response.json() as { source_currency: string, target_currency: string, value: number }[];
        return c.json(rates);

    } catch (error) {
        console.error('Error in /exchange-rates endpoint:', error);
        return c.json({ error: 'Internal Server Error' }, 500);
    }
});

export default paymentsRoute