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
    credits: z.number(), // Este 'credits' es el unit_price que envías a MP
});

// Define una interfaz más detallada para la respuesta de merchant_order
interface MerchantOrderPayment {
    id: number;
    transaction_amount?: number;
    total_paid_amount?: number;
    status?: string; 
    status_detail?: string;
    date_approved?: string;
}

interface MerchantOrderItem {
    id: string;
    title: string;
    unit_price: number;
    quantity: number;
    currency_id: string;
}

interface MerchantOrderElement {
    id: number;
    status: string; 
    preference_id: string;
    payments: MerchantOrderPayment[];
    items: MerchantOrderItem[];
    order_status: string;
    paid_amount: number;
}

interface MerchantOrderResponse {
    elements: MerchantOrderElement[];
}


paymentsRoute.post("/create-preference", zValidator("json",creditSchema), async (c) => {
    const { credits: unit_price_for_mp } = c.req.valid("json");
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
        'Content-Type': 'application/json',
        'X-Idempotency-Key': UUID.v4()
      },
      body: JSON.stringify({
        items: [
          {
            id: UUID.v4(), 
            title: `Carga de creditos`,
            unit_price: unit_price_for_mp,
            quantity: 1,
            currency_id: "ARS"
          }
        ],
        back_urls: {
          success: `https://my.tiendia.app/home`,
          // failure: `https://my.tiendia.app/payment-failed`,
          // pending: `https://my.tiendia.app/payment-pending`,
        },
        notification_url: "https://api.tiendia.app/api/payments/webhook",
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

    console.log("PREFERENCEID: ", preference.id);
    return c.json({ preference });
});

paymentsRoute.post('/webhook', async (c) => {
    try {
      const notification = await c.req.json() as any;
      console.log("Received Webhook:", JSON.stringify(notification, null, 2));

      
      let merchantOrderId: string | null = null;
    
      const id = c.req.query('id') || (notification.type === "merchant_order" && notification.data?.id);


      if (!id) {
          console.error('Missing merchant_order id in webhook notification query or body.');
          return c.json({ error: 'Missing id parameter in notification' }, 400);
      }

      const url = `https://api.mercadopago.com/merchant_orders/${id}`;
      const db = drizzle(pool);

      console.log(`Fetching merchant order: ${url}`);
      const response = await fetch(url,{
              headers: {
                  'Content-Type': 'application/json',
                  'Authorization': 'Bearer '+ process.env.MP_ACCESS_TOKEN
              }
      });

      if (!response.ok) {
          console.error(`Error fetching merchant_order ${id}: ${response.status} ${response.statusText}`);
          const errorBody = await response.text();
          console.error("Error body:", errorBody);
          return c.json({ error: 'Failed to fetch merchant order details' }, 500);
      }

      const merchantOrderData = await response.json() as MerchantOrderResponse; 

      if (!merchantOrderData || !merchantOrderData.elements || merchantOrderData.elements.length === 0) {
          console.error("Merchant order data is empty or invalid for id:", id);
          return c.json({ error: 'Invalid merchant order data received' }, 500);
      }
      
      const order = merchantOrderData.elements[0];
      console.log("Merchant Order Details:", JSON.stringify(order, null, 2));

      const unitPriceFromOrder = order.items[0]?.unit_price; 
      const preferenceId = order.preference_id;

      const isOrderPaid = order.order_status === 'paid';
      const hasApprovedPayment = order.payments && order.payments.some(p => p.status === 'approved');

      if (!isOrderPaid || !hasApprovedPayment) {
          console.log(`Order ${id} (Preference: ${preferenceId}) is not yet paid or approved. Order status: ${order.order_status}, Payments: ${JSON.stringify(order.payments)}`);
          return c.json({ message: 'Order not yet paid or approved' }, 200); 
      }

      console.log(`Processing approved payment for preferenceId: ${preferenceId}, unitPrice: ${unitPriceFromOrder}`);

      const userRecord = await db.select().from(users)
          .where(eq(users.lastPreferenceId, preferenceId));

      if (userRecord[0] && userRecord[0].credits != null && !userRecord[0].lastPreferencePaid) {
          let creditsToAdd = 0;
          
          if (typeof unitPriceFromOrder !== 'number') {
              console.error(`Invalid unit_price in order items for preferenceId: ${preferenceId}`);
              return c.json({ error: 'Invalid item price in order' }, 500);
          }

          
          if (unitPriceFromOrder === 80) {
              creditsToAdd = 50;
          } else if (unitPriceFromOrder === 800) {
              creditsToAdd = 500;
          } else if (unitPriceFromOrder === 3500) {
              creditsToAdd = 2500;
          } else if (unitPriceFromOrder === 6800) {
              creditsToAdd = 5000;
          } else {
              console.warn(`No credit tier matched for unit_price: ${unitPriceFromOrder} on preferenceId: ${preferenceId}`);
              return c.json({ message: 'No credit tier matched for the paid amount.' }, 200);
          }
          
          if (creditsToAdd > 0) {
              console.log(`Adding ${creditsToAdd} credits to user ${userRecord[0].id} for preference ${preferenceId}`);
              await db.update(users).set({
                  credits: userRecord[0].credits + creditsToAdd,
                  lastPreferencePaid: true,
              }).where(eq(users.lastPreferenceId, preferenceId));
              console.log(`User ${userRecord[0].id} successfully credited.`);
          }
      } else if (userRecord[0] && userRecord[0].lastPreferencePaid) {
          console.log(`Preference ${preferenceId} already processed for user ${userRecord[0].id}. Ignoring duplicate notification.`);
      } else {
          console.warn(`User not found for preferenceId: ${preferenceId} or user has null credits.`);
      }

      return c.json({ message: 'Webhook processed successfully' }, 200);
    } catch (error) {
        console.error("Error processing webhook:", error);
        // No envíes error.stack al cliente en producción
        const errorMessage = error instanceof Error ? error.message : "Unknown error";
        return c.json({ error: 'Internal Server Error', details: errorMessage }, 500);
    }
});

export default paymentsRoute;