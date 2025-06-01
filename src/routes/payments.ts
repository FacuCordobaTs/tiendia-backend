import { zValidator } from "@hono/zod-validator";
import { Hono } from "hono";
import { z } from "zod";
import jwt, { JwtPayload } from "jsonwebtoken";
import { getCookie } from "hono/cookie";
import * as UUID from 'uuid';
import { users } from "../db/schema"; // Ensure this path is correct
import { drizzle } from "drizzle-orm/mysql2";
import { pool } from "../db"; // Ensure this path is correct
import { eq } from "drizzle-orm";

export type Env = {}; // Define your environment variables if any, e.g., { Bindings: { MP_ACCESS_TOKEN: string } }

// Use the interfaces from the previous good example
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
    id: number; // This is the merchant_order_id
    status: string;
    preference_id: string; // Your system's preference_id
    payments: MerchantOrderPayment[];
    items: MerchantOrderItem[];
    order_status: string;
    paid_amount: number;
    external_reference?: string;
    // ... other relevant fields
}
interface MerchantOrderResponse {
    elements: MerchantOrderElement[];
}

// Interface for Payment v1 response (simplified)
interface PaymentV1 {
    id: number; // payment_id
    status: string; // "approved", "pending", "rejected", etc.
    order?: {
        id: number; // merchant_order_id
        type: string;
    };
    preference_id?: string; // Can also be here
    external_reference?: string;
    // ... other relevant fields
}


const paymentsRoute = new Hono<{ Bindings: Env }>();

const creditSchema = z.object({
    credits: z.number(),
});

paymentsRoute.post("/create-preference", zValidator("json", creditSchema), async (c) => {
    // ... (tu código de /create-preference parece estar bien, mantenlo como estaba)
    // Asegúrate de que process.env.MP_ACCESS_TOKEN y process.env.TOKEN_SECRET estén disponibles
    const { credits: unit_price_for_mp } = c.req.valid("json");
    const token = getCookie(c, 'token');
    if (!token) return c.json({ error: 'Unauthorized' }, 401);
    const db = drizzle(pool);

    let decodedPayload: JwtPayload;
    try {
        decodedPayload = await new Promise<JwtPayload>((resolve, reject) => {
            jwt.verify(token, process.env.TOKEN_SECRET || 'my-secret', (error, decoded) => {
                if (error || typeof decoded === 'string' || !decoded) reject(error || new Error("Invalid token payload"));
                else resolve(decoded as JwtPayload);
            });
        });
    } catch (e) {
        console.error("Token verification failed:", e);
        return c.json({ error: 'Unauthorized - Invalid token' }, 401);
    }


    const preferenceResponse = await fetch('https://api.mercadopago.com/checkout/preferences', {
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
        },
        notification_url: "https://api.tiendia.app/api/payments/webhook" // TU URL DE WEBHOOK
      }),
    });
    const preference = await preferenceResponse.json() as { id: string };

    if (preference && preference.id) {
      await db.update(users).set({
        lastPreferenceId: preference.id,
        lastPreferencePaid: false,
      })
      .where(eq(users.id, decodedPayload.id));
    }
    console.log("PREFERENCEID CREATED: ", preference.id);
    return c.json({ preference });
});


paymentsRoute.post('/webhook', async (c) => {
    const notification = await c.req.json() as any;
    console.log(`Timestamp: ${new Date().toISOString()} --- Received Webhook:`, JSON.stringify(notification, null, 2));

    const db = drizzle(pool);
    let merchantOrderIdToProcess: string | null = null;
    let sourcePreferenceId: string | null = null; // To find the user

    try {
        if (notification.topic === 'merchant_order' || notification.type === 'merchant_order') {
            const moIdMatch = notification.resource?.match(/\/merchant_orders\/(\d+)/);
            merchantOrderIdToProcess = notification.data?.id?.toString() || moIdMatch?.[1];
            if (merchantOrderIdToProcess) {
                 console.log(`Webhook is for MERCHANT_ORDER ID: ${merchantOrderIdToProcess}. Will attempt to fetch MO directly.`);
                // For merchant_order notifications, we fetch it directly.
                // If it's too early, it might not be "paid" yet.
            } else {
                console.warn("Merchant Order notification received, but could not extract ID.", notification);
                return c.json({ message: "Notification acknowledged, ID extraction issue." }, 200);
            }
        } else if (notification.topic === 'payment' || notification.type === 'payment') {
            const paymentId = notification.data?.id?.toString() || notification.resource?.toString();
            if (!paymentId) {
                console.warn("Payment notification received, but could not extract Payment ID.", notification);
                return c.json({ message: "Notification acknowledged, Payment ID extraction issue." }, 200);
            }

            console.log(`Webhook is for PAYMENT ID: ${paymentId}. Fetching payment details.`);
            const paymentDetailsUrl = `https://api.mercadopago.com/v1/payments/${paymentId}`;
            const paymentResponse = await fetch(paymentDetailsUrl, {
                headers: { 'Authorization': 'Bearer ' + process.env.MP_ACCESS_TOKEN }
            });

            if (!paymentResponse.ok) {
                const errorBody = await paymentResponse.text();
                console.error(`Error fetching payment details for ${paymentId}: ${paymentResponse.status}`, errorBody);
                return c.json({ message: "Notification acknowledged, failed to fetch payment." }, 200);
            }

            const paymentData = await paymentResponse.json() as PaymentV1;
            console.log(`Payment details for ${paymentId}:`, JSON.stringify(paymentData, null, 2));

            if (paymentData.status === 'approved') {
                if (paymentData.order && paymentData.order.id) {
                    merchantOrderIdToProcess = paymentData.order.id.toString();
                    sourcePreferenceId = paymentData.preference_id || null; // Get preference_id from payment if available
                    console.log(`Payment ${paymentId} is APPROVED. Corresponding Merchant Order ID: ${merchantOrderIdToProcess}. Preference ID from payment: ${sourcePreferenceId}`);
                } else {
                    console.warn(`Payment ${paymentId} is APPROVED but has no associated Merchant Order ID in payment details. Cannot proceed with MO logic. External Ref: ${paymentData.external_reference}, Preference ID: ${paymentData.preference_id}`);
                    // Potentially handle crediting based on external_reference or preference_id directly if this case is valid for you
                    // For now, we require a merchant order.
                    return c.json({ message: "Notification acknowledged, payment approved but no MO link." }, 200);
                }
            } else {
                console.log(`Payment ${paymentId} status is '${paymentData.status}'. No action taken.`);
                return c.json({ message: "Notification acknowledged, payment not approved." }, 200);
            }
        } else {
            console.log("Webhook received with unknown topic/type:", notification);
            return c.json({ message: "Notification acknowledged, unknown type." }, 200);
        }

        if (!merchantOrderIdToProcess) {
            console.log("Could not determine a Merchant Order ID to process from the notification. No action taken.");
            return c.json({ message: "Notification acknowledged, no actionable MO ID." }, 200);
        }

        // --- Fetch and Process Merchant Order ---
        console.log(`Fetching Merchant Order details for MO ID: ${merchantOrderIdToProcess}`);
        const moUrl = `https://api.mercadopago.com/merchant_orders/${merchantOrderIdToProcess}`;
        const moResponse = await fetch(moUrl, {
            headers: { 'Authorization': 'Bearer ' + process.env.MP_ACCESS_TOKEN }
        });

        if (!moResponse.ok) {
            const errorBody = await moResponse.text();
            console.error(`Error fetching Merchant Order ${merchantOrderIdToProcess}: ${moResponse.status}`, errorBody);
            return c.json({ message: "Notification acknowledged, failed to fetch MO." }, 200);
        }

        const moData = await moResponse.json() as MerchantOrderResponse;
        if (!moData.elements || moData.elements.length === 0) {
            console.warn(`Merchant Order ${merchantOrderIdToProcess} data is empty or invalid. It might be too early or an issue with the order.`);
            return c.json({ message: "Notification acknowledged, MO data not found/invalid." }, 200);
        }

        const order = moData.elements[0];
        console.log(`Merchant Order ${merchantOrderIdToProcess} details:`, JSON.stringify(order, null, 2));

        const actualPreferenceId = order.preference_id || sourcePreferenceId; // Prefer MO's preference_id, fallback to one from payment
        const unitPriceFromOrder = order.items[0]?.unit_price;

        if (!actualPreferenceId) {
            console.error(`Critical: Could not determine Preference ID for MO ${merchantOrderIdToProcess}. Cannot find user. External Ref: ${order.external_reference}`);
            return c.json({ message: "Notification acknowledged, Preference ID missing in MO." }, 200);
        }

        const isOrderPaid = order.order_status === 'paid';
        const hasApprovedPaymentInMO = order.payments && order.payments.some(p => p.status === 'approved');

        if (isOrderPaid && hasApprovedPaymentInMO) {
            console.log(`MO ${merchantOrderIdToProcess} (Preference: ${actualPreferenceId}) is PAID and has APPROVED payment. Proceeding to credit user.`);

            const userRecords = await db.select().from(users)
                .where(eq(users.lastPreferenceId, actualPreferenceId)); // Use the preference_id associated with this order

            if (userRecords.length === 0) {
                console.warn(`No user found with lastPreferenceId: ${actualPreferenceId} for MO ${merchantOrderIdToProcess}.`);
                return c.json({ message: "Notification acknowledged, user not found for preference." }, 200);
            }
            const user = userRecords[0];

            if (user.credits != null && !user.lastPreferencePaid) {
                let creditsToAdd = 0;
                if (typeof unitPriceFromOrder !== 'number') {
                     console.error(`Invalid unit_price in order items for MO: ${merchantOrderIdToProcess}, Preference: ${actualPreferenceId}`);
                     return c.json({ message: 'Invalid item price in order' }, 200);
                }

                if (unitPriceFromOrder === 80) creditsToAdd = 50;
                else if (unitPriceFromOrder === 800) creditsToAdd = 500;
                else if (unitPriceFromOrder === 3500) creditsToAdd = 2500;
                else if (unitPriceFromOrder === 6800) creditsToAdd = 5000;
                else {
                    console.warn(`No credit tier matched for unit_price: ${unitPriceFromOrder} on MO ${merchantOrderIdToProcess}, Preference: ${actualPreferenceId}`);
                    return c.json({ message: 'No credit tier matched.' }, 200);
                }
                
                if (creditsToAdd > 0) {
                    console.log(`Attempting to add ${creditsToAdd} credits to user ${user.id} for Preference ${actualPreferenceId}. Current credits: ${user.credits}`);
                    await db.update(users).set({
                        credits: (user.credits || 0) + creditsToAdd, // Ensure user.credits is not null
                        lastPreferencePaid: true,
                    }).where(eq(users.id, user.id)); // Update by user.id for safety
                    console.log(`User ${user.id} CREDITED successfully for Preference ${actualPreferenceId} / MO ${merchantOrderIdToProcess}.`);
                }
            } else if (user.lastPreferencePaid) {
                console.log(`Preference ${actualPreferenceId} (MO: ${merchantOrderIdToProcess}) already marked as paid for user ${user.id}. Ignoring.`);
            } else {
                 console.warn(`User ${user.id} (Preference: ${actualPreferenceId}) has null credits or other issue. lastPreferencePaid: ${user.lastPreferencePaid}`);
            }
        } else {
            console.log(`MO ${merchantOrderIdToProcess} (Preference: ${actualPreferenceId}) status not 'paid' or no approved payment. Order Status: ${order.order_status}, Payments: ${JSON.stringify(order.payments.map(p=>p.status))}`);
        }

        return c.json({ message: 'Webhook processed' }, 200);

    } catch (error) {
        console.error(`Timestamp: ${new Date().toISOString()} --- Webhook processing error:`, error);
        // For internal errors, MP might retry if you send 500.
        // If it's a data issue that won't resolve with a retry, 200 is better.
        return c.json({ error: 'Internal Server Error during webhook processing' }, 500);
    }
});

export default paymentsRoute;