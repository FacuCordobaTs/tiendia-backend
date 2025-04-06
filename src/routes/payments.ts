import { zValidator } from "@hono/zod-validator";
import { Hono } from "hono";
import { z } from "zod";
import { eq } from "drizzle-orm";
import { drizzle } from 'drizzle-orm/mysql2';
import { pool } from '../db';
import { getCookie } from "hono/cookie";
import jwt, { JwtPayload } from "jsonwebtoken";
import { users } from "../db/schema";
import { MercadoPagoConfig, Payment } from "mercadopago";

export type Env = {};

const paymentsRoute = new Hono<{ Bindings: Env }>();

// paymentsRoute.post('/notification', async (c) => {
//   try {
//     // Obtener el ID del pago desde la query string
//     const id = await c.req.query('id');
//     if (!id) {
//       return c.json({ error: 'Payment ID is required' }, 400);
//     }

//     // Configurar Mercado Pago con el access token
//     const mercadopago = new MercadoPagoConfig({ accessToken: process.env.MP_ACCESS_TOKEN || '' });
//     const payment = await new Payment(mercadopago).get({ id });

//     // Verificar si el pago está aprobado
//     if (payment.status === 'approved') {
//       const db = drizzle(pool);
//       const orderId = payment.metadata.order_id;

//       // Verificar si la orden existe y si ya está pagada
//       const existingOrder = await db.select().from(orders).where(eq(orders.id, orderId));
//       if (existingOrder.length === 0) {
//         console.error(`No se encontró la orden con ID ${orderId}`);
//         return c.json({ error: 'Order not found' }, 404);
//       }
//       if (existingOrder[0].paid === 1) {
//         console.log(`La orden ${orderId} ya ha sido pagada.`);
//         return c.status(200); // Respuesta exitosa, pero no se hace nada
//       }

//       // Actualizar la orden a "pagada"
//       await db.update(orders)
//         .set({ paid: 1 }) // Opcional: agregar fecha de pago
//         .where(eq(orders.id, orderId));

//       console.log(`Orden ${orderId} actualizada a pagada exitosamente.`);
//     }

//     return c.status(200); // Respuesta exitosa para Mercado Pago
//   } catch (error: any) {
//     console.error('Error procesando la notificación de pago:', error.message);
//     return c.json({ error: 'Error interno del servidor' }, 500);
//   }
// });

// paymentsRoute.post('/chargeCredits', async (c) => {
//   const amount = c.req.json()
//   try {
//     const response = await fetch('https://api.mercadopago.com/checkout/preferences', {
//       method: 'POST',
//       headers: {
//         'Authorization': 'Bearer ' + process.env.MP_ACCESS_TOKEN,
//         'Content-Type': 'application/json'
//       },
//       body: JSON.stringify({
//         items: [
//           {
//             id: UUID.v4(),
//             title: `Carga de creditos`,
//             unit_price: amount,
//             quantity: 1,
//             currency_id: "ARS"
//           }
//         ],
//         metadata: {
//           user_id: (decoded as JwtPayload).id
//         },
//         back_urls: {
//           success: `http://localhost:5173/completeProfile`,
//         },
//         notification_url: "https://api.tiendia.app/api/payments/webhook"
//       }),
//     });
//     const preference = await response.json();

//     return c.json({ preference });
//   } catch (error: any) {
//     return c.json({ error: error.message }, 500);
//   }
// });

export default paymentsRoute;