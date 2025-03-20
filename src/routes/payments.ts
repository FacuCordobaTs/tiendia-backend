import { zValidator } from "@hono/zod-validator";
import { Hono } from "hono";
import { z } from "zod";
import { eq } from "drizzle-orm";
import { drizzle } from 'drizzle-orm/mysql2';
import { pool } from '../db';
import { getCookie } from "hono/cookie";
import jwt, { JwtPayload } from "jsonwebtoken";
import { orders, users } from "../db/schema";
import { MercadoPagoConfig, Payment } from "mercadopago";

const TOKEN_SECRET = 'my-token-secret';

export type Env = {};

interface MercadoPagoTokens {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  user_id: number;
}

const createPreferenceSchema = z.object({
  items: z.array(z.object({
    id: z.string(),
    title: z.string(),
    currency_id: z.string(),
    picture_url: z.string(),
    unit_price: z.number(),
    quantity: z.number()
  })),
  order_id: z.string()
});

const paymentsRoute = new Hono<{ Bindings: Env }>();

// Función para renovar el access_token
async function refreshAccessToken(refreshToken: string): Promise<MercadoPagoTokens> {
  const response = await fetch('https://api.mercadopago.com/oauth/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${process.env.MP_ACCESS_TOKEN}`
    },
    body: JSON.stringify({
      client_secret: 'jgtoNNgHpgeZpbhODosFb3ah5jxN65Ze',
      client_id: 6137280226622490,
      grant_type: 'refresh_token',
      refresh_token: refreshToken
    })
  });

  if (!response.ok) {
    throw new Error('No se pudo renovar el access_token');
  }

  return await response.json() as MercadoPagoTokens;
}

// Crear nueva preferencia de pago
paymentsRoute.post('/createPreference/:username', zValidator("json", createPreferenceSchema), async (c) => {
  try {
    const db = drizzle(pool);
    const username = c.req.param('username');
    const { items, order_id } = c.req.valid("json");

    const userResult = await db.select().from(users).where(eq(users.username, username));
    let user = userResult[0];

    if (!user) {
      return c.json({ message: 'Usuario no encontrado' }, 404);
    }

    if (user.mp_token_expires && Date.now() > user.mp_token_expires) {
      if (!user.mp_refresh_token) {
        throw new Error('Refresh token is missing');
      }
      const newTokens = await refreshAccessToken(user.mp_refresh_token);
      await db.update(users)
        .set({
          mp_access_token: newTokens.access_token,
          mp_refresh_token: newTokens.refresh_token,
          mp_token_expires: Date.now() + (newTokens.expires_in * 1000)
        })
        .where(eq(users.id, user.id));
      const updatedUserResult = await db.select().from(users).where(eq(users.id, user.id));
      user = updatedUserResult[0];
    }

    const response = await fetch('https://api.mercadopago.com/checkout/preferences', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + user.mp_access_token,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        items,
        notification_url: "https://ecommerceplantilla-back.fileit-contact.workers.dev/api/payments/notification",
        metadata: {
          order_id
        }
      })
    });

    const preference = await response.json();

    return c.json({
      message: 'Preferencia creada exitosamente',
      preference
    }, 201);
  } catch (error: any) {
    return c.json({ message: error.message }, 500);
  }
});

// Webhook para notificaciones de pago
// Webhook para notificaciones de pago
paymentsRoute.post('/notification', async (c) => {
  try {
    // Obtener el ID del pago desde la query string
    const id = await c.req.query('id');
    if (!id) {
      return c.json({ error: 'Payment ID is required' }, 400);
    }

    // Configurar Mercado Pago con el access token
    const mercadopago = new MercadoPagoConfig({ accessToken: process.env.MP_ACCESS_TOKEN || '' });
    const payment = await new Payment(mercadopago).get({ id });

    // Verificar si el pago está aprobado
    if (payment.status === 'approved') {
      const db = drizzle(pool);
      const orderId = payment.metadata.order_id;

      // Verificar si la orden existe y si ya está pagada
      const existingOrder = await db.select().from(orders).where(eq(orders.id, orderId));
      if (existingOrder.length === 0) {
        console.error(`No se encontró la orden con ID ${orderId}`);
        return c.json({ error: 'Order not found' }, 404);
      }
      if (existingOrder[0].paid === 1) {
        console.log(`La orden ${orderId} ya ha sido pagada.`);
        return c.status(200); // Respuesta exitosa, pero no se hace nada
      }

      // Actualizar la orden a "pagada"
      await db.update(orders)
        .set({ paid: 1 }) // Opcional: agregar fecha de pago
        .where(eq(orders.id, orderId));

      console.log(`Orden ${orderId} actualizada a pagada exitosamente.`);
    }

    return c.status(200); // Respuesta exitosa para Mercado Pago
  } catch (error: any) {
    console.error('Error procesando la notificación de pago:', error.message);
    return c.json({ error: 'Error interno del servidor' }, 500);
  }
});

// Conectar cuenta de Mercado Pago
paymentsRoute.get('/connect/:code', async (c) => {
  const token = getCookie(c, 'token');
  if (!token) return c.json({ message: 'No token' }, 404);

  const code = c.req.param('code');
  if (!code) return c.json({ message: 'No code' }, 404);

  try {
    const mpResponse = await fetch('https://api.mercadopago.com/oauth/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.MP_ACCESS_TOKEN}`
      },
      body: JSON.stringify({
        client_secret: 'jgtoNNgHpgeZpbhODosFb3ah5jxN65Ze',
        client_id: 6137280226622490,
        grant_type: "authorization_code",
        code,
        redirect_uri: 'https://ecommerce-admin-eyh.pages.dev/loadingmp'
      })
    });

    const tokens = await mpResponse.json() as MercadoPagoTokens;

    const db = drizzle(pool);
    const decoded = jwt.verify(token, TOKEN_SECRET);

    await db.update(users)
      .set({
        mp_access_token: tokens.access_token,
        mp_refresh_token: tokens.refresh_token,
        mp_token_expires: Date.now() + (tokens.expires_in * 1000),
        connected_mp: 1,
      })
      .where(eq(users.id, (decoded as JwtPayload).id));

    return c.json({
      message: 'Usuario actualizado correctamente',
      tokens
    }, 200);
  } catch (error: any) {
    return c.json({ message: error.message }, 404);
  }
});

// Crear suscripción (sin cambios por ahora)
paymentsRoute.post('/create-subscription', async (c) => {
  const token = getCookie(c, 'token');
  if (!token) return c.json({ error: 'Unauthorized' }, 401);

  const { planId }: { planId: 'basic' | 'pro' | 'auto' } = await c.req.json();

  try {
    const decoded = jwt.verify(token, TOKEN_SECRET);

    const PLAN_PRICES: { [key: string]: [number, string] } = {
      basic: [5000, 'Basico'],
      pro: [10000, 'Profesional'],
      auto: [50000, 'Piloto Automático']
    };

    const amount = PLAN_PRICES[planId][0];
    if (!amount) return c.json({ error: 'Plan inválido' }, 400);

    const response = await fetch('https://api.mercadopago.com/checkout/preferences', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + process.env.MP_ACCESS_TOKEN,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        items: [
          {
            id: planId,
            title: `Suscripción ${PLAN_PRICES[planId][1]}`,
            unit_price: amount,
            quantity: 1,
            currency_id: "ARS"
          }
        ],
        metadata: {
          user_id: (decoded as JwtPayload).id
        },
        back_urls: {
          success: `http://localhost:5173/completeProfile`,
        },
        notification_url: "https://ecommerceplantilla-back.fileit-contact.workers.dev/api/payments/webhook"
      }),
    });
    const preference = await response.json();

    return c.json({ preference });
  } catch (error: any) {
    return c.json({ error: error.message }, 500);
  }
});

// Webhook para suscripciones
paymentsRoute.post('/webhook', async (c) => {
  const id = await c.req.query('id');
  const mercadopago = new MercadoPagoConfig({ accessToken: process.env.MP_ACCESS_TOKEN || '' });

  if (!id) {
    return c.json({ error: 'Payment ID is required' }, 400);
  }
  const payment = await new Payment(mercadopago).get({ id });

  if (payment.status === 'approved') {
    const db = drizzle(pool);
    const nextPayment = new Date();
    nextPayment.setMonth(nextPayment.getMonth() + 1);

    await db.update(users)
      .set({
        lastPaymentDate: new Date(),
        nextPaymentDate: nextPayment
      })
      .where(eq(users.id, payment.metadata.user_id));
  }

  return c.status(200);
});

export default paymentsRoute;