import { zValidator } from "@hono/zod-validator";
import { Hono } from "hono";
import { z } from "zod";
import { drizzle } from 'drizzle-orm/mysql2'; // Cambiamos a mysql2
import { pool } from '../db'; // Importamos el pool de MySQL
import { orders, orderItems, users, products } from "../db/schema";
import { authMiddleware } from "../middlewares/auth.middleware";
import { desc, eq } from "drizzle-orm";
import { EnhancedFcmMessage, FCM, FcmOptions } from "fcm-cloudflare-workers";

interface Size {
  size: string;
  stock: number;
}

// Esquema de validación
const createOrderSchema = z.object({
  order: z.array(z.object({
    id: z.number(),
    comment: z.string().optional(),
    size: z.string().optional(),
  })),
  price: z.number(),
  phone_number: z.string(),
  address: z.string().optional(),
  paymentMethod: z.string(),
  deliveryType: z.string(),
  username: z.string()
});

const ordersRoute = new Hono();

// Endpoint para crear una nueva orden
ordersRoute.post('/create', zValidator("json", createOrderSchema), async (c) => {
  try {
    const { order, price, phone_number, address, paymentMethod, deliveryType, username } = c.req.valid("json");
    const db = drizzle(pool); // Usamos el pool de MySQL

    // Insertar la orden
    const [newOrder] = await db.insert(orders).values({
      totalPrice: price,
      phoneNumber: phone_number,
      address,
      paymentMethod,
      paid: 0,
      deliveryType,
      createdAt: new Date(),
      shopUsername: username
    }).$returningId();

    let productsArr = []
    // Insertar los items de la orden
    for (const item of order) {
      const [product] = await db.select()
      .from(products)
      .where(eq(products.id, item.id));

      productsArr.push(product);

      await db.insert(orderItems).values({
        productId: item.id,
        comment: item.comment,
        orderId: newOrder.id,
        size: item.size
      });

      if (item.size && product.sizes) {
        // const sizes = product.sizes;
        // const sizeIndex = sizes.findIndex((size: Size) => size.size === item.size);
        // sizes[sizeIndex].stock -= 1;

        // await db.update(products).set({ sizes }).where(eq(products.id, item.id));
      }
      else if (product.stock) {
        await db.update(products).set({ stock: product.stock - 1 }).where(eq(products.id, item.id));
      }
    }

    // Obtener el token FCM del usuario
    const user = await db.select().from(users).where(eq(users.username, username));

    if (user[0].fcmToken) {
      // Configurar FCM con la cuenta de servicio (la librería se encargará de generar y cachear el access token)
      const fcmOptions = new FcmOptions({
        serviceAccount:{
          "type": process.env.FCM_TYPE || "",
          "project_id": process.env.FCM_PROJECT_ID || "",
          "private_key_id": process.env.FCM_PRIVATE_KEY_ID || "",
          "private_key": process.env.FCM_PRIVATE_KEY || "",
          "client_email": process.env.FCM_CLIENT_EMAIL || "",
          "client_id": process.env.FCM_CLIENT_ID || "",
          "auth_uri": process.env.FCM_AUTH_URI || "",
          "token_uri": process.env.FCM_TOKEN_URI || "",
          "auth_provider_x509_cert_url": process.env.FCM_AUTH_PROVIDER_X509_CERT_URL || "",
          "client_x509_cert_url": process.env.FCM_CLIENT_X509_CERT_URL || "",
        }        
      });
      const fcm = new FCM(fcmOptions);

      const message: EnhancedFcmMessage = {
        notification: {
            title: "Nuevo pedido! 😁",
            body: `Tienes un nuevo pedido de $${price}`,
        },
      }
      
      try {
        await fcm.sendToToken(message, user[0].fcmToken);
      } catch (error: any) {
        return c.json({ message: error.message }, 200);
      }
    }


    // Nota: La lógica de FCM se ha eliminado. Si necesitas notificaciones, configura un servicio compatible.

    return c.json({ 
      message: 'Orden creada exitosamente',
      newOrder,
      productsArr
    }, 201);
  } catch (error: any) {
    return c.json({ message: error.message }, 500); // Cambiamos el código de estado a 500 para errores
  }
});

// Listar órdenes
ordersRoute.get('/list/:username', authMiddleware, async (c) => {
  const db = drizzle(pool);
  const username = c.req.param('username');
  
  try {
    const ordersListed = await db.select({
      id: orders.id,
      totalPrice: orders.totalPrice,
      phoneNumber: orders.phoneNumber,
      address: orders.address,
      createdAt: orders.createdAt,
      paymentMethod: orders.paymentMethod,
      deliveryType: orders.deliveryType,
      paid: orders.paid,
    })
    .from(orders)
    .where(eq(orders.shopUsername, username))
    .orderBy(desc(orders.createdAt))

    return c.json({ orders: ordersListed }, 200);
  } catch (error) {
    return c.json({ message: 'Error al obtener las órdenes' }, 500);
  }
});

// Obtener una orden específica
ordersRoute.get('/get/:id', authMiddleware, async (c) => {
  const db = drizzle(pool);
  const id = Number(c.req.param('id'));

  try {
    const order = await db.select({
      id: orders.id,
      totalPrice: orders.totalPrice,
      phoneNumber: orders.phoneNumber,
      address: orders.address,
      createdAt: orders.createdAt,
      paymentMethod: orders.paymentMethod,
      deliveryType: orders.deliveryType,
      paid: orders.paid,
    })
    .from(orders)
    .where(eq(orders.id, id))

    if (!order) return c.json({ message: 'Orden no encontrada' }, 404);

    const items = await db.select({
      id: orderItems.id,
      productId: orderItems.productId,
      comment: orderItems.comment,
      size: orderItems.size
    })
    .from(orderItems)
    .where(eq(orderItems.orderId, id))

    return c.json({ 
      order: {
        ...order,
        items
      } 
    }, 200);
  } catch (error) {
    console.error('Error obteniendo orden:', error);
    return c.json({ message: 'Error al obtener la orden' }, 500);
  }
});

// Eliminar una orden
ordersRoute.delete('/delete/:id', authMiddleware, async (c) => {
  const db = drizzle(pool);
  const id = Number(c.req.param('id'));

  try {
    await db.delete(orderItems).where(eq(orderItems.orderId, id));
    await db.delete(orders).where(eq(orders.id, id));

    return c.json({ message: 'Orden eliminada correctamente' }, 200);
  } catch (error) {
    console.error('Error eliminando orden:', error);
    return c.json({ message: 'Error al eliminar la orden' }, 500);
  }
});

// Alternar estado de pago
ordersRoute.put('/togglePaid/:id', authMiddleware, async (c) => {
  const db = drizzle(pool);
  const id = Number(c.req.param('id'));

  try {
    const order = await db.select().from(orders).where(eq(orders.id, id));
    if (!order) return c.json({ message: 'Orden no encontrada' }, 404);

    await db.update(orders).set({ paid: order[0].paid ? 0 : 1 }).where(eq(orders.id, id));

    return c.json({ message: 'Estado de pago actualizado' }, 200);
  } catch (error) {
    console.error('Error actualizando estado de pago:', error);
    return c.json({ message: 'Error al actualizar el estado de pago' }, 500);
  }
});
// Nueva ruta para obtener los detalles completos de la orden
ordersRoute.get('/details/:id', async (c) => {
  const db = drizzle(pool);
  const id = Number(c.req.param('id'));

  try {
    // Obtener la orden
    const orderArr = await db.select().from(orders).where(eq(orders.id, id));
    if (!orderArr.length) return c.json({ message: 'Orden no encontrada' }, 404);
    const order = orderArr[0];
    
    // Obtener los items de la orden
    const items = await db.select({
      id: orderItems.id,
      productId: orderItems.productId,
      comment: orderItems.comment,
      size: orderItems.size
    })
    .from(orderItems)
    .where(eq(orderItems.orderId, id));
    
    // Obtener información de la tienda usando shopUsername
    const shopArr = await db.select({
      shopname: users.shopname,
      address: users.address,
      whatsappNumber: users.whatsappNumber,
    })
    .from(users)
    .where(order.shopUsername ? eq(users.username, order.shopUsername) : undefined);
    
    const shop = shopArr.length ? shopArr[0] : null;
    
    return c.json({
      order: {
        id: order.id,
        totalPrice: order.totalPrice,
        phoneNumber: order.phoneNumber,
        address: order.address,
        createdAt: order.createdAt,
        paymentMethod: order.paymentMethod,
        deliveryType: order.deliveryType,
        paid: order.paid,
        items,
        shop,
      }
    }, 200);
  } catch (error: any) {
    console.error('Error obteniendo detalles de la orden:', error);
    return c.json({ message: 'Error al obtener detalles de la orden' }, 500);
  }
});

export default ordersRoute;