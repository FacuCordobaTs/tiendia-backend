 import { Hono } from 'hono';
import { eq } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/mysql2';
import { pool } from '../db';
import { z } from "zod";
import { zValidator } from "@hono/zod-validator";
import {
    getCookie,
    setCookie,
    deleteCookie,
} from 'hono/cookie';
import jwt from "jsonwebtoken";
import { users } from '../db/schema';
import bcrypt from "bcryptjs";
import { createAccessToken } from "../libs/jwt";
import UUID from 'uuid-js';
import { authMiddleware } from '../middlewares/auth.middleware';
import { writeFile, unlink } from "fs/promises";
import { join } from "path";

const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB
const ALLOWED_MIME_TYPES = ['image/jpeg', 'image/png', 'image/webp'];

const UPLOAD_DIR = join(process.cwd(), 'public', 'uploads');

// Funciones de manejo de imágenes
async function saveImage(base64String: string): Promise<string> {
  const base64Data = base64String.replace(/^data:image\/\w+;base64,/, "");
  const buffer = Buffer.from(base64Data, 'base64');
  
  const uuid = UUID.create().toString();
  const fileName = `${uuid}.png`;
  const filePath = join(UPLOAD_DIR, fileName);
  
  await writeFile(filePath, buffer);
  return `/uploads/${fileName}`;
}

async function updateImage(oldUrl: string, newBase64: string): Promise<string> {
  await deleteImage(oldUrl);
  return await saveImage(newBase64);
}

async function deleteImage(imageUrl: string): Promise<void> {
  const fileName = imageUrl.split('/').pop();
  if (!fileName) throw new Error('URL de imagen inválida');
  
  const filePath = join(UPLOAD_DIR, fileName);
  await unlink(filePath);
}

// Esquemas de validación
const userSchema = z.object({
  email: z.string().min(3).max(255),
  password: z.string().min(6),
});

const signUpSchema = z.object({
  email: z.string().min(3).max(255),
  password: z.string().min(6),
  shopname: z.string(),
  username: z.string(),
  address: z.string().optional(),
  category: z.string()
});

// Esquema de actualización actualizado
const updateSchema = z.object({
  id: z.number(),
  username: z.string().optional(), // Hacer opcional
  shopname: z.string().optional(), // Hacer opcional
  address: z.string().optional(),
  imageBase64: z.string().optional(),
  businessHours: z.array(z.object({
    name: z.string(),
    active: z.boolean(),
    timeSlots: z.array(z.object({
      start: z.string(),
      end: z.string()
    }))
  })).optional().nullable(),
  paymentMethod: z.enum(['mercadopago', 'whatsapp']).optional(), // Nuevo campo
  whatsappNumber: z.string().optional() // Nuevo campo
});

// Rutas
export const authRoute = new Hono()
  .post('/register', zValidator("json", signUpSchema), async (c) => {
    const { email, password, shopname, username, address, category } = c.req.valid("json");
    const db = drizzle(pool);

    try {
      const existingEmail = await db.select().from(users)
        .where(eq(users.email, email));

      if (existingEmail.length) {
        return c.json({ error: 'Email already used', existingEmail }, 409);
      }

      const existingUser = await db.select().from(users)
        .where(eq(users.username, username));

      if (existingUser.length) {
        return c.json({ error: 'Username already used' }, 409);
      }

      const passwordHash = await bcrypt.hash(password, 10);
      await db.insert(users).values({
        email,
        password: passwordHash,
        username,
        shopname,
        address: address ? address : '',
        category,
        createdAt: new Date()
      });

      const newUser = await db.select().from(users)
        .where(eq(users.email, email))
        .limit(1);

      const token = await createAccessToken({ id: newUser[0].id });
      setCookie(c, 'token', token as string, {
        path: '/',
        sameSite: 'None',
        secure: true,
        maxAge: 7 * 24 * 60 * 60,
      });

      return c.json({ message: 'Usuario registrado correctamente', newUser }, 200);
    } catch (error: any) {
      return c.json({ message: 'Error al registrar el usuario: ' + error.message }, 400);
    }
  })
  .post('/login', zValidator("json", userSchema), async (c) => {
    const { email, password } = c.req.valid("json");
    const db = drizzle(pool);

    try {
      const user = await db.select().from(users)
        .where(eq(users.email, email));

      if (!user.length) { // Cambiar !user a !user.length
        return c.json({ message: 'Usuario no encontrado' }, 400);
      }

      const isMatch = await bcrypt.compare(password, user[0].password);
      if (!isMatch) {
        return c.json({ message: 'Contraseña incorrecta' }, 400);
      }

      const token = await createAccessToken({ id: user[0].id });
      setCookie(c, 'token', token as string, {
        path: '/',
        sameSite: 'None',
        secure: true,
        maxAge: 7 * 24 * 60 * 60,
      });

      return c.json({ message: 'Inicio de sesión realizado con éxito', user }, 200);
    } catch (error) {
      return c.json({ error: 'Login failed' }, 500);
    }
  })
  .get('/profile', async (c) => {
    const token = getCookie(c, 'token');
    if (!token) {
      return c.json({ message: 'No hay token' }, 200);
    }

    const decoded = await new Promise((resolve, reject) => {
      jwt.verify(token, process.env.TOKEN_SECRET || 'my-secret', (error, decoded) => {
        if (error) reject(error);
        resolve(decoded);
      });
    });

    const db = drizzle(pool);
    const user = await db.select().from(users)
      .where(eq(users.id, (decoded as jwt.JwtPayload).id));

    if (!user.length) { // Cambiar !user a !user.length
      return c.json({ message: 'Usuario no encontrado' }, 400);
    }
    return c.json({ user }, 200);
  })
  .delete('/logout', async (c) => {
    deleteCookie(c, 'token');
    return c.json({ message: 'Logout successful' }, 200);
  })
  .put('/fcm-token', authMiddleware, async (c) => {
    try {
      const { token, id } = await c.req.json();
      const db = drizzle(pool);

      await db.update(users)
        .set({ fcmToken: token })
        .where(eq(users.id, id));

      return c.json({ message: 'Token actualizado: ' + token }, 200);
    } catch (error: any) {
      return c.json({ message: error.message }, 200);
    }
  })
  .put('/update', zValidator("json", updateSchema), async (c) => {
    try {
      const { id, shopname, username, address, imageBase64, businessHours, paymentMethod, whatsappNumber } = c.req.valid("json");
      const db = drizzle(pool);

      let profileImageURL: string | undefined;

      if (imageBase64) {
        const [meta, data] = imageBase64.split(',');
        const mimeType = meta.match(/:(.*?);/)?.[1];

        if (!mimeType || !ALLOWED_MIME_TYPES.includes(mimeType)) {
          return c.json({ error: 'Tipo de archivo no permitido' }, 400);
        }

        const buffer = Buffer.from(data, 'base64');
        if (buffer.byteLength > MAX_FILE_SIZE) {
          return c.json({ error: 'La imagen es demasiado grande' }, 400);
        }

        profileImageURL = await saveImage(imageBase64);
      }

      // Objeto con los datos a actualizar, solo incluye campos proporcionados
      const updateData: Partial<typeof users.$inferInsert> = {
        ...(username && { username }),
        ...(shopname && { shopname }),
        ...(address && { address }),
        ...(profileImageURL && { profileImageURL }),
        ...(businessHours && { businessHours }),
        ...(paymentMethod && { paymentMethod }),
        ...(whatsappNumber && { whatsappNumber })
      };

      if (Object.keys(updateData).length === 0) {
        return c.json({ message: 'No se proporcionaron datos para actualizar' }, 400);
      }

      const [updatedUser] = await db.update(users)
        .set(updateData)
        .where(eq(users.id, id))
        
      return c.json({ 
        message: 'Usuario actualizado correctamente',
        user: updatedUser
      }, 200);
    } catch (error: any) {
      return c.json({ message: error.message }, 500);
    }
  })
  .get('/get/:username', async (c) => {
    const db = drizzle(pool);
    const username = c.req.param('username');

    try {
      const user = await db.select({
        username: users?.username,
        shopname: users?.shopname,
        profileImageURL: users?.profileImageURL,
        connected_mp: users?.connected_mp,
        address: users?.address,
        category: users?.category,
        createdAt: users?.createdAt,
        nextPaymentDate: users?.nextPaymentDate,
        lastPaymentDate: users?.lastPaymentDate,
        businessHours: users?.businessHours,
        whatsappNumber: users?.whatsappNumber
      }).from(users)
        .where(eq(users.username, username));

      if (user.length) { // Cambiar if (user) a if (user.length)
        const getPaymentDates = () => {
          let dueDate: Date;
          
          if (user[0].nextPaymentDate) {
            dueDate = new Date(user[0].nextPaymentDate);
          } else {
            const createdAt = new Date(user[0].createdAt);
            dueDate = new Date(createdAt);
            dueDate.setMonth(createdAt.getMonth() + 1);
          }

          const cutoffDate = new Date(dueDate);
          cutoffDate.setDate(dueDate.getDate() + 5);
          
          return { dueDate, cutoffDate };
        };

        const { cutoffDate } = getPaymentDates();
        const currentDate = new Date();

        if (currentDate > cutoffDate) {
          return c.json({ user: null, showPage: false }, 404);
        } else {
          return c.json({ 
            user: {
              shopname: user[0].shopname,
              username: user[0].username,
              profileImageURL: user[0].profileImageURL,
              connected_mp: user[0].connected_mp,
              address: user[0].address,
              category: user[0].category,
              businessHours: user[0].businessHours,
              whatsappNumber: user[0].whatsappNumber
            }, 
            showPage: true 
          }, 200);
        }
      } else {
        return c.json({ user: null, showPage: false }, 404);
      }
    } catch (error) {
      return c.json({ message: 'Error al obtener el producto' }, 400);
    }
  });