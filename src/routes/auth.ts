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
import jwt, { JwtPayload } from "jsonwebtoken";
import { users } from '../db/schema';
import bcrypt from "bcryptjs";
import { createAccessToken } from "../libs/jwt";
import UUID from 'uuid-js';
import { OAuth2Client } from 'google-auth-library';
import crypto from 'crypto';
import { authMiddleware } from '../middlewares/auth.middleware';
import { S3Client, PutObjectCommand, DeleteObjectCommand } from "@aws-sdk/client-s3";
import { Buffer } from 'buffer';
import { products } from '../db/schema';

// --- Configuración del Cliente S3 (R2) ---
const R2_ACCOUNT_ID = process.env.R2_ACCOUNT_ID;
const R2_ACCESS_KEY_ID = process.env.R2_ACCESS_KEY_ID;
const R2_SECRET_ACCESS_KEY = process.env.R2_SECRET_ACCESS_KEY;
const R2_BUCKET_NAME = process.env.R2_BUCKET_NAME;
const R2_PUBLIC_URL = process.env.R2_PUBLIC_URL?.replace(/\/$/, ''); // Asegura que no termine con /

if (!R2_ACCOUNT_ID || !R2_ACCESS_KEY_ID || !R2_SECRET_ACCESS_KEY || !R2_BUCKET_NAME || !R2_PUBLIC_URL) {
  console.error("FATAL ERROR: Faltan variables de entorno de Cloudflare R2. La aplicación no puede manejar imágenes.");
  process.exit(1);
}

const s3Client = new S3Client({
  region: "auto",
  endpoint: `https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
  credentials: {
    accessKeyId: R2_ACCESS_KEY_ID,
    secretAccessKey: R2_SECRET_ACCESS_KEY,
  },
});

// Funciones de manejo de imágenes con R2
async function saveImage(base64String: string): Promise<string> {
  const match = base64String.match(/^data:(image\/\w+);base64,/);
  if (!match) {
      throw new Error('Formato de base64 inválido para saveImage');
  }
  const mimeType = match[1];
  const fileExtension = mimeType.split('/')[1] || 'png'; // Extrae extensión

  const base64Data = base64String.replace(/^data:image\/\w+;base64,/, "");
  const buffer = Buffer.from(base64Data, "base64");

  const uuid = UUID.create().toString();
  const fileName = `${uuid}.${fileExtension}`; // Nombre del objeto en R2

  const command = new PutObjectCommand({
    Bucket: R2_BUCKET_NAME,
    Key: fileName,
    Body: buffer,
    ContentType: mimeType,
  });

  try {
    await s3Client.send(command);
    const publicUrl = `${R2_PUBLIC_URL}/${fileName}`; // Construye la URL pública completa
    console.log(`Imagen guardada en R2: ${publicUrl}`);
    return publicUrl;
  } catch (error) {
    console.error(`Error al subir ${fileName} a R2:`, error);
    throw new Error("Error al guardar la imagen en el almacenamiento en la nube.");
  }
}

async function deleteImage(imageUrl: string): Promise<void> {
  if (!imageUrl || !imageUrl.startsWith(R2_PUBLIC_URL!)) {
    console.warn("deleteImage: URL inválida o no pertenece a R2 gestionado:", imageUrl);
    return;
  }
  try {
    const urlObject = new URL(imageUrl);
    const key = urlObject.pathname.substring(1); // Extrae la 'Key' (path sin / inicial)

    if (!key) {
      console.warn("deleteImage: No se pudo extraer la clave de la URL R2:", imageUrl);
      return;
    }

    const command = new DeleteObjectCommand({
      Bucket: R2_BUCKET_NAME,
      Key: key,
    });

    console.log(`Eliminando objeto ${key} de R2 bucket ${R2_BUCKET_NAME}...`);
    await s3Client.send(command);
    console.log(`Objeto ${key} eliminado de R2.`);

  } catch (error: any) {
     console.error(`Error al eliminar objeto de R2 (${imageUrl}):`, error);
  }
}

async function updateImage(oldUrl: string, newBase64: string): Promise<string> {
    await deleteImage(oldUrl);
    return await saveImage(newBase64);
}


const googleClient = new OAuth2Client(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_REDIRECT_URI
);


// Esquemas de validación
const userSchema = z.object({
    email: z.string().min(3).max(255),
    password: z.string().min(6),
});

const signUpSchema = z.object({
    email: z.string().min(3).max(255),
    password: z.string().min(6),
});

const miTiendiaSchema = z.object({
  storeName: z.string().min(3).max(255),
  storeLogo: z.string().optional(), // Base64 image
  phoneNumber: z.string().min(10).max(20),
  countryCode: z.string().min(2).max(3),
});

// Rutas
export const authRoute = new Hono()
.post('/register', zValidator("json", signUpSchema), async (c) => {
    const { email, password } = c.req.valid("json");
    const db = drizzle(pool);

    try {
        const existingEmail = await db.select().from(users)
            .where(eq(users.email, email));

        if (existingEmail.length) {
            return c.json({ error: 'Email ya utilizado', existingEmail }, 409);
        }

        const passwordHash = await bcrypt.hash(password, 10);
        await db.insert(users).values({
            email,
            password: passwordHash,
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
        return c.json({ message: 'Error al registrar el usuario'}, 400);
    }
})
.post('/login', zValidator("json", userSchema), async (c) => {
    const { email, password } = c.req.valid("json");
    const db = drizzle(pool);

    try {
        const user = await db.select().from(users)
            .where(eq(users.email, email));

        if (!user.length) {
            return c.json({ message: 'Usuario no encontrado' }, 400);
        }

        if (!user[0].password) {
            return c.json({ message: 'Contraseña no válida' }, 400);
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
.post('/login-or-register', zValidator("json", userSchema), async (c) => {
    const { email, password } = c.req.valid("json");
    const db = drizzle(pool);
    try {
        let user = await db.select().from(users)
            .where(eq(users.email, email));
        if (user.length) {
            // User exists, try login
            if (!user[0].password) {
                return c.json({ message: 'Contraseña no válida' }, 400);
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
        } else {
            // Register new user
            const passwordHash = await bcrypt.hash(password, 10);
            await db.insert(users).values({
                email,
                password: passwordHash,
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
            return c.json({ message: 'Usuario registrado correctamente', user: newUser }, 200);
        }
    } catch (error: any) {
        return c.json({ message: 'Error en login o registro'}, 400);
    }
})
.get('/profile', async (c) => {
    try {     
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

        if (!user.length) {
            return c.json({ message: 'Usuario no encontrado' }, 400);
        }
        return c.json({ user }, 200);
    } catch (error) {
        return c.json({ message: 'Error al obtener el perfil del usuario'}, 400);
    }
})
.delete('/logout', async (c) => {
    deleteCookie(c, 'token');
    return c.json({ message: 'Logout successful' }, 200);
})
.get('/google', async (c) => {
    const state = crypto.randomBytes(16).toString('hex');
    const redirectUri = c.req.query('redirect_uri') || 'https://my.tiendia.app/home';
    // Codifica state y redirectUri en base64
    const stateObj = { state, redirectUri };
    const stateParam = Buffer.from(JSON.stringify(stateObj)).toString('base64');
    setCookie(c, 'oauth_state', state, {
        path: '/api/auth/google/callback',
        httpOnly: true,
        maxAge: 600,
        sameSite: 'None',
        secure: process.env.NODE_ENV === 'production',
    });
    // Ya no se usa oauth_redirect_uri

    const authUrl = googleClient.generateAuthUrl({
        access_type: 'offline',
        scope: [
            'https://www.googleapis.com/auth/userinfo.email',
            'https://www.googleapis.com/auth/userinfo.profile',
            'openid', 
        ],
        state: stateParam,
    });
    return c.redirect(authUrl);
})

.get('/google/callback', async (c) => {
    const db = drizzle(pool);
    const code = c.req.query('code');
    
    deleteCookie(c, 'oauth_state', { path: '/api/auth/google/callback' });

    // Decodifica el parámetro state
    let redirectUri = 'https://my.tiendia.app/home';
    try {
      const stateParam = c.req.query('state');
      if (stateParam) {
        const stateObj = JSON.parse(Buffer.from(stateParam, 'base64').toString('utf-8'));
        if (stateObj.redirectUri) {
          redirectUri = stateObj.redirectUri;
        }
      }
    } catch (e) {
      // Si falla, usa el default
      redirectUri = 'https://my.tiendia.app/home';
    }

    if (!code) {
        const error = c.req.query('error');
        console.error("Google OAuth Error:", error);
        return c.redirect(`${redirectUri}?error=${error || 'unknown_google_error'}`);
    }

    try {
        const { tokens } = await googleClient.getToken(code);
        googleClient.setCredentials(tokens); 

        if (!tokens.id_token) {
            throw new Error("ID token not received from Google.");
        }
        const loginTicket = await googleClient.verifyIdToken({
            idToken: tokens.id_token,
            audience: process.env.GOOGLE_CLIENT_ID,
        });
        const payload = loginTicket.getPayload();
        if (!payload || !payload.sub || !payload.email) {
            throw new Error('Información de perfil de Google inválida.');
        }

        const googleId = payload.sub;
        const email = payload.email;

        let user = null;
        const existingUser = await db.select().from(users)
            .where(eq(users.email, email))
            .limit(1);

        if (existingUser.length) {
            user = existingUser[0];
            if (!user.googleId) {
                await db.update(users)
                .set({ googleId: googleId }) 
                .where(eq(users.id, user.id));
                user.googleId = googleId; 
            } else if (user.googleId !== googleId) {
                return c.redirect(`${redirectUri}?error=email_google_conflict`);
            }
        } else {
            const insertResult = await db.insert(users).values({
                email,
                googleId,
                createdAt: new Date(),
            });
            const userId = insertResult[0].insertId;
            const newUserResult = await db.select().from(users)
            .where(eq(users.id, userId))
            .limit(1);
            if (!newUserResult.length) {
                throw new Error("No se pudo encontrar el usuario de Google recién creado.");
            }
            user = newUserResult[0];
        }

        if (!user) { 
            throw new Error("No se pudo obtener o crear la información del usuario.");
        }
        const token = await createAccessToken({ id: user.id });

        setCookie(c, 'token', token as string, {
            path: '/',
            sameSite: 'None',
            secure: true,
            maxAge: 7 * 24 * 60 * 60,
        });
        return c.redirect(redirectUri);
    } catch (error: any) {
        console.error("Google Callback Error:", error);
        return c.redirect(`${redirectUri}?error=google_callback_failed`);
    }
})
.post('/mi-tiendia', authMiddleware, zValidator("json", miTiendiaSchema), async (c) => {
    const { storeName, storeLogo, phoneNumber, countryCode } = c.req.valid("json");
    const db = drizzle(pool);
    
    try {
        const token = getCookie(c, 'token');
        if (!token) {
            return c.json({ error: 'No hay token' }, 401);
        }

        const decoded = await new Promise((resolve, reject) => {
            jwt.verify(token, process.env.TOKEN_SECRET || 'my-secret', (error, decoded) => {
                if (error) reject(error);
                resolve(decoded);
            });
        });

        const userId = (decoded as JwtPayload).id;
        
        // Get current user data to check for existing logo
        const currentUser = await db.select().from(users)
            .where(eq(users.id, userId))
            .limit(1);
        
        // Generate store URL from store name
        const storeUrl = storeName
            .toLowerCase()
            .replace(/[^a-z0-9]/g, '')
            .substring(0, 20);
        
        // Handle logo upload if provided
        let logoUrl: string | undefined;
        if (storeLogo) {
            try {
                // If user already has a logo, delete the old one first
                if (currentUser[0]?.imageUrl) {
                    await deleteImage(currentUser[0].imageUrl);
                }
                
                logoUrl = await saveImage(storeLogo);
                console.log("Logo guardado en R2:", logoUrl);
            } catch (error) {
                console.error("Error al guardar el logo:", error);
                return c.json({ error: 'Error al procesar el logo' }, 400);
            }
        }

        // Update user with store information
        await db.update(users).set({
            name: storeName, // Use existing name field for store name
            username: storeUrl, // Use existing username field for store URL
            phone: phoneNumber, // Use existing phone field
            imageUrl: logoUrl || currentUser[0]?.imageUrl, // Keep existing logo if no new one provided
        }).where(eq(users.id, userId));

        // Get updated user data
        const updatedUser = await db.select().from(users)
            .where(eq(users.id, userId))
            .limit(1);

        return c.json({
            message: 'Tienda creada exitosamente',
            store: {
                name: storeName,
                url: storeUrl,
                logoUrl: logoUrl || currentUser[0]?.imageUrl,
                phoneNumber: phoneNumber,
                countryCode: countryCode
            },
            user: updatedUser[0]
        }, 200);

    } catch (error: any) {
        console.error("Error en la ruta /mi-tiendia:", error);
        return c.json({ error: 'Error al crear la tienda' }, 500);
    }
})
.get('/store/:username', async (c) => {
    const username = c.req.param('username');
    const db = drizzle(pool);
    
    try {
        // Get user by username
        const user = await db.select().from(users)
            .where(eq(users.username, username))
            .limit(1);

        if (!user.length) {
            return c.json({ error: 'Esta página no existe' }, 404);
        }

        // Check if user has paid for MiTiendia or is within grace period
        const isPaid = user[0].paidMiTienda;
        
        let shouldShowStore = isPaid;
        
        if (isPaid) {
            shouldShowStore = true;
        }

        if (!shouldShowStore) {
            return c.json({ error: 'Esta página no existe' }, 404);
        }

        // Get user's products
        const userProducts = await db.select({
            id: products.id,
            name: products.name,
            imageURL: products.imageURL,
            price: products.price,
            sizes: products.sizes,
            storeImageURLs: products.storeImageURLs,
        })
        .from(products)
        .where(eq(products.createdById, user[0].id));

        return c.json({
            store: {
                name: user[0].name,
                username: user[0].username,
                phone: user[0].phone,
                imageUrl: user[0].imageUrl,
            },
            products: userProducts
        }, 200);

    } catch (error: any) {
        console.error("Error en la ruta /store/:username:", error);
        return c.json({ error: 'Error interno del servidor' }, 500);
    }
});

export default authRoute;
