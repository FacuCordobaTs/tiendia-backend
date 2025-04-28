import { zValidator } from "@hono/zod-validator";
import { Hono } from "hono";
import { z } from "zod";
import { drizzle } from "drizzle-orm/mysql2";
import { pool } from "../db";
import { images, products, users } from "../db/schema";
import { authMiddleware } from "../middlewares/auth.middleware";
import { eq, sql } from "drizzle-orm";
import UUID from "uuid-js";
import { readFile, writeFile, unlink } from "fs/promises";
import { join } from "path";
import * as fs from "fs";
import jwt, {JwtPayload} from "jsonwebtoken";
import { getCookie } from "hono/cookie";
import { GeminiRequestQueue } from "../libs/GeminiRequestQueue";
import { S3Client, PutObjectCommand, DeleteObjectCommand } from "@aws-sdk/client-s3";
import { Buffer } from 'buffer'; // Importa Buffer explícitamente si es necesario en tu entorno

// --- Constantes (mantienes las de validación) ---
const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB
const ALLOWED_MIME_TYPES = ["image/jpeg", "image/png", "image/webp"];

// --- Configuración del Cliente S3 (asegúrate que las variables de entorno estén cargadas) ---
const R2_ACCOUNT_ID = process.env.R2_ACCOUNT_ID;
const R2_ACCESS_KEY_ID = process.env.R2_ACCESS_KEY_ID;
const R2_SECRET_ACCESS_KEY = process.env.R2_SECRET_ACCESS_KEY;
const R2_BUCKET_NAME = process.env.R2_BUCKET_NAME;
const R2_PUBLIC_URL = process.env.R2_PUBLIC_URL?.replace(/\/$/, ''); // Asegura que no termine con /

if (!R2_ACCOUNT_ID || !R2_ACCESS_KEY_ID || !R2_SECRET_ACCESS_KEY || !R2_BUCKET_NAME || !R2_PUBLIC_URL) {
  console.error("FATAL ERROR: Faltan variables de entorno de Cloudflare R2. La aplicación no puede manejar imágenes.");
  // En un escenario real, podrías querer detener la app o manejar esto más elegantemente
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

const generateProductSchema = z.object({
  image: z.string().min(10),
  includeModel: z.boolean().optional().default(false),
});

const UPLOAD_DIR = join(process.cwd(), "public", "uploads");

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
  // Verifica si es una URL de R2 gestionada por esta app
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
     // Es común que S3 devuelva un error si el objeto ya no existe, podríamos querer ignorarlo.
     // Revisar el tipo de error si es necesario (ej. error.name === 'NoSuchKey')
     console.error(`Error al eliminar objeto de R2 (${imageUrl}):`, error);
     // No relanzar para permitir que la lógica de la BD continúe si es deseado.
  }
}

const updateProductSchema = z.object({
  name: z.string().min(3).max(255),
  imageBase64: z.string().optional(),
  id: z.number(),
});

export const productsRoute = new Hono()
  .put("/update", zValidator("json", updateProductSchema), async (c) => {
    try {
      const { name, imageBase64, id } = c.req.valid("json");
      const db = drizzle(pool);

      let imageURL: string | undefined;

      if (imageBase64) {
        const [meta, data] = imageBase64.split(",");
        const mimeType = meta.match(/:(.*?);/)?.[1];

        if (!mimeType || !ALLOWED_MIME_TYPES.includes(mimeType)) {
          return c.json({ error: "Tipo de archivo no permitido" }, 400);
        }

        const buffer = Buffer.from(data, "base64");
        if (buffer.byteLength > MAX_FILE_SIZE) {
          return c.json({ error: "La imagen es demasiado grande" }, 400);
        }

        imageURL = await saveImage(imageBase64);
      }

        await db
        .update(products)
        .set({
          name,
          ...(imageURL && { imageURL }),
        })
        .where(eq(products.id, id));
      return c.json(
        {
          message: "Producto actualizado correctamente",
          product: {
            name,
            imageURL,
          },
        },
        200
      );
    } catch (error) {
      return c.json({ message: "Error al actualizar el producto" }, 400);
    }
  })

  .delete("/delete/:id", authMiddleware, async (c) => {
    const db = drizzle(pool);
    const id = Number(c.req.param("id"));
    try {
      const product = await db.select().from(products).where(eq(products.id, id));

      if (!product || product.length === 0) {
        return c.json({ message: "Producto no encontrado" }, 404);
      }

      if (product[0].imageURL) {
        await deleteImage(product[0].imageURL);
      }

      // Eliminar todas las imágenes asociadas al producto
      const associatedImages = await db.select().from(images).where(eq(images.productId, id));

      for (const image of associatedImages) {
        if (image.url) {
          await deleteImage(image.url); // Eliminar archivo físico
        }
      }

      await db.delete(images).where(eq(images.productId, id)); // Eliminar registros de la base de datos
      await db.delete(products).where(eq(products.id, id));

      return c.json({ message: "Producto eliminado correctamente" }, 200);
    } catch (error) {
      console.error("Error eliminando producto:", error);
      return c.json({ message: "Error al eliminar el producto" }, 500);
    }
  })
  .get("/list/:id", async (c) => {
    const db = drizzle(pool);
    const id = c.req.param("id");

    try {
      const productsListed = await db
        .select({
          id: products.id,
          name: products.name,
          imageURL: products.imageURL,
          createdAt: products.createdAt,
        })
        .from(products)
        .where(eq(products.createdById, Number(id)));

      if (!productsListed || productsListed.length === 0) {
        return c.json({ message: "No hay productos registrados" }, 404);
      }


      return c.json({ products: productsListed }, 200);
    } catch (error) {
      return c.json({ message: "Error al obtener los productos" }, 400);
    }
  })
  .post("/generate-ad/:id", authMiddleware, async (c) => {
    const id = Number(c.req.param("id"));
    const db = drizzle(pool);
    const workerUrl = "https://gemini-worker.facucordoba200.workers.dev";
    const requestQueue = GeminiRequestQueue.getInstance();
    const token = getCookie(c, 'token');
    if (!token) return c.json({ error: 'Unauthorized' }, 401);

    const decoded = await new Promise((resolve, reject) => {
      jwt.verify(token, process.env.TOKEN_SECRET || 'my-secret', (error, decoded) => {
          if (error) reject(error);
          resolve(decoded);
      });
  });

  const userId = (decoded as JwtPayload).id


    const credits = await db.select({
      credits: users.credits,
    })
    .from(users)
    .where(eq(users.id, userId))

    if (credits && credits[0] && credits[0].credits && credits[0].credits < 50) {
      return c.json({ message: "Creditos no suficientes" }, { status: 400 });
    }
    if (isNaN(id)) {
      return c.json({ error: "ID de producto inválido" }, { status: 400 }); // Usa init object
    }

    let includeModel = true;
    try {
        const body = await c.req.json();
        if (typeof body?.includeModel === 'boolean') {
             includeModel = body.includeModel;
        }
        console.log(`Opción 'includeModel' recibida: ${includeModel}`);
    } catch (e) {
         console.warn("No se pudo parsear el body o 'includeModel' no presente/válido.");
    }

    try {
      // 1. Buscar el producto
      const productResult = await db
        .select({
          imageURL: products.imageURL,
        })
        .from(products)
        .where(eq(products.id, id))
        .limit(1);

      if (!productResult || productResult.length === 0) {
        return c.json({ message: "Producto no encontrado" }, { status: 404 }); // Usa init object
      }
      const product = productResult[0];

      // 2. Verificar imagen original
      if (!product.imageURL) {
        return c.json(
          { message: "El producto no tiene una imagen para generar publicidad." },
          { status: 400 } // Usa init object
        );
      }
      const originalProductImageUrl = product.imageURL

      // 3. Leer imagen original y convertir a Base64
      const originalImageName = product.imageURL.split("/").pop();
       if (!originalImageName) {
         console.error("No se pudo extraer el nombre de archivo de:", product.imageURL);
         return c.json({ message: "Error al procesar la URL de la imagen original." }, { status: 500 });
       }
      
      let originalImageBase64: string;
      let originalMimeType: string;
 
      try {
        console.log(`Descargando imagen original desde R2: ${originalProductImageUrl}`);
        const response = await fetch(originalProductImageUrl); // Usar fetch global
        if (!response.ok) {
            throw new Error(`Error HTTP ${response.status} al descargar imagen de R2`);
        }
        const contentTypeHeader = response.headers.get("content-type");

        // Determinar MimeType (priorizar header, luego extensión URL)
        if (contentTypeHeader && ALLOWED_MIME_TYPES.includes(contentTypeHeader)) {
            originalMimeType = contentTypeHeader;
        } else {
            const urlPath = new URL(originalProductImageUrl).pathname;
            const extension = urlPath.split('.').pop()?.toLowerCase();
            if (extension === "jpg" || extension === "jpeg") originalMimeType = "image/jpeg";
            else if (extension === "png") originalMimeType = "image/png";
            else if (extension === "webp") originalMimeType = "image/webp";
            else { throw new Error("Tipo MIME desconocido o no permitido para la imagen original."); }
            console.warn(`Usando MimeType ${originalMimeType} basado en extensión para ${originalProductImageUrl}`);
        }

        const imageBuffer = await response.arrayBuffer();
        originalImageBase64 = Buffer.from(imageBuffer).toString("base64");
        console.log(`Imagen original descargada de R2 y convertida a Base64 (${(originalImageBase64.length * 3/4 / 1024).toFixed(2)} KB)`);

    } catch (fetchError: any) {
        console.error(`Error al obtener/procesar la imagen original desde R2 (${originalProductImageUrl}):`, fetchError);
        return c.json({ message: "Error crítico al acceder a la imagen original del producto." }, { status: 500 });
    }

      // 4. Enviar datos al Worker a través de la cola
      console.log(`Enviando solicitud al worker para el producto ID: ${id}`);
      const workerPayload = {
        imageBase64: originalImageBase64,
        mimeType: originalMimeType,
        includeModel: includeModel,
      };

      // Usar la cola para gestionar la solicitud
      const workerResponse = await requestQueue.enqueue(workerPayload, workerUrl);
      console.log(`Respuesta del worker recibida correctamente`);

      try {
        const adImageUrl = await saveImage(`data:image/png;base64,${workerResponse.geminiData.candidates[0].content.parts[0].inlineData.data}`); // <--- Ahora es seguro

        const result = await db.insert(images).values({
          url: adImageUrl,      // La URL relativa guardada localmente
          productId: id,         // El ID del producto para el que se generó
          createdAt: new Date(), // Fecha de creación
        })
        .$returningId()
        console.log(`Registro insertado en tabla 'images' para producto ${id}, URL: ${adImageUrl}`);


        if (credits[0] && credits[0].credits) { 
          await db.update(users).set({
            credits: credits[0].credits - 50,
          })
          .where(eq(users.id, userId))
        }

        return c.json(
          {
            message: "Publicidad generada correctamente.",
            adImageUrl: adImageUrl,
            imageId: result[0].id
            },
          { status: 200 } 
        );
      } catch (error: any) {
        console.error("Error al guardar la imagen generada:", error);
        return c.json({ message: "Error al guardar la imagen generada por el worker." }, { status: 500 });
      }

    } catch (error: any) {
      console.error("Error en la ruta /generate-ad:", error);
      const errorMessage = error.message || "Error interno del servidor al generar la publicidad.";
      return c.json({ message: errorMessage }, { status: 500 }); // <- Usa también el objeto init aquí
    }
  })
  .get("/images/by-user/:userId", authMiddleware, async (c) => {
    const db = drizzle(pool);
    const userIdParam = c.req.param("userId");
    const userId = Number(userIdParam);

    if (isNaN(userId)) {
        return c.json({ error: "ID de usuario inválido" }, 400);
    }

    try {
        const userImages = await db.select({
            imageId: images.id,
            imageUrl: images.url,
            productId: images.productId,
            productName: products.name, // Opcional: incluir el nombre del producto
            createdAt: images.createdAt,
        })
        .from(images)
        .innerJoin(products, eq(images.productId, products.id))
        .where(eq(products.createdById, userId)); // Compara con el ID numérico del usuario

        // Devuelve las imágenes encontradas (puede ser un array vacío)
        return c.json({ images: userImages }, 200);

    } catch (error: any) {
        console.error(`Error al obtener imágenes para el usuario ${userId}:`, error);
        return c.json({ message: "Error interno al obtener las imágenes generadas." }, 500);
    }
})
.delete("/images/:imageId", authMiddleware, async (c) => {
  const db = drizzle(pool);
  const imageIdParam = c.req.param("imageId");
  const imageId = Number(imageIdParam);


  if (isNaN(imageId)) {
      return c.json({ error: "ID de imagen inválido" }, 400);
  }

  try {
      // 1. Buscar la imagen y verificar la propiedad a través del producto
          const imageResult = await db.select({
              imageUrl: images.url,
          })
          .from(images)
          .where(eq(images.id, imageId))
      if (!imageResult || imageResult.length === 0) {
          return c.json({ message: "Imagen no encontrada" }, 404);
      }

      const imageToDelete = imageResult[0];

      if (imageToDelete.imageUrl) {
           await deleteImage(imageToDelete.imageUrl); // Usa tu función existente
           console.log(`Archivo físico ${imageToDelete.imageUrl} marcado para eliminación (o eliminado).`);
      } else {
           console.warn(`La imagen ${imageId} no tenía URL registrada para eliminar archivo.`);
      }


      // 4. Eliminar el registro de la base de datos
      await db.delete(images).where(eq(images.id, imageId));
      console.log(`Registro de imagen ${imageId} eliminado de la base de datos.`);

      return c.json({ message: "Imagen eliminada correctamente" }, 200);

  } catch (error: any) {
      console.error(`Error al eliminar imagen ${imageId}:`, error);
      return c.json({ message: "Error interno al eliminar la imagen." }, 500);
  }
})

// NUEVO ENDPOINT PARA MODIFICAR IMAGEN
productsRoute.post("/images/modify/:imageId", authMiddleware, zValidator("json", z.object({ prompt: z.string().min(1) })), async (c) => {
  const db = drizzle(pool);
  const imageIdParam = c.req.param("imageId");
  const imageId = Number(imageIdParam);
  const { prompt } = c.req.valid("json");
  const workerUrl = "https://gemini-worker.facucordoba200.workers.dev";
  const requestQueue = GeminiRequestQueue.getInstance();

  if (isNaN(imageId)) {
    return c.json({ error: "ID de imagen inválido" }, 400);
  }

  const token = getCookie(c, 'token');
  if (!token) return c.json({ error: 'Unauthorized' }, 401);

  let userId: number;
  try {
    const decoded = await new Promise<JwtPayload>((resolve, reject) => {
      jwt.verify(token, process.env.TOKEN_SECRET || 'my-secret', (error, decoded) => {
        if (error) reject(error);
        resolve(decoded as JwtPayload);
      });
    });
    userId = decoded.id;
  } catch (error) {
    return c.json({ error: 'Invalid token' }, 401);
  }

  try {
    // 1. Verificar créditos
    const creditsResult = await db.select({ credits: users.credits }).from(users).where(eq(users.id, userId));
    const currentCredits = creditsResult[0]?.credits ?? 0;
    if (currentCredits < 50) { // Asumiendo que modificar cuesta 50 créditos
      return c.json({ message: "Créditos insuficientes" }, { status: 400 });
    }

    // 2. Buscar la imagen original y su producto asociado
    const imageResult = await db.select({
        imageUrl: images.url,
        productId: images.productId
      })
      .from(images)
      .where(eq(images.id, imageId))
    console.log(imageResult)
    if (!imageResult ) {
      return c.json({ message: "Imagen original no encontrada, con imageId: "+imageId  }, 404);
    }
    const originalImage = imageResult[0];
    console.log(originalImage)
    if (!imageResult || imageResult.length === 0 || !originalImage || !originalImage.imageUrl) {
        return c.json({ message: "La imagen original no tiene URL" }, 400);
    }
    const originalImageUrl = originalImage.imageUrl; // URL de R2

    // 3. Leer imagen original y convertir a Base64
    const originalImageName = originalImage.imageUrl.split("/").pop();
    if (!originalImageName) {
      console.error("No se pudo extraer el nombre de archivo de:", originalImage.imageUrl);
      return c.json({ message: "Error al procesar la URL de la imagen original." }, { status: 500 });
    }
    
    let originalImageBase64: string;
    let originalMimeType: string;

    try {
      console.log(`Descargando imagen a modificar desde R2: ${originalImageUrl}`);
      const response = await fetch(originalImageUrl);
      if (!response.ok) { throw new Error(`Error HTTP ${response.status} al descargar imagen de R2`); }
      const contentTypeHeader = response.headers.get("content-type");
      // ... (Lógica para determinar originalMimeType igual que en /generate-ad) ...
       if (contentTypeHeader && ALLOWED_MIME_TYPES.includes(contentTypeHeader)) {
           originalMimeType = contentTypeHeader;
       } else {
          const urlPath = new URL(originalImageUrl).pathname;
          const extension = urlPath.split('.').pop()?.toLowerCase();
          if (extension === "jpg" || extension === "jpeg") originalMimeType = "image/jpeg";
          else if (extension === "png") originalMimeType = "image/png";
          else if (extension === "webp") originalMimeType = "image/webp";
          else { throw new Error("Tipo MIME desconocido o no permitido para la imagen original."); }
           console.warn(`Usando MimeType ${originalMimeType} basado en extensión para ${originalImageUrl}`);
       }

      const imageBuffer = await response.arrayBuffer();
      originalImageBase64 = Buffer.from(imageBuffer).toString("base64");
      console.log(`Imagen a modificar descargada de R2 y convertida a Base64.`);
  } catch (fetchError: any) {
      console.error(`Error al obtener/procesar la imagen a modificar desde R2 (${originalImageUrl}):`, fetchError);
      return c.json({ message: "Error crítico al acceder a la imagen a modificar." }, { status: 500 });
  }

    // 4. Enviar datos al Worker para modificación
    console.log(`Enviando solicitud de modificación al worker para imagen ID: ${imageId}`);
    const workerPayload = {
      task: 'modify_image', // Nueva tarea para el worker
      imageBase64: originalImageBase64,
      mimeType: originalMimeType,
      prompt: prompt, // Instrucciones del usuario
    };

    // Usar la cola para gestionar la solicitud
    const workerResponse = await requestQueue.enqueue(workerPayload, workerUrl);
    console.log(`Respuesta de modificación del worker recibida`);

    // 5. Procesar respuesta del worker y guardar nueva imagen
    const modifiedImageData = workerResponse.geminiData?.candidates?.[0]?.content?.parts?.[0]?.inlineData?.data;

    if (!modifiedImageData) {
      console.error("El worker no devolvió datos de imagen modificada:", workerResponse);
      return c.json({ message: "Error al generar la imagen modificada por el worker." }, { status: 500 });
    }

    let modifiedImageUrl: string;
    try {
      modifiedImageUrl = await saveImage(`data:image/png;base64,${modifiedImageData}`);
      console.log("Imagen modificada guardada en:", modifiedImageUrl);

      // 6. Insertar registro de la nueva imagen en la BD (asociada al mismo producto)
      const result = await db.insert(images).values({
        url: modifiedImageUrl,
        productId: originalImage.productId, // Asociar al producto original
        createdAt: new Date(),
      }).$returningId();
      console.log(`Registro insertado en tabla 'images' para imagen modificada, URL: ${modifiedImageUrl}`);

      // 7. Deducir créditos
      await db.update(users).set({
        credits: currentCredits - 50,
      })
      .where(eq(users.id, userId));

      return c.json(
        {
          message: "Imagen modificada correctamente.",
          modifiedImageUrl: modifiedImageUrl,
          imageId: result[0].id
        },
        { status: 200 }
      );
    } catch (saveError: any) {
      console.error("Error al guardar la imagen modificada:", saveError);
      // Intentar eliminar el archivo si se creó pero falló la inserción en BD
      if (modifiedImageUrl!) {
        try { await deleteImage(modifiedImageUrl!); } catch (delErr) { console.error("Error al intentar limpiar imagen guardada tras fallo:", delErr); }
      }
      return c.json({ message: "Error al guardar la imagen modificada." }, { status: 500 });
    }

  } catch (error: any) {
    console.error(`Error en la ruta /images/modify/${imageId}:`, error);
    const errorMessage = error.message || "Error interno del servidor al modificar la imagen.";
    return c.json({ message: errorMessage }, { status: 500 });
  }
});

productsRoute.post("/generate-product-and-image",authMiddleware, zValidator("json", generateProductSchema), async (c) => {
  const { image: userImageBase64, includeModel } = c.req.valid("json");
  const db = drizzle(pool);
  
  const workerUrl = "https://gemini-worker.facucordoba200.workers.dev";
  const requestQueue = GeminiRequestQueue.getInstance();
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
  const userId = (decoded as jwt.JwtPayload).id

  if (!userId) {
    return c.json({ message: "Usuario no autenticado" }, { status: 401 });
  }

  const credits = await db.select({
    credits: users.credits,
  })
  .from(users)
  .where(eq(users.id, userId))

  if (credits[0].credits && credits[0].credits < 50) {
    return c.json({ message: "Creditos no suficientes" }, { status: 400 });
  }

  let originalImageUrl: string | null = null;
  let generatedImageUrl: string | null = null;
  let productName = "Producto";

  const [meta, data] = userImageBase64.split(",");
  const mimeType = meta?.match(/:(.*?);/)?.[1];

  if (!mimeType || !ALLOWED_MIME_TYPES.includes(mimeType)) {
    return c.json({ error: "Tipo de archivo no permitido" }, 400);
  }
  const buffer = Buffer.from(data, "base64");
  if (buffer.byteLength > MAX_FILE_SIZE) {
    return c.json({ error: "La imagen es demasiado grande" }, 400);
  }

  originalImageUrl = await saveImage(userImageBase64);
  console.log("Imagen original guardada en:", originalImageUrl);

  console.log("Llamando al worker para generar nombre...");
  const nameWorkerPayload = {
    task: 'generate_name', // Indicador de tarea
    imageBase64: data,
    mimeType: mimeType,
  };

  // Usar la cola para la solicitud de nombre
  try {
    const nameResult = await requestQueue.enqueue(nameWorkerPayload, workerUrl);
    if (nameResult.generatedName) {
      productName = nameResult.generatedName;
      console.log(`Nombre generado por worker: ${productName}`);
    } else {
      console.warn("Worker no devolvió nombre generado:", nameResult);
    }
  } catch (error) {
    console.error("Error del worker (generando nombre):", error);
    // Continuar con el nombre predeterminado
  }
  
  console.log(`Llamando al worker para generar imagen (includeModel: ${includeModel})...`);
  const imageWorkerPayload = {
    task: 'generate_image',
    imageBase64: data,
    mimeType: mimeType,
    includeModel: includeModel,
  };

  // Usar la cola para la solicitud de imagen
  try {
    const imageResult = await requestQueue.enqueue(imageWorkerPayload, workerUrl);
    const generatedImageData = imageResult.geminiData?.candidates?.[0]?.content?.parts?.[0]?.inlineData?.data;

    if (generatedImageData) {
      generatedImageUrl = await saveImage(`data:image/png;base64,${generatedImageData}`);
      console.log("Imagen generada guardada en:", generatedImageUrl);
    } else {
      console.warn("Worker no devolvió imagen generada:", imageResult);
    }
  } catch (error) {
    console.error("Error del worker (generando imagen):", error);
    // Continuar sin imagen generada
  }
  const insertedProduct = await db.insert(products).values({
    name: productName,
    imageURL: originalImageUrl,
    createdById: userId,
    createdAt: new Date(),
  }).$returningId();

  const productId = insertedProduct[0].id;

  let imageId;
  if (generatedImageUrl) {
    const result = await db.insert(images).values({
      url: generatedImageUrl,
      productId: productId,
      createdAt: new Date(),
    }).$returningId();
    imageId = result[0].id;
  }

  if (credits[0] && credits[0].credits) { 
    await db.update(users).set({
      credits: credits[0].credits - 50,
    })
    .where(eq(users.id, userId))
  }
  
  return c.json(
    {
      message: "Producto procesado correctamente.",
      product: {
        id: productId,
        name: productName,
        originalImageUrl: originalImageUrl,
        generatedImageUrl: generatedImageUrl,
      },
      imageId
    },
    { status: 200 }
  );
})