import { zValidator } from "@hono/zod-validator";
import { Hono } from "hono";
import { z } from "zod";
import { drizzle } from "drizzle-orm/mysql2";
import { pool } from "../db";
import { images, products, users } from "../db/schema";
import { authMiddleware } from "../middlewares/auth.middleware";
import { eq, sql, like, notLike, and } from "drizzle-orm"; // Added 'and', removed like and notLike from previous comment
import UUID from "uuid-js";
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

const updateProductSchema = z.object({
  name: z.string().min(3).max(255),
  imageBase64: z.string().optional(),
  id: z.number(),
});

const personalizeSchema = z.object({
  gender: z.enum(['male', 'female']).optional(),
  age: z.enum(['youth', 'adult', 'senior']).optional(),
  skinTone: z.enum(['light', 'medium', 'dark']).optional(),
  bodyType: z.enum(['slim', 'athletic', 'curvy']).optional()
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

      const associatedImages = await db.select().from(images).where(eq(images.productId, id));

      for (const image of associatedImages) {
        if (image.url) {
          await deleteImage(image.url);
        }
      }

      await db.delete(images).where(eq(images.productId, id));
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

    const userId = (decoded as JwtPayload).id;

    const credits = await db.select({
      credits: users.credits,
    })
    .from(users)
    .where(eq(users.id, userId));

    if (credits && credits[0] && credits[0].credits && credits[0].credits < 50) {
      return c.json({ message: "Creditos no suficientes" }, { status: 400 });
    }
    if (isNaN(id)) {
      return c.json({ error: "ID de producto inválido" }, { status: 400 });
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
      const productResult = await db
        .select({
          imageURL: products.imageURL,
        })
        .from(products)
        .where(eq(products.id, id))
        .limit(1);

      if (!productResult || productResult.length === 0) {
        return c.json({ message: "Producto no encontrado" }, { status: 404 });
      }
      const product = productResult[0];

      if (!product.imageURL) {
        return c.json(
          { message: "El producto no tiene una imagen para generar publicidad." },
          { status: 400 }
        );
      }
      const originalProductImageUrl = product.imageURL;

      const originalImageName = product.imageURL.split("/").pop();
       if (!originalImageName) {
         console.error("No se pudo extraer el nombre de archivo de:", product.imageURL);
         return c.json({ message: "Error al procesar la URL de la imagen original." }, { status: 500 });
       }
      
      let originalImageBase64: string;
      let originalMimeType: string;
 
      try {
        console.log(`Descargando imagen original desde R2: ${originalProductImageUrl}`);
        const response = await fetch(originalProductImageUrl);
        if (!response.ok) {
            throw new Error(`Error HTTP ${response.status} al descargar imagen de R2`);
        }
        const contentTypeHeader = response.headers.get("content-type");

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

      console.log(`Enviando solicitud al worker para el producto ID: ${id}`);
      const workerPayload = {
        imageBase64: originalImageBase64,
        mimeType: originalMimeType,
        includeModel: includeModel,
      };

      const workerResponse = await requestQueue.enqueue(workerPayload, workerUrl);
      console.log(`Respuesta del worker recibida correctamente`);

      const imagePart = workerResponse.geminiData?.candidates?.[0]?.content?.parts?.find((part: { inlineData: any; }) => part.inlineData);
      if (imagePart?.inlineData) {
        const generatedImageData = imagePart.inlineData.data;
        const mimeType = imagePart.inlineData.mimeType || "image/png";
        const adImageUrl = await saveImage(`data:${mimeType};base64,${generatedImageData}`);
        console.log("Imagen generada guardada en:", adImageUrl);

        const result = await db.insert(images).values({
          url: adImageUrl,
          productId: id,
          createdAt: new Date(),
        }).$returningId();
        console.log(`Registro insertado en tabla 'images' para producto ${id}, URL: ${adImageUrl}`);

        if (credits[0] && credits[0].credits) { 
          await db.update(users).set({
            credits: credits[0].credits - 50,
          }).where(eq(users.id, userId));
        }

        return c.json({
          message: "Publicidad generada correctamente.",
          adImageUrl: adImageUrl,
          imageId: result[0].id
        }, { status: 200 });
      } else {
        console.warn("No se encontró inlineData en la respuesta del worker:", workerResponse);
        return c.json({ message: "El worker no devolvió una imagen generada." }, { status: 500 });
      }

    } catch (error: any) {
      console.error("Error en la ruta /generate-ad:", error);
      const errorMessage = error.message || "Error interno del servidor al generar la publicidad.";
      return c.json({ message: errorMessage }, { status: 500 });
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
            productName: products.name,
            createdAt: images.createdAt,
        })
        .from(images)
        .innerJoin(products, eq(images.productId, products.id))
        .where(eq(products.createdById, userId));

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
           await deleteImage(imageToDelete.imageUrl);
           console.log(`Archivo físico ${imageToDelete.imageUrl} marcado para eliminación (o eliminado).`);
      } else {
           console.warn(`La imagen ${imageId} no tenía URL registrada para eliminar archivo.`);
      }

      await db.delete(images).where(eq(images.id, imageId));
      console.log(`Registro de imagen ${imageId} eliminado de la base de datos.`);

      return c.json({ message: "Imagen eliminada correctamente" }, 200);

  } catch (error: any) {
      console.error(`Error al eliminar imagen ${imageId}:`, error);
      return c.json({ message: "Error interno al eliminar la imagen." }, 500);
  }
})

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
    const creditsResult = await db.select({ credits: users.credits }).from(users).where(eq(users.id, userId));
    const currentCredits = creditsResult[0]?.credits ?? 0;
    if (currentCredits < 50) {
      return c.json({ message: "Créditos insuficientes" }, { status: 400 });
    }

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
    const originalImageUrl = originalImage.imageUrl;

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

    console.log(`Enviando solicitud de modificación al worker para imagen ID: ${imageId}`);
    const workerPayload = {
      task: 'modify_image',
      imageBase64: originalImageBase64,
      mimeType: originalMimeType,
      prompt: prompt,
    };

    const workerResponse = await requestQueue.enqueue(workerPayload, workerUrl);
    console.log(`Respuesta de modificación del worker recibida`);

    // Modificación: Usar el mismo patrón que en generate-ad
    const imagePart = workerResponse.geminiData?.candidates?.[0]?.content?.parts?.find((part: { inlineData: any; }) => part.inlineData);
    if (!imagePart?.inlineData) {
      console.error("El worker no devolvió datos de imagen modificada:", workerResponse);
      return c.json({ message: "Error al generar la imagen modificada por el worker." }, { status: 500 });
    }

    const modifiedImageData = imagePart.inlineData.data;
    const mimeType = imagePart.inlineData.mimeType || "image/png";

    let modifiedImageUrl: string;
    try {
      modifiedImageUrl = await saveImage(`data:${mimeType};base64,${modifiedImageData}`);
      console.log("Imagen modificada guardada en:", modifiedImageUrl);

      const result = await db.insert(images).values({
        url: modifiedImageUrl,
        productId: originalImage.productId,
        createdAt: new Date(),
      }).$returningId();
      console.log(`Registro insertado en tabla 'images' para imagen modificada, URL: ${modifiedImageUrl}`);

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
    task: 'generate_name',
    imageBase64: data,
    mimeType: mimeType,
  };

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
  }
  
  console.log(`Llamando al worker para generar imagen (includeModel: ${includeModel})...`);
  const imageWorkerPayload = {
    task: 'generate_image',
    imageBase64: data,
    mimeType: mimeType,
    includeModel: includeModel,
  };

  try {
    const imageResult = await requestQueue.enqueue(imageWorkerPayload, workerUrl);
    const imagePart = imageResult.geminiData?.candidates?.[0]?.content?.parts?.find((part: { inlineData: any; }) => part.inlineData);

    if (imagePart?.inlineData) {
      const generatedImageData = imagePart.inlineData.data;
      const mimeType = imagePart.inlineData.mimeType || "image/png";
      generatedImageUrl = await saveImage(`data:${mimeType};base64,${generatedImageData}`);
      console.log("Imagen generada guardada en:", generatedImageUrl);
    } else {
      console.warn("No se encontró inlineData en la respuesta del worker:", imageResult);
    }
  } catch (error) {
    console.error("Error del worker (generando imagen):", error);
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

productsRoute.post("/migrate-images", authMiddleware, async (c) => {
  const db = drizzle(pool);
  let updatedProductUrlsCount = 0;
  let updatedGeneratedImageUrlsCount = 0;
  let errors: string[] = [];
  const OLD_R2_DOMAIN_PATTERN = 'images.tiendia.app/%';

  try {
    console.log("Iniciando migración de URLs de imágenes de productos...");
    const productsToUpdate = await db.select({
        id: products.id,
        imageURL: products.imageURL
      })
      .from(products)
      .where(and(
        like(products.imageURL, OLD_R2_DOMAIN_PATTERN),
        notLike(products.imageURL, `${R2_PUBLIC_URL}/%`)
      ));

    console.log(`Encontrados ${productsToUpdate.length} productos con URLs de R2 antiguas para actualizar.`);

    for (const product of productsToUpdate) {
      if (!product.imageURL) {
        console.warn(`Producto ID ${product.id} tiene imageURL nulo/vacío en los resultados, saltando.`);
        continue;
      }

      try {
        const oldUrl = product.imageURL;
        const fileName = oldUrl.split('/').pop();

        if (!fileName) {
          console.warn(`No se pudo extraer el nombre de archivo de la URL: ${oldUrl} para el producto ID ${product.id}. Saltando.`);
          errors.push(`Error extrayendo nombre de archivo para producto ${product.id}: ${oldUrl}`);
          continue;
        }

        const newR2Url = `${R2_PUBLIC_URL}/${fileName}`;

        await db.update(products)
          .set({ imageURL: newR2Url })
          .where(eq(products.id, product.id));

        console.log(`Producto ID ${product.id}: URL de imagen actualizada a ${newR2Url}`);
        updatedProductUrlsCount++;

      } catch (error: any) {
        console.error(`Error actualizando URL para producto ID ${product.id} (${product.imageURL}):`, error);
        errors.push(`Error producto ${product.id} (${product.imageURL}): ${error.message}`);
      }
    }
    console.log("Migración de URLs de imágenes de productos completada.");

  } catch (error: any) {
    console.error("Error durante la migración de URLs de imágenes de productos:", error);
    errors.push(`Error general en migración de URLs de productos: ${error.message}`);
  }

  try {
    console.log("Iniciando migración de URLs de imágenes generadas...");
    const generatedImagesToUpdate = await db.select({
        id: images.id,
        url: images.url
      })
      .from(images)
      .where(and(
        like(images.url, OLD_R2_DOMAIN_PATTERN),
        notLike(images.url, `${R2_PUBLIC_URL}/%`)
      ));

    console.log(`Encontradas ${generatedImagesToUpdate.length} imágenes generadas con URLs de R2 antiguas para actualizar.`);

    for (const image of generatedImagesToUpdate) {
      if (!image.url) {
        console.warn(`Imagen generada ID ${image.id} tiene URL nula/vacía en los resultados, saltando.`);
        continue;
      }

      try {
        const oldUrl = image.url;
        const fileName = oldUrl.split('/').pop();

        if (!fileName) {
          console.warn(`No se pudo extraer el nombre de archivo de la URL: ${oldUrl} para la imagen ID ${image.id}. Saltando.`);
          errors.push(`Error extrayendo nombre de archivo para imagen ${image.id}: ${oldUrl}`);
          continue;
        }
        
        const newR2Url = `${R2_PUBLIC_URL}/${fileName}`;

        await db.update(images)
          .set({ url: newR2Url })
          .where(eq(images.id, image.id));

        console.log(`Imagen generada ID ${image.id}: URL actualizada a ${newR2Url}`);
        updatedGeneratedImageUrlsCount++;

      } catch (error: any) {
        console.error(`Error actualizando URL para imagen generada ID ${image.id} (${image.url}):`, error);
        errors.push(`Error imagen ${image.id} (${image.url}): ${error.message}`);
      }
    }
    console.log("Migración de URLs de imágenes generadas completada.");

  } catch (error: any) {
    console.error("Error durante la migración de URLs de imágenes generadas:", error);
    errors.push(`Error general en migración de URLs de imágenes generadas: ${error.message}`);
  }

  const summary = `Migración de URLs completada. URLs de productos actualizadas: ${updatedProductUrlsCount}. URLs de imágenes generadas actualizadas: ${updatedGeneratedImageUrlsCount}. Errores: ${errors.length}`;
  console.log(summary);
  if (errors.length > 0) {
    console.error("Errores detallados:", errors);
  }

  return c.json({
    message: summary,
    updatedProductUrls: updatedProductUrlsCount,
    updatedGeneratedImageUrls: updatedGeneratedImageUrlsCount,
    errors: errors,
  });
});

productsRoute.post("/upload-images", authMiddleware, async (c) => {
  const db = drizzle(pool);
  const token = getCookie(c, 'token');
  if (!token) {
    return c.json({ message: 'No hay token' }, 401);
  }

  const decoded = await new Promise((resolve, reject) => {
    jwt.verify(token, process.env.TOKEN_SECRET || 'my-secret', (error, decoded) => {
      if (error) reject(error);
      resolve(decoded);
    });
  });
  const userId = (decoded as jwt.JwtPayload).id;

  if (!userId) {
    return c.json({ message: "Usuario no autenticado" }, 401);
  }

  try {
    const formData = await c.req.formData();
    const files = formData.getAll('images') as File[];
    
    if (!files.length) {
      return c.json({ message: "No se proporcionaron imágenes" }, 400);
    }

    const workerUrl = "https://gemini-worker.facucordoba200.workers.dev";
    const requestQueue = GeminiRequestQueue.getInstance();
    const savedProducts = [];

    // Procesar cada imagen y crear un producto para cada una
    for (const file of files) {
      let productName = "Producto";
      const buffer = await file.arrayBuffer();
      const base64 = Buffer.from(buffer).toString('base64');
      const mimeType = file.type;

      // Generar nombre del producto para esta imagen
      console.log("Llamando al worker para generar nombre...");
      const nameWorkerPayload = {
        task: 'generate_name',
        imageBase64: base64,
        mimeType: mimeType,
      };

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
      }

      // Guardar la imagen en R2
      const imageUrl = await saveImage(`data:${mimeType};base64,${base64}`);

      // Crear el producto con su imagen
      const insertedProduct = await db.insert(products).values({
        name: productName,
        imageURL: imageUrl,
        createdById: userId,
        createdAt: new Date(),
      }).$returningId();

      const productId = insertedProduct[0].id;

      savedProducts.push({
        id: productId,
        name: productName,
        imageUrl: imageUrl
      });
    }

    return c.json({
      message: "Productos creados correctamente",
      products: savedProducts
    }, 200);

  } catch (error: any) {
    console.error("Error en la ruta /upload-images:", error);
    return c.json({ message: error.message || "Error al crear los productos" }, 500);
  }
});

productsRoute.post("/generate-pro/:id", authMiddleware, async (c) => {
  const id = Number(c.req.param("id"));
  const db = drizzle(pool);
  const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
  const OPENAI_API_URL = 'https://api.openai.com/v1/images/edits';

  if (!OPENAI_API_KEY) {
    return c.json({ error: 'OpenAI API key not configured' }, 500);
  }

  const token = getCookie(c, 'token');
  if (!token) return c.json({ error: 'Unauthorized' }, 401);

  const decoded = await new Promise((resolve, reject) => {
    jwt.verify(token, process.env.TOKEN_SECRET || 'my-secret', (error, decoded) => {
      if (error) reject(error);
      resolve(decoded);
    });
  });

  const userId = (decoded as JwtPayload).id;

  const credits = await db.select({
    credits: users.credits,
  })
  .from(users)
  .where(eq(users.id, userId));

  if (credits && credits[0] && credits[0].credits && credits[0].credits < 100) {
    return c.json({ message: "Creditos no suficientes" }, { status: 400 });
  }

  if (isNaN(id)) {
    return c.json({ error: "ID de producto inválido" }, { status: 400 });
  }

  try {
    const productResult = await db
      .select({
        imageURL: products.imageURL,
      })
      .from(products)
      .where(eq(products.id, id))
      .limit(1);

    if (!productResult || productResult.length === 0) {
      return c.json({ message: "Producto no encontrado" }, { status: 404 });
    }
    const product = productResult[0];

    if (!product.imageURL) {
      return c.json(
        { message: "El producto no tiene una imagen para generar publicidad." },
        { status: 400 }
      );
    }
    const originalProductImageUrl = product.imageURL;

    const originalImageName = product.imageURL.split("/").pop();
    if (!originalImageName) {
      console.error("No se pudo extraer el nombre de archivo de:", product.imageURL);
      return c.json({ message: "Error al procesar la URL de la imagen original." }, { status: 500 });
    }
    
    let originalImageBase64: string;
    let originalMimeType: string;

    try {
      console.log(`Descargando imagen original desde R2: ${originalProductImageUrl}`);
      const response = await fetch(originalProductImageUrl);
      if (!response.ok) {
        throw new Error(`Error HTTP ${response.status} al descargar imagen de R2`);
      }
      const contentTypeHeader = response.headers.get("content-type");

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

    // Validate mime type
    if (!['image/png', 'image/jpeg', 'image/webp'].includes(originalMimeType)) {
      return c.json({ error: 'Invalid mime type. Must be image/png, image/jpeg, or image/webp.' }, 400);
    }

    // Check file size (25MB limit)
    const imageBuffer = Buffer.from(originalImageBase64, 'base64');
    if (imageBuffer.length > 25 * 1024 * 1024) {
      return c.json({ error: 'Image size exceeds 25MB limit.' }, 400);
    }

    // Create a Blob-like object
    const imageBlob = new Blob([imageBuffer], { type: originalMimeType });

    const prompt = `Generate a fashion-forward, editorial-style image with these exact specifications:  
  The clothing item must be worn by a model (male or female) with a bold, expressive pose that conveys confidence or attitude  
  Model visibility: flexible – can include waist-up, full body, or dynamic crop depending on composition  
  Pose and body angle must look like a candid or intentional street-style photo – dynamic, casual or confident  
  Facial expression should feel natural or slightly aloof – model can look at the camera or away  
  Lighting should mimic on-camera flash photography: harsh flash shadows, high contrast, slightly overexposed skin highlights  
  Scene must resemble a real-life environment: urban backdrops (walls, streets, elevators, rooftops), daylight or nightlife  
  Slight grain or imperfection to mimic analog/digital flash aesthetic  
  Background can include tiled walls, elevators, skies, or street textures – no plain studio setups  
  Fashion styling can include accessories like sunglasses, bags, or earrings if they match the look  
  The image should feel like a mix of 90s/2000s Y2K, streetwear, or Instagram fashion influencer vibes  
  Clothing and fabric must remain sharp and color-accurate despite the creative lighting  
  High resolution, realistic depth, professional post-processing  
  No graphic design elements, logos, or overlay text  
  9:16 proportion`;

    console.log(`Enviando solicitud a OpenAI para el producto ID: ${id}`);
    const formData = new FormData();
    formData.append('model', 'gpt-image-1');
    formData.append('prompt', prompt);
    formData.append('n', '1');
    formData.append('size', '1024x1536');
    formData.append('quality', 'high');
    formData.append('image', imageBlob, 'image.' + originalMimeType.split('/')[1]);

    const openaiResponse = await fetch(OPENAI_API_URL, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${OPENAI_API_KEY}`,
      },
      body: formData
    });

    if (!openaiResponse.ok) {
      const errorBody = await openaiResponse.text();
      console.error("Error from OpenAI API:", openaiResponse.status, errorBody);
      return c.json({ 
        error: "Failed to generate image from OpenAI", 
        details: errorBody 
      }, 500);
    }

    const result = await openaiResponse.json() as { 
      created: number;
      data: { b64_json: string }[];
      usage: {
        total_tokens: number;
        input_tokens: number;
        output_tokens: number;
        input_tokens_details: {
          text_tokens: number;
          image_tokens: number;
        };
      };
    };

    if (!result.data?.[0]?.b64_json) {
      throw new Error('No image data in OpenAI response');
    }

    const savedImageUrl = await saveImage(`data:${originalMimeType};base64,${result.data[0].b64_json}`);
    console.log("Imagen generada guardada en:", savedImageUrl);

    const dbResult = await db.insert(images).values({
      url: savedImageUrl,
      productId: id,
      createdAt: new Date(),
    }).$returningId();
    console.log(`Registro insertado en tabla 'images' para producto ${id}, URL: ${savedImageUrl}`);

    if (credits[0] && credits[0].credits) { 
      await db.update(users).set({
        credits: credits[0].credits - 100,
      }).where(eq(users.id, userId));
    }

    return c.json({
      message: "Publicidad generada correctamente.",
      adImageUrl: savedImageUrl,
      imageId: dbResult[0].id
    }, { status: 200 });

  } catch (error: any) {
    console.error("Error en la ruta /generate-pro:", error);
    const errorMessage = error.message || "Error interno del servidor al generar la publicidad.";
    return c.json({ message: errorMessage }, { status: 500 });
  }
});

// Add WebSocket endpoint for generate-pro

productsRoute.get("/sse/generate-pro/:id", async (c) => {
  console.log('🔌 New SSE connection request received');
  
  const headers = new Headers({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Cache-Control'
  });

  const stream = new ReadableStream({
    start(controller) {
      const sendEvent = (data: any) => {
        console.log('📤 Sending SSE event:', data);
        const message = `data: ${JSON.stringify(data)}\n\n`;
        controller.enqueue(new TextEncoder().encode(message));
      };

      const processRequest = async () => {
        try {
          const id = Number(c.req.param("id"));
          console.log('🔄 Starting Pro generation process for product:', id);
          
          const db = drizzle(pool);
          const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
          const OPENAI_API_URL = 'https://api.openai.com/v1/images/edits';

          if (!OPENAI_API_KEY) {
            console.error('❌ OpenAI API key not configured');
            throw new Error('OpenAI API key not configured');
          }

          const token = getCookie(c, 'token');
          if (!token) {
            console.error('❌ No authentication token found');
            throw new Error("Unauthorized");
          }

          console.log('🔑 Verifying user token');
          const decoded = await new Promise((resolve, reject) => {
            jwt.verify(token, process.env.TOKEN_SECRET || 'my-secret', (error, decoded) => {
              if (error) reject(error);
              else resolve(decoded);
            });
          });

          const userId = (decoded as JwtPayload).id;
          console.log('👤 User authenticated:', userId);

          const credits = await db.select({ credits: users.credits })
            .from(users)
            .where(eq(users.id, userId));

          if (!credits?.[0]?.credits || credits[0].credits < 100) {
            console.error('❌ Insufficient credits:', credits?.[0]?.credits);
            throw new Error("Créditos insuficientes");
          }

          if (isNaN(id)) {
            console.error('❌ Invalid product ID:', id);
            throw new Error("ID inválido");
          }

          sendEvent({ status: "processing", message: "Obteniendo producto..." });
          console.log('📥 Fetching product details');

          const productResult = await db
            .select({ imageURL: products.imageURL })
            .from(products)
            .where(eq(products.id, id))
            .limit(1);

          const product = productResult[0];
          if (!product || !product.imageURL) {
            console.error('❌ Product not found or has no image:', { productId: id, hasImage: !!product?.imageURL });
            throw new Error("Producto no encontrado o sin imagen");
          }

          sendEvent({ status: "processing", message: "Descargando imagen..." });
          console.log('📥 Downloading product image');

          const response = await fetch(product.imageURL);
          if (!response.ok) {
            console.error('❌ Failed to download image:', response.status);
            throw new Error(`Error HTTP ${response.status} al descargar imagen`);
          }

          let mime = response.headers.get("content-type") || "";
          if (!['image/png', 'image/jpeg', 'image/webp'].includes(mime)) {
            const ext = product.imageURL.split('.').pop()?.toLowerCase();
            if (ext === "jpg" || ext === "jpeg") mime = "image/jpeg";
            else if (ext === "png") mime = "image/png";
            else if (ext === "webp") mime = "image/webp";
            else {
              console.error('❌ Invalid mime type:', mime);
              throw new Error("Tipo MIME no permitido");
            }
          }

          const arrayBuf = await response.arrayBuffer();
          const buffer = Buffer.from(arrayBuf);
          
          if (buffer.length > 25 * 1024 * 1024) {
            console.error('❌ Image too large:', buffer.length);
            throw new Error("Imagen mayor a 25MB");
          }

          const imageBlob = new Blob([buffer], { type: mime });

          sendEvent({ status: "processing", message: "Generando imagen con IA..." });
          console.log('🤖 Sending request to OpenAI');

          const prompt = `Generate a fashion-forward, editorial-style image with these exact specifications:  
          The clothing item must be worn by a model (male or female) with a bold, expressive pose that conveys confidence or attitude  
          Model visibility: flexible – can include waist-up, full body, or dynamic crop depending on composition  
          Pose and body angle must look like a candid or intentional street-style photo – dynamic, casual or confident  
          Facial expression should feel natural or slightly aloof – model can look at the camera or away  
          Lighting should mimic on-camera flash photography: harsh flash shadows, high contrast, slightly overexposed skin highlights  
          Scene must resemble a real-life environment: urban backdrops (walls, streets, elevators, rooftops), daylight or nightlife  
          Slight grain or imperfection to mimic analog/digital flash aesthetic  
          Background can include tiled walls, elevators, skies, or street textures – no plain studio setups  
          Fashion styling can include accessories like sunglasses, bags, or earrings if they match the look  
          The image should feel like a mix of 90s/2000s Y2K, streetwear, or Instagram fashion influencer vibes  
          Clothing and fabric must remain sharp and color-accurate despite the creative lighting  
          High resolution, realistic depth, professional post-processing  
          No graphic design elements, logos, or overlay text  
          9:16 proportion`;

          const formData = new FormData();
          formData.append('model', 'gpt-image-1');
          formData.append('prompt', prompt);
          formData.append('n', '1');
          formData.append('size', '1024x1536');
          formData.append('quality', 'high');
          formData.append('image', imageBlob, 'image.' + mime.split('/')[1]);

          const openaiResponse = await fetch(OPENAI_API_URL, {
            method: 'POST',
            headers: {
              'Authorization': `Bearer ${OPENAI_API_KEY}`,
            },
            body: formData
          });

          if (!openaiResponse.ok) {
            const errorBody = await openaiResponse.text();
            console.error('❌ OpenAI API error:', { status: openaiResponse.status, body: errorBody });
            throw new Error(`OpenAI error: ${errorBody}`);
          }

          console.log('📥 Received response from OpenAI');
          const result = await openaiResponse.json() as {
            data: { b64_json: string }[];
          };

          const imageB64 = result.data?.[0]?.b64_json;
          if (!imageB64) {
            console.error('❌ No image data in OpenAI response');
            throw new Error("No image data in response");
          }

          sendEvent({ status: "processing", message: "Guardando imagen..." });
          console.log('💾 Saving generated image');

          const savedImageUrl = await saveImage(`data:${mime};base64,${imageB64}`);
          console.log('✅ Image saved successfully:', savedImageUrl);

          const dbResult = await db.insert(images).values({
            url: savedImageUrl,
            productId: id,
            createdAt: new Date(),
          }).$returningId();
          console.log('💾 Image record created in database:', dbResult[0].id);

          await db.update(users).set({
            credits: credits[0].credits - 100,
          }).where(eq(users.id, userId));
          console.log('💳 Updated user credits');

          sendEvent({
            status: "done",
            imageUrl: savedImageUrl,
            imageId: dbResult[0].id
          });
          console.log('✅ Pro generation completed successfully');

        } catch (error: any) {
          console.error('❌ Error in SSE process:', error);
          sendEvent({
            status: "error",
            message: error.message || "Error inesperado"
          });
        } finally {
          console.log('🏁 Closing SSE connection');
          controller.close();
        }
      };

      processRequest();
    }
  });

  return new Response(stream, { headers });
});

productsRoute.post("/personalize/:id", authMiddleware, zValidator("json", personalizeSchema), async (c) => {
  const id = Number(c.req.param("id"));
  const db = drizzle(pool);
  const workerUrl = "https://personalized-worker.facucordoba200.workers.dev";
  const requestQueue = GeminiRequestQueue.getInstance();
  const token = getCookie(c, 'token');
  if (!token) return c.json({ error: 'Unauthorized' }, 401);

  const decoded = await new Promise((resolve, reject) => {
    jwt.verify(token, process.env.TOKEN_SECRET || 'my-secret', (error, decoded) => {
      if (error) reject(error);
      resolve(decoded);
    });
  });

  const userId = (decoded as JwtPayload).id;

  const credits = await db.select({
    credits: users.credits,
  })
  .from(users)
  .where(eq(users.id, userId));

  if (credits && credits[0] && credits[0].credits && credits[0].credits < 50) {
    return c.json({ message: "Creditos no suficientes" }, { status: 400 });
  }

  if (isNaN(id)) {
    return c.json({ error: "ID de producto inválido" }, { status: 400 });
  }

  try {
    const productResult = await db
      .select({
        imageURL: products.imageURL,
      })
      .from(products)
      .where(eq(products.id, id))
      .limit(1);

    if (!productResult || productResult.length === 0) {
      return c.json({ message: "Producto no encontrado" }, { status: 404 });
    }
    const product = productResult[0];

    if (!product.imageURL) {
      return c.json(
        { message: "El producto no tiene una imagen para personalizar." },
        { status: 400 }
      );
    }

    const originalProductImageUrl = product.imageURL;
    const originalImageName = product.imageURL.split("/").pop();
    if (!originalImageName) {
      console.error("No se pudo extraer el nombre de archivo de:", product.imageURL);
      return c.json({ message: "Error al procesar la URL de la imagen original." }, { status: 500 });
    }
    
    let originalImageBase64: string;
    let originalMimeType: string;

    try {
      console.log(`Descargando imagen original desde R2: ${originalProductImageUrl}`);
      const response = await fetch(originalProductImageUrl);
      if (!response.ok) {
        throw new Error(`Error HTTP ${response.status} al descargar imagen de R2`);
      }
      const contentTypeHeader = response.headers.get("content-type");

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
      console.log(`Imagen original descargada de R2 y convertida a Base64`);

    } catch (fetchError: any) {
      console.error(`Error al obtener/procesar la imagen original desde R2 (${originalProductImageUrl}):`, fetchError);
      return c.json({ message: "Error crítico al acceder a la imagen original del producto." }, { status: 500 });
    }

    const personalizationParams = c.req.valid("json");
    const workerPayload = {
      imageBase64: originalImageBase64,
      mimeType: originalMimeType,
      ...personalizationParams
    };

    console.log(`Enviando solicitud al worker para personalizar el producto ID: ${id}`);
    const workerResponse = await requestQueue.enqueue(workerPayload, workerUrl);
    console.log(`Respuesta del worker recibida correctamente`);

    const imagePart = workerResponse.geminiData?.candidates?.[0]?.content?.parts?.find((part: { inlineData: any; }) => part.inlineData);
    if (imagePart?.inlineData) {
      const generatedImageData = imagePart.inlineData.data;
      const mimeType = imagePart.inlineData.mimeType || "image/png";
      const personalizedImageUrl = await saveImage(`data:${mimeType};base64,${generatedImageData}`);
      console.log("Imagen personalizada guardada en:", personalizedImageUrl);

      const result = await db.insert(images).values({
        url: personalizedImageUrl,
        productId: id,
        createdAt: new Date(),
      }).$returningId();
      console.log(`Registro insertado en tabla 'images' para producto ${id}, URL: ${personalizedImageUrl}`);

      if (credits[0] && credits[0].credits) { 
        await db.update(users).set({
          credits: credits[0].credits - 50,
        }).where(eq(users.id, userId));
      }

      return c.json({
        message: "Imagen personalizada generada correctamente.",
        personalizedImageUrl: personalizedImageUrl,
        imageId: result[0].id
      }, { status: 200 });
    } else {
      console.warn("No se encontró inlineData en la respuesta del worker:", workerResponse);
      return c.json({ message: "El worker no devolvió una imagen generada." }, { status: 500 });
    }

  } catch (error: any) {
    console.error("Error en la ruta /personalize:", error);
    const errorMessage = error.message || "Error interno del servidor al personalizar la imagen.";
    return c.json({ message: errorMessage }, { status: 500 });
  }
});

export default productsRoute;