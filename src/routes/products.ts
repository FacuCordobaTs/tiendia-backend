import { zValidator } from "@hono/zod-validator";
import { Hono } from "hono";
import { z } from "zod";
import { drizzle } from "drizzle-orm/mysql2";
import { pool } from "../db";
import { images, products } from "../db/schema";
import { authMiddleware } from "../middlewares/auth.middleware";
import { eq, sql } from "drizzle-orm";
import UUID from "uuid-js";
import { readFile, writeFile, unlink } from "fs/promises";
import { join } from "path";
import * as fs from "fs";
import jwt  from "jsonwebtoken";
import { getCookie } from "hono/cookie";


const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB
const ALLOWED_MIME_TYPES = ["image/jpeg", "image/png", "image/webp"];

const generateProductSchema = z.object({
  image: z.string().min(10),
  includeModel: z.boolean().optional().default(false),
});

const UPLOAD_DIR = join(process.cwd(), "public", "uploads");

async function saveImage(base64String: string): Promise<string> {
  const base64Data = base64String.replace(/^data:image\/\w+;base64,/, "");
  const buffer = Buffer.from(base64Data, "base64");

  const uuid = UUID.create().toString();
  const fileName = `${uuid}.png`;
  const filePath = join(UPLOAD_DIR, fileName);

  await writeFile(filePath, buffer);
  return `/uploads/${fileName}`;
}

async function deleteImage(imageUrl: string): Promise<void> {
  try {
    const fileName = imageUrl.split("/").pop();
    if (!fileName) {
      console.warn("URL de imagen inválida:", imageUrl);
      return;
    }

    const filePath = join(UPLOAD_DIR, fileName);
    await unlink(filePath);
  } catch (error: any) {
    if (error.code === "ENOENT") {
      console.warn("Imagen no encontrada:", imageUrl);
    } else {
      console.error("Error al eliminar la imagen:", error);
    }
  }
}

const productSchema = z.object({
  name: z.string().min(3).max(255),
  price: z.number().min(1),
  image: z.string().optional(),
  id: z.number(),
});

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

      // 3. Leer imagen original y convertir a Base64
      const originalImageName = product.imageURL.split("/").pop();
       if (!originalImageName) {
         console.error("No se pudo extraer el nombre de archivo de:", product.imageURL);
         return c.json({ message: "Error al procesar la URL de la imagen original." }, { status: 500 });
       }
      const originalImagePath = join(UPLOAD_DIR, originalImageName);
      let originalImageBase64: string;
      let originalMimeType: string;

      try {
        const imageData = await readFile(originalImagePath); // Ahora debería encontrar readFile
        originalImageBase64 = imageData.toString("base64");
        const extension = originalImageName.split(".").pop()?.toLowerCase();
        if (extension === "jpg" || extension === "jpeg") originalMimeType = "image/jpeg";
        else if (extension === "png") originalMimeType = "image/png";
        else if (extension === "webp") originalMimeType = "image/webp";
        else {
           console.warn(`Tipo MIME desconocido para ${originalImageName}, usando image/jpeg.`);
           originalMimeType = "image/jpeg";
        }
      } catch (readError: any) {
        if (readError.code === 'ENOENT') {
             console.error("Archivo de imagen original no encontrado en:", originalImagePath);
             return c.json({ message: "Archivo de imagen original no encontrado." }, { status: 404 });
        }
        console.error("Error al leer la imagen original:", readError);
        return c.json({ message: "Error al leer la imagen original del producto." }, { status: 500 });
      }

      // 4. Enviar datos al Worker
      console.log(`Enviando solicitud al worker para el producto ID: ${id}`);
      const workerPayload = {
        imageBase64: originalImageBase64,
        mimeType: originalMimeType,
        includeModel: includeModel,
      };

      const response = await fetch(workerUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(workerPayload),
      });

      console.log(`Respuesta del worker recibida con estado: ${response.status}`);

      if (!response.ok) {
        const errorBody = await response.text();
        console.error("Error desde el worker:", response.status, errorBody);

        return c.json({
            message: `Error al generar la publicidad: ${response.statusText}`,
            details: errorBody
        });
        // --- FIN NUEVA FORMA ---
     }

      type WorkerResponse = {
        geminiData: {
          candidates: Array<{
            content: {
              parts: Array<{
                inlineData: {
                  data: string;
                };
              }>;
            };
          }>;
        };
      };

      const workerResponse: WorkerResponse = await response.json();

      try {
        const adImageUrl = await saveImage(`data:image/png;base64,${workerResponse.geminiData.candidates[0].content.parts[0].inlineData.data}`); // <--- Ahora es seguro

        await db.insert(images).values({
          url: adImageUrl,      // La URL relativa guardada localmente
          productId: id,         // El ID del producto para el que se generó
          createdAt: new Date(), // Fecha de creación
        });
        console.log(`Registro insertado en tabla 'images' para producto ${id}, URL: ${adImageUrl}`);

        return c.json(
          {
            message: "Publicidad generada correctamente.",
            adImageUrl: adImageUrl,
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

productsRoute.post("/generate-product-and-image",authMiddleware, zValidator("json", generateProductSchema), async (c) => {
  const { image: userImageBase64, includeModel } = c.req.valid("json");
  const db = drizzle(pool);
  
  const workerUrl = "https://gemini-worker.facucordoba200.workers.dev";
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

  const nameWorkerResponse = await fetch(workerUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(nameWorkerPayload),
  });

  if (!nameWorkerResponse.ok) {
    const errorBody = await nameWorkerResponse.text();
    console.error("Error del worker (generando nombre):", nameWorkerResponse.status, errorBody);
  } else {
    try {
      const nameResult: { generatedName?: string; error?: string } = await nameWorkerResponse.json();
      if (nameResult.generatedName) {
        productName = nameResult.generatedName;
        console.log(`Nombre generado por worker: ${productName}`);
      } else {
        console.warn("Worker no devolvió nombre generado:", nameResult);
      }
    } catch (parseError) {
        console.error("Error al parsear respuesta del worker (nombre):", parseError)
    }
  }
  console.log(`Llamando al worker para generar imagen (includeModel: ${includeModel})...`);
  const imageWorkerPayload = {
    task: 'generate_image',
    imageBase64: data,
    mimeType: mimeType,
    includeModel: includeModel,
  };

  const imageWorkerResponse = await fetch(workerUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(imageWorkerPayload),
  });
  if (!imageWorkerResponse.ok) {
    const errorBody = await imageWorkerResponse.text();
    console.error("Error del worker (generando imagen):", imageWorkerResponse.status, errorBody);
    // Continuar sin imagen generada
  } else {
       try {
          type ImageWorkerResponse = {
            geminiData?: { candidates: Array<{ content: { parts: Array<{ inlineData?: { data: string; }; }>; }; }>; };
            message?: string; error?: string;
          };
          const imageResult: ImageWorkerResponse = await imageWorkerResponse.json();
          const generatedImageData = imageResult.geminiData?.candidates?.[0]?.content?.parts?.[0]?.inlineData?.data;

          if (generatedImageData) {
            generatedImageUrl = await saveImage(`data:image/png;base64,${generatedImageData}`);
            console.log("Imagen generada guardada en:", generatedImageUrl);
          } else {
            console.warn("Worker no devolvió imagen generada:", imageResult);
          }
      } catch (parseError) {
         console.error("Error al parsear respuesta del worker (imagen):", parseError)
      }
  };
  const insertedProduct = await db.insert(products).values({
    name: productName,
    imageURL: originalImageUrl,
    createdById: userId,
    createdAt: new Date(),
  }).$returningId();

  const productId = insertedProduct[0].id;
  if (generatedImageUrl) {
    await db.insert(images).values({
      url: generatedImageUrl,
      productId: productId,
      createdAt: new Date(),
    });
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
    },
    { status: 200 }
  );
})