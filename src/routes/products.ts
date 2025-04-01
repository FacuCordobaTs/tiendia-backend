import { zValidator } from "@hono/zod-validator";
import { Hono } from "hono";
import { z } from "zod";
import { drizzle } from "drizzle-orm/mysql2";
import { pool } from "../db";
import { products } from "../db/schema";
import { authMiddleware } from "../middlewares/auth.middleware";
import { eq } from "drizzle-orm";
import UUID from "uuid-js";
import { readFile, writeFile, unlink } from "fs/promises";
import { join } from "path";
import * as fs from "fs";
import { GoogleGenAI } from "@google/genai";


const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB
const ALLOWED_MIME_TYPES = ["image/jpeg", "image/png", "image/webp"];

const UPLOAD_DIR = join(process.cwd(), "public", "uploads");

interface WorkerResponse {
  message?: string;
  generatedImageBase64?: string;
  error?: string;
  details?: any;
}

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
  description: z.string().min(3).max(255),
  image: z.string().optional(),
  username: z.string(),
  sizes: z.array(z.object({ size: z.string(), stock: z.number() })).optional(),
  stock: z.number().optional(),
});

const updateProductSchema = z.object({
  name: z.string().min(3).max(255),
  price: z.number().min(1),
  description: z.string().min(3).max(255),
  imageBase64: z.string().optional(),
  id: z.number(),
  sizes: z.array(z.object({ size: z.string(), stock: z.number() })).optional().nullable(),
  stock: z.number().optional().nullable(),
});

export const productsRoute = new Hono()
  .post("/create", authMiddleware, zValidator("json", productSchema), async (c) => {
    const { name, price, description, image, username, sizes, stock } = c.req.valid("json");
    const db = drizzle(pool);
    let imageUrl: string | null = null;

    try {
      if (image) {
        const [meta, data] = image.split(",");
        const mimeType = meta.match(/:(.*?);/)?.[1];

        if (!mimeType || !ALLOWED_MIME_TYPES.includes(mimeType)) {
          return c.json({ error: "Tipo de archivo no permitido" }, 400);
        }

        const buffer = Buffer.from(data, "base64");
        if (buffer.byteLength > MAX_FILE_SIZE) {
          return c.json({ error: "La imagen es demasiado grande" }, 400);
        }

        imageUrl = await saveImage(image);
      }

      await db.insert(products).values({
        name,
        price,
        description,
        imageURL: imageUrl,
        sizes: sizes ? JSON.stringify(sizes) : null,
        stock: stock || null,
        createdAt: new Date(),
        createdBy: username,
      });

      return c.json(
        {
          message: "Producto registrado correctamente",
          product: {
            name,
            price,
            description,
            imageURL: imageUrl,
            sizes,
            stock,
            createdAt: new Date(),
            createdBy: username,
          },
        },
        200
      );
    } catch (error) {
      console.error("Error:", error);
      return c.json({ message: "Error al registrar el producto" }, 500);
    }
  })

  .get("/list/:username", async (c) => {
    const db = drizzle(pool);
    const username = c.req.param("username");

    try {
      const productsListed = await db
        .select({
          id: products.id,
          name: products.name,
          price: products.price,
          description: products.description,
          imageURL: products.imageURL,
          sizes: products.sizes,
          stock: products.stock,
          createdAt: products.createdAt,
        })
        .from(products)
        .where(eq(products.createdBy, username));

      if (!productsListed || productsListed.length === 0) {
        return c.json({ message: "No hay productos registrados" }, 404);
      }

      const parsedProducts = productsListed.map((product: any) => ({
        ...product,
        sizes: product.sizes ? JSON.parse(product.sizes) : null,
      }));

      return c.json({ products: parsedProducts }, 200);
    } catch (error) {
      return c.json({ message: "Error al obtener los productos" }, 400);
    }
  })

  .get("/get/:id", async (c) => {
    const db = drizzle(pool);
    const id = Number(c.req.param("id"));

    try {
      const product = await db
        .select({
          id: products.id,
          name: products.name,
          price: products.price,
          description: products.description,
          imageURL: products.imageURL,
          sizes: products.sizes,
          stock: products.stock,
          createdAt: products.createdAt,
        })
        .from(products)
        .where(eq(products.id, id));

      if (!product || product.length === 0) {
        return c.json({ message: "Producto no encontrado" }, 404);
      }

      const parsedProduct = {
        ...product[0],
        sizes: typeof product[0].sizes === "string" ? JSON.parse(product[0].sizes) : null,
      };

      return c.json({ products: parsedProduct }, 200);
    } catch (error) {
      return c.json({ message: "Error al obtener el producto" }, 400);
    }
  })

  .put("/update", zValidator("json", updateProductSchema), async (c) => {
    try {
      const { name, price, description, imageBase64, id, sizes, stock } = c.req.valid("json");
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
          price,
          description,
          ...(imageURL && { imageURL }),
          ...(sizes && { sizes: JSON.stringify(sizes) }),
          ...(stock !== undefined && { stock }),
        })
        .where(eq(products.id, id));

      return c.json(
        {
          message: "Producto actualizado correctamente",
          product: {
            name,
            price,
            description,
            imageURL,
            sizes,
            stock,
            createdAt: new Date(),
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
  // ... tus otras rutas (.post('/create'), .get('/list'), etc.) ...
  .post("/generate-ad/:id", authMiddleware, async (c) => {
    const id = Number(c.req.param("id"));
    const db = drizzle(pool);
    const workerUrl = "https://gemini-worker.facucordoba200.workers.dev";

    if (isNaN(id)) {
      return c.json({ error: "ID de producto inválido" }, { status: 400 }); // Usa init object
    }

    try {
      // 1. Buscar el producto
      const productResult = await db
        .select({
          name: products.name,
          description: products.description,
          price: products.price,
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
        productName: product.name,
        productDescription: product.description,
        productPrice: product.price,
        imageBase64: originalImageBase64,
        mimeType: originalMimeType,
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
   
        // --- NUEVA FORMA ---
        // 1. Establece el código de estado usando c.status()
        //    Hono espera un tipo específico, pero podemos forzarlo o usar un fallback.
        //    Probemos casteando a 'any' primero por simplicidad.
        try {
           c.status(response.status as any); // O intenta con StatusCode si la importaste
        } catch(e) {
            console.warn(`Could not set status to ${response.status}. Falling back to 500.`, e)
            c.status(500); // Código de fallback si falla el casteo/status dinámico
        }
   
        // 2. Devuelve SÓLO el cuerpo JSON con c.json()
        return c.json({
            message: `Error al generar la publicidad: ${response.statusText}`,
            details: errorBody
        });
        // --- FIN NUEVA FORMA ---
     }

      const workerResponse = await response.json() as WorkerResponse; // <--- CORRECCIÓN AQUÍ (Assertion)

      // 5. Verificar si el worker devolvió la imagen Base64 generada
      if (!workerResponse || typeof workerResponse.generatedImageBase64 !== 'string') { // <--- CORRECCIÓN AQUÍ (Check)
          console.error("El worker no devolvió 'generatedImageBase64' como string. Respuesta:", workerResponse);
          return c.json(
            { message: "La respuesta del worker no contenía la imagen generada en el formato esperado." },
            { status: 500 } // <- Usa también el objeto init aquí
          );
      }
      console.log(workerResponse)
      // 6. Guardar la imagen generada por IA
      let adImageUrl: string;
     try {
       adImageUrl = await saveImage(`data:image/png;base64,${workerResponse.generatedImageBase64}`); // <--- Ahora es seguro
     } catch (error: any) {
        console.error("Error al guardar la imagen generada:", error);
        return c.json({ message: "Error al guardar la imagen generada por el worker." }, { status: 500 });
     }
     console.log(`Imagen generada guardada en: ${adImageUrl}`);

      // 7. Devolver la URL
      return c.json(
        {
          message: "Publicidad generada y guardada correctamente.",
          adImageUrl: adImageUrl,
        },
        { status: 200 } // <- Usa también el objeto init aquí por consistencia
      );

    } catch (error: any) {
      console.error("Error en la ruta /generate-ad:", error);
      const errorMessage = error.message || "Error interno del servidor al generar la publicidad.";
      return c.json({ message: errorMessage }, { status: 500 }); // <- Usa también el objeto init aquí
    }
  })