import { zValidator } from "@hono/zod-validator";
import { Hono } from "hono";
import { z } from "zod";
import { drizzle } from "drizzle-orm/mysql2";
import { pool } from "../db";
import { products } from "../db/schema";
import { authMiddleware } from "../middlewares/auth.middleware";
import { eq } from "drizzle-orm";
import UUID from "uuid-js";
import { writeFile, unlink } from "fs/promises";
import { join } from "path";
import * as fs from "fs";
import { GoogleGenAI } from "@google/genai";

const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB
const ALLOWED_MIME_TYPES = ["image/jpeg", "image/png", "image/webp"];

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
  });
  productsRoute.post("/generate-ad/:id", authMiddleware, async (c) => {
    const db = drizzle(pool);
    const id = Number(c.req.param("id"));
    try {
      const product = await db.select().from(products).where(eq(products.id, id));

      if (!product || product.length === 0) {
        return c.json({ message: "Producto no encontrado" }, 404);
      }

      if (!product[0].imageURL) {
        return c.json({ message: "El producto no tiene imagen" }, 400);
      }
      
      const imagePath = join(UPLOAD_DIR, product[0].imageURL?.split("/").pop() || "");
      const imageData = fs.readFileSync(imagePath);
      const base64Image = imageData.toString('base64');
      
      // Send product image and description to the API to generate an ad image
      const contents = [
        { text: "Can you add a llama next to the image?" },
        {
            inlineData: {
                mimeType: 'image/png',
                data: base64Image
            }
        }
    ];
    
    const response = await ai.models.generateContent({
      model: 'gemini-2.0-flash-exp-image-generation',
      contents: contents,
      config: {
          responseModalities: ['Text', 'Image']
      },
      });
      
      if (!response.candidates || response.candidates.length === 0 || !response.candidates[0].content || !response.candidates[0].content.parts) {
        throw new Error("No candidates found");
      }

      for (const part of response.candidates[0].content.parts) {
        if (part.inlineData) {
          const imageData = part.inlineData.data;
          if (!imageData) {
            throw new Error("Image data is undefined");
          }
          const buffer = Buffer.from(imageData, 'base64');
          const uuid = UUID.create().toString();
          const fileName = `${uuid}.png`;
          const filePath = join(UPLOAD_DIR, fileName);
          await writeFile(filePath, buffer);
          return c.json({ message: "Anuncio generado correctamente", imageUrl: `/uploads/${fileName}` }, 200);
        }
      }


    } catch (error) {
      console.error("Error generando anuncio:", error);
      return c.json({ message: "Error al generar el anuncio" }, 500);
    }
  })