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
  const fileName = imageUrl.split("/").pop();
  if (!fileName) throw new Error("URL de imagen inválida");

  const filePath = join(UPLOAD_DIR, fileName);
  await unlink(filePath);
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