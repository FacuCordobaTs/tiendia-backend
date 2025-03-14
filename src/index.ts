import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { serveStatic } from 'hono/serve-static';
import { readFile } from 'fs/promises';
import { join } from 'path';
import { existsSync, mkdirSync } from 'fs';
import { authRoute } from './routes/auth';
import { productsRoute } from './routes/products';
import ordersRoute from './routes/orders';
import paymentsRoute from './routes/payments';

const app = new Hono();
const allowedOrigins = [
  'https://ecommerce-admin-eyh.pages.dev',
  'https://burg-ecom.pages.dev',
  'http://localhost:5173' // Desarrollo local
];

// Crear directorio para uploads si no existe
const UPLOAD_DIR = join(process.cwd(), 'public', 'uploads');
if (!existsSync(UPLOAD_DIR)) {
  mkdirSync(UPLOAD_DIR, { recursive: true });
}

// Configuración CORS corregida
app.use('*', cors({
  origin: (origin) => {
    // Si no hay origin o es una cadena vacía, devolver un valor por defecto o rechazar
    if (!origin) {
      return allowedOrigins[0]; // O usa '' para rechazar CORS si prefieres
    }
    try {
      return allowedOrigins.includes(new URL(origin).origin)
        ? origin
        : allowedOrigins[0]; // Valor por defecto si no coincide
    } catch (e) {
      // Manejar error de parseo de URL
      return allowedOrigins[0]; // O '' para rechazar
    }
  },
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  exposeHeaders: ['Content-Length'],
  maxAge: 600,
}));

// Servir archivos estáticos (imágenes)
app.use('/uploads/*', serveStatic({
  root: './public',
  getContent: async (path) => {
    try {
      console.log()
      const filePath = join(process.cwd(), '', path);
      const content = await readFile(filePath);
      return new Response(content, {
        headers: {
          'Content-Type': getMimeType(path),
        },
      });
    } catch (error) {
      return null;
    }
  },
}));

// Rutas
app.basePath("/api")
  .route("/auth", authRoute)
  .route("/products", productsRoute)
  .route("/orders", ordersRoute)
  .route("/payments", paymentsRoute);

// Función auxiliar para determinar el tipo MIME
function getMimeType(path: string): string {
  const ext = path.split('.').pop()?.toLowerCase();
  switch (ext) {
    case 'jpg':
    case 'jpeg':
      return 'image/jpeg';
    case 'png':
      return 'image/png';
    case 'webp':
      return 'image/webp';
    default:
      return 'application/octet-stream';
  }
}

export default app;