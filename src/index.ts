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
import { config } from 'dotenv';
import path from 'path';

// Carga el archivo .env desde una ruta absoluta
config({ path: path.resolve('/home/appuser/app', '.env') });

const app = new Hono();
const allowedOrigins = [
  'https://admin.tiendia.app',
  'https://tiendia.app',
  'http://localhost:5173', // Desarrollo local
  "https://api.mercadopago.com"
];

// Crear directorio para uploads si no existe
const UPLOAD_DIR = join(process.cwd(), 'public', 'uploads');
if (!existsSync(UPLOAD_DIR)) {
  mkdirSync(UPLOAD_DIR, { recursive: true });
}

// Configuración CORS corregida
app.use('*', cors({
  origin: (origin) => {
    if (!origin || !allowedOrigins.includes(origin)) {
      return allowedOrigins[0]; // O '' para rechazar si no hay coincidencia
    }
    return origin; // Devuelve el origen si está en la lista
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

app.get('/', (c) => c.text('Hello, World!'));

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

export default {
  port: 3000,
  fetch: app.fetch, 
  idleTimeout: 100000, 
};