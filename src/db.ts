import { createPool } from 'mysql2/promise';

export const pool = createPool({
  host: 'localhost',         // Cambia esto según tu configuración de MySQL
  user: process.env.DB_USER,        // Reemplaza con tu usuario de MySQL
  password:  process.env.DB_PASSWORD, // Reemplaza con tu contraseña de MySQL
  database: process.env.DB_NAME, // Nombre de tu base de datos MySQL
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Verificar si el servidor se inició correctamente
pool.getConnection()
  .then(connection => {
    console.log('Conexión a la base de datos establecida correctamente.');
    connection.release();
  })
  .catch(err => {
    console.error('Error al conectar a la base de datos:', err);
  });