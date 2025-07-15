require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const cookieParser = require('cookie-parser'); // <-- PRIMERO
const authMiddleware = require('./middleware/authMiddleware');

const app = express();

// 1. CORS
app.use(cors({
  origin: process.env.FRONTEND_ORIGIN,    // Solo uno, sin espacios, sin slash final
  credentials: true,
}));

// 2. Cookies
app.use(cookieParser());

// 3. JSON
app.use(express.json());

// 4. Log para debug (opcional)
app.use((req, res, next) => {
  console.log("🌍 Origin:", req.headers.origin);
  console.log("🍪 Cookies recibidas:", req.cookies);
  next();
});

// Pool de conexiones (mejor práctica)
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD, 
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

app.get('/api/usuarios', authMiddleware.verifyToken, async (req, res) => {
  try {
    const search = req.query.search || '';
    const page = parseInt(req.query.page) || 1;
    const pageSize = parseInt(req.query.pageSize) || 20;
    const offset = (page - 1) * pageSize;

    let where = '';
    let params = [];
    if (search) {
      where = `WHERE nombre LIKE ? OR email LIKE ? OR centro LIKE ?`;
      params = [`%${search}%`, `%${search}%`, `%${search}%`];
    }

    const [rows] = await pool.query(
      `SELECT id, nombre, email, rol, centro, creado_en,
        \`STATUS OF AGENT\`, \`NEXT VOLT\`, RUSHMORE, INDRA, APGE, CLEANSKY,
        WGL, NGE, \`SPARK AUTO\`, \`SPARK LIVE\`, ECOPLUS
       FROM usuarios ${where} LIMIT ? OFFSET ?`,
      [...params, pageSize, offset]
    );

    const [[{ total }]] = await pool.query(
      `SELECT COUNT(*) as total FROM usuarios ${where}`, params
    );

    res.json({ usuarios: rows, total });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error en el servidor" });
  }
});

// AGREGAR USUARIO (POST)
app.post('/api/usuarios', authMiddleware.verifyToken, async (req, res) => {
  try {
    const {
      nombre,
      email,
      rol,
      centro,
      password,
      'STATUS OF AGENT': status,
      'NEXT VOLT': nextVolt,
      RUSHMORE,
      INDRA,
      APGE,
      CLEANSKY,
      WGL,
      NGE,
      'SPARK AUTO': sparkAuto,
      'SPARK LIVE': sparkLive,
      ECOPLUS,
    } = req.body;

    // Validar campos obligatorios
    if (!nombre || !email || !rol || !centro || !password) {
      return res.status(400).json({ error: 'Faltan datos obligatorios' });
    }

    // INSERT
    await pool.query(
      `INSERT INTO usuarios
        (nombre, email, rol, centro, password, creado_en,
         \`STATUS OF AGENT\`, \`NEXT VOLT\`, RUSHMORE, INDRA, APGE, CLEANSKY,
         WGL, NGE, \`SPARK AUTO\`, \`SPARK LIVE\`, ECOPLUS)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        nombre,
        email,
        rol,
        centro,
        password,
        new Date().toISOString().slice(0, 19).replace('T', ' '), // Formato de fecha: yyyy-mm-dd HH:MM:SS
        status || '',
        nextVolt || '',
        RUSHMORE || '',
        INDRA || '',
        APGE || '',
        CLEANSKY || '',
        WGL || '',
        NGE || '',
        sparkAuto || '',
        sparkLive || '',
        ECOPLUS || '',
      ]
    );

    res.json({ ok: true, message: 'Usuario agregado correctamente' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al agregar usuario' });
  }
});

const PORT = process.env.PORT;
app.listen(PORT, () => {
  console.log(`API usuarios corriendo en http://localhost:${PORT}`);
});
