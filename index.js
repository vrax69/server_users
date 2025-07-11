require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');

const app = express();
app.use(cors());
app.use(express.json());

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

app.get('/api/usuarios', async (req, res) => {
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

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`API usuarios corriendo en http://localhost:${PORT}`);
});
