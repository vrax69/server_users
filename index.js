require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const cookieParser = require('cookie-parser');
const authMiddleware = require('./middleware/authMiddleware');

const app = express();

// 1. CORS
app.use(cors({
  origin: process.env.FRONTEND_ORIGIN,
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
  console.log("📍 Route:", req.method, req.path);
  next();
});

// Pool de conexiones
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD, 
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// GET - Obtener todos los usuarios
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
        \`STATUS_OF_AGENT\`, \`NEXT_VOLT\`, RUSHMORE, INDRA, APGE, CLEANSKY,
        WGL, NGE, \`SPARK_AUTO\`, \`SPARK_LIVE\`, ECOPLUS
       FROM usuarios ${where} LIMIT ? OFFSET ?`,
      [...params, pageSize, offset]
    );

    const [[{ total }]] = await pool.query(
      `SELECT COUNT(*) as total FROM usuarios ${where}`, params
    );

    res.json({ usuarios: rows, total });
  } catch (error) {
    console.error('Error en GET /api/usuarios:', error);
    res.status(500).json({ error: "Error en el servidor" });
  }
});

// POST - Agregar usuario
app.post('/api/usuarios', authMiddleware.verifyToken, async (req, res) => {
  try {
    const {
      nombre,
      email,
      rol,
      centro,
      password,
      'STATUS_OF_AGENT': status,
      'NEXT_VOLT': nextVolt,
      RUSHMORE,
      INDRA,
      APGE,
      CLEANSKY,
      WGL,
      NGE,
      'SPARK_AUTO': sparkAuto,
      'SPARK_LIVE': sparkLive,
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
         \`STATUS_OF_AGENT\`, \`NEXT_VOLT\`, RUSHMORE, INDRA, APGE, CLEANSKY,
         WGL, NGE, \`SPARK_AUTO\`, \`SPARK_LIVE\`, ECOPLUS)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        nombre,
        email,
        rol,
        centro,
        password,
        new Date().toISOString().slice(0, 19).replace('T', ' '),
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
    console.error('Error en POST /api/usuarios:', error);
    res.status(500).json({ error: 'Error al agregar usuario' });
  }
});

// GET - Obtener usuario por ID
app.get('/api/usuarios/:id', authMiddleware.verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    const [rows] = await pool.query(
      `SELECT id, nombre, email, rol, centro, creado_en,
        \`STATUS_OF_AGENT\`, \`NEXT_VOLT\`, RUSHMORE, INDRA, APGE, CLEANSKY,
        WGL, NGE, \`SPARK_AUTO\`, \`SPARK_LIVE\`, ECOPLUS
       FROM usuarios WHERE id = ?`,
      [id]
    );
    
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }
    
    res.json(rows[0]);
  } catch (error) {
    console.error('Error en GET /api/usuarios/:id:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// PUT - Actualizar usuario
app.put('/api/usuarios/:id', authMiddleware.verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const updateData = req.body;
    
    console.log('PUT /api/usuarios/:id - ID:', id);
    console.log('PUT /api/usuarios/:id - Data:', updateData);
    
    // Verificar que el usuario existe
    const [existingUser] = await pool.query(
      'SELECT id FROM usuarios WHERE id = ?',
      [id]
    );
    
    if (existingUser.length === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }
    
    // Construir la consulta SQL dinámicamente
    const fields = [];
    const values = [];
    
    // Campos que se pueden actualizar
    const allowedFields = [
      'nombre', 'email', 'rol', 'centro', 'password', 
      'STATUS_OF_AGENT', 'NEXT_VOLT', 'RUSHMORE', 'INDRA', 
      'APGE', 'CLEANSKY', 'WGL', 'NGE', 'SPARK_AUTO', 
      'SPARK_LIVE', 'ECOPLUS', 'creado_en'
    ];
    
    // Iterar sobre los campos permitidos
    allowedFields.forEach(field => {
      if (updateData.hasOwnProperty(field) && updateData[field] !== undefined) {
        // Manejar campos con backticks
        if (['STATUS_OF_AGENT', 'NEXT_VOLT', 'SPARK_AUTO', 'SPARK_LIVE'].includes(field)) {
          fields.push(`\`${field}\` = ?`);
        } else {
          fields.push(`${field} = ?`);
        }
        values.push(updateData[field]);
      }
    });
    
    if (fields.length === 0) {
      return res.status(400).json({ error: 'No hay campos para actualizar' });
    }
    
    // Añadir el ID al final para la cláusula WHERE
    values.push(id);
    
    // Construir la consulta
    const query = `UPDATE usuarios SET ${fields.join(', ')} WHERE id = ?`;
    
    console.log('Query:', query);
    console.log('Values:', values);
    
    // Ejecutar la consulta
    const [result] = await pool.query(query, values);
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado o no se pudo actualizar' });
    }
    
    // Obtener el usuario actualizado
    const [updatedUser] = await pool.query(
      `SELECT id, nombre, email, rol, centro, creado_en,
        \`STATUS_OF_AGENT\`, \`NEXT_VOLT\`, RUSHMORE, INDRA, APGE, CLEANSKY,
        WGL, NGE, \`SPARK_AUTO\`, \`SPARK_LIVE\`, ECOPLUS
       FROM usuarios WHERE id = ?`,
      [id]
    );
    
    res.json({
      ok: true,
      message: 'Usuario actualizado exitosamente',
      usuario: updatedUser[0]
    });
    
  } catch (error) {
    console.error('Error en PUT /api/usuarios/:id:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// DELETE - Eliminar usuario
app.delete('/api/usuarios/:id', authMiddleware.verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    console.log('DELETE /api/usuarios/:id - ID:', id);
    
    // Verificar que el usuario existe
    const [existingUser] = await pool.query(
      'SELECT id FROM usuarios WHERE id = ?',
      [id]
    );
    
    if (existingUser.length === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }
    
    // Eliminar el usuario
    const [result] = await pool.query(
      'DELETE FROM usuarios WHERE id = ?',
      [id]
    );
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }
    
    res.json({
      ok: true,
      message: 'Usuario eliminado exitosamente'
    });
    
  } catch (error) {
    console.error('Error en DELETE /api/usuarios/:id:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`API usuarios corriendo en http://localhost:${PORT}`);
});