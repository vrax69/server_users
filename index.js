const dotenv = require('dotenv');
const fs = require('fs');

// ✅ Cargar archivo .env.local si existe, si no usar .env
if (fs.existsSync('.env.local')) {
  dotenv.config({ path: '.env.local' });
  console.log('📄 .env.local cargado');
} else {
  dotenv.config({ path: '.env' });
  console.log('📄 .env cargado');
}

const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const cookieParser = require('cookie-parser');
const authMiddleware = require('./middleware/authMiddleware');

const app = express();

// Debug de variables de entorno mejorado
console.log('🔧 Variables de entorno cargadas:');
console.log('NODE_ENV:', process.env.NODE_ENV);
console.log('SKIP_AUTH:', process.env.SKIP_AUTH);
console.log('DB_HOST:', process.env.DB_HOST);
console.log('DB_NAME:', process.env.DB_NAME);
console.log('DB_USER:', process.env.DB_USER);
console.log('🛡️ DB_PASS cargado:', process.env.DB_PASS ? 'OK ✅' : '❌ NO DEFINIDO');

// Middleware condicional para autenticación
const requireAuth =
  process.env.SKIP_AUTH === '1'
    ? (_req, _res, next) => next()           // NO pide token (modo test)
    : authMiddleware.verifyToken;            // modo normal

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
  password: process.env.DB_PASS,  // Cambiar de DB_PASSWORD a DB_PASS
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// Helper: obtener todos los proveedores
async function getAllProviders(pool) {
  const [rows] = await pool.query('SELECT id, codigo FROM proveedores ORDER BY codigo');
  return rows; // [{id, codigo}, ...]
}

// GET - Obtener todos los usuarios
app.get('/api/usuarios', requireAuth, async (req, res) => {
  try {
    console.log('🔍 Iniciando GET /api/usuarios');
    
    const search = req.query.search || '';
    const centro = req.query.centro || '';
    const page = parseInt(req.query.page) || 1;
    const pageSize = parseInt(req.query.pageSize) || 20;
    const offset = (page - 1) * pageSize;

    console.log('📋 Parámetros recibidos:', { search, centro, page, pageSize });

    // Verificar conexión primero
    await pool.query('SELECT 1');
    console.log('✅ Conexión DB OK');

    // WHERE dinámico
    const conditions = [];
    const params = [];
    if (search) {
      conditions.push(`(u.nombre LIKE ? OR u.email LIKE ? OR u.centro LIKE ?)`);
      params.push(`%${search}%`, `%${search}%`, `%${search}%`);
    }
    if (centro) {
      conditions.push(`u.centro = ?`);
      params.push(centro);
    }
    const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

    // total
    const [[{ total }]] = await pool.query(
      `SELECT COUNT(*) AS total FROM usuarios u ${where}`,
      params
    );

    console.log('Total encontrado:', total);

    // usuarios base (AHORA CON STATUS - incluir el campo status)
    const [users] = await pool.query(
      `SELECT u.id, u.nombre, u.email, u.rol, u.centro, u.creado_en, u.status
       FROM usuarios u
       ${where}
       ORDER BY u.id DESC
       LIMIT ? OFFSET ?`,
      [...params, pageSize, offset]
    );

    console.log('Usuarios base encontrados:', users.length);

    if (users.length === 0) {
      return res.json({ usuarios: [], total });
    }

    // proveedores (para construir las columnas)
    const providers = await getAllProviders(pool);
    const userIds = users.map(u => u.id);

    console.log('Proveedores disponibles:', providers.map(p => p.codigo));

    // todas las cuentas TPV de los usuarios en la página
    const [accounts] = await pool.query(
      `SELECT a.user_id, p.codigo,
              a.tpv_id, a.tpv_username, a.tpv_password, a.status, a.updated_at
       FROM user_provider_account a
       JOIN proveedores p ON p.id = a.provider_id
       WHERE a.user_id IN (${userIds.map(() => '?').join(',')})
       ORDER BY p.codigo`,
      userIds
    );

    console.log('Cuentas TPV encontradas:', accounts.length);

    // indexar accounts por user_id
    const accByUser = new Map();
    for (const row of accounts) {
      if (!accByUser.has(row.user_id)) accByUser.set(row.user_id, []);
      accByUser.get(row.user_id).push(row);
    }

    // construir salida: usuario base + columnas por proveedor
    const usuariosOut = users.map(u => {
      const base = {
        id: u.id,
        nombre: u.nombre,
        email: u.email,
        rol: u.rol,
        centro: u.centro,
        creado_en: u.creado_en,
        STATUS_OF_AGENT: u.status  // ← 🔥 Usar el campo real de la tabla
      };

      // inicializa todas las columnas por proveedor
      for (const p of providers) {
        base[p.codigo] = null;
        base[`${p.codigo}_STATUS`] = null;
        base[`${p.codigo}_USERNAME`] = null;
        base[`${p.codigo}_PASSWORD`] = null;
      }

      // rellena con lo que haya en cuentas
      const rows = accByUser.get(u.id) || [];
      for (const r of rows) {
        base[r.codigo] = r.tpv_id || null;
        base[`${r.codigo}_STATUS`] = r.status || null;
        base[`${r.codigo}_USERNAME`] = r.tpv_username || null;
        base[`${r.codigo}_PASSWORD`] = r.tpv_password || null;
      }

      return base;
    });

    console.log('Respuesta final generada para', usuariosOut.length, 'usuarios');
    res.json({ usuarios: usuariosOut, total });
  } catch (error) {
    console.error('❌ Error completo en GET /api/usuarios:', error);
    console.error('Stack trace:', error.stack);
    res.status(500).json({ 
      error: "Error en el servidor",
      details: error.message,
      code: error.code 
    });
  }
});

// GET - Obtener usuario por ID
app.get('/api/usuarios/:id', requireAuth, async (req, res) => {
  try {
    console.log('🔍 Iniciando GET /api/usuarios/:id');
    
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) {
      return res.status(400).json({ error: 'ID inválido' });
    }

    console.log('🆔 Buscando usuario ID:', id);

    // Verificar conexión primero
    await pool.query('SELECT 1');
    console.log('✅ Conexión DB OK');

    const [[u]] = await pool.query(
      `SELECT id, nombre, email, rol, centro, creado_en, status
       FROM usuarios WHERE id = ? LIMIT 1`,
      [id]
    );
    if (!u) return res.status(404).json({ error: 'Usuario no encontrado' });

    const providers = await getAllProviders(pool);

    const [rows] = await pool.query(
      `SELECT p.codigo, a.tpv_id, a.tpv_username, a.tpv_password, a.status
       FROM user_provider_account a
       JOIN proveedores p ON p.id = a.provider_id
       WHERE a.user_id = ?`,
      [id]
    );

    // arma salida pivot
    const out = {
      id: u.id,
      nombre: u.nombre,
      email: u.email,
      rol: u.rol,
      centro: u.centro,
      creado_en: u.creado_en,
      STATUS_OF_AGENT: u.status  // ← 🔥 Usar el campo real de la tabla
    };

    for (const p of providers) {
      out[p.codigo] = null;
      out[`${p.codigo}_STATUS`] = null;
      out[`${p.codigo}_USERNAME`] = null;
      out[`${p.codigo}_PASSWORD`] = null;
    }

    for (const r of rows) {
      out[r.codigo] = r.tpv_id || null;
      out[`${r.codigo}_STATUS`] = r.status || null;
      out[`${r.codigo}_USERNAME`] = r.tpv_username || null;
      out[`${r.codigo}_PASSWORD`] = r.tpv_password || null;
    }

    res.json(out);
  } catch (error) {
    console.error('❌ Error completo en GET /api/usuarios/:id:', error);
    console.error('Stack trace:', error.stack);
    res.status(500).json({ 
      error: 'Error interno del servidor',
      details: error.message,
      code: error.code 
    });
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

// Ruta de salud rápida (para ver que el server y la BD responden)
app.get('/health', async (_req, res) => {
  try {
    const [r] = await pool.query('SELECT DATABASE() db, 1 ping');
    res.json(r[0]);
  } catch (e) {
    console.error('HEALTH ERROR:', e);
    res.status(500).json({ error: e.code || 'DB_ERROR', msg: e.message });
  }
});

// Helper: resolver provider_id por code
async function getProviderIdByCode(pool, code) {
  const [rows] = await pool.query(
    'SELECT id FROM proveedores WHERE codigo = ? LIMIT 1',
    [code]
  );
  return rows.length ? rows[0].id : null;
}

// GET - Todas las cuentas TPV de un usuario
app.get('/api/usuarios/:userId/providers', requireAuth, async (req, res) => {
  try {
    const userId = Number(req.params.userId);
    if (!Number.isInteger(userId)) {
      return res.status(400).json({ error: 'userId inválido' });
    }

    const [rows] = await pool.query(
      `SELECT p.codigo AS code, p.nombre AS name,
              a.tpv_id, a.tpv_username, a.status, a.updated_at
       FROM user_provider_account a
       JOIN proveedores p ON p.id = a.provider_id
       WHERE a.user_id = ?
       ORDER BY p.codigo`,
      [userId]
    );

    res.json(rows);
  } catch (err) {
    console.error('GET /usuarios/:userId/providers error', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// GET - Una cuenta TPV específica (usuario + proveedor)
app.get('/api/usuarios/:userId/providers/:code', requireAuth, async (req, res) => {
  try {
    const userId = Number(req.params.userId);
    const code = String(req.params.code || '').trim();

    if (!Number.isInteger(userId) || !code) {
      return res.status(400).json({ error: 'Parámetros inválidos' });
    }

    const [rows] = await pool.query(
      `SELECT p.codigo AS code, p.nombre AS name,
              a.tpv_id, a.tpv_username, a.tpv_password, a.status, a.updated_at
       FROM user_provider_account a
       JOIN proveedores p ON p.id = a.provider_id
       WHERE a.user_id = ? AND p.codigo = ?
       LIMIT 1`,
      [userId, code]
    );

    if (!rows.length) return res.status(404).json({ error: 'No existe cuenta TPV para ese proveedor' });
    res.json(rows[0]);
  } catch (err) {
    console.error('GET /usuarios/:userId/providers/:code error', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// PUT - Crear/actualizar TPV ID + credenciales (UPSERT)
app.put('/api/usuarios/:userId/providers/:code', requireAuth, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const userId = Number(req.params.userId);
    const code = String(req.params.code || '').trim();
    const { tpv_id, tpv_username, tpv_password, status } = req.body || {};

    if (!Number.isInteger(userId) || !code || !tpv_id) {
      return res.status(400).json({ error: 'userId/code/tpv_id obligatorios' });
    }

    const providerId = await getProviderIdByCode(pool, code);
    if (!providerId) {
      return res.status(404).json({ error: `Proveedor ${code} no existe` });
    }

    await conn.beginTransaction();

    // PK(user_id, provider_id) → ON DUPLICATE KEY UPDATE hace UPSERT
    const sql = `
      INSERT INTO user_provider_account
        (user_id, provider_id, tpv_id, tpv_username, tpv_password, status, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, NOW(), NOW())
      ON DUPLICATE KEY UPDATE
        tpv_id = VALUES(tpv_id),
        tpv_username = VALUES(tpv_username),
        tpv_password = VALUES(tpv_password),
        status = VALUES(status),
        updated_at = NOW()
    `;

    await conn.query(sql, [
      userId,
      providerId,
      tpv_id,
      tpv_username || null,
      tpv_password || null,
      status || null
    ]);

    await conn.commit();
    res.json({ ok: true });
  } catch (err) {
    await (conn?.rollback?.());
    console.error('PUT /usuarios/:userId/providers/:code error', err);
    res.status(500).json({ error: 'Error interno' });
  } finally {
    conn.release();
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`API usuarios corriendo en http://localhost:${PORT}`);
});