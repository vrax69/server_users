const dotenv = require('dotenv');
const fs = require('fs');

// ✅ Cargar archivo .env.local si existe, si no usar .env
if (fs.existsSync('.env.local')) {
  dotenv.config({ path: '.env.local' });
} else {
  dotenv.config({ path: '.env' });
}

const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');

// Crear pool de conexiones aquí también o recibirlo como parámetro
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,  // ✅ Cambiar de DB_PASSWORD a DB_PASS
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

const verifyToken = async (req, res, next) => {
  const token = req.cookies.token;
  
  if (!token) {
    return res.status(401).json({ 
      message: "Token faltante", 
      code: "NO_TOKEN" 
    });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Verificar si el usuario existe y está activo en la base de datos
    const [userRows] = await pool.execute(
      'SELECT id, nombre, email, rol, centro, STATUS_OF_AGENT FROM usuarios WHERE id = ?',
      [decoded.id]
    );

    if (userRows.length === 0) {
      return res.status(401).json({ 
        message: "Usuario no encontrado", 
        code: "USER_NOT_FOUND" 
      });
    }

    const user = userRows[0];

    // Verificar si el usuario está activo
    if (user.STATUS_OF_AGENT !== 'active') {
      return res.status(403).json({ 
        message: "Cuenta inactiva. Contacta al administrador.", 
        code: "ACCOUNT_INACTIVE",
        status: user.STATUS_OF_AGENT 
      });
    }

    // Agregar información del usuario al request
    req.user = {
      id: decoded.id,
      nombre: user.nombre,
      email: user.email,
      rol: user.rol,
      centro: user.centro,
      status: user.STATUS_OF_AGENT
    };
    
    next();
  } catch (error) {
    console.error("Error en verificación de token:", error);
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        message: "Token expirado", 
        code: "TOKEN_EXPIRED" 
      });
    }
    
    return res.status(403).json({ 
      message: "Token inválido", 
      code: "INVALID_TOKEN" 
    });
  }
};

module.exports = {
  verifyToken
};