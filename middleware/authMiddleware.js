// middleware/authMiddleware.js
import jwt from "jsonwebtoken";
import { db } from "../config.js";

export const verifyToken = async (req, res, next) => {
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
    const [userRows] = await db.execute(
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