const jwt = require('jsonwebtoken');
const SECRET = process.env.JWT_SECRET || 'secreto_super_seguro';

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ error: 'Token de acceso requerido' });
  }

  jwt.verify(token, SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Token inválido o expirado' });
    }
    
    req.user = user; // Agregar información del usuario a la request
    next();
  });
};

module.exports = {
  authenticateToken
}; 