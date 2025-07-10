const express = require('express');
const router = express.Router();
const { subirImagenServicio, eliminarImagenServicio } = require('../controllers/uploadController');

// Rutas para subida de imágenes
router.post('/servicio', subirImagenServicio);           // POST /uploads/servicio - Subir imagen de servicio
router.delete('/servicio/:filename', eliminarImagenServicio); // DELETE /uploads/servicio/:filename - Eliminar imagen

module.exports = router; 