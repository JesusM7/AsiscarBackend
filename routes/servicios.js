const express = require('express');
const router = express.Router();
const { authenticateToken } = require('../middleware/auth');
const {
  crearServicio,
  obtenerServicios,
  obtenerMisServicios,
  obtenerServicioPorId,
  actualizarServicio,
  eliminarServicio,
  buscarServiciosCercanos,
  cambiarDisponibilidad
} = require('../controllers/servicioController');

// Rutas públicas (sin autenticación)
router.get('/', obtenerServicios);                  // GET /servicios - Obtener todos los servicios
router.get('/cercanos', buscarServiciosCercanos);   // GET /servicios/cercanos - Buscar servicios cercanos

// Rutas protegidas (requieren autenticación)
router.get('/mis-servicios', authenticateToken, obtenerMisServicios);           // GET /servicios/mis-servicios - Obtener servicios del usuario
router.get('/:id', obtenerServicioPorId);           // GET /servicios/:id - Obtener servicio por ID
router.post('/', authenticateToken, crearServicio);                    // POST /servicios - Crear servicio (solo mecánicos, grúas y admins)
router.put('/:id', authenticateToken, actualizarServicio);             // PUT /servicios/:id - Actualizar servicio (solo propietario)
router.delete('/:id', authenticateToken, eliminarServicio);            // DELETE /servicios/:id - Eliminar servicio (solo propietario)
router.patch('/:id/disponibilidad', authenticateToken, cambiarDisponibilidad); // PATCH /servicios/:id/disponibilidad (solo propietario)

module.exports = router; 