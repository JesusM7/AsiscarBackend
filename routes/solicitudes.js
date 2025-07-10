const express = require('express');
const router = express.Router();
const { crearSolicitud, obtenerSolicitudes, asignarProveedor } = require('../controllers/solicitudController');

router.post('/', crearSolicitud);
router.get('/', obtenerSolicitudes); // 👈 esta es la nueva línea

router.post('/asignar', asignarProveedor);

module.exports = router;
