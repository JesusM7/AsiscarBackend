const express = require('express');
const router = express.Router();
const { registrarProveedor, obtenerProveedores } = require('../controllers/proveedorController');

router.post('/registrar', registrarProveedor);
router.get('/', obtenerProveedores); // 👈 nueva línea


module.exports = router;