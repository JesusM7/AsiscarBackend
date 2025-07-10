const { PrismaClient } = require('@prisma/client');
const { validateProviderName } = require('../utils/validation');
const prisma = new PrismaClient();

//REGISTRAR PROVEEDOR

const registrarProveedor = async (req, res) => {
  const {
    nombre,
    tipo,
    latitud,
    longitud,
    radioKm
  } = req.body;

  try {
    // Validaciones de entrada
    if (!nombre || !tipo || !latitud || !longitud || !radioKm) {
      return res.status(400).json({ 
        error: 'Faltan campos obligatorios. Por favor, completa todos los campos.' 
      });
    }

    // Validar nombre del proveedor
    const nombreValidation = validateProviderName(nombre);
    if (!nombreValidation.isValid) {
      return res.status(400).json({ error: nombreValidation.error });
    }

    // Validar tipo de servicio
    const tipoLimpio = tipo.trim().toLowerCase();
    if (!['grua', 'mecanico'].includes(tipoLimpio)) {
      return res.status(400).json({ 
        error: 'Tipo de servicio inválido. Debe ser "grua" o "mecanico"' 
      });
    }

    // Validar coordenadas
    const lat = parseFloat(latitud);
    const lng = parseFloat(longitud);
    const radio = parseFloat(radioKm);

    if (isNaN(lat) || isNaN(lng)) {
      return res.status(400).json({ 
        error: 'Latitud y longitud deben ser números válidos' 
      });
    }

    if (isNaN(radio) || radio <= 0 || radio > 100) {
      return res.status(400).json({ 
        error: 'El radio debe ser un número entre 1 y 100 kilómetros' 
      });
    }

    const nuevoProveedor = await prisma.proveedor.create({
      data: {
        nombre: nombre.trim(),
        tipo: tipoLimpio,
        latitud: lat,
        longitud: lng,
        radioKm: radio,
        disponible: true, // Por defecto
      },
    });

    res.status(201).json({
      mensaje: 'Proveedor registrado exitosamente',
      proveedor: nuevoProveedor,
    });
  } catch (error) {
    console.error('Error al registrar proveedor:', error);
    
    let mensajeError = 'Error interno del servidor al registrar proveedor';
    
    if (error.code === 'P2002') {
      mensajeError = 'Ya existe un proveedor con estos datos.';
    } else if (error.message && error.message.includes('Invalid')) {
      mensajeError = 'Datos inválidos. Por favor, revisa todos los campos.';
    }
    
    res.status(500).json({ error: mensajeError });
  }
};

//LISTAR PROVEEDORES

const obtenerProveedores = async (req, res) => {
  try {
    const proveedores = await prisma.proveedor.findMany();
    res.json(proveedores);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener proveedores' });
  }
};

module.exports = { registrarProveedor, obtenerProveedores };
