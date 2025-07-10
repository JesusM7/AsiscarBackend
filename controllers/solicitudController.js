const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

const crearSolicitud = async (req, res) => {
  const { tipoServicio, latitud, longitud, clienteId } = req.body;

  try {
    const solicitud = await prisma.solicitudDelivery.create({
      data: {
        tipoServicio,
        latitud,
        longitud,
        cliente: { connect: { id: clienteId } },
      },
    });

    res.status(201).json(solicitud);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al crear solicitud' });
  }
};

const obtenerSolicitudes = async (req, res) => {
  try {
    const solicitudes = await prisma.solicitudDelivery.findMany({
      include: {
        cliente: true,
        proveedor: true,
      },
    });
    res.json(solicitudes);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener solicitudes' });
  }
};

//Asignar Proveedor

const getDistanceKm = require('../utils/distance');

const asignarProveedor = async (req, res) => {
  const { solicitudId } = req.body;

  try {
    const solicitud = await prisma.solicitudDelivery.findUnique({
      where: { id: solicitudId },
    });

    if (!solicitud) return res.status(404).json({ error: 'Solicitud no encontrada' });

    console.log(`🎯 Solicitud: tipo = ${solicitud.tipoServicio}, ubicación = (${solicitud.latitud}, ${solicitud.longitud})`);

    const proveedores = await prisma.proveedor.findMany({
      where: {
        tipo: solicitud.tipoServicio,
        disponible: true,
      },
    });

    console.log(`🔍 Proveedores encontrados con tipo '${solicitud.tipoServicio}': ${proveedores.length}`);

    const disponiblesCercanos = proveedores.filter((prov) => {
      const distancia = getDistanceKm(
        solicitud.latitud,
        solicitud.longitud,
        prov.latitud,
        prov.longitud
      );

      console.log(`📏 Proveedor ${prov.nombre}: ${distancia.toFixed(2)} km`);

      return distancia <= prov.radioKm;
    });

    if (disponiblesCercanos.length === 0) {
      return res.status(404).json({ error: 'No hay proveedores disponibles cercanos' });
    }

    // Seleccionar el más cercano (puedes cambiar este criterio)
    const proveedorAsignado = disponiblesCercanos[0];

    const actualizada = await prisma.solicitudDelivery.update({
        where: { id: solicitudId },
        data: {
            proveedorId: proveedorAsignado.id,
            estado: 'aceptada',
        },
        include: {
            proveedor: true, // 👈 esto incluye los datos del proveedor
        },
    });


    // res.json({
    //   mensaje: 'Proveedor asignado',
    //   solicitud: actualizada,
    // });
    res.json({
        mensaje: 'Proveedor asignado',
        proveedor: actualizada.proveedor, // 👈 nombre, tipo, ubicación, etc.
        solicitud: {
            id: actualizada.id,
            tipoServicio: actualizada.tipoServicio,
            estado: actualizada.estado,
            fecha: actualizada.fecha,
        },
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al asignar proveedor' });
  }
};

module.exports = { crearSolicitud, obtenerSolicitudes, asignarProveedor };

// module.exports = { crearSolicitud, obtenerSolicitudes };

