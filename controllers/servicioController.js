const { PrismaClient } = require('@prisma/client');
const { validateProviderName, validateEmail, validatePhone } = require('../utils/validation');
const prisma = new PrismaClient();
const getDistanceKm = require('../utils/distance');

// CREAR SERVICIO
const crearServicio = async (req, res) => {
  const {
    tipoServicio,
    titulo,
    descripcion,
    precio,
    nombreProveedor,
    telefonoProveedor,
    emailProveedor,
    cedulaProveedor,
    latitud,
    longitud,
    direccion,
    ciudad,
    cobertura,
    fotoUrl,
    horarioInicio,
    horarioFin,
    diasDisponibles
  } = req.body;

  try {
    // Validar que el usuario tenga permisos para crear servicios
    const rolesPermitidos = ['mecanico', 'grua', 'admin'];
    if (!rolesPermitidos.includes(req.user.user_type)) {
      return res.status(403).json({ 
        error: 'No tienes permisos para crear servicios. Solo mecánicos, conductores de grúa y administradores pueden crear servicios.' 
      });
    }

    // Validaciones de entrada
    if (!tipoServicio || !['grua', 'mecanico'].includes(tipoServicio)) {
      return res.status(400).json({ 
        error: 'Tipo de servicio inválido. Debe ser "grua" o "mecanico"' 
      });
    }

    // Validar campos requeridos
    if (!titulo || !descripcion || !precio || !nombreProveedor || !telefonoProveedor || 
        !emailProveedor || !cedulaProveedor || !latitud || !longitud || !direccion || !ciudad || !cobertura) {
      return res.status(400).json({ 
        error: 'Faltan campos obligatorios. Por favor, completa toda la información requerida.' 
      });
    }

    // Validar nombre del proveedor
    const nombreValidation = validateProviderName(nombreProveedor);
    if (!nombreValidation.isValid) {
      return res.status(400).json({ error: nombreValidation.error });
    }

    // Validar email del proveedor
    const emailValidation = validateEmail(emailProveedor);
    if (!emailValidation.isValid) {
      return res.status(400).json({ error: emailValidation.error });
    }

    // Validar teléfono del proveedor
    const phoneValidation = validatePhone(telefonoProveedor);
    if (!phoneValidation.isValid) {
      return res.status(400).json({ error: phoneValidation.error });
    }

    // Validar cédula (formato básico)
    if (!/^[0-9]{7,8}$/.test(cedulaProveedor)) {
      return res.status(400).json({ error: 'La cédula debe tener 7 u 8 dígitos' });
    }

    // Validar datos numéricos
    const precioNum = parseFloat(precio);
    const latitudNum = parseFloat(latitud);
    const longitudNum = parseFloat(longitud);
    const coberturaNum = parseFloat(cobertura);

    if (isNaN(precioNum) || precioNum <= 0) {
      return res.status(400).json({ error: 'El precio debe ser un número mayor a 0' });
    }

    if (isNaN(latitudNum) || isNaN(longitudNum)) {
      return res.status(400).json({ error: 'Latitud y longitud deben ser números válidos' });
    }

    if (isNaN(coberturaNum) || coberturaNum <= 0) {
      return res.status(400).json({ error: 'La cobertura debe ser un número mayor a 0' });
    }

    // NOTA: Permitimos que el mismo usuario tenga múltiples servicios con su email/cédula
    // Solo validamos que otros usuarios no usen estos datos
    const servicioExistente = await prisma.servicio.findFirst({
      where: {
        AND: [
          { userId: { not: req.user.id } }, // Excluir servicios del usuario actual
          { activo: true }, // Solo servicios activos
          {
            OR: [
              { emailProveedor: emailProveedor.toLowerCase() },
              { cedulaProveedor }
            ]
          }
        ]
      }
    });

    if (servicioExistente) {
      return res.status(400).json({ 
        error: 'Ya existe un servicio activo registrado por otro usuario con este email o cédula' 
      });
    }

    const nuevoServicio = await prisma.servicio.create({
      data: {
        userId: req.user.id, // ID del usuario autenticado
        tipoServicio: tipoServicio.toLowerCase(),
        titulo: titulo.trim(),
        descripcion: descripcion.trim(),
        precio: precioNum,
        nombreProveedor: nombreProveedor.trim(),
        telefonoProveedor: telefonoProveedor.replace(/\s/g, ''),
        emailProveedor: emailProveedor.toLowerCase().trim(),
        cedulaProveedor: cedulaProveedor.trim(),
        latitud: latitudNum,
        longitud: longitudNum,
        direccion: direccion.trim(),
        ciudad: ciudad.trim(),
        cobertura: coberturaNum,
        fotoUrl,
        horarioInicio,
        horarioFin,
        diasDisponibles,
        disponible: true,
        verificado: false,
        activo: true
      }
    });

    res.status(201).json({
      mensaje: 'Servicio creado exitosamente',
      servicio: nuevoServicio
    });

  } catch (error) {
    console.error('Error al crear servicio:', error);
    
    // Proporcionar mensajes más específicos basados en el tipo de error
    let mensajeError = 'Error interno del servidor al crear servicio';
    
    if (error.code === 'P2002') {
      // Error de restricción única de Prisma
      mensajeError = 'Ya existe un servicio con estos datos. Por favor, verifica la información.';
    } else if (error.code === 'P2003') {
      // Error de restricción de clave foránea
      mensajeError = 'Error de datos relacionados. Por favor, verifica la información.';
    } else if (error.code === 'P2025') {
      // Registro no encontrado
      mensajeError = 'No se encontró el registro requerido para crear el servicio.';
    } else if (error.message && error.message.includes('Invalid')) {
      // Errores de validación de datos
      mensajeError = 'Datos inválidos. Por favor, revisa todos los campos del formulario.';
    } else if (error.message && error.message.includes('required')) {
      // Campos requeridos faltantes
      mensajeError = 'Faltan campos obligatorios. Por favor, completa toda la información requerida.';
    }
    
    res.status(500).json({ error: mensajeError });
  }
};

// OBTENER TODOS LOS SERVICIOS
const obtenerServicios = async (req, res) => {
  const { tipo, ciudad, disponible } = req.query;

  try {
    const filtros = {
      activo: true
    };

    // Aplicar filtros opcionales
    if (tipo) {
      filtros.tipoServicio = tipo.toLowerCase();
    }
    if (ciudad) {
      filtros.ciudad = { contains: ciudad, mode: 'insensitive' };
    }
    if (disponible !== undefined) {
      filtros.disponible = disponible === 'true';
    }

    const servicios = await prisma.servicio.findMany({
      where: filtros,
      include: {
        user: {
          select: {
            id: true,
            username: true,
            user_type: true
          }
        }
      },
      orderBy: {
        createdAt: 'desc'
      }
    });

    res.json({
      servicios,
      total: servicios.length
    });

  } catch (error) {
    console.error('Error al obtener servicios:', error);
    res.status(500).json({ error: 'Error interno del servidor al obtener servicios' });
  }
};

// OBTENER SERVICIO POR ID
const obtenerServicioPorId = async (req, res) => {
  const { id } = req.params;

  try {
    const servicio = await prisma.servicio.findUnique({
      where: { 
        id: parseInt(id),
        activo: true 
      }
    });

    if (!servicio) {
      return res.status(404).json({ error: 'Servicio no encontrado' });
    }

    res.json(servicio);

  } catch (error) {
    console.error('Error al obtener servicio:', error);
    res.status(500).json({ error: 'Error interno del servidor al obtener servicio' });
  }
};

// ACTUALIZAR SERVICIO
const actualizarServicio = async (req, res) => {
  const { id } = req.params;
  const datosActualizacion = req.body;

  try {
    // Verificar que el servicio existe
    const servicioExistente = await prisma.servicio.findUnique({
      where: { 
        id: parseInt(id),
        activo: true 
      }
    });

    if (!servicioExistente) {
      return res.status(404).json({ error: 'Servicio no encontrado' });
    }

    // Verificar que el usuario es el propietario del servicio
    if (servicioExistente.userId !== req.user.id) {
      return res.status(403).json({ 
        error: 'No tienes permiso para editar este servicio. Solo puedes editar servicios que hayas creado.' 
      });
    }

    // Si se está actualizando el email o cédula, verificar que no existan en servicios de OTROS usuarios
    if (datosActualizacion.emailProveedor || datosActualizacion.cedulaProveedor) {
      const conflicto = await prisma.servicio.findFirst({
        where: {
          AND: [
            { id: { not: parseInt(id) } }, // Excluir el servicio actual
            { userId: { not: req.user.id } }, // Excluir servicios del usuario actual
            {
              OR: [
                { emailProveedor: datosActualizacion.emailProveedor },
                { cedulaProveedor: datosActualizacion.cedulaProveedor }
              ]
            }
          ]
        }
      });

      if (conflicto) {
        return res.status(400).json({ 
          error: 'Ya existe un servicio de otro usuario con este email o cédula' 
        });
      }
    }

    // Procesar campos numéricos
    if (datosActualizacion.precio) {
      datosActualizacion.precio = parseFloat(datosActualizacion.precio);
    }
    if (datosActualizacion.latitud) {
      datosActualizacion.latitud = parseFloat(datosActualizacion.latitud);
    }
    if (datosActualizacion.longitud) {
      datosActualizacion.longitud = parseFloat(datosActualizacion.longitud);
    }
    if (datosActualizacion.cobertura) {
      datosActualizacion.cobertura = parseFloat(datosActualizacion.cobertura);
    }

    const servicioActualizado = await prisma.servicio.update({
      where: { id: parseInt(id) },
      data: datosActualizacion
    });

    res.json({
      mensaje: 'Servicio actualizado exitosamente',
      servicio: servicioActualizado
    });

  } catch (error) {
    console.error('Error al actualizar servicio:', error);
    
    // Proporcionar mensajes más específicos basados en el tipo de error
    let mensajeError = 'Error interno del servidor al actualizar servicio';
    
    if (error.code === 'P2002') {
      // Error de restricción única de Prisma
      mensajeError = 'Ya existe un servicio con estos datos. Por favor, verifica la información.';
    } else if (error.code === 'P2003') {
      // Error de restricción de clave foránea
      mensajeError = 'Error de datos relacionados. Por favor, verifica la información.';
    } else if (error.code === 'P2025') {
      // Registro no encontrado
      mensajeError = 'El servicio que intentas actualizar no existe o ha sido eliminado.';
    } else if (error.message && error.message.includes('Invalid')) {
      // Errores de validación de datos
      mensajeError = 'Datos inválidos. Por favor, revisa todos los campos del formulario.';
    } else if (error.message && error.message.includes('required')) {
      // Campos requeridos faltantes
      mensajeError = 'Faltan campos obligatorios. Por favor, completa toda la información requerida.';
    }
    
    res.status(500).json({ error: mensajeError });
  }
};

// ELIMINAR SERVICIO (SOFT DELETE)
const eliminarServicio = async (req, res) => {
  const { id } = req.params;

  try {
    const servicio = await prisma.servicio.findUnique({
      where: { 
        id: parseInt(id),
        activo: true 
      }
    });

    if (!servicio) {
      return res.status(404).json({ error: 'Servicio no encontrado' });
    }

    // Verificar permisos: propietario del servicio O administrador
    const esPropioPropietario = servicio.userId === req.user.id;
    const esAdministrador = req.user.user_type === 'admin';
    
    if (!esPropioPropietario && !esAdministrador) {
      return res.status(403).json({ 
        error: 'No tienes permiso para eliminar este servicio. Solo puedes eliminar servicios que hayas creado o ser administrador.' 
      });
    }

    // Soft delete - marcar como inactivo
    await prisma.servicio.update({
      where: { id: parseInt(id) },
      data: { activo: false }
    });

    res.json({ mensaje: 'Servicio eliminado exitosamente' });

  } catch (error) {
    console.error('Error al eliminar servicio:', error);
    res.status(500).json({ error: 'Error interno del servidor al eliminar servicio' });
  }
};

// BUSCAR SERVICIOS CERCANOS
const buscarServiciosCercanos = async (req, res) => {
  const { latitud, longitud, tipo, radioMaximo = 50 } = req.query;

  try {
    if (!latitud || !longitud) {
      return res.status(400).json({ 
        error: 'Se requieren las coordenadas de latitud y longitud' 
      });
    }

    const lat = parseFloat(latitud);
    const lng = parseFloat(longitud);
    const maxRadio = parseFloat(radioMaximo);

    // Filtros base
    const filtros = {
      activo: true,
      disponible: true
    };

    if (tipo) {
      filtros.tipoServicio = tipo.toLowerCase();
    }

    // Obtener todos los servicios que coincidan con los filtros
    const servicios = await prisma.servicio.findMany({
      where: filtros
    });

    // Calcular distancias y filtrar por cobertura
    const serviciosCercanos = servicios
      .map(servicio => {
        const distancia = getDistanceKm(lat, lng, servicio.latitud, servicio.longitud);
        return {
          ...servicio,
          distanciaKm: Math.round(distancia * 100) / 100 // Redondear a 2 decimales
        };
      })
      .filter(servicio => 
        servicio.distanciaKm <= servicio.cobertura && 
        servicio.distanciaKm <= maxRadio
      )
      .sort((a, b) => a.distanciaKm - b.distanciaKm); // Ordenar por distancia

    res.json({
      serviciosEncontrados: serviciosCercanos,
      total: serviciosCercanos.length,
      ubicacionBusqueda: { latitud: lat, longitud: lng },
      radioMaximoBusqueda: maxRadio
    });

  } catch (error) {
    console.error('Error al buscar servicios cercanos:', error);
    res.status(500).json({ error: 'Error interno del servidor al buscar servicios' });
  }
};

// CAMBIAR DISPONIBILIDAD
const cambiarDisponibilidad = async (req, res) => {
  const { id } = req.params;
  const { disponible } = req.body;

  try {
    const servicio = await prisma.servicio.findUnique({
      where: { 
        id: parseInt(id),
        activo: true 
      }
    });

    if (!servicio) {
      return res.status(404).json({ error: 'Servicio no encontrado' });
    }

    // Verificar permisos: propietario del servicio O administrador
    const esPropioPropietario = servicio.userId === req.user.id;
    const esAdministrador = req.user.user_type === 'admin';
    
    if (!esPropioPropietario && !esAdministrador) {
      return res.status(403).json({ 
        error: 'No tienes permiso para modificar este servicio. Solo puedes modificar servicios que hayas creado o ser administrador.' 
      });
    }

    const servicioActualizado = await prisma.servicio.update({
      where: { id: parseInt(id) },
      data: { disponible: disponible === true || disponible === 'true' }
    });

    res.json({
      mensaje: `Servicio ${servicioActualizado.disponible ? 'activado' : 'desactivado'} exitosamente`,
      servicio: servicioActualizado
    });

  } catch (error) {
    console.error('Error al cambiar disponibilidad:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
};

// OBTENER SERVICIOS DEL USUARIO AUTENTICADO
const obtenerMisServicios = async (req, res) => {
  try {
    const servicios = await prisma.servicio.findMany({
      where: {
        userId: req.user.id,
        activo: true
      },
      orderBy: {
        createdAt: 'desc'
      }
    });

    res.json({
      servicios,
      total: servicios.length
    });

  } catch (error) {
    console.error('Error al obtener mis servicios:', error);
    res.status(500).json({ error: 'Error interno del servidor al obtener servicios' });
  }
};

module.exports = {
  crearServicio,
  obtenerServicios,
  obtenerMisServicios,
  obtenerServicioPorId,
  actualizarServicio,
  eliminarServicio,
  buscarServiciosCercanos,
  cambiarDisponibilidad
}; 