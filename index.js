const express = require("express");
const cors = require("cors");
const { PrismaClient } = require("@prisma/client");
const path = require("path");

require('dotenv').config();

const app = express();
const prisma = new PrismaClient();

const authRoutes = require('./routes/auth.routes');

app.use(cors());
app.use(express.json());

// Middleware para servir archivos estáticos (imágenes)
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Rutas existentes
app.use('/api', authRoutes);

const solicitudRoutes = require('./routes/solicitudes');
app.use('/solicitudes', solicitudRoutes);

const proveedorRoutes = require('./routes/proveedores');
app.use('/proveedores', proveedorRoutes);

// Nuevas rutas para servicios
const servicioRoutes = require('./routes/servicios');
app.use('/servicios', servicioRoutes);

const uploadRoutes = require('./routes/uploads');
app.use('/uploads', uploadRoutes);

app.listen(3000, () => {
  console.log('Servidor corriendo en puerto 3000');
});






