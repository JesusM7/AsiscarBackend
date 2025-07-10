// EJEMPLOS DE USO DE LA API DE SERVICIOS
// ===================================

/*
ESTRUCTURA DE UN SERVICIO:
{
  tipoServicio: "grua" | "mecanico",
  titulo: "Nombre del servicio",
  descripcion: "Descripción detallada",
  precio: 50000.00,
  nombreProveedor: "Juan Pérez",
  telefonoProveedor: "+573001234567",
  emailProveedor: "juan@email.com",
  cedulaProveedor: "12345678",
  latitud: 4.7110,
  longitud: -74.0721,
  direccion: "Calle 123 #45-67",
  ciudad: "Bogotá",
  cobertura: 15,
  fotoUrl: "https://ejemplo.com/foto.jpg",
  horarioInicio: "08:00",
  horarioFin: "18:00",
  diasDisponibles: "L,M,X,J,V,S"
}
*/

// EJEMPLO 1: CREAR SERVICIO DE GRÚA
const ejemploGrua = {
  tipoServicio: "grua",
  titulo: "Grúa 24 Horas - Servicio Express",
  descripcion: "Servicio de grúa disponible las 24 horas. Atendemos emergencias vehiculares, remolque de autos, motos y vehículos medianos. Personal especializado y equipos certificados.",
  precio: 80000,
  nombreProveedor: "Carlos Rodríguez",
  telefonoProveedor: "+573123456789",
  emailProveedor: "carlos.grua@email.com",
  cedulaProveedor: "80123456",
  latitud: 4.7110,
  longitud: -74.0721,
  direccion: "Carrera 15 #85-20, Zona Rosa",
  ciudad: "Bogotá",
  cobertura: 25,
  horarioInicio: "00:00",
  horarioFin: "23:59",
  diasDisponibles: "L,M,X,J,V,S,D"
};

// EJEMPLO 2: CREAR SERVICIO MECÁNICO
const ejemploMecanico = {
  tipoServicio: "mecanico",
  titulo: "Mecánica a Domicilio - Reparaciones Express",
  descripcion: "Servicio de mecánica a domicilio especializado en diagnóstico, cambio de aceite, reparación de frenos, mantenimiento preventivo y correctivo. Atención inmediata.",
  precio: 45000,
  nombreProveedor: "Ana García",
  telefonoProveedor: "+573198765432",
  emailProveedor: "ana.mecanica@email.com",
  cedulaProveedor: "53987654",
  latitud: 4.6482,
  longitud: -74.0776,
  direccion: "Calle 72 #10-50, Chapinero",
  ciudad: "Bogotá",
  cobertura: 20,
  horarioInicio: "07:00",
  horarioFin: "19:00",
  diasDisponibles: "L,M,X,J,V,S"
};

// LLAMADAS EJEMPLO CON cURL:

/*
1. CREAR SERVICIO:
curl -X POST http://localhost:3000/servicios \
  -H "Content-Type: application/json" \
  -d '{
    "tipoServicio": "grua",
    "titulo": "Grúa 24 Horas",
    "descripcion": "Servicio de grúa disponible 24/7",
    "precio": 80000,
    "nombreProveedor": "Carlos Rodríguez",
    "telefonoProveedor": "+573123456789",
    "emailProveedor": "carlos@email.com",
    "cedulaProveedor": "80123456",
    "latitud": 4.7110,
    "longitud": -74.0721,
    "direccion": "Carrera 15 #85-20",
    "ciudad": "Bogotá",
    "cobertura": 25
  }'

2. OBTENER TODOS LOS SERVICIOS:
curl http://localhost:3000/servicios

3. FILTRAR POR TIPO:
curl "http://localhost:3000/servicios?tipo=grua"

4. BUSCAR SERVICIOS CERCANOS:
curl "http://localhost:3000/servicios/cercanos?latitud=4.7110&longitud=-74.0721&tipo=grua&radioMaximo=30"

5. OBTENER SERVICIO POR ID:
curl http://localhost:3000/servicios/1

6. ACTUALIZAR SERVICIO:
curl -X PUT http://localhost:3000/servicios/1 \
  -H "Content-Type: application/json" \
  -d '{"precio": 85000, "disponible": true}'

7. CAMBIAR DISPONIBILIDAD:
curl -X PATCH http://localhost:3000/servicios/1/disponibilidad \
  -H "Content-Type: application/json" \
  -d '{"disponible": false}'

8. SUBIR IMAGEN:
curl -X POST http://localhost:3000/uploads/servicio \
  -F "foto=@/ruta/a/imagen.jpg"

9. ELIMINAR SERVICIO:
curl -X DELETE http://localhost:3000/servicios/1
*/

module.exports = {
  ejemploGrua,
  ejemploMecanico
}; 