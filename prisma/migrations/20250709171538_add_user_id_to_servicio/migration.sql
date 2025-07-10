-- CreateTable
CREATE TABLE "servicios" (
    "id" SERIAL NOT NULL,
    "userId" INTEGER NOT NULL,
    "tipoServicio" TEXT NOT NULL,
    "titulo" TEXT NOT NULL,
    "descripcion" TEXT NOT NULL,
    "precio" DOUBLE PRECISION NOT NULL,
    "nombreProveedor" TEXT NOT NULL,
    "telefonoProveedor" TEXT NOT NULL,
    "emailProveedor" TEXT NOT NULL,
    "cedulaProveedor" TEXT NOT NULL,
    "latitud" DOUBLE PRECISION NOT NULL,
    "longitud" DOUBLE PRECISION NOT NULL,
    "direccion" TEXT NOT NULL,
    "ciudad" TEXT NOT NULL,
    "cobertura" DOUBLE PRECISION NOT NULL,
    "fotoUrl" TEXT,
    "disponible" BOOLEAN NOT NULL DEFAULT true,
    "verificado" BOOLEAN NOT NULL DEFAULT false,
    "activo" BOOLEAN NOT NULL DEFAULT true,
    "horarioInicio" TEXT,
    "horarioFin" TEXT,
    "diasDisponibles" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "servicios_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "servicios_emailProveedor_key" ON "servicios"("emailProveedor");

-- CreateIndex
CREATE UNIQUE INDEX "servicios_cedulaProveedor_key" ON "servicios"("cedulaProveedor");

-- AddForeignKey
ALTER TABLE "servicios" ADD CONSTRAINT "servicios_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
