const { uploadSingle, getImageUrl, deleteFile } = require('../utils/imageUpload');
const path = require('path');

// Subir imagen de servicio
const subirImagenServicio = (req, res) => {
  uploadSingle(req, res, function (err) {
    if (err) {
      console.error('Error al subir imagen:', err);
      
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({ 
          error: 'El archivo es demasiado grande. Máximo 5MB permitido.' 
        });
      }
      
      return res.status(400).json({ 
        error: err.message || 'Error al subir la imagen' 
      });
    }

    if (!req.file) {
      return res.status(400).json({ 
        error: 'No se seleccionó ningún archivo' 
      });
    }

    // Generar URL de la imagen
    const imageUrl = getImageUrl(req, req.file.filename);

    res.json({
      mensaje: 'Imagen subida exitosamente',
      archivo: {
        filename: req.file.filename,
        originalName: req.file.originalname,
        size: req.file.size,
        url: imageUrl
      }
    });
  });
};

// Eliminar imagen de servicio
const eliminarImagenServicio = (req, res) => {
  const { filename } = req.params;

  if (!filename) {
    return res.status(400).json({ 
      error: 'Nombre de archivo requerido' 
    });
  }

  const filePath = path.join(__dirname, '../uploads', filename);
  const deleted = deleteFile(filePath);

  if (deleted) {
    res.json({ 
      mensaje: 'Imagen eliminada exitosamente',
      filename: filename 
    });
  } else {
    res.status(404).json({ 
      error: 'Archivo no encontrado o ya eliminado' 
    });
  }
};

module.exports = {
  subirImagenServicio,
  eliminarImagenServicio
}; 