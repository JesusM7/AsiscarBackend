const express = require('express');
const bcrypt = require('bcryptjs');
const { PrismaClient } = require('@prisma/client');
const { validateName, validateLastName, validateEmail, validatePhone } = require('../utils/validation');
const router = express.Router();



const prisma = new PrismaClient();

// Middleware para verificar autenticación y rol de admin
const verifyAdmin = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'Token de acceso requerido' });
    }

    const token = authHeader.substring(7);
    const jwt = require('jsonwebtoken');
    const SECRET = process.env.JWT_SECRET || 'secreto_super_seguro';
    
    const decoded = jwt.verify(token, SECRET);
    
    if (decoded.user_type !== 'admin') {
      return res.status(403).json({ message: 'Solo los administradores pueden acceder a esta función' });
    }

    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ message: 'Token inválido' });
  }
};

router.post('/register', async (req, res) => {
  const {
    email,
    username,
    last_name,
    phone,
    birth_date,
    user_type,
    password,
    confirm_password,
  } = req.body;

  try {
    // Validaciones de entrada
    if (password !== confirm_password) {
      return res.status(400).json({ message: 'Las contraseñas no coinciden' });
    }

    // Validar email
    const emailValidation = validateEmail(email);
    if (!emailValidation.isValid) {
      return res.status(400).json({ message: emailValidation.error });
    }

    // Validar nombre
    const nameValidation = validateName(username);
    if (!nameValidation.isValid) {
      return res.status(400).json({ message: nameValidation.error });
    }

    // Validar apellido (opcional)
    const lastNameValidation = validateLastName(last_name);
    if (!lastNameValidation.isValid) {
      return res.status(400).json({ message: lastNameValidation.error });
    }

    // Validar teléfono
    const phoneValidation = validatePhone(phone);
    if (!phoneValidation.isValid) {
      return res.status(400).json({ message: phoneValidation.error });
    }

    // Validar contraseña
    if (!password || password.length < 6) {
      return res.status(400).json({ message: 'La contraseña debe tener al menos 6 caracteres' });
    }

    // Validar tipo de usuario - ADMIN NO PERMITIDO EN REGISTRO PÚBLICO
    const validUserTypes = ['cliente', 'mecanico', 'grua'];
    if (!validUserTypes.includes(user_type)) {
      return res.status(400).json({ message: 'Tipo de usuario inválido' });
    }

    const existingUser = await prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      return res.status(400).json({ message: 'El correo ya está registrado' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const nuevoUsuario = await prisma.user.create({
      data: {
        email: email.trim().toLowerCase(),
        username: username.trim(),
        last_name: last_name ? last_name.trim() : null,
        phone: phone.replace(/\s/g, ''),
        birth_date: birth_date ? new Date(birth_date) : null,
        user_type,
        password: hashedPassword,
      },
    });

    return res.status(201).json({ message: 'Usuario registrado con éxito' });
  } catch (error) {
    console.error('Error al registrar:', error);
    return res.status(500).json({message: error.message || 'Error en el servidor' });
  }
});

// NUEVO ENDPOINT: Registro de administradores (solo para admins)
router.post('/register-admin', verifyAdmin, async (req, res) => {
  const {
    email,
    username,
    last_name,
    phone,
    birth_date,
    password,
    confirm_password,
  } = req.body;

  try {
    // Validaciones de entrada
    if (password !== confirm_password) {
      return res.status(400).json({ message: 'Las contraseñas no coinciden' });
    }

    // Validar email
    const emailValidation = validateEmail(email);
    if (!emailValidation.isValid) {
      return res.status(400).json({ message: emailValidation.error });
    }

    // Validar nombre
    const nameValidation = validateName(username);
    if (!nameValidation.isValid) {
      return res.status(400).json({ message: nameValidation.error });
    }

    // Validar apellido (opcional)
    const lastNameValidation = validateLastName(last_name);
    if (!lastNameValidation.isValid) {
      return res.status(400).json({ message: lastNameValidation.error });
    }

    // Validar teléfono
    const phoneValidation = validatePhone(phone);
    if (!phoneValidation.isValid) {
      return res.status(400).json({ message: phoneValidation.error });
    }

    // Validar contraseña
    if (!password || password.length < 6) {
      return res.status(400).json({ message: 'La contraseña debe tener al menos 6 caracteres' });
    }

    const existingUser = await prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      return res.status(400).json({ message: 'Ya existe un usuario con este correo electrónico' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const nuevoAdmin = await prisma.user.create({
      data: {
        email: email.trim().toLowerCase(),
        username: username.trim(),
        last_name: last_name ? last_name.trim() : null,
        phone: phone.replace(/\s/g, ''),
        birth_date: birth_date ? new Date(birth_date) : null,
        user_type: 'admin',
        password: hashedPassword,
      },
    });

    return res.status(201).json({ 
      message: 'Administrador registrado con éxito',
      admin: {
        id: nuevoAdmin.id,
        email: nuevoAdmin.email,
        username: nuevoAdmin.username,
        last_name: nuevoAdmin.last_name,
        createdAt: nuevoAdmin.createdAt
      }
    });
  } catch (error) {
    console.error('Error al registrar administrador:', error);
    return res.status(500).json({message: error.message || 'Error en el servidor' });
  }
});

// NUEVO ENDPOINT: Obtener lista de administradores (solo para admins)
router.get('/admins', verifyAdmin, async (req, res) => {
  try {
    const admins = await prisma.user.findMany({
      where: { user_type: 'admin' },
      select: {
        id: true,
        email: true,
        username: true,
        last_name: true,
        phone: true,
        createdAt: true
      },
      orderBy: { createdAt: 'desc' }
    });

    return res.status(200).json({ 
      admins,
      total: admins.length 
    });
  } catch (error) {
    console.error('Error al obtener administradores:', error);
    return res.status(500).json({ message: 'Error en el servidor' });
  }
});

const jwt = require('jsonwebtoken');
const SECRET = process.env.JWT_SECRET || 'secreto_super_seguro';

router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
      return res.status(400).json({ message: 'Usuario no encontrado' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ message: 'Contraseña incorrecta' });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, user_type: user.user_type, username: user.username },
      SECRET,
      { expiresIn: '3h' }
    );

    return res.status(200).json({
      message: 'Login exitoso',
      token,
      user_type: user.user_type,
    });
  } catch (error) {
    console.error('Error al iniciar sesión:', error);
    return res.status(500).json({ message: 'Error en el servidor' });
  }
});


module.exports = router;