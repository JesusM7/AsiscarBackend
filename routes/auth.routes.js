const express = require('express');
const bcrypt = require('bcryptjs');
const { PrismaClient } = require('@prisma/client');
const { validateName, validateLastName, validateEmail, validatePhone } = require('../utils/validation');
const router = express.Router();
const nodemailer = require('nodemailer');
const crypto = require('crypto');
require('dotenv').config();

const frontendURL = process.env.FRONTEND_URL;
const backendURL = process.env.BACKEND_URL;



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

    // Generar token de verificación (opcional, si se implementa verificación por email)

    const tokenVerificacion = crypto.randomBytes(32).toString('hex');

    const nuevoUsuario = await prisma.user.create({
      data: {
        email: email.trim().toLowerCase(),
        username: username.trim(),
        last_name: last_name ? last_name.trim() : null,
        phone: phone.replace(/\s/g, ''),
        birth_date: birth_date ? new Date(birth_date) : null,
        user_type,
        password: hashedPassword,
        isVerified: false, // Por defecto, el usuario no está verificado
        verificationToken: tokenVerificacion, // Guardar el token de verificación
      },
    });

    const transporter = nodemailer.createTransport({
      service: 'gmail', // o tu proveedor SMTP
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    // const urlVerificacion = `${frontendURL}/${tokenVerificacion}`;
    const urlVerificacion = `${backendURL}/api/verificar/${tokenVerificacion}`;

    await transporter.sendMail({
      to: email,
      subject: 'Verifica tu cuenta',
      html: `<p>¡Hola ${username}! 👋</p>

            <p>Gracias por registrarte en <strong>Asiscar</strong>, tu aliado confiable en servicios de grúa, asistencia mecánica y soluciones viales en los momentos más críticos. Estamos comprometidos con brindarte atención segura, rápida y personalizada para que nunca te quedes varado sin apoyo.</p>

            <p>Para comenzar a disfrutar de todos nuestros servicios, necesitamos que verifiques tu cuenta. Esto nos permite proteger tu información y garantizar una experiencia más segura para todos nuestros usuarios.</p>

            <p>Haz clic en el siguiente enlace para confirmar tu correo electrónico y activar tu cuenta:</p>

            <p><a href="${urlVerificacion}" style="color: #0057D8; font-weight: bold;">✅ Verificar mi cuenta</a></p>

            <p>Este enlace estará disponible durante un tiempo limitado, así que te recomendamos verificar lo antes posible.</p>

            <p>Una vez que tu cuenta esté activa, podrás solicitar grúas, contactar mecánicos cercanos y recibir asistencia técnica desde cualquier lugar, todo desde nuestra plataforma.</p>

            <p>Si no solicitaste este registro, puedes ignorar este mensaje. Si tienes dudas o necesitas soporte adicional, nuestro equipo está disponible para ayudarte en <a href="mailto:soporte@asiscar.com">soporte@asiscar.com</a>.</p>

            <p>Gracias por confiar en <strong>Asiscar</strong> — estamos aquí para ti, siempre que lo necesites. 🚗🛠️</p>

            <p>El equipo de Asiscar</p>`,
});

    return res.status(201).json({ message: 'Usuario registrado con éxito' });
  } catch (error) {
    console.error('Error al registrar:', error);
    return res.status(500).json({message: error.message || 'Error en el servidor' });
  }
});

router.get('/verificar/:token', async (req, res) => {
  const { token } = req.params;

  const user = await prisma.user.findUnique({
    where: { verificationToken: token },
  });

  if (!user) return res.status(400).send('Token inválido');

  await prisma.user.update({
    where: { id: user.id },
    data: {
      isVerified: true,
      verificationToken: null,
    },
  });

  res.redirect(`${frontendURL}/cuenta-verificada`);
  // Redirigir a una página de éxito en el frontend

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

    if (!user.isVerified) {
      return res.status(403).json({ message: 'Tu cuenta no está verificada. Revisa tu correo electrónico.' });
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

// Reenviar enlace de verificación

router.post('/resend-verification', async (req, res) => {
  const { email } = req.body;

  try {
    const user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
      return res.status(404).json({ message: 'No se encontró ningún usuario con ese correo' });
    }

    if (user.isVerified) {
      return res.status(400).json({ message: 'Tu cuenta ya está verificada' });
    }

    const nuevoToken = crypto.randomBytes(32).toString('hex');

    await prisma.user.update({
      where: { id: user.id },
      data: { verificationToken: nuevoToken },
    });

    const urlVerificacion = `${frontendURL}/api/verificar/${nuevoToken}`;

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    await transporter.sendMail({
      to: email,
      subject: 'Nuevo enlace de verificación',
      html: `Hola ${user.username},<br><br>
            <p>Haz clic en el siguiente botón para confirmar tu correo electrónico y completar el proceso:</p>

            <p><a href="${urlVerificacion}" style="background-color: #D32F2F; color: white; padding: 12px 20px; border-radius: 6px; text-decoration: none; font-weight: bold;">✅ Verificar cuenta</a></p>

            <p>Este enlace estará disponible por tiempo limitado. Verificar tu cuenta te permite solicitar asistencia mecánica, pedir grúas y acceder a todos nuestros servicios desde la plataforma de Asiscar.</p>

            <p>¿No solicitaste esta verificación? Puedes ignorar este mensaje. Si necesitas ayuda, estamos para ti en <a href="mailto:soporte@asiscar.com">soporte@asiscar.com</a>.</p>

            <p>Gracias por confiar en Asiscar. Estamos contigo en cada kilómetro 🚗🛠️</p>

            <p>— El equipo de Asiscar</p>`,
    });

    res.json({ message: 'Se ha enviado un nuevo enlace de verificación a tu correo' });
  } catch (error) {
    console.error('Error reenviando verificación:', error);
    res.status(500).json({ message: 'Error al reenviar el enlace de verificación' });
  }
});


module.exports = router;