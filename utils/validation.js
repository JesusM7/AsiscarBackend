// Utilidades de validación para el backend

/**
 * Valida que un nombre sea válido
 * @param {string} name - Nombre a validar
 * @returns {object} - { isValid: boolean, error: string|null }
 */
const validateName = (name) => {
  if (!name || typeof name !== 'string') {
    return { isValid: false, error: 'El nombre es obligatorio' };
  }

  const trimmed = name.trim();
  
  // Verificar longitud
  if (trimmed.length < 2) {
    return { isValid: false, error: 'El nombre debe tener al menos 2 caracteres' };
  }
  
  if (trimmed.length > 30) {
    return { isValid: false, error: 'El nombre no puede tener más de 30 caracteres' };
  }

  // Permitir solo letras, espacios, acentos y algunos caracteres especiales latinos
  const nameRegex = /^[a-zA-ZáéíóúÁÉÍÓÚñÑüÜ\s'-]+$/;
  if (!nameRegex.test(trimmed)) {
    return { isValid: false, error: 'El nombre solo puede contener letras, espacios y acentos' };
  }

  // Verificar caracteres repetidos (más de 3 seguidos)
  if (/(.)\1{3,}/.test(trimmed)) {
    return { isValid: false, error: 'El nombre no puede tener más de 3 caracteres iguales seguidos' };
  }

  // Verificar que no sea solo un carácter repetido
  if (/^(.)\1+$/.test(trimmed)) {
    return { isValid: false, error: 'El nombre no puede ser solo un carácter repetido' };
  }

  // Verificar que no sean solo números
  if (/^\d+$/.test(trimmed)) {
    return { isValid: false, error: 'El nombre no puede ser solo números' };
  }

  return { isValid: true, error: null };
};

/**
 * Valida que un apellido sea válido
 * @param {string} lastName - Apellido a validar
 * @returns {object} - { isValid: boolean, error: string|null }
 */
const validateLastName = (lastName) => {
  // Apellido puede ser opcional
  if (!lastName) {
    return { isValid: true, error: null };
  }

  if (typeof lastName !== 'string') {
    return { isValid: false, error: 'El apellido debe ser texto' };
  }

  const trimmed = lastName.trim();
  
  // Si está vacío después del trim, es válido (opcional)
  if (trimmed.length === 0) {
    return { isValid: true, error: null };
  }

  // Verificar longitud
  if (trimmed.length < 2) {
    return { isValid: false, error: 'El apellido debe tener al menos 2 caracteres' };
  }
  
  if (trimmed.length > 40) {
    return { isValid: false, error: 'El apellido no puede tener más de 40 caracteres' };
  }

  // Mismas reglas que el nombre
  const nameRegex = /^[a-zA-ZáéíóúÁÉÍÓÚñÑüÜ\s'-]+$/;
  if (!nameRegex.test(trimmed)) {
    return { isValid: false, error: 'El apellido solo puede contener letras, espacios y acentos' };
  }

  if (/(.)\1{3,}/.test(trimmed)) {
    return { isValid: false, error: 'El apellido no puede tener más de 3 caracteres iguales seguidos' };
  }

  if (/^(.)\1+$/.test(trimmed)) {
    return { isValid: false, error: 'El apellido no puede ser solo un carácter repetido' };
  }

  if (/^\d+$/.test(trimmed)) {
    return { isValid: false, error: 'El apellido no puede ser solo números' };
  }

  return { isValid: true, error: null };
};

/**
 * Valida nombre completo del proveedor (nombre y apellido)
 * @param {string} fullName - Nombre completo a validar
 * @returns {object} - { isValid: boolean, error: string|null }
 */
const validateProviderName = (fullName) => {
  if (!fullName || typeof fullName !== 'string') {
    return { isValid: false, error: 'El nombre del proveedor es obligatorio' };
  }

  const trimmed = fullName.trim();
  
  if (trimmed.length < 3) {
    return { isValid: false, error: 'El nombre debe tener al menos 3 caracteres' };
  }
  
  if (trimmed.length > 60) {
    return { isValid: false, error: 'El nombre no puede tener más de 60 caracteres' };
  }

  const nameRegex = /^[a-zA-ZáéíóúÁÉÍÓÚñÑüÜ\s'-]+$/;
  if (!nameRegex.test(trimmed)) {
    return { isValid: false, error: 'Solo se permiten letras, espacios y acentos' };
  }

  // Debe tener al menos 2 palabras (nombre y apellido)
  const words = trimmed.split(/\s+/).filter(word => word.length > 0);
  if (words.length < 2) {
    return { isValid: false, error: 'Debe incluir nombre y apellido completos' };
  }

  // Cada palabra debe tener al menos 2 caracteres
  for (const word of words) {
    if (word.length < 2) {
      return { isValid: false, error: 'Cada nombre/apellido debe tener al menos 2 caracteres' };
    }
  }

  if (/(.)\1{3,}/.test(trimmed)) {
    return { isValid: false, error: 'No puede tener más de 3 caracteres iguales seguidos' };
  }

  if (/^\d+$/.test(trimmed)) {
    return { isValid: false, error: 'No puede ser solo números' };
  }

  return { isValid: true, error: null };
};

/**
 * Valida email
 * @param {string} email - Email a validar
 * @returns {object} - { isValid: boolean, error: string|null }
 */
const validateEmail = (email) => {
  if (!email || typeof email !== 'string') {
    return { isValid: false, error: 'El email es obligatorio' };
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return { isValid: false, error: 'Formato de email inválido' };
  }

  if (email.length > 254) {
    return { isValid: false, error: 'El email es demasiado largo' };
  }

  return { isValid: true, error: null };
};

/**
 * Valida teléfono venezolano
 * @param {string} phone - Teléfono a validar
 * @returns {object} - { isValid: boolean, error: string|null }
 */
const validatePhone = (phone) => {
  if (!phone || typeof phone !== 'string') {
    return { isValid: false, error: 'El teléfono es obligatorio' };
  }

  const cleaned = phone.replace(/\s/g, '');
  const phoneRegex = /^[0-9]{11}$/;
  
  if (!phoneRegex.test(cleaned)) {
    return { isValid: false, error: 'El teléfono debe tener 11 dígitos' };
  }

  return { isValid: true, error: null };
};

module.exports = {
  validateName,
  validateLastName,
  validateProviderName,
  validateEmail,
  validatePhone
}; 