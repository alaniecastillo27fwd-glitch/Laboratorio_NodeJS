import crypto from 'node:crypto';
import argon2 from 'argon2';

const AES_ALGORITHM = 'aes-256-gcm';
const IV_LENGTH_BYTES = 12; // 96 bits recomendados por NIST SP 800-38D para AES-GCM
const AUTH_TAG_LENGTH_BYTES = 16; // 128 bits para verificación de integridad GMAC
const KEY_LENGTH_BYTES = 32; // 256 bits

/**
 * Obtiene y valida la llave maestra simétrica de 32 bytes desde variables de entorno.
 * Soporta ENCRYPTION_KEY o ENCRYPTION_KEY_V1 para rotación de llaves (Sección 4).
 */
const getMasterKey = () => {
  const rawKey = process.env.ENCRYPTION_KEY || process.env.ENCRYPTION_KEY_V1;
  if (!rawKey) {
    throw new Error('Configuración criptográfica incompleta: ENCRYPTION_KEY no está definida');
  }

  const keyBuffer = Buffer.from(rawKey, 'base64');
  if (keyBuffer.length !== KEY_LENGTH_BYTES) {
    throw new Error(
      `Longitud de ENCRYPTION_KEY inválida: se requieren exactamente ${KEY_LENGTH_BYTES} bytes (256 bits) codificados en Base64`
    );
  }

  return keyBuffer;
};

/**
 * Obtiene el secreto para firmas HMAC-SHA256.
 */
const getHmacSecret = () => {
  const secret = process.env.HMAC_SECRET || process.env.JWT_SECRET || process.env.ENCRYPTION_KEY;
  if (!secret) {
    throw new Error('Configuración criptográfica incompleta: secreto HMAC no definido');
  }
  return Buffer.from(secret, 'utf8');
};

/**
 * 1. HASH LENTO CON SAL PARA CONTRASEÑAS (Argon2id)
 * Parámetros obligatorios Sección 4: memoria >= 19 MiB (19456 KiB), iteraciones >= 2, paralelismo 1.
 */
export const hashPassword = async (plain) => {
  if (typeof plain !== 'string' || plain.length === 0) {
    throw new Error('La contraseña a hashear debe ser una cadena no vacía');
  }

  return argon2.hash(plain, {
    type: argon2.argon2id,
    memoryCost: 19456, // 19 MiB
    timeCost: 2,
    parallelism: 1,
  });
};

/**
 * Verifica una contraseña en texto plano contra un hash Argon2id almacenado.
 */
export const verifyPassword = async (hash, plain) => {
  if (typeof hash !== 'string' || typeof plain !== 'string' || !hash || !plain) {
    return false;
  }

  try {
    return await argon2.verify(hash, plain);
  } catch {
    return false;
  }
};

/**
 * 2. CIFRADO AUTENTICADO PARA NOTAS Y DATOS SENSIBLES (AES-256-GCM)
 * Genera un IV aleatorio único de 12 bytes por operación y concatena:
 * Buffer.concat([iv (12B), authTag (16B), encrypted]) codificado en Base64.
 */
export const encrypt = (plainText) => {
  if (typeof plainText !== 'string') {
    throw new Error('El valor a cifrar debe ser una cadena de texto');
  }

  const key = getMasterKey();
  const iv = crypto.randomBytes(IV_LENGTH_BYTES);
  const cipher = crypto.createCipheriv(AES_ALGORITHM, key, iv, {
    authTagLength: AUTH_TAG_LENGTH_BYTES,
  });

  const encrypted = Buffer.concat([cipher.update(plainText, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return Buffer.concat([iv, authTag, encrypted]).toString('base64');
};

/**
 * Descifra un payload en Base64 generado por encrypt().
 * Separa IV (12 bytes), Auth Tag (16 bytes) y ciphertext, y verifica la autenticidad
 * con setAuthTag(). Si cualquier bit fue alterado en la BD, lanza un error (Fail-Closed).
 */
export const decrypt = (payloadBase64) => {
  if (typeof payloadBase64 !== 'string' || payloadBase64.trim().length === 0) {
    throw new Error('Payload cifrado inválido o vacío');
  }

  const key = getMasterKey();
  const payload = Buffer.from(payloadBase64, 'base64');

  const minLength = IV_LENGTH_BYTES + AUTH_TAG_LENGTH_BYTES;
  if (payload.length < minLength) {
    const integrityError = new Error('Fallo de integridad criptográfica: payload truncado o corrupto');
    integrityError.code = 'CRYPTO_INTEGRITY_FAILURE';
    throw integrityError;
  }

  const iv = payload.subarray(0, IV_LENGTH_BYTES);
  const authTag = payload.subarray(IV_LENGTH_BYTES, IV_LENGTH_BYTES + AUTH_TAG_LENGTH_BYTES);
  const ciphertext = payload.subarray(IV_LENGTH_BYTES + AUTH_TAG_LENGTH_BYTES);

  try {
    const decipher = crypto.createDecipheriv(AES_ALGORITHM, key, iv, {
      authTagLength: AUTH_TAG_LENGTH_BYTES,
    });
    decipher.setAuthTag(authTag);

    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return decrypted.toString('utf8');
  } catch {
    const integrityError = new Error(
      'Fallo de integridad criptográfica: los datos cifrados fueron manipulados o la llave es inválida'
    );
    integrityError.code = 'CRYPTO_INTEGRITY_FAILURE';
    throw integrityError;
  }
};

/**
 * 3. TOKENS DE RECUPERACIÓN DE ALTA ENTROPÍA Y HASH RÁPIDO (SHA-256)
 * Genera 32 bytes aleatorios criptográficos (64 caracteres hexadecimales).
 */
export const generateResetToken = () => {
  return crypto.randomBytes(32).toString('hex');
};

/**
 * Calcula el hash SHA-256 en hexadecimal (CHAR(64)) de un token de recuperación
 * para almacenarlo en la base de datos sin guardar nunca el token original.
 */
export const hashToken = (token) => {
  if (typeof token !== 'string' || token.trim().length === 0) {
    throw new Error('Token inválido para hashear');
  }

  return crypto.createHash('sha256').update(token, 'utf8').digest('hex');
};

/**
 * 4. FIRMA E INTEGRIDAD DE DATOS (HMAC-SHA256)
 */
export const signData = (data) => {
  const payload = typeof data === 'string' ? data : JSON.stringify(data);
  const secret = getHmacSecret();
  return crypto.createHmac('sha256', secret).update(payload, 'utf8').digest('hex');
};

/**
 * Verifica una firma HMAC-SHA256 en tiempo constante (crypto.timingSafeEqual)
 * para prevenir ataques de canal lateral por temporización (Timing Attacks).
 */
export const verifySignature = (data, signature) => {
  if (typeof signature !== 'string' || !/^[a-fA-F0-9]{64}$/.test(signature)) {
    return false;
  }

  const expectedSignatureHex = signData(data);
  const expectedBuffer = Buffer.from(expectedSignatureHex, 'hex');
  const providedBuffer = Buffer.from(signature, 'hex');

  if (expectedBuffer.length !== providedBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(expectedBuffer, providedBuffer);
};

/**
 * 5. ENMASCARAMIENTO DE DATO SENSIBLE DE PERFIL (RF-05)
 * Muestra únicamente los últimos 4 caracteres con el formato ***-***-1234.
 */
export const maskSensitiveData = (value) => {
  if (typeof value !== 'string' || value.trim().length === 0) {
    return null;
  }

  const clean = value.trim();
  const lastFour = clean.slice(-4).padStart(4, '*');
  return `***-***-${lastFour}`;
};
