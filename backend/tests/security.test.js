import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  hashPassword,
  verifyPassword,
  encrypt,
  decrypt,
  generateResetToken,
  hashToken,
  signData,
  verifySignature,
  maskSensitiveData,
} from '../src/utils/crypto.js';
import app from '../src/app.js';

describe('Suite de Pruebas de Seguridad — SecureVault (OWASP Top 10:2025)', () => {
  before(() => {
    // Configurar llaves efímeras en memoria para la ejecución aislada de pruebas en CI/CD
    if (!process.env.ENCRYPTION_KEY) {
      process.env.ENCRYPTION_KEY = crypto.randomBytes(32).toString('base64');
    }
    if (!process.env.JWT_SECRET) {
      process.env.JWT_SECRET = crypto.randomBytes(64).toString('hex');
    }
  });

  test('1. Argon2id: hashPassword genera hash $argon2id$ y verifyPassword valida correctamente (OWASP A04)', async () => {
    const plain = 'PasswordUltraSegura2025!';
    const hash = await hashPassword(plain);

    assert.ok(
      hash.startsWith('$argon2id$'),
      `El hash debe comenzar con $argon2id$, recibido: ${hash.slice(0, 15)}`
    );
    assert.ok(
      hash.includes('m=19456,t=2,p=1'),
      'El hash Argon2id debe aplicar memoryCost=19456 (19 MiB), timeCost=2, parallelism=1'
    );

    const isValid = await verifyPassword(hash, plain);
    assert.equal(isValid, true, 'verifyPassword debe devolver true para la contraseña correcta');

    const isInvalid = await verifyPassword(hash, 'PasswordIncorrecta123!');
    assert.equal(isInvalid, false, 'verifyPassword debe devolver false para contraseña incorrecta');
  });

  test('2. AES-256-GCM: encrypt produce ciphertexts distintos (IV aleatorio único de 12B) y decrypt recupera el texto original (OWASP A04)', () => {
    const secretNote = 'Nota confidencial de SecureVault con datos sensibles';

    const ciphertext1 = encrypt(secretNote);
    const ciphertext2 = encrypt(secretNote);

    assert.notEqual(
      ciphertext1,
      ciphertext2,
      'Dos cifrados del mismo texto plano deben ser distintos gracias al IV aleatorio de 12 bytes'
    );

    assert.equal(decrypt(ciphertext1), secretNote);
    assert.equal(decrypt(ciphertext2), secretNote);
  });

  test('3. AES-256-GCM: decrypt falla de forma segura (Fail-Closed) si se altera 1 solo byte del payload en la BD (Integridad GMAC 16B - OWASP A04/A08)', () => {
    const secretNote = 'Contenido protegido por etiqueta de autenticación GCM de 16 bytes';
    const payloadBase64 = encrypt(secretNote);

    const rawBuffer = Buffer.from(payloadBase64, 'base64');
    // Alterar 1 bit en el último byte (ciphertext) o en el AuthTag
    rawBuffer[rawBuffer.length - 1] ^= 0xff;
    const tamperedBase64 = rawBuffer.toString('base64');

    assert.throws(
      () => decrypt(tamperedBase64),
      (err) => err.code === 'CRYPTO_INTEGRITY_FAILURE',
      'decrypt debe lanzar CRYPTO_INTEGRITY_FAILURE cuando el ciphertext o AuthTag es manipulado'
    );
  });

  test('4. Tokens de recuperación (RF-06), HMAC-SHA256 y enmascaramiento (RF-05)', () => {
    const rawToken = generateResetToken();
    assert.match(rawToken, /^[a-f0-9]{64}$/, 'El token debe tener 32 bytes (64 chars hex)');

    const tokenHash = hashToken(rawToken);
    assert.match(tokenHash, /^[a-f0-9]{64}$/, 'El hash SHA-256 debe tener 64 chars hex');
    assert.notEqual(rawToken, tokenHash, 'El hash SHA-256 no debe ser igual al token en claro');

    const data = { userId: '123', action: 'test' };
    const sig = signData(data);
    assert.equal(verifySignature(data, sig), true);
    assert.equal(verifySignature({ userId: '123', action: 'tampered' }, sig), false);

    assert.equal(maskSensitiveData('506-8888-1234'), '***-***-1234');
  });

  test('5. Endpoint HTTP y Cabeceras de Seguridad: sin X-Powered-By y con Helmet CSP + HSTS (OWASP A02 / RF-08)', async () => {
    const server = app.listen(0);
    try {
      const { port } = server.address();
      const response = await fetch(`http://127.0.0.1:${port}/health`);

      // En CI sin BD local activa puede responder 200 (con BD) o 503 (sin BD), pero nunca exponer X-Powered-By ni versiones
      assert.ok(
        response.status === 200 || response.status === 503,
        `Código inesperado en /health: ${response.status}`
      );

      assert.equal(
        response.headers.get('x-powered-by'),
        null,
        'La cabecera X-Powered-By debe estar desactivada'
      );

      const csp = response.headers.get('content-security-policy');
      assert.ok(csp && csp.includes("default-src 'self'"), 'Debe incluir Content-Security-Policy');
      assert.ok(!csp.includes('unsafe-inline'), 'CSP no debe permitir unsafe-inline');

      const hsts = response.headers.get('strict-transport-security');
      assert.ok(hsts && hsts.includes('max-age=31536000'), 'Debe incluir cabecera HSTS');

      assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
      assert.equal(response.headers.get('x-frame-options'), 'DENY');

      const body = await response.json();
      assert.ok(
        body.status === 'ok' || body.status === 'error',
        'El cuerpo de /health solo debe devolver { status } sin revelar versiones ni datos internos'
      );
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });
});
