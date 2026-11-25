# Fase 4: Guion Ejecutable de Verificación y Pruebas Éticas de Seguridad (Pentesting Propio)

> **Nota Ética Obligatoria (Sección 11):** Todos los comandos de este documento se ejecutan **exclusivamente contra la instancia propia de SecureVault** desplegada por el estudiante. Está estrictamente prohibido ejecutar estas pruebas contra sistemas de terceros o de otros equipos.

---

## 0. Preparación de Variables en Terminal (Sin exponer credenciales en comandos)

Define en tu sesión de terminal la URL pública de tu backend en Render y las contraseñas de prueba en variables locales (nunca las escribas directamente en scripts versionados):

### En Bash / Git Bash / WSL:
```bash
export API_URL="https://TU-BACKEND.onrender.com"
export USER_A_EMAIL="usuarioA@securevault.test"
export USER_A_PASS="<TU_PASSWORD_USUARIO_A>"
export USER_B_EMAIL="usuarioB@securevault.test"
export USER_B_PASS="<TU_PASSWORD_USUARIO_B>"
```

### En Windows PowerShell:
```powershell
$env:API_URL = "https://TU-BACKEND.onrender.com"
$env:USER_A_EMAIL = "usuarioA@securevault.test"
$env:USER_A_PASS = "<TU_PASSWORD_USUARIO_A>"
$env:USER_B_EMAIL = "usuarioB@securevault.test"
$env:USER_B_PASS = "<TU_PASSWORD_USUARIO_B>"
```

---

## 1. Prueba A01:2025 (Broken Access Control — Prevención de IDOR)

**Objetivo:** Demostrar que el **Usuario A** autenticado no puede leer (`GET`), editar (`PUT`) ni eliminar (`DELETE`) una nota privada cuyo `UUID` pertenece al **Usuario B**, recibiendo `HTTP 404` y dejando rastro forense `ACCESS_DENIED` en `audit_logs`.

```bash
# Paso 1.1: Iniciar sesión como Usuario B y guardar su cookie HttpOnly en cookies_userB.txt
curl -i -s -c cookies_userB.txt -X POST "$API_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$USER_B_EMAIL\",\"password\":\"$USER_B_PASS\"}"

# Paso 1.2: Usuario B crea una nota privada cifrada (copia el UUID "id" devuelto en el JSON)
curl -i -s -b cookies_userB.txt -X POST "$API_URL/api/notes" \
  -H "Content-Type: application/json" \
  -d '{"title":"Secreto de Usuario B","content":"Credenciales bancarias privadas de B"}'

# Exporta el UUID de la nota recién creada por el Usuario B:
export NOTE_B_ID="<PEGA_AQUI_EL_UUID_DE_LA_NOTA_DE_B>"

# Paso 1.3: Iniciar sesión como Usuario A y guardar su cookie HttpOnly en cookies_userA.txt
curl -i -s -c cookies_userA.txt -X POST "$API_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$USER_A_EMAIL\",\"password\":\"$USER_A_PASS\"}"

# Paso 1.4 (ATAQUE IDOR - LECTURA): Usuario A intenta leer la nota del Usuario B
curl -i -s -b cookies_userA.txt -X GET "$API_URL/api/notes/$NOTE_B_ID"

# Paso 1.5 (ATAQUE IDOR - EDICIÓN): Usuario A intenta modificar la nota del Usuario B
curl -i -s -b cookies_userA.txt -X PUT "$API_URL/api/notes/$NOTE_B_ID" \
  -H "Content-Type: application/json" \
  -d '{"title":"Nota saboteada por A","content":"Intento de sobrescritura IDOR"}'

# Paso 1.6 (ATAQUE IDOR - BORRADO): Usuario A intenta eliminar la nota del Usuario B
curl -i -s -b cookies_userA.txt -X DELETE "$API_URL/api/notes/$NOTE_B_ID"
```

* **Evidencia esperada (Captura para el informe):**
  * Respuesta HTTP en los tres intentos (1.4, 1.5 y 1.6):
    ```http
    HTTP/2 404
    content-type: application/json; charset=utf-8

    {"error":"Nota no encontrada"}
    ```
  * En la tabla `audit_logs` (y en el panel `/admin`) aparecen registrados los 3 eventos `ACCESS_DENIED` con el `user_id` del Usuario A y `targetNoteId: NOTE_B_ID`.

---

## 2. Prueba A05:2025 (Injection — SQL Injection y Cross-Site Scripting XSS)

### 2.1. Intento de SQL Injection (`' OR 1=1 --`) en Login y en Parámetro UUID
```bash
# Ataque SQLi 1: Payload clásico de evasión de autenticación en el campo email
curl -i -s -X POST "$API_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"'\'' OR 1=1 --","password":"cualquier_password"}'

# Ataque SQLi 2: Payload SQLi con formato de correo válido para pasar a la consulta parametrizada ($1)
curl -i -s -X POST "$API_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin'\''--@securevault.test","password":"PasswordFuerte123!"}'

# Ataque SQLi 3: Inyección SQL en el parámetro de ruta :id de notas
curl -i -s -b cookies_userA.txt -X GET "$API_URL/api/notes/1'%20OR%20'1'='1"
```

* **Evidencia esperada:**
  * El **Ataque SQLi 1 y 2** responden `HTTP/2 401` `{"error":"Credenciales inválidas"}` (rechazado por el esquema **Zod** y neutralizado como literal inofensivo por el parámetro `$1` de `pg`).
  * El **Ataque SQLi 3** responde `HTTP/2 400` `{"error":"Identificador de nota inválido"}` antes siquiera de tocar la base de datos.

### 2.2. Intento de Cross-Site Scripting (XSS) en Creación de Nota y Dato Sensible
```bash
# Ataque XSS 1: Inyectar etiqueta <script> en el dato sensible de perfil (rechazado por regex de Zod)
curl -i -s -b cookies_userA.txt -X PUT "$API_URL/api/profile/sensitive" \
  -H "Content-Type: application/json" \
  -d '{"sensitiveData":"<script>alert(1)</script>"}'

# Ataque XSS 2: Crear nota con payload <script>alert(1)</script> en el título
curl -i -s -b cookies_userA.txt -X POST "$API_URL/api/notes" \
  -H "Content-Type: application/json" \
  -d '{"title":"<script>alert(1)</script>","content":"Prueba XSS neutralizada por React y CSP"}'
```

* **Evidencia esperada:**
  * **Ataque XSS 1:** Responde `HTTP/2 400 Bad Request` (`"Dato sensible inválido"`).
  * **Ataque XSS 2:** En el frontend React (que escapa automáticamente el DOM y no utiliza `dangerouslySetInnerHTML`), el título se renderiza literalmente como texto plano `<script>alert(1)</script>` sin ejecutarse, y la cabecera `Content-Security-Policy: default-src 'self'; script-src 'self'` bloquea cualquier ejecución de scripts inline.

---

## 3. Prueba A07:2025 (Authentication Failures — Bloqueo de Fuerza Bruta HTTP 429)

**Objetivo:** Enviar 6 intentos fallidos de inicio de sesión consecutivos para demostrar que los primeros intentos devuelven `HTTP 401` y, a partir del límite configurado (5 intentos), el servidor bloquea la ráfaga con **`HTTP 429 Too Many Requests`** y emite la alerta `BRUTE_FORCE_DETECTED` (OWASP A09).

### Opción A — Bucle en Bash / Git Bash:
```bash
for i in {1..6}; do
  echo "=== Intento de Fuerza Bruta #$i ==="
  curl -i -s -X POST "$API_URL/api/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$USER_A_EMAIL\",\"password\":\"ClaveIncorrecta_$i!\"}" | head -n 15
  echo ""
done
```

### Opción B — Bucle en Windows PowerShell:
```powershell
1..6 | ForEach-Object {
  Write-Host "=== Intento de Fuerza Bruta #$_ ==="
  curl.exe -i -s -X POST "$env:API_URL/api/auth/login" `
    -H "Content-Type: application/json" `
    -d "{`"email`":`"$env:USER_A_EMAIL`",`"password`":`"ClaveIncorrecta_$_!`"}"
  Write-Host "`n"
}
```

* **Evidencia esperada (Captura para el informe):**
  * Intentos 1 al 4/5: `HTTP/2 401` `{"error":"Credenciales inválidas"}`.
  * Intento 5/6:
    ```http
    HTTP/2 429
    ratelimit-limit: 5
    ratelimit-remaining: 0
    retry-after: 900
    content-type: application/json; charset=utf-8

    {"error":"Demasiados intentos de inicio de sesión. Por favor, intente nuevamente en 15 minutos."}
    ```
  * En los logs de Render (`winston`) aparece el JSON estructurado con `"alert":"BRUTE_FORCE_DETECTED"` y en `audit_logs` el evento `ACCOUNT_LOCKED` / `LOGIN_FAILED`.

---

## 4. Prueba A10:2025 (Mishandling of Exceptional Conditions — Fail-Closed sin Stack Traces)

**Objetivo:** Forzar condiciones excepcionales en el servidor (JSON corrupto y payload superior al límite de `10kb`) para verificar que el manejador global (`errorHandler.js`) responde con un mensaje genérico sin filtrar *stack traces*, rutas de archivos internos ni versiones, registrando el detalle únicamente en `winston`.

```bash
# Prueba 4.1: Enviar un cuerpo JSON sintácticamente corrupto/truncado
curl -i -s -X POST "$API_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email": "roto@securevault.test", "password": '

# Prueba 4.2: Enviar un payload que excede el límite estricto de 10 KB (OWASP A06 / A10)
node -e "console.log(JSON.stringify({title:'DoS', content:'A'.repeat(15000)}))" | \
  curl -i -s -b cookies_userA.txt -X POST "$API_URL/api/notes" \
  -H "Content-Type: application/json" \
  -d @-
```

* **Evidencia esperada:**
  * **Prueba 4.1:** `HTTP/2 400` con cuerpo exacto `{"error":"Formato JSON inválido"}` (cero líneas de `SyntaxError: Unexpected end of JSON input at JSON.parse...`).
  * **Prueba 4.2:** `HTTP/2 413` con cuerpo exacto `{"error":"El tamaño de la solicitud excede el límite permitido"}` y registro `PAYLOAD_TOO_LARGE` en el log interno JSON de Render.

---

## 5. Verificación de Criptografía en Base de Datos (OWASP A04:2025 — SQL en Supabase)

Abre el **SQL Editor** en tu proyecto de **Supabase** y ejecuta esta consulta de **solo lectura** (`SELECT`) para tomar la captura de pantalla exigida en la página 3 de la guía (*"Captura de la BD mostrando datos cifrados y hashes"*):

```sql
-- 1. Evidencia de Hashes Argon2id ($argon2id$v=19$m=19456,t=2,p=1$...) y Dato Sensible Cifrado (AES-256-GCM Base64)
SELECT
    id,
    email,
    role,
    LEFT(password_hash, 48) || '...' AS argon2id_password_hash_sample,
    LEFT(sensitive_data_enc, 44) || '...' AS aes256gcm_sensitive_data_sample,
    key_version,
    created_at
FROM users
ORDER BY created_at DESC
LIMIT 5;

-- 2. Evidencia de Notas Privadas Cifradas con AES-256-GCM (IV 12B + AuthTag 16B + Ciphertext en Base64)
SELECT
    id,
    owner_id,
    title,
    LEFT(content_enc, 60) || '...' AS aes256gcm_note_ciphertext_sample,
    octet_length(decode(content_enc, 'base64')) AS raw_bytes_len,
    key_version,
    created_at
FROM notes
ORDER BY created_at DESC
LIMIT 5;

-- 3. Evidencia de Tokens de Recuperación Hasheados con SHA-256 (CHAR(64) hexadecimal)
SELECT
    id,
    user_id,
    token_hash AS sha256_token_hash,
    expires_at,
    used
FROM password_reset_tokens
ORDER BY created_at DESC
LIMIT 5;
```

* **Qué demuestra esta captura:**
  1. `argon2id_password_hash_sample` comienza estrictamente con `$argon2id$v=19$m=19456,t=2,p=1$...` (confirmando memoria de 19 MiB, 2 iteraciones y sal aleatoria única).
  2. `aes256gcm_note_ciphertext_sample` y `aes256gcm_sensitive_data_sample` son cadenas Base64 completamente ilegibles cuyo tamaño en bytes (`raw_bytes_len`) es `>= 29 bytes` (`12B IV + 16B AuthTag + Ciphertext`).
  3. `sha256_token_hash` contiene únicamente el resumen hexadecimal de 64 caracteres (`SHA-256`), nunca el token en claro.
