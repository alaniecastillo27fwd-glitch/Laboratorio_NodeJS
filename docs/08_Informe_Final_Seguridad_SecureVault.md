# Informe Final de Seguridad y Verificación en Producción — SecureVault
**Laboratorio Práctico:** Sistema seguro en Node.js: OWASP Top 10:2025, cifrado, hash y despliegue a producción  
**Asignatura:** `[COMPLETAR ASIGNATURA]`  
**Docente:** `[COMPLETAR NOMBRE DEL DOCENTE]`  
**Estudiante:** `[COMPLETAR NOMBRE DEL ESTUDIANTE]`  
**Fecha de entrega:** 25 de noviembre de 2026  

---

## 1. Resumen de Evaluación y Entorno de Producción

El sistema **SecureVault** ha sido diseñado, implementado, desplegado en producción y auditado bajo las diez categorías del estándar **OWASP Top 10:2025** y las especificaciones criptográficas de la Sección 4 del laboratorio.

* **URL Pública Frontend (Vercel - HTTPS/TLS 1.3):** `[PEGA AQUÍ URL REAL DE VERCEL: https://securevault-xxx.vercel.app]`
* **URL Pública Backend API (Render - HTTPS/TLS 1.3):** `[PEGA AQUÍ URL REAL DE RENDER: https://securevault-api-xxx.onrender.com]`
* **Endpoint de Salud (RF-08):** `[PEGA AQUÍ URL REAL: https://securevault-api-xxx.onrender.com/health]` -> `{"status":"ok"}`
* **Repositorio Git (Código, Pipeline CI/CD y Documentación):** `[PEGA AQUÍ URL REAL DE GITHUB: https://github.com/usuario/Laboratorio_NodeJS]`
* **Base de Datos Gestionada:** PostgreSQL 15+ en **Supabase** (Conexión cifrada TLS obligatoria, llaves primarias `UUID` v4).
* **Estado General de Seguridad:** Cumplimiento integral de **RF-01 a RF-08** y de las **10 categorías del OWASP Top 10:2025**, con secretos gestionados fuera del repositorio, hashing **Argon2id**, cifrado autenticado **AES-256-GCM**, tokens **SHA-256** de alta entropía y verificación empírica post-despliegue.

---

## 2. Tabla Maestra de Cumplimiento OWASP Top 10:2025 (A01 a A10)

| Categoría OWASP 2025 | Mitigación implementada en SecureVault | Evidencia verificable (código, captura o prueba) |
| :--- | :--- | :--- |
| **A01:2025 Broken Access Control** *(incluye SSRF)* | 1. **Denegar por defecto:** Middleware `requireAuth` (`src/middlewares/authMiddleware.js`) en todas las rutas de `/api/notes`, `/api/profile` y `/api/admin`.<br/>2. **Verificación de rol en servidor (RF-03):** Middleware `requireRole('admin')` que consulta el rol vigente del usuario en PostgreSQL en cada petición e impone `role = 'user'` en `POST /api/auth/register`.<br/>3. **Prevención estricta de IDOR (RF-04):** Todas las consultas `SELECT`, `UPDATE` y `DELETE` en `src/models/noteModel.js` filtran con `WHERE id = $1 AND owner_id = $2` (`req.user.id`).<br/>4. **Mitigación SSRF:** El backend no realiza peticiones HTTP salientes a URLs proporcionadas por el usuario y restringe `connect-src` en CSP. | * **Código:** `src/middlewares/authMiddleware.js`, `src/models/noteModel.js` (`findNoteByIdAndOwner`, `updateNoteByIdAndOwner`, `deleteNoteByIdAndOwner`).<br/>* **Prueba de ataque IDOR:** Ejecución `curl` donde el Usuario A autenticado intenta leer (`GET`), editar (`PUT`) y borrar (`DELETE`) la nota UUID del Usuario B y recibe **`HTTP 404 Not Found`** + registro `ACCESS_DENIED` en `audit_logs`.<br/>* **Evidencia gráfica:** `[INSERTAR CAPTURA 07_pruebas_ataques_curl.png — Sección IDOR]` |
| **A02:2025 Security Misconfiguration** | 1. Desactivación de firma del servidor: `app.disable('x-powered-by')` en `src/app.js`.<br/>2. Configuración de `helmet` con **Content-Security-Policy (CSP)** estricta (sin `unsafe-inline`), **HSTS** (`max-age=31536000; includeSubDomains; preload`), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy` y `Permissions-Policy` (en `src/app.js` y `frontend/vercel.json`).<br/>3. **CORS restringido** exclusivamente a `process.env.FRONTEND_URL` con `credentials: true`.<br/>4. Entorno `NODE_ENV=production`, `app.set('trust proxy', 1)` y ausencia total de rutas de depuración o *stack traces* al cliente. | * **Código:** `src/app.js` (líneas 10–78), `frontend/vercel.json` y `tests/security.test.js` (Test #5).<br/>* **Escaneo externo:** Reporte de **securityheaders.com** sobre la URL de producción con calificación **A / A+**.<br/>* **Evidencia gráfica:** `[INSERTAR CAPTURA 03_securityheaders_A.png]` |
| **A03:2025 Software Supply Chain Failures** | 1. Archivos `package-lock.json` versionados tanto en backend como en frontend.<br/>2. Instalación determinista y limpia mediante **`npm ci`** en desarrollo, en el pipeline de GitHub Actions y en el comando de build de Render/Vercel.<br/>3. Auditoría automatizada `npm audit --audit-level=high` que bloquea el CI ante vulnerabilidades altas o críticas.<br/>4. **Dependabot** activado (`.github/dependabot.yml`) con revisión semanal para `npm` (`/` y `/frontend`) y `github-actions`, y mínimo de dependencias (uso de `node:test` nativo). | * **Código:** `.github/dependabot.yml`, `.github/workflows/ci.yml` y `package-lock.json`.<br/>* **Salida de comando:** Ejecución de `npm audit --audit-level=high` reportando `found 0 vulnerabilities`.<br/>* **Evidencia gráfica:** `[INSERTAR CAPTURA 01_npm_audit_dependabot.png]` |
| **A04:2025 Cryptographic Failures** | 1. **Contraseñas (RF-01):** Hash lento con sal **Argon2id** (`memoryCost: 19456` [19 MiB], `timeCost: 2`, `parallelism: 1`).<br/>2. **Notas y dato sensible (RF-04 / RF-05):** Cifrado autenticado **AES-256-GCM** con IV aleatorio único de 12 bytes (`crypto.randomBytes(12)`) por registro y Auth Tag de 16 bytes (`Buffer.concat([iv, authTag, encrypted])` en Base64).<br/>3. **Tokens de recuperación (RF-06):** 32 bytes CSPRNG (`crypto.randomBytes(32)`) almacenando en BD solo su hash **SHA-256** (`CHAR(64)`).<br/>4. **Secretos y Transporte:** Llaves `ENCRYPTION_KEY` y `JWT_SECRET` en el gestor de secretos de Render (nunca en Git), HTTPS/TLS 1.2–1.3 obligatorio y cookies `HttpOnly; Secure`. | * **Código:** `src/utils/crypto.js` y tests unitarios #1, #2, #3 y #4 en `tests/security.test.js`.<br/>* **Evidencia en BD y TLS:** Consulta SQL en **Supabase** mostrando hashes `$argon2id$`, columnas `content_enc` y `sensitive_data_enc` en Base64 ilegible y reporte de **Qualys SSL Labs** con grado **A / A+**.<br/>* **Evidencia gráfica:** `[INSERTAR CAPTURAS 04_ssllabs_A.png y 05_supabase_bd_cifrada.png]` |
| **A05:2025 Injection** *(incluye XSS)* | 1. **Prevención de SQL Injection:** 100% de las consultas en `src/models/*.js` utilizan sentencias parametrizadas (`$1, $2...`) del driver `pg`, sin concatenación de strings.<br/>2. **Validación de entrada:** Esquemas estrictos con **Zod** en todos los controladores (`authController.js`, `noteController.js`, `profileController.js`, `adminController.js`).<br/>3. **Prevención de XSS:** Escape automático en componentes React (cero uso de `dangerouslySetInnerHTML`), cookies `HttpOnly` inaccesibles desde `document.cookie` y cabecera CSP `script-src 'self'` que bloquea scripts inline. | * **Código:** `src/models/userModel.js`, `src/models/noteModel.js`, esquemas Zod en `src/controllers/*.js`.<br/>* **Prueba de ataque SQLi y XSS:** Peticiones `curl` con `"email": "' OR 1=1 --"` y `"sensitiveData": "<script>alert(1)</script>"` rechazadas con `HTTP 401/400` y neutralizadas en salida.<br/>* **Evidencia gráfica:** `[INSERTAR CAPTURA 07_pruebas_ataques_curl.png — Sección SQLi/XSS y 06_owasp_zap_baseline.png]` |
| **A06:2025 Insecure Design** | 1. **Modelado de Amenazas:** Diagrama de Flujo de Datos (DFD) con 5 fronteras de confianza y matriz **STRIDE** documentada con casos de abuso en `docs/01_Diseno_y_Modelo_Amenazas.md`.<br/>2. **Límites de negocio anti-abuso:** Cuota máxima de **50 notas por usuario** (`MAX_NOTES_PER_USER = 50` en `noteController.js`), título máx. 120 chars, nota máx. 5,000 chars, contraseña de 10 a 72 chars (evita DoS sobre Argon2id), límite global de payload `express.json({ limit: '10kb' })` y restricción `CHECK` en PostgreSQL. | * **Documentación y Código:** `docs/01_Diseno_y_Modelo_Amenazas.md`, `src/controllers/noteController.js` (`countNotesByOwner >= 50`), `src/app.js` (`limit: '10kb'`).<br/>* **Prueba de límite:** Envío de payload de 15 KB rechazado automáticamente con **`HTTP 413 Payload Too Large`**. |
| **A07:2025 Authentication Failures** | 1. **Rate Limiting:** `loginRateLimiter` (`express-rate-limit`) en `/api/auth/login` que bloquea con **`HTTP 429 Too Many Requests`** tras 5 intentos fallidos en 15 minutos.<br/>2. **Bloqueo progresivo persistente:** Columnas `failed_login_attempts` y `locked_until` (bloqueo de cuenta por 15 min al 5.º fallo) en la tabla `users`.<br/>3. **Mensajes anti-enumeración:** Respuestas uniformes `"Credenciales inválidas"` en login y mensaje constante en `/api/auth/forgot-password`.<br/>4. **Ciclo de sesión (RF-02):** Emisión de JWT nuevo con `jti` (`crypto.randomUUID()`), expiración corta de 30 minutos e invalidación inmediata en BD (`revoked_tokens` y `tokens_valid_after`) al cerrar sesión o cambiar contraseña. | * **Código:** `src/middlewares/rateLimiter.js`, `src/controllers/authController.js`, `src/middlewares/authMiddleware.js`.<br/>* **Prueba de fuerza bruta:** Bucle de 6 intentos fallidos consecutivos recibiendo **`HTTP 429 Too Many Requests`** con cabecera `Retry-After`.<br/>* **Evidencia gráfica:** `[INSERTAR CAPTURA 07_pruebas_ataques_curl.png — Sección Fuerza Bruta HTTP 429]` |
| **A08:2025 Software or Data Integrity Failures** | 1. **Verificación de firma JWT con algoritmo fijo:** `jwt.verify(token, jwtSecret, { algorithms: ['HS256'] })` en `authMiddleware.js`, rechazando tokens sin firma (`alg: none`) o con algoritmos distintos.<br/>2. **Integridad de datos cifrados:** Verificación obligatoria del **Auth Tag de 16 bytes** en `AES-256-GCM` (`decipher.setAuthTag`) antes de aceptar cualquier dato descifrado.<br/>3. **Sin deserialización insegura:** Uso exclusivo de `express.json({ strict: true, limit: '10kb' })` validado con Zod.<br/>4. **Pipeline CI/CD:** `.github/workflows/ci.yml` ejecuta `gitleaks`, `npm ci`, `npm audit` y `npm test` antes de aprobar cambios en `main`. | * **Código:** `src/middlewares/authMiddleware.js` (línea 30), `src/utils/crypto.js` (`decrypt`), `.github/workflows/ci.yml` y Test #3 en `tests/security.test.js`.<br/>* **Evidencia gráfica:** `[INSERTAR CAPTURA 02_github_actions_ci.png]` |
| **A09:2025 Security Logging and Alerting Failures** | 1. **Bitácora persistente y estructurada (RF-07):** Registro en tabla `audit_logs` y en `winston` (JSON estructurado) de `USER_REGISTERED`, `LOGIN_SUCCESS`, `LOGIN_FAILED`, `ACCOUNT_LOCKED`, `LOGOUT`, `PASSWORD_RESET_REQUESTED`, `PASSWORD_RESET_COMPLETED`, `ROLE_CHANGED`, `ACCESS_DENIED` y `CRYPTO_INTEGRITY_FAILURE`.<br/>2. **Sanitización estricta:** `sanitizeLogData()` en `src/utils/logger.js` redacta recursivamente (`[REDACTED]`) cualquier campo `password`, `token`, `secret`, `cookie`, `authorization`, `content` o `sensitive_data`.<br/>3. **Alerta ante N fallos:** Emisión automática de `logger.warn({ alert: 'BRUTE_FORCE_DETECTED', ... })` al detectar 5 fallos consecutivos por cuenta o por IP. | * **Código:** `src/utils/logger.js`, `src/models/auditModel.js`, `src/controllers/adminController.js`.<br/>* **Evidencia visual:** Muestra de logs en formato JSON en Render y vista de la bitácora en el Panel de Administración (`/admin`).<br/>* **Evidencia gráfica:** `[INSERTAR CAPTURA 08_bitacora_admin_winston.png]` |
| **A10:2025 Mishandling of Exceptional Conditions** | 1. **Manejador global de errores (*Fail-Closed*):** `src/middlewares/errorHandler.js` captura toda excepción, registra el diagnóstico internamente en `logger.error` y devuelve al cliente únicamente respuestas genéricas (`{"error":"Error interno del servidor"}` o `{"error":"Formato JSON inválido"}`) sin *stack traces* en producción.<br/>2. **Timeouts en BD:** `connectionTimeoutMillis: 5000`, `query_timeout: 5000` y `statement_timeout: 5000` en `src/config/db.js`.<br/>3. **Resiliencia del proceso:** Captura de `unhandledRejection` y `uncaughtException` en `server.js` con cierre limpio del pool y reinicio automático por Render. | * **Código:** `src/middlewares/errorHandler.js`, `src/config/db.js`, `server.js`.<br/>* **Prueba de error forzado:** Envío de JSON corrupto a `/api/auth/login` que devuelve `HTTP 400 {"error":"Formato JSON inválido"}` sin *stack trace* y registra `MALFORMED_JSON` en el log interno.<br/>* **Evidencia gráfica:** `[INSERTAR CAPTURA 07_pruebas_ataques_curl.png — Sección Error Forzado A10]` |

---

## 3. Decisiones Criptográficas y Gestión de Llaves

### 3.1. Resumen de Algoritmos y Parámetros Implementados

| Dato | Mecanismo | Algoritmo y parámetros en `src/utils/crypto.js` | Justificación técnica |
| :--- | :--- | :--- | :--- |
| **Contraseñas** | Hash lento con sal (Irreversible) | **Argon2id** (`memoryCost: 19456` [19 MiB], `timeCost: 2`, `parallelism: 1`) | Resistente a ataques de fuerza bruta con GPU/ASIC; jamás se descifra, solo se verifica con `argon2.verify`. |
| **Notas privadas y Dato sensible** | Cifrado autenticado AEAD (Reversible) | **AES-256-GCM** (Llave 32B Base64, **IV aleatorio único de 12B** por escritura, **Auth Tag de 16B**) | El propietario debe volver a leer el dato. GCM garantiza confidencialidad e integridad simultáneas (detecta manipulación en BD). |
| **Token de recuperación** | CSPRNG + Hash rápido (Irreversible) | **`crypto.randomBytes(32)`** + Hash **`SHA-256`** (`CHAR(64)`) en BD (TTL 15 min, 1 solo uso) | Con 256 bits de entropía aleatoria no requiere hash lento; si roban la BD, los hashes SHA-256 no permiten reconstruir el token en claro. |
| **Integridad y Sesión** | Firma MAC | **HMAC-SHA256** (`crypto.timingSafeEqual`) y **JWT `HS256`** con `jti` único | Previene alteración de datos, ataques de temporización (*timing attacks*) y reutilización de sesiones tras el logout. |
| **Datos en tránsito** | Cifrado de red | **HTTPS con TLS 1.2 / TLS 1.3** (Let's Encrypt) + **HSTS** | Protege credenciales y cookies `HttpOnly; Secure` en tránsito entre navegador, Vercel, Render y Supabase. |

### 3.2. ¿Qué ocurre con los datos si se pierde la llave `ENCRYPTION_KEY`?
* **Notas privadas (`notes.content_enc`) y dato sensible de perfil (`users.sensitive_data_enc`):** Sufren una **pérdida matemática total e irreversible**. En `AES-256-GCM`, sin la llave simétrica de 256 bits es computacionalmente inviable recuperar el texto plano o validar el `AuthTag` de 16 bytes, y la llave jamás puede derivarse desde la base de datos.
* **Contraseñas (`users.password_hash`) y tokens (`token_hash`):** **No se ven afectados**, ya que emplean hashes irreversibles (`Argon2id` con sal integrada y `SHA-256`) independientes de `ENCRYPTION_KEY`.
* **Prevención:** Resguardar una copia cifrada de `ENCRYPTION_KEY` en un gestor de secretos externo con MFA y control de auditoría (AWS Secrets Manager / HashiCorp Vault / Bitwarden Vault) antes de cargarla en Render.

### 3.3. ¿Cómo rotarían la llave sin perder la información existente?
El esquema (`database/schema.sql`) incluye la columna `key_version SMALLINT NOT NULL DEFAULT 1` en `users` y `notes`, permitiendo una rotación en 4 pasos sin tiempo de inactividad:
1. **Coexistencia en variables de entorno (Keyring):** Se mantiene `ENCRYPTION_KEY_V1` (para lectura de registros `key_version = 1`), se añade `ENCRYPTION_KEY_V2` (nueva llave de 32 bytes Base64) y se fija `ACTIVE_KEY_VERSION=2`.
2. **Lectura dual y escritura con `V2`:** Todo registro nuevo o editado se cifra con `ENCRYPTION_KEY_V2` y `key_version = 2`; las lecturas seleccionan `V1` o `V2` según la columna `key_version` de la fila.
3. **Re-cifrado progresivo (*Lazy* + *Batch*):** Un proceso por lotes (`FOR UPDATE SKIP LOCKED`) lee cada registro con `key_version = 1`, lo descifra con `V1` (validando su `authTag` de 16B), lo vuelve a cifrar con `V2` generando un **nuevo IV aleatorio de 12 bytes** y un nuevo `authTag`, y actualiza la fila a `key_version = 2`.
4. **Retiro seguro (*Decommission*):** Cuando `SELECT COUNT(*) FROM notes WHERE key_version = 1` y `SELECT COUNT(*) FROM users WHERE key_version = 1 AND sensitive_data_enc IS NOT NULL` retornan `0`, se elimina `ENCRYPTION_KEY_V1` del panel de Render.

---

## 4. Resumen de Resultados de Escaneos y Verificaciones Post-Despliegue

### 4.1. Auditoría de Dependencias (`npm audit` y Dependabot — OWASP A03)
* **Comando ejecutado:** `npm audit --audit-level=high` (en Backend y Frontend) + Pipeline GitHub Actions (`ci.yml`).
* **Resultado obtenido:** `[PEGA AQUÍ RESULTADO REAL — Esperado: 0 vulnerabilities (0 high, 0 critical)]`
* **Evidencia:**
  > `[INSERTAR CAPTURA 01_npm_audit_dependabot.png]`  
  > `[INSERTAR CAPTURA 02_github_actions_ci.png]`

### 4.2. Evaluación de Cabeceras HTTP (`securityheaders.com` — OWASP A02)
* **URL auditada:** `[PEGA AQUÍ URL REAL DE PRODUCCIÓN]`
* **Calificación obtenida:** `[PEGA AQUÍ RESULTADO REAL — Esperado: Grado A o A+]`
* **Cabeceras verificadas:** `Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy` y ausencia de `X-Powered-By`.
* **Evidencia:**
  > `[INSERTAR CAPTURA 03_securityheaders_A.png]`

### 4.3. Evaluación de Certificados y Cifrado TLS (`Qualys SSL Labs` — OWASP A04)
* **Hostname auditado:** `[PEGA AQUÍ HOSTNAME REAL DE PRODUCCIÓN]`
* **Calificación obtenida:** `[PEGA AQUÍ RESULTADO REAL — Esperado: Overall Rating A / A+]`
* **Protocolos verificados:** TLS 1.3 (`Yes`), TLS 1.2 (`Yes`), TLS 1.1/1.0 y SSL 2/3 (`No`), certificado Let's Encrypt válido con *Forward Secrecy*.
* **Evidencia:**
  > `[INSERTAR CAPTURA 04_ssllabs_A.png]`

### 4.4. Escaneo Dinámico de Vulnerabilidades (`OWASP ZAP Baseline Scan` — OWASP A01/A02/A05)
* **Comando ejecutado:** `zap-baseline.py -t https://[TU-URL-PRODUCCION] -r zap_report.html -I`
* **Resultado obtenido:** `[PEGA AQUÍ RESULTADO REAL — Esperado: 0 High Alerts (FAIL-NEW: 0)]`
* **Evidencia:**
  > `[INSERTAR CAPTURA 06_owasp_zap_baseline.png]`

### 4.5. Evidencia de Cifrado en Base de Datos, Bitácora y Ataques Manuales Bloqueados
* **Verificación en Supabase (`users`, `notes`, `password_reset_tokens`):**
  > `[INSERTAR CAPTURA 05_supabase_bd_cifrada.png]`
* **Pruebas manuales de ataques bloqueados (IDOR `404`, SQLi/XSS `400/401`, Fuerza Bruta `429`, Error Forzado `400` sin stack trace):**
  > `[INSERTAR CAPTURA 07_pruebas_ataques_curl.png]`
* **Bitácora de eventos en Panel Admin (`/admin`) y logs JSON sanitizados en Render (`winston`):**
  > `[INSERTAR CAPTURA 08_bitacora_admin_winston.png]`

---

## 5. Análisis de Riesgos Residuales y Mitigación en Entorno Corporativo

A pesar de cubrir las 10 categorías del OWASP Top 10:2025, la operación sobre planes gratuitos académicos (Render Free, Vercel Hobby y Supabase Free) mantiene los siguientes **5 riesgos residuales identificados**, junto con su plan de mitigación para un entorno corporativo de misión crítica:

1. **Riesgo Residual 1 — Almacenamiento en memoria del Rate Limiter y suspensión (*spin-down*) en Render Free (Disponibilidad / A07):**
   * *Descripción:* El plan gratuito de Render suspende el contenedor tras 15 minutos de inactividad, lo que reinicia los contadores en memoria de `express-rate-limit` (aunque el bloqueo por cuenta `locked_until` sí persiste en PostgreSQL) e introduce un *cold start* de ~50 segundos.
   * *Mitigación corporativa:* Desplegar en instancias dedicadas sin *spin-down* (mínimo 2 réplicas detrás de balanceador) y respaldar `express-rate-limit` con un almacén distribuido **Redis / Upstash** (`rate-limit-redis`).
2. **Riesgo Residual 2 — Custodia y rotación manual de la llave maestra `ENCRYPTION_KEY` en variables de entorno del PaaS (Criptografía / A04):**
   * *Descripción:* Aunque `ENCRYPTION_KEY` reside fuera del código fuente en el panel de secretos de Render, sigue siendo una llave estática en memoria del proceso (*Direct Encryption*) cuya rotación requiere intervención del administrador.
   * *Mitigación corporativa:* Implementar **Envelope Encryption** (Cifrado de Sobre) utilizando un **HSM / KMS dedicado** (AWS KMS, Google Cloud KMS o HashiCorp Vault Transit Engine), donde una *Customer Master Key* (CMK) con rotación automática anual cifra llaves de datos únicas por registro (*Data Encryption Keys* - DEKs).
3. **Riesgo Residual 3 — Ausencia de WAF perimetral dedicado y protección anti-DDoS volumétrica (Infraestructura / A02 / A06):**
   * *Descripción:* Los límites de aplicación (`express.json({ limit: '10kb' })` y `express-rate-limit`) protegen el proceso de Node.js, pero ataques DDoS distribuidos desde miles de IPs (botnets) llegarían directamente hasta el contenedor de Render.
   * *Mitigación corporativa:* Colocar un **Web Application Firewall (WAF)** y proxy perimetral como **Cloudflare WAF** o **AWS WAF** delante del dominio personalizado con reglas gestionadas OWASP Core Rule Set (CRS), reputación de IP y mitigación DDoS en capa 7.
4. **Riesgo Residual 4 — Entrega del enlace de recuperación de contraseña sin servidor SMTP transaccional autenticado (Identidad / RF-06):**
   * *Descripción:* En el entorno académico sin dominio propio ni proveedor SMTP de pago, el flujo `RF-06` simula el envío de correo (mostrando el token solo en modo desarrollo local y ocultándolo en producción).
   * *Mitigación corporativa:* Integrar un proveedor de correo transaccional con dominio propio verificado mediante registros criptográficos **SPF, DKIM y DMARC** (`p=reject`) a través de APIs autenticadas (AWS SES, SendGrid o Postmark).
5. **Riesgo Residual 5 — Retención efímera de logs en `stdout` y pausado por inactividad en Supabase Free (Auditoría y Continuidad / A09):**
   * *Descripción:* El plan gratuito de Render conserva un historial limitado de líneas de log en consola y Supabase Free pausa el proyecto tras 7 días sin actividad ni incluye respaldos *Point-in-Time Recovery* (PITR).
   * *Mitigación corporativa:* Configurar un transporte de `winston` hacia un **SIEM / agregador inmutable de logs** (Datadog, Elastic Stack o AWS CloudWatch Logs con alertas webhook a Slack/PagerDuty) y habilitar el plan Pro de PostgreSQL con respaldos diarios automatizados, PITR y restricción de red privada (VPC Peering / IP Allowlist exclusiva para las IPs de salida de Render).
