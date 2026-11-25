# Fase 4: Guía Práctica de Auditoría Automatizada Post-Despliegue (`npm audit`, OWASP ZAP, SecurityHeaders.com y Qualys SSL Labs)

> **Nota Ética:** Ejecuta estos escaneos exclusivamente contra tus propias URLs de producción en **Vercel** (`https://TU-FRONTEND.vercel.app`) y **Render** (`https://TU-BACKEND.onrender.com`). Utiliza únicamente el modo pasivo `baseline scan` en OWASP ZAP para no infringir los términos de uso del plan gratuito de Render/Vercel.

---

## 1. Herramienta 1: `npm audit` (OWASP A03:2025 — Software Supply Chain Failures)

### 1.1. Comandos exactos de ejecución
Ejecuta la auditoría tanto en el backend (raíz del repositorio) como en la carpeta `frontend/`:

```bash
# 1. Auditoría de dependencias del Backend (Node.js LTS + Express)
npm audit --audit-level=high

# 2. Auditoría de dependencias del Frontend (React + Vite)
cd frontend
npm audit --audit-level=high
```

### 1.2. Resultado esperado para calificación máxima
* Salida en terminal: **`found 0 vulnerabilities`** (o **`0 high, 0 critical`**) y código de salida `0`, acompañado del archivo `.github/dependabot.yml` activo en el repositorio de GitHub.

### 1.3. Solución rápida (Troubleshooting)
1. **Si aparece una vulnerabilidad transitiva en un sub-paquete:** Ejecuta `npm audit fix` (sin `--force` para no romper versiones mayores) y vuelve a correr `npm test` para confirmar que no rompió el sistema.
2. **Si `npm ci` falla en GitHub Actions tras `npm audit fix`:** Recuerda hacer `git add package-lock.json frontend/package-lock.json` y `git commit` para que el lockfile actualizado suba al repositorio.

---

## 2. Herramienta 2: OWASP ZAP — Baseline Scan (OWASP A01, A02, A05)

### 2.1. Comandos exactos de ejecución (Docker oficial `ghcr.io/zaproxy/zaproxy:stable`)
El *Baseline Scan* realiza un rastreo pasivo (*spidering* de 1 minuto) sin lanzar ataques activos destructivos. Ejecútalo desde tu terminal con Docker Desktop activo:

**En Bash / Git Bash / Linux / macOS:**
```bash
# Escaneo Baseline del Frontend en Vercel (genera reporte HTML en la carpeta actual)
docker run --rm -v "$(pwd):/zap/wrk/:rw" -t ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t https://TU-FRONTEND.vercel.app -r zap_report_frontend.html -I

# Escaneo Baseline del Backend en Render (/health)
docker run --rm -v "$(pwd):/zap/wrk/:rw" -t ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t https://TU-BACKEND.onrender.com/health -r zap_report_backend.html -I
```

**En Windows PowerShell:**
```powershell
# Escaneo Baseline del Frontend en Vercel
docker run --rm -v "${PWD}:/zap/wrk/:rw" -t ghcr.io/zaproxy/zaproxy:stable `
  zap-baseline.py -t https://TU-FRONTEND.vercel.app -r zap_report_frontend.html -I

# Escaneo Baseline del Backend en Render (/health)
docker run --rm -v "${PWD}:/zap/wrk/:rw" -t ghcr.io/zaproxy/zaproxy:stable `
  zap-baseline.py -t https://TU-BACKEND.onrender.com/health -r zap_report_backend.html -I
```
*(Alternativa sin Docker: Abrir **OWASP ZAP Desktop** -> **Automated Scan** -> pegar la URL -> desmarcar "Use traditional spider" si se desea solo pasivo o usar un límite de 1 min, sin lanzar Active Scan).*

### 2.2. Resultado esperado para calificación máxima
* **`FAIL-NEW: 0`** (**0 alertas de riesgo High / Alto**).
* Las reglas críticas de cabeceras (`Content Security Policy (CSP) Header Not Set`, `Strict-Transport-Security Header Not Set`, `Missing Anti-clickjacking Header`, `X-Content-Type-Options Header Missing` y `Server Leaks Information via "X-Powered-By"`) deben aparecer como **`PASS`**.

### 2.3. Solución rápida (Troubleshooting) para los 2 hallazgos más comunes
1. **Alerta `Cookie with SameSite=None` o advertencia informativa de CSRF en arquitectura Cross-Site (Vercel <-> Render):**
   * *Explicación técnica para el informe:* Cuando el frontend está en `*.vercel.app` y el backend en `*.onrender.com`, el navegador exige `SameSite=None; Secure; HttpOnly` para enviar la cookie en peticiones `fetch` cross-origin. La protección contra CSRF se garantiza mediante la política **CORS estricta** (`origin: process.env.FRONTEND_URL`, rechazando orígenes externos), la exigencia de `Content-Type: application/json` (que fuerza un *preflight* `OPTIONS` no falsificable por formularios HTML simples) y cookies `Secure + HttpOnly`. (Si se desea usar `SameSite=Strict`, basta con agregar en `frontend/vercel.json` un rewrite `{"source": "/api/(.*)", "destination": "https://TU-BACKEND.onrender.com/api/$1"}` para que todo opere bajo el mismo dominio de Vercel).
2. **Alerta `Permissions Policy Header Not Set` o `Sec-Fetch-*` en el Backend Express:**
   * En `frontend/vercel.json` ya está incluida la cabecera `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()`. Si ZAP la reporta sobre la URL directa de Render, puedes añadir en `src/app.js`:
     `app.use((_req, res, next) => { res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()'); next(); });`

---

## 3. Herramienta 3: SecurityHeaders.com / Mozilla Observatory (OWASP A02:2025)

### 3.1. URLs exactas de ejecución
1. Abre **https://securityheaders.com/**
2. Marca la casilla **"Hide results"** (para mantener tu URL privada fuera de la lista pública).
3. Ejecuta el análisis dos veces:
   * Primero con la URL de tu **Frontend en Vercel:** `https://TU-FRONTEND.vercel.app`
   * Segundo con la URL de salud de tu **Backend en Render:** `https://TU-BACKEND.onrender.com/health`
*(Opcional complementario: **https://developer.mozilla.org/en-US/observatory**).*

### 3.2. Resultado esperado para calificación máxima
* **Calificación `A` o `A+`** (requisito obligatorio de la tabla A02 en página 3: *"Reporte de cabeceras (securityheaders.com) con calificación A o superior"*).
* Las 6 etiquetas en color verde: `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy` y `Permissions-Policy`.

### 3.3. Solución rápida (Troubleshooting)
1. **Si SecurityHeaders da calificación `B` por falta de `Permissions-Policy` en Render:**
   * `helmet()` por defecto configura CSP, HSTS, X-Frame-Options, X-Content-Type-Options y Referrer-Policy (lo que da grado **A**). Con el archivo `frontend/vercel.json` que ya incluye `Permissions-Policy`, la URL de Vercel obtiene directamente **`A+`**.
2. **Si muestra advertencia amarilla en `Content-Security-Policy`:**
   * Verifica que en `script-src` y `style-src` figure únicamente `'self'` y **nunca** `'unsafe-inline'` ni `'unsafe-eval'`.

---

## 4. Herramienta 4: Qualys SSL Labs (OWASP A04:2025 — Cryptographic Failures / TLS)

### 4.1. URL exacta de ejecución
1. Abre **https://www.ssllabs.com/ssltest/**
2. Marca la casilla **"Do not show the results on the boards"**.
3. Ingresa el hostname de tu aplicación en producción (sin `https://` ni rutas, por ejemplo: `TU-FRONTEND.vercel.app` o `TU-BACKEND.onrender.com`) y haz clic en **Submit**.
4. Espera ~2 minutos a que termine el análisis de las IPs del balanceador Edge.

### 4.2. Resultado esperado para calificación máxima
* **Overall Rating: `A` o `A+`**.
* **Certificate:** `100%` (Certificado válido emitido por Let's Encrypt / Google Trust Services, cadena de confianza completa).
* **Protocol Support:** **TLS 1.3 (`Yes`)** y **TLS 1.2 (`Yes`)** habilitados; **TLS 1.1, TLS 1.0, SSL 3 y SSL 2 (`No`)** completamente deshabilitados.
* **Forward Secrecy:** Soportado en suites ECDHE.

### 4.3. Solución rápida (Troubleshooting)
1. **Si SSL Labs muestra resultados antiguos en caché:** Haz clic en el enlace **"Clear cache"** debajo del hostname para que reevalúe el certificado actual junto con la cabecera `Strict-Transport-Security` (`max-age=31536000`).
2. **Si Render aún está aprovisionando el certificado TLS tras el primer deploy:** Espera 2 a 3 minutos después de que el servicio pase a estado `Live` antes de lanzar el test en SSL Labs.

---

## 5. Lista Exacta de Capturas de Pantalla para el Informe Final de Seguridad

Guarda estas **8 capturas de pantalla** para integrarlas en tu Informe Final de Seguridad (Sección 8):

1. **`01_npm_audit_dependabot.png` (OWASP A03):** Salida de terminal de `npm audit --audit-level=high` mostrando `found 0 vulnerabilities` + captura del archivo `.github/dependabot.yml` o pestaña *Insights -> Dependency graph -> Dependabot* en GitHub.
2. **`02_github_actions_ci.png` (OWASP A08):** Captura de la pestaña **Actions** en GitHub con los 3 jobs (`Secret Scanning (Gitleaks)`, `Backend CI` y `Frontend CI`) en color verde (**✓**).
3. **`03_securityheaders_grade_A.png` (OWASP A02):** Reporte de **securityheaders.com** sobre tu URL de producción mostrando la insignia verde **`A` o `A+`** y las cabeceras CSP y HSTS activas.
4. **`04_ssllabs_grade_A.png` (OWASP A04):** Reporte de **Qualys SSL Labs** mostrando **Overall Rating `A` / `A+`** y la tabla *Protocols* con TLS 1.2 y TLS 1.3 en `Yes` y protocolos antiguos en `No`.
5. **`05_supabase_encrypted_data.png` (OWASP A04):** Captura del SQL Editor o Table Editor de **Supabase** mostrando que `password_hash` inicia con `$argon2id$`, que `content_enc` y `sensitive_data_enc` son cadenas Base64 ilegibles y que `token_hash` es un hash SHA-256 de 64 caracteres.
6. **`06_owasp_zap_baseline.png` (OWASP A01/A02/A05):** Resumen del reporte HTML generado por **OWASP ZAP Baseline Scan** (`zap_report_frontend.html` / `zap_report_backend.html`) mostrando **`High: 0`**.
7. **`07_ataques_idor_sqli_ratelimit.png` (OWASP A01/A05/A07/A10):** Captura de la terminal ejecutando los comandos `curl` de la guía `05_Guion_Pruebas_Seguridad_y_Ataques.md` donde se observe:
   * Intento IDOR del Usuario A sobre la nota del Usuario B rechazado con `HTTP 404`.
   * Intento de SQLi `' OR 1=1 --` y `<script>` rechazados.
   * Sexto intento de login consecutivo bloqueado con **`HTTP 429 Too Many Requests`**.
   * Error forzado (JSON malformado / payload > 10kb) respondiendo mensaje genérico sin *stack trace*.
8. **`08_admin_audit_logs_winston.png` (OWASP A09):** Captura dividida mostrando la vista del **Panel de Administración (`/admin`)** con la tabla de bitácora (`LOGIN_FAILED`, `ACCOUNT_LOCKED`, `ACCESS_DENIED`, `ROLE_CHANGED`) y una muestra de los logs en formato **JSON** en la consola de Render (`winston`) sin contraseñas ni tokens.
