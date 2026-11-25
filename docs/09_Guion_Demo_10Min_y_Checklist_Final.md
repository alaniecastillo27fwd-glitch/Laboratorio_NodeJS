# Guion Cronometrado de Demostración en Vivo (10 Minutos) y Checklist Final Pre-Entrega (Secciones 8 y 10)

> **ADVERTENCIA DE SEGURIDAD ANTES DE GRABAR O COMPARTIR PANTALLA:**
> 1. **Jamás** abras ni muestres en pantalla los valores revelados del panel **Environment Variables** de Render ni la cadena `DATABASE_URL` con contraseña de Supabase.
> 2. Antes de iniciar el cronómetro, haz una petición previa a `https://TU-BACKEND.onrender.com/health` para despertar el contenedor de Render Free y evitar perder 50 segundos de *cold start* durante la grabación.
> 3. Ten abiertas 4 pestañas listas: (1) Frontend en Vercel con DevTools (`F12`), (2) Endpoint `/health` en Render, (3) SQL Editor de Supabase con la consulta de solo lectura lista, y (4) Terminal con las variables `$API_URL`, `$USER_A_PASS` y `$USER_B_PASS` cargadas en memoria (ocultas).

---

## 1. Guion Cronometrado de 10 Minutos Exactos

| Minuto | Qué mostrar en pantalla | Qué explicar verbalmente |
| :---: | :--- | :--- |
| **0:00 – 1:30** *(1.5 min)* | 1. Barra de direcciones de **Vercel** (`https://...vercel.app`) y endpoint `/health` en **Render** (`https://...onrender.com/health` respondiendo `{"status":"ok"}`).<br/>2. Pestaña **Network** en Chrome DevTools (`F12`) mostrando cabeceras de respuesta HTTP (`Strict-Transport-Security`, `Content-Security-Policy`, ausencia de `X-Powered-By`) y cookie `sv_token` con flags `HttpOnly`, `Secure` y `SameSite=None`. | *"Presentamos SecureVault en producción: Frontend React en Vercel, API Express en Render detrás de proxy inverso con `trust proxy` y PostgreSQL en Supabase con TLS obligatorio. El endpoint `/health` (RF-08) confirma disponibilidad sin revelar versiones internas. En DevTools observamos las cabeceras de Helmet y que la sesión JWT (`HS256`, 30m) viaja en una cookie `HttpOnly` y `Secure`, inaccesible desde `document.cookie`."* |
| **1:30 – 4:00** *(2.5 min)* | 1. En la UI de Vercel: Login (`RF-02`), creación/edición de una nota privada (`RF-04`) y vista de **Mi Perfil** (`RF-05`) mostrando el teléfono enmascarado `***-***-1234` y el botón **Revelar Dato Completo**.<br/>2. Cambiar a la pestaña del **SQL Editor de Supabase** y ejecutar la query `SELECT` sobre `users`, `notes` y `password_reset_tokens`. | *"Verificamos el flujo funcional y criptográfico (OWASP A04): creamos una nota privada y consultamos el dato sensible de perfil, que por defecto se muestra enmascarado (`***-***-1234`). Al inspeccionar directamente PostgreSQL en Supabase, demostramos que ninguna contraseña ni nota está en claro: `password_hash` inicia con `$argon2id$v=19$m=19456,t=2,p=1$`, mientras que `content_enc` y `sensitive_data_enc` son bloques Base64 ilegibles cifrados con `AES-256-GCM` (IV aleatorio de 12B + AuthTag de 16B), y los tokens de recuperación son hashes `SHA-256`."* |
| **4:00 – 7:30** *(3.5 min)* | **Ejecución en vivo de 3 Ataques Bloqueados (Terminal / UI):**<br/>1. **Ataque 1 — IDOR (A01):** En terminal, el Usuario A autenticado ejecuta `curl -i -b cookies_userA.txt GET /api/notes/<UUID_NOTA_B>` -> Recibe **`HTTP 404 Not Found`**.<br/>2. **Ataque 2 — SQLi y XSS (A05):** Ejecutar `curl` enviando `"email": "' OR 1=1 --"` en login y `"sensitiveData": "<script>alert(1)</script>"` -> Rechazados con **`HTTP 401 / 400`** y script neutralizado como texto plano.<br/>3. **Ataque 3 — Fuerza Bruta (A07):** Ejecutar el bucle `for` de 6 logins fallidos consecutivos -> Los primeros dan `401` y el 5.º/6.º es bloqueado con **`HTTP 429 Too Many Requests`** (`Retry-After`). | *"Ahora ejecutamos tres ataques reales contra nuestra URL de producción:<br/>1. **IDOR (OWASP A01):** Con la sesión activa del Usuario A intentamos leer y borrar el UUID de una nota del Usuario B. Gracias al filtro parametrizado `WHERE id = $1 AND owner_id = $2`, el servidor bloquea el acceso con `404` y audita el intento.<br/>2. **Inyección SQL y XSS (OWASP A05):** Enviamos `' OR 1=1 --` y `<script>alert(1)</script>`. Zod, las consultas parametrizadas `$1` de `pg`, el escape de React y la política CSP sin `unsafe-inline` neutralizan ambos vectores.<br/>3. **Fuerza Bruta (OWASP A07):** Lanzamos 6 intentos fallidos seguidos; al quinto intento, `express-rate-limit` y el bloqueo progresivo `locked_until` devuelven **`HTTP 429`**."* |
| **7:30 – 9:00** *(1.5 min)* | 1. Iniciar sesión como **Administrador** en Vercel -> entrar a **`/admin` (RF-07)**: mostrar la tabla de usuarios (con selector de cambio de rol) y la tabla de **Bitácora de Eventos (`audit_logs`)** donde aparecen en tiempo real los eventos `ACCESS_DENIED`, `LOGIN_FAILED` y `ACCOUNT_LOCKED` recién disparados.<br/>2. Mostrar brevemente los logs JSON de `winston` en Render (sin contraseñas ni tokens) y la pestaña **GitHub Actions** con `Gitleaks`, `npm ci`, `npm audit` y `npm test` en verde (**✓**). | *"En el Panel de Administración (RF-07, protegido por `requireRole('admin')`), vemos registrados en tiempo real los ataques recién bloqueados: los intentos `ACCESS_DENIED` del IDOR y la alerta `ACCOUNT_LOCKED` / `BRUTE_FORCE_DETECTED` (OWASP A09), sin exponer jamás contraseñas ni tokens gracias al sanitizador de `winston`. Asimismo, en GitHub Actions verificamos nuestro pipeline CI/CD (OWASP A03 y A08) con `npm ci`, `npm audit` en cero vulnerabilidades, `node:test` y `Gitleaks` en verde."* |
| **9:00 – 10:00** *(1.0 min)* | Mostrar las pestañas con los reportes de **securityheaders.com** (Grado **A / A+**) y **Qualys SSL Labs** (Grado **A / A+** con TLS 1.2/1.3) y mencionar la sección de **Riesgos Residuales** del informe final. | *"Para cerrar, confirmamos la calificación **A/A+** en SecurityHeaders.com y en Qualys SSL Labs sobre nuestros endpoints en producción. En el informe documentamos también los riesgos residuales propios del nivel gratuito (como el rate-limit en memoria ante spin-down y la rotación manual de `ENCRYPTION_KEY`) y su mitigación corporativa mediante Redis, WAF dedicado y Envelope Encryption con KMS."* |

---

## 2. Checklist Interactivo Pre-Entrega (Sección 10 del Laboratorio)

Ejecuta cada comando o verificación rápida y marca las casillas antes de enviar tu entrega final:

- [ ] **1. El archivo `.env` no aparece en ningún commit del historial:**
  * *Comando de verificación:*
    ```bash
    git log --all --full-history -- "**/.env" ".env"
    ```
  * *Criterio:* La salida debe ser **completamente vacía** (0 líneas).

- [ ] **2. `npm audit` no reporta vulnerabilidades altas ni críticas:**
  * *Comando de verificación:*
    ```bash
    npm audit --audit-level=high && cd frontend && npm audit --audit-level=high
    ```
  * *Criterio:* Ambos comandos devuelven `found 0 vulnerabilities` (código de salida `0`).

- [ ] **3. Un usuario no puede ver, editar ni borrar notas de otro usuario (Prevención IDOR - A01):**
  * *Acción de verificación:* Ejecutar los pasos `1.4`, `1.5` y `1.6` de `docs/05_Guion_Pruebas_Seguridad_y_Ataques.md` (`GET`, `PUT` y `DELETE` sobre `$NOTE_B_ID` usando la cookie del Usuario A).
  * *Criterio:* Las 3 peticiones responden **`HTTP 404`** y generan 3 filas `ACCESS_DENIED` en `audit_logs`.

- [ ] **4. Las contraseñas en la BD comienzan con `$argon2id$` o `$2b$`:**
  * *Consulta SQL en Supabase:*
    ```sql
    SELECT email, LEFT(password_hash, 30) FROM users;
    ```
  * *Criterio:* Todos los registros inician con **`$argon2id$v=19$m=19456,t=2,p=1$`** (además, la tabla `users` tiene un `CHECK` que rechaza cualquier otro formato).

- [ ] **5. El contenido de las notas en la BD es ilegible (Base64 con IV, tag y datos):**
  * *Consulta SQL en Supabase:*
    ```sql
    SELECT title, LEFT(content_enc, 50), octet_length(decode(content_enc, 'base64')) AS bytes FROM notes;
    ```
  * *Criterio:* `content_enc` es una cadena Base64 ilegible con longitud decodificada `>= 29 bytes` (`12B IV + 16B AuthTag + Ciphertext`).

- [ ] **6. La app responde solo por HTTPS y las cookies tienen `HttpOnly`, `Secure` y `SameSite`:**
  * *Comando de verificación:*
    ```bash
    curl -I http://TU-BACKEND.onrender.com/health
    ```
  * *Criterio:* Redirige con `301/308` a `https://...`, y en el login de producción la cabecera `Set-Cookie` incluye `HttpOnly; Secure; SameSite=None`.

- [ ] **7. Los errores muestran un mensaje genérico; el detalle solo queda en los logs:**
  * *Comando de verificación:*
    ```bash
    curl -i -X POST "https://TU-BACKEND.onrender.com/api/auth/login" -H "Content-Type: application/json" -d '{"email": "roto'
    ```
  * *Criterio:* Responde `HTTP 400 {"error":"Formato JSON inválido"}` sin una sola línea de *stack trace*.

- [ ] **8. El login devuelve `429` después de varios intentos fallidos:**
  * *Acción de verificación:* Ejecutar el bucle de 6 intentos fallidos de login (Sección 3 de `docs/05_Guion_Pruebas_Seguridad_y_Ataques.md`).
  * *Criterio:* A partir del 5.º/6.º intento devuelve **`HTTP 429 Too Many Requests`**.

- [ ] **9. Los logs no contienen contraseñas, tokens ni datos sensibles:**
  * *Acción de verificación:* Revisar la consola de logs en Render (`winston`) y la columna `details` en `audit_logs` después de registrarse, iniciar sesión, crear notas y recuperar contraseña.
  * *Criterio:* Ningún log contiene `password`, `token`, `cookie` ni texto plano de notas (`sanitizeLogData` los reemplaza por `[REDACTED]`).

- [ ] **10. El `README.md` explica cómo reproducir el despliegue (y las credenciales se entregan por canal privado):**
  * *Acción de verificación:* Revisar [`README.md`](../README.md) confirmando que documenta la arquitectura, instalación local, nombres de variables de entorno (sin valores) y pasos reproducibles de despliegue en Supabase, Render y Vercel, y enviar las credenciales de prueba (`user` y `admin`) al docente por mensaje privado.
