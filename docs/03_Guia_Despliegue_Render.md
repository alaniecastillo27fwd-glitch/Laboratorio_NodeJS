# Guía Paso a Paso: Despliegue Seguro del Backend en Render (Fase 3)

Esta guía documenta la configuración exacta de producción para el backend de **SecureVault** (Node.js LTS + Express) en **Render**, cumpliendo todos los requisitos de la **Sección 6** del laboratorio y el estándar **OWASP Top 10:2025**.

---

## 1. Configuración Exacta del Web Service en Render

1. Inicia sesión en [Render Dashboard](https://dashboard.render.com/) -> **New +** -> **Web Service**.
2. Conecta tu repositorio de GitHub (`SecureVault` / `Laboratorio_NodeJS`).
3. Configura los parámetros del servicio exactamente como se indica a continuación:

| Parámetro en Render | Valor Exacto | Justificación Técnica y de Seguridad |
| :--- | :--- | :--- |
| **Name** | `securevault-api` | Genera el subdominio público con TLS automático (`https://securevault-api.onrender.com`). |
| **Region** | `Ohio (US East)` o `Oregon (US West)` | Seleccionar la misma región donde se alojó el proyecto en **Supabase** para minimizar latencia TLS. |
| **Branch** | `main` | Rama protegida por el pipeline de **GitHub Actions** (`ci.yml`). |
| **Root Directory** | *(Dejar vacío `/` si `server.js` está en la raíz, o escribir `backend` si se movió a `/backend`)* | Directorio donde residen `package.json`, `package-lock.json` y `server.js`. |
| **Runtime** | `Node` (Node.js 20 LTS) | Versión LTS activa requerida por el laboratorio (`engines: >=20.0.0`). |
| **Build Command** | `npm ci` | Instalación determinista desde `package-lock.json` (OWASP A03). |
| **Start Command** | `node server.js` | Ejecuta el servidor en modo producción con cierre limpio y reinicio automático gestionado por Render. |
| **Instance Type** | `Free` | 512 MB RAM / 0.1 vCPU con proxy inverso, terminación TLS (Let's Encrypt) y supervisión de proceso. |
| **Health Check Path** | `/health` | Render consulta periódicamente `GET /health` (RF-08); si falla o el proceso cae, reinicia el contenedor automáticamente. |

> **Nota sobre `trust proxy`:** En `src/app.js` ya está configurado `app.set('trust proxy', 1)` para que Express confíe en el balanceador/proxy inverso de Render, permitiendo que `req.secure` sea `true` (cookies `Secure`) y que `express-rate-limit` lea la IP real del cliente desde `X-Forwarded-For`.

---

## 2. Tabla de Variables de Entorno en el Panel de Secretos de Render

En el panel de Render -> **Environment** -> **Environment Variables**, agrega las siguientes variables. **Jamás subas un archivo `.env` al repositorio Git.**

| Variable | Propósito | Ejemplo de formato / Cómo generarla |
| :--- | :--- | :--- |
| `NODE_ENV` | Activa el modo producción en Express, desactiva *stack traces* en respuestas de error, fuerza `ssl` hacia PostgreSQL y activa los atributos `Secure` y `SameSite=None` en cookies (Sección 6 / OWASP A02). | `production` |
| `PORT` | Puerto interno en el que escucha el contenedor de Express detrás del proxy inverso de Render. | `10000` *(Render lo inyecta por defecto o puedes fijarlo en `10000`)* |
| `DATABASE_URL` | Cadena de conexión cifrada (TLS) hacia la instancia PostgreSQL gestionada en **Supabase** (Transaction/Session Pooler o conexión directa con usuario de mínimo privilegio). | `postgresql://securevault_app:<PASSWORD_ROBUSTA>@aws-0-us-east-1.pooler.supabase.com:6543/postgres?sslmode=require` |
| `ENCRYPTION_KEY` | Llave simétrica maestra de **32 bytes (256 bits)** en Base64 para el cifrado autenticado `AES-256-GCM` de notas (`RF-04`) y dato sensible de perfil (`RF-05`). | Base64 de 44 caracteres terminado en `=` generado exclusivamente para producción (ver Sección 3). |
| `JWT_SECRET` | Secreto criptográfico de alta entropía (**64 bytes / 512 bits**) para firmar y verificar tokens de sesión JWT con algoritmo fijo `HS256` (`RF-02` / OWASP A08). | Cadena hexadecimal de 128 caracteres generada exclusivamente para producción (ver Sección 3). |
| `FRONTEND_URL` | Origen exacto autorizado en la política **CORS** (`credentials: true`) y en la directiva `connect-src` de **Helmet CSP** (OWASP A02 / A05). Prohibido usar `*`. | `https://securevault-frontend.vercel.app` *(sin barra `/` al final)* |

---

## 3. Comandos de Generación de Llaves Exclusivas para Producción

Ejecuta estos dos comandos en tu terminal local **una sola vez** para generar llaves nuevas exclusivas de producción (diferentes a las de tu `.env` de desarrollo local) y cópialas directamente al panel **Environment Variables** de Render:

```bash
# 1. Generar ENCRYPTION_KEY exclusiva de producción (32 bytes / 256 bits en Base64 para AES-256-GCM)
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"

# 2. Generar JWT_SECRET exclusivo de producción (64 bytes / 512 bits en Hexadecimal para HS256)
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

---

## 4. Checklist de Verificación Post-Despliegue del Backend (`curl -I`)

Una vez que Render indique **`Live`** en el despliegue, ejecuta los siguientes comandos desde tu terminal reemplazando `<TU-APP>.onrender.com` por tu subdominio real:

### 4.1. Verificar redirección obligatoria HTTP -> HTTPS (Sección 6)
```bash
curl -I http://securevault-api.onrender.com/health
```
* **Resultado esperado:** Código `HTTP/1.1 301 Moved Permanently` (o `308 Permanent Redirect`) con la cabecera `Location: https://securevault-api.onrender.com/health`.

### 4.2. Verificar Endpoint de Salud `/health` (RF-08) y Cabeceras de Seguridad Helmet (OWASP A02 / A05)
```bash
curl -i https://securevault-api.onrender.com/health
```
* **Checklist de lo que debes confirmar en la salida:**
  - [ ] **Estado y cuerpo:** `HTTP/2 200` y cuerpo exacto `{"status":"ok"}` (confirma conexión TLS activa con Supabase sin revelar versiones de Node.js ni de PostgreSQL).
  - [ ] **Ausencia de `X-Powered-By`:** La cabecera `x-powered-by: Express` **NO** aparece en la respuesta.
  - [ ] **Presencia de `Strict-Transport-Security` (HSTS):** `strict-transport-security: max-age=31536000; includeSubDomains; preload`.
  - [ ] **Presencia de `Content-Security-Policy` (CSP):** `content-security-policy: default-src 'self'; script-src 'self'; ...` (sin `unsafe-inline`).
  - [ ] **Protección contra MIME Sniffing y Clickjacking:** `x-content-type-options: nosniff`, `x-frame-options: DENY` y `referrer-policy: no-referrer`.
