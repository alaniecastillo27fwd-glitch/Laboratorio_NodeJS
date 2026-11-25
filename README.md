# SecureVault — Sistema Seguro en Node.js (OWASP Top 10:2025)

**SecureVault** es una aplicación web diseñada para almacenar y gestionar notas privadas cifradas y datos personales sensibles bajo los controles de seguridad del estándar **OWASP Top 10:2025**. El sistema aplica defensa en profundidad desde el diseño (modelo de amenazas STRIDE), hashing lento con sal (**Argon2id**) para contraseñas, cifrado autenticado (**AES-256-GCM**) con IV único por registro para datos confidenciales, tokens de recuperación hasheados (**SHA-256**), bitácora forense en JSON estructurado y un pipeline CI/CD automatizado.

---

## 1. Arquitectura Desplegada en Producción

El sistema opera bajo una arquitectura distribuida de tres capas con cifrado TLS 1.2/1.3 de extremo a extremo:

* **Frontend (SPA React + Vite en Vercel):** Distribución global en Edge CDN con HTTPS obligatorio, cabeceras de seguridad HTTP estrictas (`Content-Security-Policy` sin `unsafe-inline`, `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy` y `Permissions-Policy`) y comunicación con la API exclusivamente mediante cookies `HttpOnly` (`credentials: 'include'`), sin almacenar jamás tokens en `localStorage` ni `sessionStorage`.
* **Backend (Node.js 20 LTS + Express en Render):** API REST modular detrás del proxy inverso gestionado de Render (`app.set('trust proxy', 1)`), con reinicio automático ante fallos monitoreado vía `GET /health`, límite de tamaño de payload (`10kb`), validación de esquemas con **Zod**, limitación de tasa (`express-rate-limit`) y secretos inyectados desde el panel de entorno de la plataforma.
* **Base de Datos (PostgreSQL Gestionado en Supabase):** Esquema relacional endurecido con llaves primarias `UUID` v4 (`gen_random_uuid()`), conexión cifrada TLS obligatoria, restricciones de integridad `CHECK` en motor y tablas dedicadas para revocación de sesiones (`revoked_tokens`) y auditoría (`audit_logs`).

---

## 2. Estructura del Proyecto

```text
Laboratorio_NodeJS/
├── .github/
│   ├── dependabot.yml                 # Monitoreo semanal de dependencias en /backend y /frontend (A03)
│   └── workflows/
│       └── ci.yml                     # Pipeline CI: Gitleaks, npm ci, npm audit y node:test (A03/A08)
├── backend/                           # Backend Node.js LTS + Express desplegado en Render
│   ├── src/
│   │   ├── config/                    # db.js (Pool PostgreSQL con timeouts y TLS) y embeddedDb.js
│   │   ├── controllers/               # authController, noteController, profileController, adminController
│   │   ├── middlewares/               # authMiddleware (JWT HS256 + RBAC), rateLimiter, errorHandler
│   │   ├── models/                    # userModel, noteModel, auditModel (100% consultas parametrizadas)
│   │   ├── routes/                    # authRoutes, noteRoutes, profileRoutes, adminRoutes
│   │   ├── utils/                     # crypto.js (Argon2id, AES-256-GCM, SHA-256, HMAC) y logger.js
│   │   └── app.js
│   ├── tests/
│   │   └── security.test.js           # Suite automatizada con node:test
│   ├── .env.example                   # Plantilla de nombres de variables del backend (sin valores)
│   ├── package.json
│   └── server.js                      # Punto de entrada y manejo de unhandledRejection/uncaughtException
├── database/
│   └── schema.sql                     # Script DDL PostgreSQL / Supabase
├── docs/
│   ├── 00_Informe_Deep_Research.md    # Entregable Fase 0: Investigación de Despliegue
│   ├── 01_Diseno_y_Modelo_Amenazas.md # Entregable Fase 1: ER, Secuencia, DFD, Límites y STRIDE
│   ├── 02_Guia_Verificacion_Local.md  # Guía de pruebas y commits de Fase 2
│   ├── 03_Guia_Despliegue_Render.md   # Guía de despliegue Backend en Render
│   ├── 04_Guia_Despliegue_Vercel.md   # Guía de despliegue Frontend en Vercel
│   ├── 05_Guion_Pruebas_Seguridad_y_Ataques.md
│   ├── 06_Guia_Herramientas_Auditoria_Fase4.md
│   ├── 07_Decisiones_Criptograficas_y_Rotacion.md
│   ├── 08_Informe_Final_Seguridad_SecureVault.md
│   └── 09_Guion_Demo_10Min_y_Checklist_Final.md
├── frontend/                          # Aplicación React (Vite) desplegada en Vercel
│   ├── src/
│   │   ├── components/Navbar.jsx
│   │   ├── context/AuthContext.jsx
│   │   ├── pages/                     # Login, Register, ResetPassword, Notes, Profile, Admin
│   │   ├── routes/ProtectedRoute.jsx
│   │   ├── services/api.js
│   │   ├── App.jsx
│   │   └── main.jsx
│   ├── .env.example
│   ├── vercel.json                    # Rewrites SPA y cabeceras HTTP de seguridad (A+)
│   └── package.json
├── scripts/
│   └── start-dev.js                   # Iniciador conjunto Backend + Frontend para desarrollo
├── .gitignore                         # Exclusión estricta de .env, llaves y node_modules
└── README.md
```

---

## 3. Requisitos Previos

* **Node.js:** Versión **20.x LTS** o superior (`node -v`).
* **npm:** Versión 10.x o superior.
* **PostgreSQL:** Versión 15+ (local para desarrollo o proyecto en **Supabase** para producción).

---

## 4. Instalación y Ejecución Local Paso a Paso

### 4.1. Clonar el repositorio y preparar la base de datos local
```bash
git clone <URL_DEL_REPOSITORIO_GIT>
cd Laboratorio_NodeJS

# Ejecutar el esquema DDL en PostgreSQL local (base de datos Laboratorio_NodeJS)
psql -U postgres -d Laboratorio_NodeJS -f database/schema.sql
```

### 4.2. Configurar e iniciar el Backend (Express)
```bash
# 1. Instalar dependencias de forma determinista
npm ci

# 2. Crear archivo .env local a partir de la plantilla (excluido de Git)
cp .env.example .env

# 3. Generar llaves criptográficas únicas para tu entorno local y copiarlas en .env:
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"

# 4. Ejecutar suite de pruebas de seguridad y auditoría de dependencias
npm test
npm audit --audit-level=high

# 5. Iniciar servidor backend en desarrollo (http://localhost:3000)
npm run dev
```

### 4.3. Configurar e iniciar el Frontend (React + Vite)
```bash
cd frontend
npm ci
cp .env.example .env
# Configurar VITE_API_URL=http://localhost:3000 en frontend/.env
npm run dev
```

---

## 5. Variables de Entorno Requeridas (Solo Nombres — Sin Valores)

> **Importante (OWASP A02 / A04):** Jamás almacene valores reales en archivos versionados. En producción, configure estas variables en el panel de secretos de **Render** y **Vercel**.

### Backend (`.env` local / Panel *Environment Variables* en Render)

| Nombre de Variable | Requerida | Descripción Técnica |
| :--- | :---: | :--- |
| `NODE_ENV` | Sí | Entorno de ejecución (`development`, `test` o `production`). En `production` activa TLS a BD, cookies `Secure; SameSite=None` y oculta *stack traces*. |
| `PORT` | Sí | Puerto HTTP de escucha del servidor Express (ej. `3000` en local, `10000` en Render). |
| `DATABASE_URL` | Sí | URI de conexión a PostgreSQL (local en desarrollo; URI de Supabase con `sslmode=require` en producción). |
| `FRONTEND_URL` | Sí | Origen exacto autorizado por la política CORS (`credentials: true`) y Helmet CSP `connect-src`. |
| `ENCRYPTION_KEY` | Sí | Llave maestra simétrica de 32 bytes (256 bits) codificada en Base64 para el cifrado autenticado `AES-256-GCM`. |
| `JWT_SECRET` | Sí | Secreto criptográfico de alta entropía (64 bytes hex) para firmar y verificar tokens de sesión JWT con algoritmo fijo `HS256`. |
| `ENCRYPTION_KEY_V1` | Opcional | Llave de versión 1 para soporte de rotación de llaves sin pérdida de datos. |
| `ENCRYPTION_KEY_V2` | Opcional | Llave de versión 2 para recifrado progresivo durante la rotación de llaves. |
| `ACTIVE_KEY_VERSION` | Opcional | Versión activa de la llave maestra de cifrado (por defecto `1`). |

### Frontend (`frontend/.env` local / Panel *Environment Variables* en Vercel)

| Nombre de Variable | Requerida | Descripción Técnica |
| :--- | :---: | :--- |
| `VITE_API_URL` | Sí | URL pública HTTPS del backend desplegado en Render (sin barra `/` final). |

---

## 6. Pasos Reproducibles de Despliegue a Producción

1. **Base de Datos en Supabase:**
   * Crear un nuevo proyecto en [Supabase](https://supabase.com/), abrir el **SQL Editor** y ejecutar íntegramente el script [`database/schema.sql`](database/schema.sql).
   * En *Database Settings*, activar **Enforce SSL on incoming connections** y copiar la cadena de conexión URI (modo Transaction/Session Pooler con TLS).
2. **Pipeline CI/CD en GitHub Actions:**
   * Hacer `git push origin main`. El workflow [`.github/workflows/ci.yml`](.github/workflows/ci.yml) ejecutará automáticamente el escaneo de secretos con **Gitleaks**, la instalación con `npm ci`, la auditoría `npm audit --audit-level=high`, la suite `npm test` y el build de producción de Vite.
3. **Backend en Render:**
   * Crear un **Web Service** en [Render](https://render.com/) conectado a la rama `main`.
   * Configurar **Build Command:** `npm ci`, **Start Command:** `node server.js` y **Health Check Path:** `/health`.
   * Cargar en **Environment Variables**: `NODE_ENV=production`, `DATABASE_URL`, `ENCRYPTION_KEY`, `JWT_SECRET` y `FRONTEND_URL`.
4. **Frontend en Vercel y Sincronización CORS:**
   * Importar el repositorio en [Vercel](https://vercel.com/) seleccionando **Root Directory:** `frontend` y **Framework Preset:** `Vite`.
   * Configurar la variable `VITE_API_URL` apuntando a la URL HTTPS de Render (`https://<servicio>.onrender.com`) y desplegar.
   * Actualizar `FRONTEND_URL` en Render con el dominio HTTPS final asignado por Vercel (`https://<proyecto>.vercel.app`) y reiniciar el servicio.

---

## 7. Resumen de Controles de Seguridad (OWASP Top 10:2025 + Criptografía)

| Categoría / Control | Implementación Verificable en SecureVault |
| :--- | :--- |
| **A01:2025 Broken Access Control** | Denegación por defecto (`requireAuth`), verificación de rol en servidor (`requireRole('admin')`) y filtro obligatorio de propiedad `WHERE id = $1 AND owner_id = $2` en cada operación de notas para erradicar **IDOR**. |
| **A02:2025 Security Misconfiguration** | `app.disable('x-powered-by')`, `helmet` con CSP estricta y HSTS, CORS restringido a `FRONTEND_URL`, `NODE_ENV=production` y cookies `HttpOnly; Secure; SameSite`. |
| **A03:2025 Software Supply Chain Failures** | `package-lock.json` versionado, instalación con `npm ci`, auditoría `npm audit --audit-level=high` en GitHub Actions y **Dependabot** semanal activo. |
| **A04:2025 Cryptographic Failures** | Contraseñas con **Argon2id** (`19 MiB`, `t=2`, `p=1`), notas y dato sensible con **AES-256-GCM** (IV único de 12B + AuthTag de 16B), tokens de recuperación con **SHA-256** (`crypto.randomBytes(32)`) y firmas con **HMAC-SHA256** (`timingSafeEqual`). |
| **A05:2025 Injection (incluye XSS)** | Consultas SQL 100% parametrizadas (`$1, $2`), validación estricta de entrada con esquemas **Zod**, CSP que bloquea scripts inline y cero uso de `dangerouslySetInnerHTML`. |
| **A06:2025 Insecure Design** | Modelo de amenazas **STRIDE** documentado, límite global `express.json({ limit: '10kb' })`, cuota máxima de 50 notas por usuario y límites de longitud en títulos, notas y contraseñas. |
| **A07:2025 Authentication Failures** | `express-rate-limit` (`HTTP 429` tras 5 intentos / 15 min), bloqueo progresivo en BD (`failed_login_attempts`, `locked_until`), errores genéricos anti-enumeración y revocación de `jti` en logout. |
| **A08:2025 Software or Data Integrity Failures** | Verificación de firma JWT forzando `algorithms: ['HS256']`, verificación de integridad GMAC de 16 bytes en AES-GCM y pipeline CI que bloquea despliegues si fallan las pruebas. |
| **A09:2025 Security Logging & Alerting Failures** | Bitácora persistente en `audit_logs` y logs JSON en `winston` con sanitización recursiva (`[REDACTED]` para secretos) y alerta automática `BRUTE_FORCE_DETECTED` ante 5 fallos consecutivos. |
| **A10:2025 Mishandling of Exceptional Conditions** | Manejador global de errores *fail-closed* con respuestas genéricas, timeouts de 5,000 ms en pool PostgreSQL y captura de `unhandledRejection` / `uncaughtException` con cierre limpio. |
