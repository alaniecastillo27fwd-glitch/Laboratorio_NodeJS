# Guía de Verificación Local y Control de Versiones (Fase 2)

Esta guía contiene los comandos exactos para verificar localmente la suite de pruebas criptográficas, la cadena de suministro (`npm audit`) y la higiene del repositorio Git antes de pasar a la Fase 3 (CI/CD y Despliegue en producción).

---

## 1. Ejecución de Pruebas Automatizadas (`node:test`)

```bash
npm test
```

## 2. Verificación de Cadena de Suministro (OWASP A03:2025)

```bash
# Instalar dependencias y generar package-lock.json (primera vez)
npm install

# Verificar instalación determinista desde package-lock.json
npm ci

# Auditar vulnerabilidades altas o críticas (debe reportar 0 high/critical)
npm audit --audit-level=high
```

## 3. Verificación de Secretos en Git (Sección 10 Checklist)

```bash
# Confirmar que .env está ignorado y no aparece en archivos por confirmar
git status --ignored

# Confirmar que .env jamás fue subido en ningún commit del historial
git log --all --full-history -- "**/.env" ".env"
```
*(La salida de `git log` debe estar completamente vacía).*

## 4. Guía de Commits Frecuentes y Descriptivos (Sección 5 - Fase 2)

```bash
git init
git add docs/ database/ .gitignore .env.example README.md
git commit -m "docs(phase-0-1): add deep research report, threat model STRIDE and PostgreSQL schema"

git add package.json src/config/ src/utils/logger.js src/middlewares/errorHandler.js server.js
git commit -m "feat(core): configure Express security headers, PostgreSQL pool timeouts and JSON logger"

git add src/utils/crypto.js
git commit -m "feat(crypto): implement Argon2id password hashing, AES-256-GCM encryption and SHA-256 token hashing"

git add src/models/ src/middlewares/ src/controllers/authController.js src/routes/authRoutes.js
git commit -m "feat(auth): implement JWT HttpOnly session, RBAC middleware, login rate-limiter and password reset"

git add src/controllers/noteController.js src/routes/noteRoutes.js src/controllers/profileController.js src/routes/profileRoutes.js src/controllers/adminController.js src/routes/adminRoutes.js src/app.js
git commit -m "feat(api): add IDOR-safe encrypted notes CRUD, masked profile and admin audit log endpoints"

git add frontend/ tests/
git commit -m "feat(frontend-tests): add React Vite SPA with CSP/HSTS headers and automated node:test security suite"
```
