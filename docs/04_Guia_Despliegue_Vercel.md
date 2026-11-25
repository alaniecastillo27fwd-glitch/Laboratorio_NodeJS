# Guía Paso a Paso: Despliegue Seguro del Frontend en Vercel y Sincronización Cross-Site (Fase 3)

Esta guía documenta el despliegue en producción del frontend de **SecureVault** (React + Vite) en **Vercel**, la configuración de cabeceras HTTP para obtener calificación **A / A+** en `securityheaders.com` (**OWASP A02 / A05**) y la validación de cookies `HttpOnly; Secure; SameSite=None` hacia el backend en **Render**.

---

## 1. Archivo `frontend/vercel.json` Definitivo (Calificación A+ en SecurityHeaders.com)

El archivo `frontend/vercel.json` configura el enrutamiento SPA de React Router y las 6 cabeceras de seguridad evaluadas por `securityheaders.com` y Mozilla Observatory, sin `unsafe-inline` en `script-src` y sin referencias a `localhost`:

```json
{
  "rewrites": [
    {
      "source": "/(.*)",
      "destination": "/index.html"
    }
  ],
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        {
          "key": "Content-Security-Policy",
          "value": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self' https://*.onrender.com; font-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; upgrade-insecure-requests"
        },
        {
          "key": "Strict-Transport-Security",
          "value": "max-age=31536000; includeSubDomains; preload"
        },
        {
          "key": "X-Content-Type-Options",
          "value": "nosniff"
        },
        {
          "key": "X-Frame-Options",
          "value": "DENY"
        },
        {
          "key": "Referrer-Policy",
          "value": "strict-origin-when-cross-origin"
        },
        {
          "key": "Permissions-Policy",
          "value": "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
        }
      ]
    }
  ]
}
```

> **Tip opcional de endurecimiento CSP:** Cuando ya tengas la URL exacta de tu servicio en Render (p. ej. `https://securevault-api-xxxx.onrender.com`), puedes reemplazar `https://*.onrender.com` en `connect-src` por tu subdominio exacto de Render.

---

## 2. Pasos de Despliegue en Vercel

1. Inicia sesión en [Vercel Dashboard](https://vercel.com/dashboard) -> **Add New...** -> **Project**.
2. Selecciona **Import Git Repository** y elige tu repositorio de GitHub (`SecureVault` / `Laboratorio_NodeJS`).
3. En la pantalla **Configure Project**, establece los siguientes valores exactos:
   * **Project Name:** `securevault-frontend`
   * **Framework Preset:** `Vite`
   * **Root Directory:** Haz clic en **Edit** y selecciona la carpeta **`frontend`**.
   * **Build and Output Settings:**
     * Build Command: `npm run build`
     * Output Directory: `dist`
     * Install Command: `npm ci`
4. Despliega la sección **Environment Variables** y agrega la única variable requerida por el frontend (nunca agregues secretos de BD ni llaves privadas en `VITE_*`):

| Nombre de Variable | Valor en Producción (Ejemplo) | Entornos |
| :--- | :--- | :--- |
| `VITE_API_URL` | `https://securevault-api-xxxx.onrender.com` *(sin barra `/` al final y nunca `localhost`)* | Production, Preview |

5. Haz clic en **Deploy** y espera (~40 segundos) a que Vercel genere tu dominio público HTTPS (ej. `https://securevault-frontend.vercel.app`).

---

## 3. Actualización Cruzada de CORS en Render

Dado que Vercel (`*.vercel.app`) y Render (`*.onrender.com`) operan en dominios de nivel superior distintos (*cross-site*), el navegador solo permitirá el intercambio de cookies `HttpOnly; Secure; SameSite=None` con `credentials: 'include'` si el servidor Express devuelve exactamente el dominio de Vercel en `Access-Control-Allow-Origin`:

1. Copia la URL pública final generada por Vercel (ej. `https://securevault-frontend.vercel.app`, **sin barra `/` final**).
2. Abre tu servicio `securevault-api` en [Render Dashboard](https://dashboard.render.com/) -> pestaña **Environment**.
3. Edita la variable `FRONTEND_URL` y pega exactamente el dominio de Vercel:
   ```text
   FRONTEND_URL=https://securevault-frontend.vercel.app
   ```
4. Haz clic en **Save, Rebuild, and Deploy** (o **Manual Deploy -> Restart Service**) y espera a que el estado vuelva a **`Live`**.

---

## 4. Prueba de Humo en Producción (5 Pasos en Chrome DevTools)

Abre tu URL de producción de Vercel (`https://securevault-frontend.vercel.app`) en una ventana limpia del navegador con **Chrome DevTools (`F12`)** abierto:

1. **Paso 1 — Registro (`RF-01`) y Verificación de Cabeceras CORS:**
   * Ve a `/register` y crea un usuario con una contraseña que cumpla la política (mín. 10 caracteres, mayúscula, minúscula, número y símbolo) y un teléfono/documento de prueba (`506-8888-1234`).
   * En **DevTools -> Network**, selecciona la petición `POST /api/auth/register` y confirma que devuelve **`201 Created`** con las cabeceras `Access-Control-Allow-Origin: https://securevault-frontend.vercel.app` y `Access-Control-Allow-Credentials: true`.
2. **Paso 2 — Login (`RF-02`) e Inspección de Flags de Cookie (`HttpOnly`, `Secure`, `SameSite=None`):**
   * Inicia sesión en `/login`.
   * En **DevTools -> Network -> `POST /api/auth/login` -> Headers**, verifica la cabecera de respuesta:
     `Set-Cookie: sv_token=eyJ...; Max-Age=1800; Path=/; HttpOnly; Secure; SameSite=None`
   * Ve a **DevTools -> Application -> Storage -> Cookies** (o ejecuta `document.cookie` en la pestaña **Console**): confirma que `document.cookie` devuelve cadena vacía `""` (demostrando que `HttpOnly` impide el robo del JWT mediante XSS).
3. **Paso 3 — CRUD de Notas Cifradas (`RF-04`) y Verificación en Supabase (`OWASP A04`):**
   * En `/notes`, crea una nota privada, edítala y verifica que se lista descifrada en pantalla.
   * Abre el **Table Editor** de **Supabase** en la tabla `notes` y verifica que la columna `content_enc` contiene únicamente una cadena Base64 ilegible (`IV + AuthTag + Ciphertext`) y que en `users.password_hash` el hash comienza con `$argon2id$`.
4. **Paso 4 — Perfil Enmascarado (`RF-05`) y Revelado Controlado:**
   * Navega a `/profile`: confirma que el dato sensible aparece enmascarado como `***-***-1234`.
   * Haz clic en **"Revelar Dato Completo"** (`GET /api/profile?reveal=true`) y comprueba que muestra `506-8888-1234` únicamente al propietario autenticado.
5. **Paso 5 — Cierre de Sesión con Revocación Server-Side (`RF-02`):**
   * Haz clic en **"Cerrar Sesión"** (`POST /api/auth/logout`).
   * Verifica en **Network** que la cookie `sv_token` es limpiada (`Max-Age=0`), que el `jti` quedó registrado en la tabla `revoked_tokens` de Supabase y que al intentar navegar manualmente a `/notes` o `/profile` eres redirigido automáticamente a `/login`.
