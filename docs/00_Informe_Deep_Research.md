# Informe de Deep Research: Despliegue Seguro a Producción en Node.js
**Proyecto:** SecureVault — Sistema Seguro en Node.js (OWASP Top 10:2025)  
**Fase:** 0 — Deep Research previo al despliegue  
**Stack Arquitectónico:** React/Vite (Vercel) + Node.js LTS/Express (Render) + PostgreSQL (Supabase) + GitHub Actions (CI/CD)

---

## 1. Resumen Ejecutivo

En el desarrollo de software moderno, una aplicación que almacena información confidencial como **SecureVault** no puede considerarse segura hasta que opera en un entorno de producción endurecido, accesible públicamente bajo cifrado estricto y resistente a vectores de ataque reales. El presente informe de *Deep Research* evalúa los paradigmas de infraestructura actuales (PaaS, Contenedores y VPS/IaaS) bajo los controles del estándar **OWASP Top 10:2025** [1], estableciendo los cimientos arquitectónicos para el despliegue del sistema.

Con el objetivo de minimizar la superficie de ataque del sistema operativo y evitar fallos de configuración (*Security Misconfiguration* - A02), se ha diseñado una arquitectura distribuida basada en servicios PaaS y DBaaS con planes gratuitos vigentes: **Vercel** para la distribución global del frontend en React (Vite) [7], **Render** para la ejecución gestionada de la API REST en Node.js LTS + Express [6], y **Supabase** para la persistencia relacional en PostgreSQL [8]. Esta topología delega la terminación TLS automatizada (Let's Encrypt) [9] y la supervisión de procesos a la infraestructura gestionada, permitiendo concentrar los esfuerzos de ingeniería en los controles críticos de la capa de aplicación: hashing de contraseñas con Argon2id [3], cifrado autenticado AES-256-GCM con gestión externa de llaves [3], validación continua de dependencias mediante **GitHub Actions** [10] y verificación empírica post-despliegue con herramientas DAST [12].

---

## 2. Respuestas a las Preguntas de Investigación

### 2.1. PaaS vs. Contenedores (Docker) vs. VPS/IaaS

La elección del modelo de despliegue para una aplicación Node.js crítica como **SecureVault** define el límite del modelo de responsabilidad compartida, la superficie de ataque del sistema operativo y la carga operativa de mantenimiento.

#### Plataforma como Servicio (PaaS) — Ej.: Render, Railway, Fly.io, Heroku
El proveedor gestiona la infraestructura subyacente, el sistema operativo, el entorno de ejecución, el balanceo de carga y la terminación TLS [6].
* **Ventajas:** Despliegue continuo integrado desde Git (`git push`), aprovisionamiento y renovación automatizada de certificados TLS, reinicio automático de procesos ante fallos y paneles nativos para la inyección de variables de entorno sin exponer archivos `.env` [3, 6]. Reduce drásticamente el riesgo de *Security Misconfiguration* (OWASP A02) a nivel de red y host [1].
* **Desventajas:** Restricciones en la configuración a bajo nivel del kernel o red, políticas de suspensión (*spin-down*) en niveles gratuitos que introducen latencia de arranque en frío (*cold start*), y dependencia de las abstracciones del proveedor [6].
* **Costos:** Modelos *freemium* o facturación por consumo de recursos (RAM/vCPU por segundo o tarifas planas mensuales por servicio). Costo operativo (OpEx) de administración cercano a cero.
* **Nivel de control:** Bajo sobre la infraestructura; alto sobre la configuración de la aplicación.

#### Contenedores (Docker) — Ej.: Imágenes OCI desplegadas en registros o motores de contenedores
Empaquetan el código de la aplicación junto con el runtime exacto de Node.js, bibliotecas del sistema y dependencias (`node_modules` instalados vía `npm ci`) en una unidad aislada e inmutable [2].
* **Ventajas:** Paridad exacta entre entornos de desarrollo, CI/CD y producción. Permite aplicar controles de endurecimiento (*hardening*) recomendados por OWASP, como ejecución con usuario sin privilegios (`USER node`), sistemas de archivos de solo lectura, imágenes base mínimas (Alpine/Distroless) y eliminación de capacidades innecesarias del kernel Linux [2].
* **Desventajas:** No constituye una infraestructura de alojamiento por sí mismo; requiere un entorno de ejecución subyacente (un PaaS con soporte Docker, un orquestador o un VPS). Introduce la obligación de escanear vulnerabilidades en las capas de la imagen base (OWASP A03) [1, 2].
* **Costos:** El empaquetado es gratuito; el costo en producción depende directamente del cómputo donde se aloje el contenedor.
* **Nivel de control:** Alto sobre el entorno de ejecución, dependencias del sistema operativo invitado y aislamiento del proceso; nulo sobre el hardware físico.

#### Servidor Privado Virtual / Infraestructura como Servicio (VPS/IaaS) — Ej.: AWS EC2, DigitalOcean Droplets, Azure VM
El proveedor entrega una máquina virtual con acceso administrativo (`root`/SSH) sobre una imagen de sistema operativo.
* **Ventajas:** Control absoluto de la pila tecnológica. Permite configurar reglas de firewall a nivel de kernel (`iptables`/`ufw`), instalar y ajustar proxies inversos dedicados (Nginx/Caddy), configurar demonios de gestión de procesos (`systemd` o PM2) y diseñar redes privadas virtuales (VPC) a medida [4].
* **Desventajas:** Alta carga operativa y mayor riesgo de errores de configuración (OWASP A02) [1]. El administrador es enteramente responsable de aplicar parches de seguridad del SO, asegurar el servicio SSH, renovar certificados TLS (Certbot), rotar logs y configurar la supervisión de procesos.
* **Costos:** Tarifa fija mensual o por hora de instancia activa, independientemente de si la aplicación recibe tráfico, más costos asociados a almacenamiento de bloques y transferencia de red saliente (*egress*).
* **Nivel de control:** Total desde el sistema operativo invitado hacia arriba.

---

### 2.2. Comparativa de plataformas con plan gratuito vigente

La siguiente tabla contrasta las tres plataformas seleccionadas para la arquitectura distribuida de **SecureVault**: **Vercel** (Frontend React), **Render** (Backend Node.js/Express) y **Supabase** (Base de datos PostgreSQL gestionada).

| Plataforma | Límites del plan gratuito | ¿Duerme por inactividad? | Soporte de BD | HTTPS automático | Regiones disponibles |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Render** (Plan *Free* — Web Services) | **Web Services:** 512 MB RAM, 0.1 vCPU compartida, 750 horas de instancia/mes y 100 GB de ancho de banda saliente/mes [6]. **Render Postgres (Free):** 1 GB de almacenamiento, expira a los 30 días de su creación [6]. | **Sí.** Los servicios web gratuitos entran en suspensión (*spin down*) tras **15 minutos** sin recibir tráfico entrante; la siguiente petición experimenta una demora de arranque de hasta ~1 minuto [6]. | **Sí.** Ofrece PostgreSQL gestionado y Key Value (compatible con Redis), aunque la instancia gratuita de PostgreSQL es efímera (expira tras 30 días) y no incluye respaldos [6]. | **Sí.** Emisión y renovación automática de certificados TLS mediante Let's Encrypt con redirección HTTP a HTTPS por defecto [6, 9]. | Oregon (US West), Ohio (US East), Virginia (US East), Frankfurt (EU Central), Singapur (Southeast Asia) [6]. |
| **Vercel** (Plan *Hobby*) | Uso estrictamente no comercial. Transferencia en red (*Fast Data Transfer*): 100 GB/mes; hasta 1 millón de invocaciones de *Edge/Serverless Functions* y tiempo máximo de ejecución de función configurable hasta 60s [7]. | **No aplica a estáticos (CDN).** Los activos de React se sirven desde la Edge Network sin suspensión. Las funciones *Serverless* escalan a cero cuando no hay peticiones y presentan un breve *cold start* al invocarse [7]. | **Sí (vía integraciones).** Ofrece almacenamiento Postgres, KV y Blob mediante proveedores nativos integrados en el Vercel Marketplace (Neon, Supabase, Upstash) con niveles gratuitos [7]. | **Sí.** Aprovisionamiento automático de certificados TLS (Let's Encrypt) para dominios `.vercel.app` y personalizados, con HSTS habilitado [7, 9]. | Red CDN Edge global para activos estáticos; ejecución de funciones en región por defecto (`iad1` Washington D.C. en plan Hobby) [7]. |
| **Supabase** (Plan *Free*) | Hasta 2 proyectos activos. **500 MB** de almacenamiento en base de datos PostgreSQL, CPU ARM compartida, 1 GB de almacenamiento de archivos, 5 GB de ancho de banda (*egress*) y hasta 50,000 usuarios activos mensuales (MAU) en Auth [8]. | **Sí.** Los proyectos en el plan gratuito se pausan automáticamente tras **7 días** consecutivos de inactividad; requieren reactivación desde el panel de control [8]. | **Sí (Nativo).** Motor PostgreSQL completo con soporte de cifrado TLS en tránsito, *Row Level Security* (RLS), extensiones (`pgcrypto`) y *connection pooling* con Supavisor [8]. | **Sí.** Todas las APIs REST/Auth expuestas y endpoints del proyecto operan exclusivamente sobre HTTPS/TLS; soporta conexiones SSL/TLS forzadas hacia PostgreSQL [8]. | Múltiples regiones sobre infraestructura AWS en América (US East/West, Canadá, São Paulo), Europa (Frankfurt, Londres, Irlanda, Estocolmo, París, Zúrich), Asia-Pacífico y Oceanía [8]. |

---

### 2.3. Gestión de variables de entorno y secretos en producción

En producción, las credenciales de base de datos, secretos de firma JWT y llaves maestras de cifrado AES-256-GCM se inyectan directamente como variables de entorno en la memoria del proceso desde el plano de control del PaaS (Render) o mediante un gestor de secretos [3, 6]. Un **gestor de secretos** (p. ej., AWS Secrets Manager, HashiCorp Vault o Doppler) es un sistema centralizado que almacena, cifra en reposo, audita el acceso y automatiza la rotación de credenciales dinámicas [3]. Depender de un archivo `.env` físico en producción es insuficiente e inseguro (OWASP A02 y A04): carece de trazabilidad de auditoría, dificulta la rotación sin redespliegue, permanece expuesto en texto plano dentro del sistema de archivos ante vulnerabilidades de *Path Traversal* y presenta alto riesgo de filtración accidental en el historial de Git [1, 2, 3].

---

### 2.4. Certificados TLS, Let's Encrypt y HSTS

Un **certificado TLS** (X.509) es un documento criptográfico firmado digitalmente por una Autoridad de Certificación (CA) que vincula una clave pública con un dominio verificable, garantizando autenticación del servidor, confidencialidad e integridad en tránsito (TLS 1.2/1.3) para mitigar fallos criptográficos (OWASP A04) [1, 3]. **Let's Encrypt** es una CA automatizada que emplea el protocolo **ACME** (*Automated Certificate Management Environment*): plataformas como Render y Vercel demuestran el control del dominio resolviendo desafíos HTTP-01 o DNS-01, automatizando la emisión y renovación periódica (cada 90 días) sin intervención humana [9]. Complementariamente, la cabecera **HSTS** (`Strict-Transport-Security`, configurada en Express mediante `helmet`) instruye al navegador del cliente a forzar conexiones exclusivamente sobre HTTPS durante un periodo definido (`max-age`), bloqueando ataques de degradación de protocolo (*SSL Stripping*) y secuestro de cookies en primera conexión [3, 11].

---

### 2.5. Proxy inverso y `trust proxy` en Express

Un **proxy inverso** (como Nginx, Caddy o el balanceador perimetral de Render) es un servidor intermediario situado frente al proceso de Node.js que recibe las peticiones de Internet, gestiona la terminación TLS, mitiga ataques DoS, comprime respuestas y encamina el tráfico hacia el puerto interno de Express mediante HTTP plano [4]. Al existir este salto intermedio, Node.js percibe que todas las conexiones provienen de la IP interna del proxy y sin cifrado directo. Configurar `app.set('trust proxy', 1)` indica a Express que confíe en el primer salto del proxy y lea las cabeceras `X-Forwarded-For` y `X-Forwarded-Proto` [4]. Técnicamente, esto es indispensable para que `req.secure` evalúe a `true` (permitiendo emitir cookies de sesión con el atributo `Secure`) y para que el *rate limiting* (OWASP A07) identifique la IP real del cliente en lugar de bloquear globalmente al proxy [1, 4].

---

### 2.6. Gestores de procesos (PM2, systemd)

Dado que Node.js se ejecuta en un único hilo de ejecución (*single-threaded event loop*), cualquier excepción no controlada o agotamiento de memoria termina el proceso abruptamente, provocando caída del servicio (OWASP A10) [1, 2, 5]. Los **gestores de procesos** como **PM2** o el demonio del sistema operativo **`systemd`** resuelven este problema en servidores VPS/IaaS: monitorizan la salud del proceso, lo reinician automáticamente ante fallos, inyectan variables de entorno, rotan archivos de log y, en el caso de PM2, permiten escalar horizontalmente en modo clúster aprovechando múltiples núcleos de CPU [4]. Sin embargo, **dejan de ser necesarios** al desplegar en contenedores Docker u orquestadores/PaaS como **Render**: en estos entornos, el propio plano de control supervisa el ciclo de vida del contenedor como PID 1, captura los flujos estándar (`stdout`/`stderr`) y reemplaza automáticamente cualquier instancia caída [2, 4, 6].

---

### 2.7. CI/CD con GitHub Actions

La **Integración Continua (CI)** y el **Despliegue Continuo (CD)** automatizan la validación e integración de código hacia producción, mitigando fallos de integridad y de cadena de suministro (OWASP A03 y A08) [1, 10]. En **GitHub Actions**, un pipeline mínimo seguro se dispara ante eventos `push` o `pull_request` hacia la rama principal y ejecuta secuencialmente:
1. **Aprovisionamiento:** Descarga del repositorio (`actions/checkout`) y configuración del runtime Node.js LTS (`actions/setup-node`) [10].
2. **Instalación determinista:** Ejecución de `npm ci`, que instala las versiones exactas fijadas en `package-lock.json` y aborta si existen discrepancias con `package.json` [2, 10].
3. **Verificación funcional:** Ejecución de pruebas automatizadas unitarias y de integración (`npm test`).
4. **Auditoría de dependencias:** Ejecución de `npm audit --audit-level=high`, bloqueando el pipeline si se detectan vulnerabilidades altas o críticas [2, 5].
5. **Despliegue (CD):** Solo si los pasos previos retornan código `0`, se autoriza el despliegue automático hacia Render y Vercel mediante *deploy hooks* o integración nativa con GitHub [6, 7, 10].

---

### 2.8. Bases de datos gestionadas y conexión segura

Proveedores DBaaS como **Supabase** (PostgreSQL dedicado con Supavisor), **Neon** (PostgreSQL *serverless*) y **MongoDB Atlas** (NoSQL) abstraen el mantenimiento del motor y los respaldos, pero exigen endurecer el acceso desde el backend en Render [3, 8]:
* **TLS obligatorio en tránsito:** La conexión entre el cliente `pg` de Node.js y Supabase debe forzar cifrado TLS 1.2/1.3 (`sslmode=verify-full` junto al certificado raíz de la CA del proyecto) y activar *SSL Enforcement* en el servidor para rechazar conexiones en texto plano (OWASP A04) [1, 3, 8].
* **Restricciones de red/IP:** Configurar listas blancas de direcciones IP (*Network Restrictions*) limitando el acceso exclusivamente a las IPs estáticas de salida de Render, o evitar la exposición directa del puerto `5432` empleando el *connection pooler* autenticado [8].
* **Mínimo privilegio:** Prohibir el uso del superusuario `postgres` en la API. Se debe crear un rol específico para SecureVault que posea únicamente permisos `SELECT, INSERT, UPDATE, DELETE` sobre el esquema de la aplicación, sin privilegios `DDL` ni `SUPERUSER` (OWASP A01) [1, 3].

---

### 2.9. Desarrollo vs. Producción en Node.js

El paso de desarrollo a producción requiere endurecer el entorno de ejecución en Render para mitigar *Security Misconfiguration* y *Mishandling of Exceptional Conditions* (OWASP A02, A09 y A10) [1, 2, 4]:
* **`NODE_ENV=production`:** Activa el almacenamiento en caché de plantillas, optimiza el rendimiento en Express y reduce la verbosidad de diagnósticos internos [4, 5].
* **Logs estructurados:** Reemplazar `console.log` por registros en formato **JSON** mediante `winston`, capturando eventos de seguridad (logins fallidos, cambios de rol) y filtrando estrictamente contraseñas, tokens, hashes y textos planos antes de escribir en `stdout` [1, 2].
* **Manejo de errores:** Implementar un middleware global que funcione en modo *fail-closed*, registrando el error internamente pero devolviendo al cliente mensajes HTTP genéricos sin exponer *stack traces* ni rutas del servidor [1, 2, 4].
* **CORS restringido:** Configurar el middleware `cors` permitiendo únicamente el origen exacto del frontend en Vercel (`https://securevault.vercel.app`), rechazando comodines (`*`) [2].
* **Cookies seguras:** Emitir cookies con `HttpOnly` (inaccesibles vía `document.cookie` ante XSS), `Secure` (transmisión exclusiva por HTTPS) y `SameSite=Strict` o `Lax` (protección contra CSRF) [2, 4].

---

### 2.10. Verificaciones de seguridad post-despliegue

Una vez publicada la aplicación en producción, es obligatorio validar empíricamente los controles sobre la URL pública antes de dar por concluido el despliegue:
* **OWASP ZAP (Baseline Scan):** Ejecuta un análisis dinámico (DAST) pasivo y de rastreo (*spidering*) contra los endpoints de Render y Vercel. Detecta ausencia de tokens anti-CSRF, fugas de versión en cabeceras (`Server`, `X-Powered-By`), configuraciones débiles de cookies y posibles vectores de inyección o XSS (OWASP A01, A02, A05) [1, 12].
* **Qualys SSL Labs (`ssllabs.com/ssltest`):** Audita la cadena de certificados TLS de Render/Vercel, verifica que solo se acepten protocolos seguros (TLS 1.2 y TLS 1.3), valida la robustez de las suites de cifrado (*Forward Secrecy*) y comprueba la resistencia frente a ataques criptográficos (OWASP A04) [1, 13].
* **SecurityHeaders.com / Mozilla Observatory:** Inspecciona las cabeceras de respuesta HTTP generadas por `helmet`, calificando la política `Content-Security-Policy` (CSP), `Strict-Transport-Security` (HSTS), `X-Content-Type-Options: nosniff` y `Referrer-Policy` [11].
* **`npm audit` y pruebas manuales:** Confirma cero vulnerabilidades altas/críticas en el árbol de dependencias en producción (OWASP A03) y se complementa con pruebas manuales de autorización (IDOR recibiendo `403/404`) y bloqueo por fuerza bruta (`HTTP 429`) [1, 2, 5].

---

## 3. Plan de Despliegue Propuesto para SecureVault

### 3.1. Plataforma elegida y justificación técnica
Con base en el análisis comparativo de la Sección 2.2, se descarta el uso de un VPS/IaaS por su alta carga operativa de parcheo y se adopta una arquitectura desacoplada sobre **Vercel + Render + Supabase**:
* **Frontend en Vercel (Plan Hobby):** Sirve los activos estáticos compilados de React desde una red CDN Edge sin suspensión por inactividad (*zero spin-down*), con aprovisionamiento TLS automático y soporte para cabeceras HTTP de seguridad e integridad de subrecursos (SRI - OWASP A08) [1, 7]. Para evitar problemas de cookies *cross-site* entre `*.vercel.app` y `*.onrender.com`, Vercel enruta las llamadas `/api/*` hacia Render mediante una regla de *Rewrite* en `vercel.json`, haciendo que el navegador opere bajo un único origen (*same-origin*) y permitiendo cookies `HttpOnly; Secure; SameSite=Strict`.
* **Backend en Render (Plan Free Web Service):** Ejecuta el servidor Node.js LTS + Express detrás de un balanceador perimetral gestionado con HTTPS obligatorio y reinicio automático ante caídas (reemplazando a PM2/`systemd`) [4, 6]. Su integración nativa con GitHub y su panel aislado de variables de entorno ofrecen un entorno seguro para la evaluación.
* **Base de datos en Supabase (Plan Free):** Supera la limitación crítica de la base de datos gratuita de Render (que expira a los 30 días) [6]. Supabase proporciona 500 MB persistentes en PostgreSQL con soporte nativo de conexiones TLS forzadas y *connection pooling* (Supavisor) [8].

### 3.2. Diagrama de arquitectura y flujo de red

```text
+-----------------------------------------------------------------------------+
|                           USUARIO / NAVEGADOR WEB                           |
+-----------------------------------------------------------------------------+
         |                                                    |
         | 1. Carga SPA React (HTTPS / TLS 1.3 + HSTS + SRI)  | 2. Peticiones API REST (/api/* via HTTPS)
         v                                                    |    Cookies: HttpOnly, Secure, SameSite=Strict
+-----------------------------------+                         |    CORS Origin: https://securevault.vercel.app
|       VERCEL (Edge Network)       |                         v
|   Frontend React (Vite Build)     |      +----------------------------------+
|   + Rewrite Proxy (/api/*)        |----->|     RENDER (PaaS Web Service)    |
+-----------------------------------+      |  [ Proxy Inverso / Load Balancer]|
                                           |    - Terminación TLS (ACME)      |
                                           |    - Cabeceras X-Forwarded-*     |
                                           +----------------------------------+
                                                              |
                                                              | HTTP interno (app.set('trust proxy', 1))
                                                              v
                                           +----------------------------------+
                                           |    Contenedor Node.js LTS        |
                                           |    API Express (NODE_ENV=prod)   |
                                           |    - Helmet (CSP, HSTS)          |
                                           |    - Rate Limiter (OWASP A07)    |
                                           |    - Argon2id + AES-256-GCM      |
                                           |    - Logs JSON (Winston)         |
                                           +----------------------------------+
                                                              |
                                                              | 3. Conexión PostgreSQL Cifrada
                                                              |    (TLS 1.2/1.3 - sslmode=verify-full)
                                                              v
                                           +----------------------------------+
                                           |      SUPABASE (Managed DBaaS)    |
                                           |  PostgreSQL + Supavisor Pooler   |
                                           |  - Usuario de mínimo privilegio  |
                                           |  - Notas/Datos en AES-256-GCM    |
                                           |  - Contraseñas en Hash Argon2id  |
                                           +----------------------------------+
```

### 3.3. Estrategia de manejo de secretos y rotación de llaves
Ningún secreto ni archivo `.env` se almacena en el repositorio Git (excluido en `.gitignore`). Las variables críticas se inyectan directamente en el panel **Environment Variables** de Render [3, 6]:
* `NODE_ENV=production`
* `DATABASE_URL`: Cadena de conexión TLS hacia Supabase.
* `ENCRYPTION_KEY_V1`: Llave maestra de 32 bytes (256 bits) en Base64 generada criptográficamente con `crypto.randomBytes(32)` para AES-256-GCM [5].
* `JWT_SECRET`: Llave de alta entropía para firma de tokens JWT (`HS256`).

**Análisis de pérdida y rotación de llaves (Sección 4 de la guía):** Si la llave maestra de cifrado se pierde sin respaldo, los datos cifrados con AES-256-GCM (notas privadas y campo sensible de perfil) se vuelven **matemáticamente irrecuperables** [3]. Para rotar la llave sin pérdida de información, las tablas `users` y `notes` incluyen la columna `key_version` (p. ej., `1`). Al rotar, se agrega `ENCRYPTION_KEY_V2` en Render manteniendo `ENCRYPTION_KEY_V1` activa para lectura; todo nuevo registro se cifra con la versión `2`, y un proceso de migración (o recifrado *lazy* al leer) descifra cada registro antiguo usando `ENCRYPTION_KEY_V1` (verificando su *auth tag* de 16 bytes) y lo vuelve a cifrar con un nuevo IV aleatorio de 12 bytes bajo `ENCRYPTION_KEY_V2`, retirando `V1` una vez completada la migración.

### 3.4. Seguridad de la base de datos y Pipeline CI/CD
1. **Base de datos endurecida:** Activación de *Enforce SSL on incoming connections* en Supabase (`sslmode=verify-full`) [8], creación de un rol dedicado `securevault_app` con privilegios restringidos a `SELECT, INSERT, UPDATE, DELETE` (sin `DDL`), y consultas 100% parametrizadas (`$1, $2`) con filtro de propiedad `WHERE owner_id = $1` [2, 3].
2. **Pipeline CI/CD reproducible:** El repositorio en GitHub cuenta con **Dependabot** activo y un flujo de **GitHub Actions** (`.github/workflows/ci.yml`) que ejecuta `npm ci`, auditoría `npm audit --audit-level=high`, escaneo de secretos y pruebas automatizadas antes de autorizar el despliegue hacia Render y Vercel [10].

---

## 4. Lista Consolidada de Referencias (Formato IEEE)

[1] OWASP Foundation, "OWASP Top 10:2025," *Open Worldwide Application Security Project*, 2025. [En línea]. Disponible en: https://owasp.org/Top10/2025

[2] OWASP Foundation, "Nodejs Security Cheat Sheet & Nodejs Docker Cheat Sheet," *OWASP Cheat Sheet Series*, 2025. [En línea]. Disponible en: https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html

[3] OWASP Foundation, "Secrets Management, Cryptographic Storage, Password Storage, Database Security & Transport Layer Protection Cheat Sheets," *OWASP Cheat Sheet Series*, 2025. [En línea]. Disponible en: https://cheatsheetseries.owasp.org/

[4] OpenJS Foundation, "Production Best Practices: Security and Performance & Express behind proxies," *Express.js Official Documentation*, 2025. [En línea]. Disponible en: https://expressjs.com/en/advanced/best-practice-security.html

[5] OpenJS Foundation, "Security Best Practices & Crypto Module API Documentation," *Node.js Official Documentation*, 2025. [En línea]. Disponible en: https://nodejs.org/en/learn/getting-started/security-best-practices

[6] Render Services Inc., "Render Documentation: Free Instance Limits, Regions, and Free TLS Certificates," *Render Docs*, 2025. [En línea]. Disponible en: https://render.com/docs

[7] Vercel Inc., "Vercel Documentation: Plans and Limits & Encryption and SSL/TLS Certificates," *Vercel Docs*, 2025. [En línea]. Disponible en: https://vercel.com/docs

[8] Supabase Inc., "Supabase Documentation: Database SSL Enforcement, Network Restrictions, and Pricing," *Supabase Docs*, 2025. [En línea]. Disponible en: https://supabase.com/docs/guides/platform/ssl-enforcement

[9] Internet Security Research Group (ISRG), "How It Works: The ACME Protocol," *Let's Encrypt Official Documentation*, 2025. [En línea]. Disponible en: https://letsencrypt.org/how-it-works/

[10] GitHub Inc., "Building and testing Node.js with GitHub Actions," *GitHub Docs*, 2025. [En línea]. Disponible en: https://docs.github.com/en/actions/use-cases-and-examples/building-and-testing/building-and-testing-nodejs

[11] Mozilla Corporation, "HTTP Strict-Transport-Security (HSTS) & Mozilla HTTP Observatory," *MDN Web Docs*, 2025. [En línea]. Disponible en: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security

[12] Checkmarx / ZAP Dev Team, "ZAP Baseline Scan Documentation," *OWASP Zed Attack Proxy (ZAP)*, 2025. [En línea]. Disponible en: https://www.zaproxy.org/docs/docker/baseline-scan/

[13] Qualys Inc., "Qualys SSL Labs: SSL Server Test," *SSL Labs*, 2025. [En línea]. Disponible en: https://www.ssllabs.com/ssltest/
