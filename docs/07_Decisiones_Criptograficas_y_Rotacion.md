# Decisiones Criptográficas, Análisis de Pérdida y Estrategia de Rotación de Llaves (Sección 4 y OWASP A04:2025)

Esta sección documenta y justifica las decisiones criptográficas implementadas en `src/utils/crypto.js` y `database/schema.sql` para **SecureVault**, respondiendo de forma técnica a las preguntas de análisis exigidas en la Sección 4 y en la rúbrica del laboratorio (20 puntos: *Hash y cifrado*).

---

## 1. Tabla de Decisiones Criptográficas en SecureVault

La arquitectura criptográfica aplica estrictamente el principio fundamental: **si nunca se necesita recuperar el valor original, se utiliza hash irreversible; si el usuario o el sistema necesita volver a leer el dato original, se utiliza cifrado simétrico autenticado**.

| Dato Protegido | Mecanismo (Hash / Cifrado / Firma / Transporte) | Algoritmo y Parámetros Exactos | Justificación Técnica y de Seguridad |
| :--- | :--- | :--- | :--- |
| **Contraseñas de usuario** (`users.password_hash`) | **Hash lento con sal** (Irreversible) | **Argon2id** (`type: argon2.argon2id`, `memoryCost: 19456` [19 MiB], `timeCost: 2`, `parallelism: 1`, sal aleatoria única de 16 bytes generada automáticamente). | Nunca se necesita descifrar una contraseña, solo verificarla (`argon2.verify`). El alto consumo de memoria RAM (`19 MiB` por hash) neutraliza ataques de fuerza bruta acelerados por GPU, FPGA y ASIC en caso de robo de la base de datos. |
| **Contenido de notas privadas** (`notes.content_enc`) | **Cifrado simétrico autenticado (AEAD)** (Reversible) | **AES-256-GCM** con llave maestra de 32 bytes (`256 bits`), **IV aleatorio único de 12 bytes** (`crypto.randomBytes(12)`) por cada escritura y **Authentication Tag de 16 bytes** (`Buffer.concat([iv, authTag, ciphertext])` en Base64). | El propietario legítimo debe poder recuperar y leer sus notas. El modo **GCM** (*Galois/Counter Mode*) garantiza simultáneamente **confidencialidad** e **integridad autenticada**: si un atacante modifica 1 solo bit del texto cifrado en PostgreSQL, la verificación del `authTag` con `decipher.setAuthTag()` falla y bloquea la lectura (*Fail-Closed*). |
| **Dato sensible de perfil: teléfono / documento** (`users.sensitive_data_enc`) | **Cifrado simétrico autenticado (AEAD)** + Enmascaramiento en salida | **AES-256-GCM** (misma estructura `IV [12B] \|\| AuthTag [16B] \|\| Ciphertext` en Base64) + función `maskSensitiveData()` que expone solo los últimos 4 caracteres (`***-***-1234`). | Protege datos personales sensibles en reposo (OWASP A04) y previene la exposición visual en pantalla (*shoulder surfing*) o en el panel de administración, permitiendo el descifrado completo únicamente al dueño autenticado (`?reveal=true`). |
| **Token de recuperación de contraseña** (`password_reset_tokens.token_hash`) | **CSPRNG + Hash criptográfico rápido** (Irreversible) | Generación con **`crypto.randomBytes(32)`** (256 bits de entropía, 64 chars hex) + almacenamiento exclusivo de su resumen **`SHA-256`** (`CHAR(64)`) con TTL de 15 minutos y `used = FALSE`. | A diferencia de una contraseña elegida por un humano, un token de 32 bytes aleatorios posee 256 bits de entropía uniforme (inmune a ataques de diccionario o fuerza bruta), por lo que no requiere un hash lento como Argon2id. Guardar solo su hash `SHA-256` garantiza que, si roban la tabla `password_reset_tokens`, el atacante no pueda reconstruir el enlace de recuperación. |
| **Firma de integridad y tokens de sesión** (`HMAC` / `JWT`) | **Código de Autenticación de Mensajes (MAC)** | **HMAC-SHA256** verificado en tiempo constante con **`crypto.timingSafeEqual`** para integridad de datos, y **JWT (`HS256`)** con secreto de 64 bytes (`JWT_SECRET`) y `jti` único. | Verifica criptográficamente que los metadatos o claims de sesión no fueron alterados por el cliente. El uso de `crypto.timingSafeEqual` y `algorithms: ['HS256']` elimina vulnerabilidades de canal lateral por tiempo (*timing attacks*) y ataques de confusión de algoritmo (`alg: none`). |
| **Datos en tránsito** (Cliente <-> Vercel <-> Render <-> Supabase) | **Cifrado de capa de transporte** | **HTTPS / TLS 1.2 y TLS 1.3** con certificados X.509 automatizados (Let's Encrypt), cabecera **HSTS** (`max-age=31536000; includeSubDomains; preload`) y conexión a PostgreSQL con `ssl` activo. | Garantiza confidencialidad, integridad y autenticidad de extremo a extremo en la red pública, protegiendo las credenciales durante el login y evitando la interceptación de la cookie `HttpOnly; Secure`. |

---

## 2. Pregunta de Análisis 1: ¿Qué ocurre con los datos si se pierde la llave `ENCRYPTION_KEY`?

Si la llave simétrica maestra de 256 bits (`ENCRYPTION_KEY`) configurada en el gestor de secretos de producción se pierde, se sobrescribe por error o se destruye sin contar con una copia de respaldo segura, el impacto sobre los activos de **SecureVault** se divide en dos categorías técnicas:

1. **Pérdida matemática total e irreversible de los datos cifrados con `AES-256-GCM`:**
   * Todo el contenido de las notas privadas (`notes.content_enc`) y los datos sensibles de perfil (`users.sensitive_data_enc`) se vuelven **permanentemente irrecuperables** (*crypto-shredding*).
   * En `AES-256-GCM`, un espacio de clave de $2^{256}$ combinaciones posibles hace computacionalmente inviable recuperar el texto plano mediante fuerza bruta, y **la llave jamás se almacena ni puede derivarse desde la base de datos**. Cualquier intento de descifrar los registros existentes con una nueva llave fallará inmediatamente en `decipher.final()` al no coincidir la etiqueta de autenticación GMAC de 16 bytes (`CRYPTO_INTEGRITY_FAILURE`).
2. **Componentes que NO se ven afectados por la pérdida de `ENCRYPTION_KEY`:**
   * **Contraseñas de usuarios (`users.password_hash`):** No sufren ningún impacto. Al estar protegidas mediante **Argon2id** (un hash unidireccional con sal integrada en la propia cadena `$argon2id$...`), su verificación no depende de `ENCRYPTION_KEY`. Los usuarios podrán seguir iniciando sesión normalmente.
   * **Tokens de recuperación (`password_reset_tokens.token_hash`) y sesiones (`JWT_SECRET`):** Tampoco se ven afectados, ya que utilizan `SHA-256` sin llave y el secreto independiente `JWT_SECRET`, respectivamente.
3. **Medidas preventivas de arquitectura:**
   * Custodiar una copia de respaldo de `ENCRYPTION_KEY` en una bóveda de secretos externa cifrada con control de acceso MFA y auditoría (p. ej., AWS Secrets Manager, HashiCorp Vault o 1Password/Bitwarden empresarial) antes de inyectarla en Render, aplicando separación de privilegios para que ningún desarrollador pueda eliminarla accidentalmente sin respaldo.

---

## 3. Pregunta de Análisis 2: ¿Cómo rotarían la llave sin perder la información existente?

Para rotar la llave maestra de cifrado periódicamente (o ante una sospecha de exposición parcial) **sin pérdida de datos y sin tiempo de inactividad (*zero-downtime key rotation*)**, el esquema de **SecureVault** (`database/schema.sql`) ya incorpora la columna `key_version SMALLINT NOT NULL DEFAULT 1` tanto en la tabla `notes` como en la tabla `users`.

El procedimiento de rotación se ejecuta en **4 fases controladas**:

### Fase 1: Aprovisionamiento del llavero multi-versión (*Keyring* en memoria)
1. Se genera una nueva llave criptográfica de 32 bytes (`node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"`).
2. En el panel de variables de entorno de Render, **no se borra la llave anterior**; se mantienen ambas versiones en un mapa de llaves indexado por número de versión:
   * `ENCRYPTION_KEY_V1=<llave_antigua_base64>` (conservada únicamente para **lectura/descifrado** de registros con `key_version = 1`).
   * `ENCRYPTION_KEY_V2=<llave_nueva_base64>` (utilizada para toda **nueva escritura/cifrado** y recifrado).
   * `ACTIVE_KEY_VERSION=2` (indica al módulo `crypto.js` qué llave usar al invocar `encrypt()`).

### Fase 2: Escritura con la nueva versión y lectura compatible hacia atrás
* **Al crear o actualizar un registro (`encrypt`):** El sistema utiliza siempre la llave correspondiente a `ACTIVE_KEY_VERSION` (`ENCRYPTION_KEY_V2`), genera un nuevo IV aleatorio de 12 bytes y guarda la fila con `key_version = 2` (o embebe el prefijo de versión `v2:<base64_payload>`).
* **Al leer un registro existente (`decrypt`):** El controlador lee la columna `key_version` de la fila en PostgreSQL (`1` o `2`) y selecciona dinámicamente `ENCRYPTION_KEY_V1` o `ENCRYPTION_KEY_V2` para ejecutar `createDecipheriv('aes-256-gcm', keyByVersion, iv)`. De este modo, ningún usuario experimenta errores durante la transición.

### Fase 3: Re-cifrado progresivo (*Lazy Re-encryption* + *Batch Migration*)
Para migrar todos los registros históricos de `key_version = 1` hacia `key_version = 2`:
1. **Recifrado *Lazy* (en caliente):** Cada vez que un usuario lee su perfil o una nota con `key_version = 1`, el backend la descifra en memoria con `ENCRYPTION_KEY_V1`, la vuelve a cifrar inmediatamente con `ENCRYPTION_KEY_V2` (generando un **nuevo IV aleatorio de 12 bytes** y un nuevo **AuthTag de 16 bytes**) y actualiza la fila en segundo plano con `key_version = 2`.
2. **Worker de migración por lotes (*Batch Script*):** Un trabajo transaccional recorre en lotes pequeños (`SELECT id, content_enc FROM notes WHERE key_version = 1 LIMIT 100 FOR UPDATE SKIP LOCKED`) los registros restantes de usuarios inactivos:
   * Descifra `content_enc` usando `ENCRYPTION_KEY_V1` (verificando previamente la integridad del `authTag` de 16 bytes).
   * Cifra el texto plano resultante usando `ENCRYPTION_KEY_V2` con un IV fresco de 12 bytes.
   * Ejecuta `UPDATE notes SET content_enc = $1, key_version = 2 WHERE id = $2` y repite el mismo proceso sobre `users.sensitive_data_enc`.

### Fase 4: Verificación de convergencia y retiro seguro (*Decommission*) de la llave antigua
1. Se verifica en PostgreSQL que no quede ningún registro dependiente de la llave antigua:
   ```sql
   SELECT
     (SELECT COUNT(*) FROM notes WHERE key_version = 1) AS pending_notes,
     (SELECT COUNT(*) FROM users WHERE sensitive_data_enc IS NOT NULL AND key_version = 1) AS pending_users;
   ```
2. Una vez que ambas cuentas retornan exactamente **`0`**, se elimina `ENCRYPTION_KEY_V1` de las variables de entorno de Render, completando la rotación criptográfica sin haber perdido un solo registro ni interrumpido el servicio.
