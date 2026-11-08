==============================================================================
  CREDICOCHA'S v3.0 — MANUAL DE DESPLIEGUE EN PRODUCCIÓN
  Compatible con:
    * ARQUITECTURA CLOUD: Neon (PostgreSQL) + Render (Docker PHP) + Firebase Hosting
    * HOSTING TRADICIONAL: cPanel / VPS (Apache/Nginx + PHP + MySQL/MariaDB)
==============================================================================

ARCHIVOS DEL PROYECTO
  index.html              Interfaz web (Frontend)
  api.php                 Backend seguro (PDO PostgreSQL / MySQL)
  config/db.php           Conexión PDO (soporta DATABASE_URL de Neon y variables DB_*)
  database_postgres.sql   Esquema y triggers para Neon (PostgreSQL)
  database.sql            Esquema y triggers para MySQL / MariaDB
  Dockerfile              Imagen Docker lista para Render (PHP 8.2 + Apache + pdo_pgsql)
  render.yaml             Plantilla de despliegue automático en Render
  firebase.json           Configuración segura de Firebase Hosting (ignora .php, .env y .sql)
  .env                    Variables de entorno locales (protegido por .gitignore y .dockerignore)

------------------------------------------------------------------------------
  GUÍA RÁPIDA: NEON (BD) + RENDER (BACKEND) + FIREBASE (FRONTEND)
------------------------------------------------------------------------------

PASO 1: BASE DE DATOS EN NEON (https://console.neon.tech)
  1. Cree su proyecto en Neon (base de datos: credicochas, rol/usuario: sowk).
  2. (Opcional pero recomendado) Abra "SQL Editor" en Neon, pegue el contenido de
     database_postgres.sql y pulse "Run".
     * Nota: Si no lo ejecuta manualmente, api.php creará todas las tablas y triggers
       automáticamente la primera vez que se conecte.
  3. Copie el "Connection string" (DATABASE_URL) que le da el Dashboard de Neon:
     postgresql://sowk:60814313Fj%4003@ep-xxxx.aws.neon.tech/credicochas?sslmode=require

PASO 2: BACKEND EN RENDER (https://dashboard.render.com)
  1. Suba este proyecto a un repositorio privado de GitHub (el archivo .gitignore ya
     evita que se suba el .env).
  2. En Render: "New +" -> "Web Service" -> conecte su repositorio de GitHub.
  3. Render detectará automáticamente el Dockerfile (Runtime: Docker).
  4. En la sección "Environment Variables" de Render, agregue:
       DATABASE_URL        = (pegue el Connection string de Neon del Paso 1)
       ADMIN_USER          = admin
       ADMIN_PASS_INICIAL  = 7wZIbz5WlhhB
       CORS_ORIGIN         = https://su-proyecto.web.app,https://su-proyecto.firebaseapp.com
                             (o deje * mientras prueba)
       APP_TIMEZONE        = America/Lima
       MORA_FEE            = 10
       SESSION_HOURS       = 12
       APP_DEBUG           = false
  5. Una vez desplegado, Render le dará una URL como:
     https://credicochas-api.onrender.com

PASO 3: FRONTEND EN FIREBASE HOSTING
  1. Abra index.html y en la línea 7 edite la etiqueta meta con la URL de su Render:
     <meta name="credicochas-api-url" content="https://credicochas-api.onrender.com/api.php">
  2. Desde la cuenta donde tienen Firebase, ejecute en esta carpeta:
     firebase login
     firebase use --add   (seleccione su proyecto de Firebase)
     firebase deploy --only hosting
     * SEGURIDAD: firebase.json ya está configurado para subir ÚNICAMENTE index.html
       y bloquear la subida de .env, *.php, *.sql y config/.
  3. Nota: También puede abrir directamente la URL de Render (https://credicochas-api.onrender.com)
     ya que sirve tanto index.html como api.php en el mismo dominio si lo desea.

------------------------------------------------------------------------------
  BLINDAJE DE SEGURIDAD INCLUIDO
------------------------------------------------------------------------------
  1. Cero SQL Injection: Sentencias preparadas reales (PDO::ATTR_EMULATE_PREPARES = false).
  2. Sesiones Persistentes en Base de Datos: El token de sesión de 256 bits se guarda
     hasheado con SHA-256 en la tabla `sesiones` (no se pierde cuando Render reinicia
     el contenedor) y funciona en móviles (Safari/Chrome) entre Firebase y Render.
  3. Protección CSRF + CORS estricto: Todas las operaciones POST exigen X-CSRF-Token.
  4. Anti Fuerza Bruta inteligente: Bloqueo tras 5 intentos fallidos en 15 minutos,
     detectando la IP real detrás del balanceador de Render / Cloudflare.
  5. Reautenticación en Operaciones Críticas: Los botones "Reiniciar" e "Importar"
     exigen ingresar la contraseña actual del administrador en un modal oculto.
  6. Cambio obligatorio de contraseña inicial (mínimo 8 caracteres) al primer ingreso
     y cierre automático de sesiones en otros dispositivos al cambiar la clave.
  7. Inmutabilidad Financiera: Triggers en PostgreSQL y MySQL que impiden modificar
     cuotas ya cobradas o alterar/borrar registros individuales de auditoría.
==============================================================================
