==============================================================================
 CREDICOCHA'S — MANUAL DE DESPLIEGUE Y CONFIGURACIÓN
 Rama de desarrollo: pruebas-v3.2
==============================================================================

1. ESTRUCTURA DEL PROYECTO

 index.html              Interfaz web (Frontend).
 api.php                 Backend y API REST.
 config/db.php           Conexión PDO con PostgreSQL o MySQL/MariaDB.
 database.sql            Esquema de base de datos MySQL/MariaDB.
 database_postgres.sql   Esquema de base de datos PostgreSQL.
 Dockerfile              Imagen Docker para despliegue.
 render.yaml             Configuración de servicio en Render.
 .env.example            Plantilla de variables de entorno.
 .gitignore              Exclusión de archivos locales y credenciales.
 .dockerignore           Exclusión de archivos en la imagen Docker.

2. REQUISITOS

 - PHP 8.2 o superior.
 - Extensiones PDO, pdo_pgsql y/o pdo_mysql según el motor utilizado.
 - PostgreSQL o MySQL/MariaDB.
 - Apache con mod_rewrite y mod_headers cuando corresponda.
 - Docker para despliegues basados en contenedores.

3. CONFIGURACIÓN DE LA BASE DE DATOS

 El sistema admite dos motores:

 A) PostgreSQL
    Configure DATABASE_URL o las variables DB_* correspondientes.

 B) MySQL/MariaDB
    Configure DB_DRIVER=mysql y los datos de conexión correspondientes.

 Para preparar una base de datos nueva, utilice el script correspondiente:
 - PostgreSQL: database_postgres.sql
 - MySQL/MariaDB: database.sql

 No utilice credenciales de ejemplo en producción.
 Mantenga las credenciales fuera del repositorio.

4. VARIABLES DE ENTORNO

 Configure las variables en el entorno local o en el panel del proveedor:

 DATABASE_URL=
 DB_DRIVER=pgsql
 DB_HOST=
 DB_PORT=5432
 DB_NAME=
 DB_USER=
 DB_PASS=
 DB_SSLMODE=require
 DB_CHARSET=utf8

 CORS_ORIGIN=
 APP_TIMEZONE=America/Lima
 APP_DEBUG=false
 MORA_FEE=10
 SESSION_HOURS=12

 ADMIN_USER=admin
 ADMIN_PASS_INICIAL=

 IMPORTANTE:
 - Utilice credenciales fuertes y únicas.
 - No publique archivos .env.
 - No escriba contraseñas reales en README, código o scripts públicos.
 - Configure CORS_ORIGIN con los dominios frontend autorizados.
 - No utilice "*" como configuración definitiva de producción.
 - Mantenga APP_DEBUG desactivado en producción.

5. DESPLIEGUE CON DOCKER Y RENDER

 1. Conecte el repositorio de GitHub al proveedor.
 2. Seleccione la rama que desea desplegar.
 3. Configure el servicio como Docker.
 4. Configure las variables de entorno requeridas.
 5. Verifique la conexión con la base de datos.
 6. Compruebe el funcionamiento del frontend y de la API.

 El archivo render.yaml contiene la configuración base del servicio.
 Revise las variables del proveedor antes de desplegar.

6. DESPLIEGUE EN HOSTING TRADICIONAL

 Para cPanel o VPS:

 1. Configure PHP y las extensiones PDO necesarias.
 2. Cree una base de datos y un usuario exclusivo para la aplicación.
 3. Importe el script SQL correspondiente.
 4. Configure las variables de entorno o la conexión en config/db.php.
 5. Publique los archivos del proyecto en el directorio web.
 6. Configure HTTPS.
 7. Compruebe los permisos y las rutas de acceso.

 No exponga archivos .env, archivos SQL ni configuraciones internas
 desde el directorio público.

7. SEGURIDAD

 - Consultas a base de datos mediante PDO.
 - Protección de sesiones y autenticación.
 - Validación de operaciones en el backend.
 - Protección CSRF para operaciones POST.
 - Registro de auditoría de operaciones.
 - Control de acceso a las operaciones administrativas.
 - Credenciales almacenadas fuera del repositorio.
 - Errores internos no expuestos al usuario en producción.

8. DESARROLLO Y REMASTERIZACIÓN

 La rama main representa la versión principal del proyecto.

 La rama pruebas-v3.2 se utiliza para desarrollar, corregir y validar
 nuevas funcionalidades antes de integrarlas en main.

 REGLAS DE TRABAJO:

 - Los cambios nuevos se realizan primero en pruebas-v3.2.
 - Se deben probar las funcionalidades antes de integrarlas.
 - No se modifica main durante el desarrollo.
 - Se deben conservar las configuraciones exclusivas de producción.
 - La integración final requiere revisión y autorización.

==============================================================================
 FIN DEL DOCUMENTO
==============================================================================
