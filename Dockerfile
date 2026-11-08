# ============================================================================
#  CREDICOCHA'S v3.0 — Dockerfile para Render (PHP 8.2 + Apache + PostgreSQL/Neon)
# ============================================================================
FROM php:8.2-apache

# Instalar extensiones PDO para PostgreSQL (Neon) y MySQL/MariaDB
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq-dev \
    && docker-php-ext-install -j"$(nproc)" pdo pdo_pgsql pdo_mysql \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Endurecer configuración de PHP en producción (ocultar versión y errores internos)
RUN { \
        echo "expose_php = Off"; \
        echo "display_errors = Off"; \
        echo "display_startup_errors = Off"; \
        echo "log_errors = On"; \
        echo "post_max_size = 32M"; \
        echo "upload_max_filesize = 32M"; \
    } > /usr/local/etc/php/conf.d/credicochas-security.ini

# Endurecer Apache y activar lectura de .htaccess y cabeceras de seguridad
RUN a2enmod headers rewrite \
    && sed -i 's/AllowOverride None/AllowOverride All/g' /etc/apache2/apache2.conf \
    && { \
        echo "ServerTokens Prod"; \
        echo "ServerSignature Off"; \
    } >> /etc/apache2/apache2.conf

WORKDIR /var/www/html
COPY . /var/www/html/

# Permisos seguros de solo lectura para código
RUN chown -R www-data:www-data /var/www/html \
    && find /var/www/html -type d -exec chmod 750 {} \; \
    && find /var/www/html -type f -exec chmod 640 {} \;

EXPOSE 80
