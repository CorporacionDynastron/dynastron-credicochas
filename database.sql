-- ============================================================================
--  CREDICOCHA'S v3.0 — Base de datos relacional (MySQL 5.7+ / MariaDB 10.3+)
--  Motor: InnoDB · Codificación: utf8mb4
--
--  CÓMO IMPORTAR
--   * Hosting compartido (cPanel / Hostinger / etc.):
--       1) Cree la base de datos y el usuario desde el panel (MySQL Databases).
--       2) Abra phpMyAdmin, SELECCIONE la base de datos en el panel izquierdo.
--       3) Pestaña "Importar" -> elija este archivo -> "Continuar".
--   * VPS con acceso por terminal:
--       mysql -u USUARIO -p NOMBRE_BD < database.sql
--
--  Este archivo NO crea ni selecciona la base de datos (en hostings compartidos
--  el nombre lleva un prefijo y no se permite CREATE DATABASE). Es seguro
--  volver a importarlo: no borra datos existentes (CREATE TABLE IF NOT EXISTS).
--
--  El usuario administrador NO se crea aquí: api.php lo crea la primera vez que
--  alguien inicia sesión, usando ADMIN_USER y ADMIN_PASS_INICIAL del archivo .env
-- ============================================================================

SET NAMES utf8mb4;

-- ----------------------------------------------------------------------------
-- 1. USUARIOS DEL SISTEMA (contraseñas guardadas con password_hash / bcrypt)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS usuarios (
  id                 INT UNSIGNED NOT NULL AUTO_INCREMENT,
  usuario            VARCHAR(50)  NOT NULL,
  password_hash      VARCHAR(255) NOT NULL,
  debe_cambiar_clave TINYINT(1)   NOT NULL DEFAULT 1,
  creado_en          DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  ultimo_acceso      DATETIME     NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_usuarios_usuario (usuario)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------------------------
-- 1B. SESIONES PERSISTENTES (token hasheado con SHA-256)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sesiones (
  token_hash   CHAR(64)     NOT NULL,
  usuario_id   INT UNSIGNED NOT NULL,
  usuario      VARCHAR(50)  NOT NULL,
  csrf_token   VARCHAR(64)  NOT NULL,
  must_change  TINYINT(1)   NOT NULL DEFAULT 0,
  ip           VARCHAR(45)  NOT NULL DEFAULT '',
  user_agent   VARCHAR(255) NOT NULL DEFAULT '',
  expira_en    BIGINT       NOT NULL,
  creado_en    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (token_hash),
  KEY idx_sesiones_expira (expira_en),
  KEY idx_sesiones_usuario (usuario_id),
  CONSTRAINT fk_sesiones_usuario FOREIGN KEY (usuario_id)
    REFERENCES usuarios (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------------------------
-- 2. INTENTOS DE LOGIN (bloqueo temporal por fuerza bruta: 5 fallos / 15 min)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS login_intentos (
  id        BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  ip        VARCHAR(45) NOT NULL,
  usuario   VARCHAR(50) NOT NULL DEFAULT '',
  exito     TINYINT(1)  NOT NULL DEFAULT 0,
  creado_en DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_login_ip_fecha (ip, exito, creado_en),
  KEY idx_login_user_fecha (usuario, exito, creado_en)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------------------------
-- 3. CLIENTES
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS clientes (
  id        VARCHAR(20)  NOT NULL,                    -- CLI-1, CLI-2, ...
  seq       BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,  -- orden de registro
  nombre    VARCHAR(150) NOT NULL,
  dni       VARCHAR(11)  NOT NULL,                    -- DNI (8) o RUC (11)
  telefono  VARCHAR(20)  NOT NULL DEFAULT '',
  direccion VARCHAR(255) NOT NULL DEFAULT '',
  creado_en DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_clientes_seq (seq),
  UNIQUE KEY uq_clientes_dni (dni),
  KEY idx_clientes_nombre (nombre)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------------------------
-- 4. PRÉSTAMOS
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS prestamos (
  id              VARCHAR(20)  NOT NULL,                    -- LOAN-1001, ...
  seq             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  cliente_id      VARCHAR(20)  NOT NULL,
  capital         DECIMAL(12,2) NOT NULL,
  interes_pct     DECIMAL(6,2)  NOT NULL DEFAULT 0,
  total_pagar     DECIMAL(12,2) NOT NULL,
  cuotas_count    SMALLINT UNSIGNED NOT NULL,
  frecuencia      ENUM('Diario','Semanal') NOT NULL DEFAULT 'Diario',
  fecha_inicio    DATE         NOT NULL,
  omitir_domingos TINYINT(1)   NOT NULL DEFAULT 1,
  estado          ENUM('ACTIVO','PAGADO') NOT NULL DEFAULT 'ACTIVO',
  creado_en       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_prestamos_seq (seq),
  KEY idx_prestamos_cliente (cliente_id),
  KEY idx_prestamos_estado (estado),
  CONSTRAINT fk_prestamos_cliente FOREIGN KEY (cliente_id)
    REFERENCES clientes (id) ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT ck_prestamos_capital CHECK (capital > 0),
  CONSTRAINT ck_prestamos_total   CHECK (total_pagar > 0),
  CONSTRAINT ck_prestamos_interes CHECK (interes_pct >= 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------------------------
-- 5. CUOTAS (cronograma de cada préstamo)
--    La mora NO se guarda mientras la cuota está pendiente: se calcula en
--    api.php (MORA_FEE del .env) y se congela en el momento del cobro.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cuotas (
  prestamo_id      VARCHAR(20)  NOT NULL,
  numero           SMALLINT UNSIGNED NOT NULL,
  fecha_programada DATE         NOT NULL,
  monto            DECIMAL(12,2) NOT NULL,
  estado           ENUM('PENDIENTE','PAGADO') NOT NULL DEFAULT 'PENDIENTE',
  fecha_pago       DATE         NULL,
  hora_pago        TIME         NULL,
  metodo_pago      ENUM('Efectivo','Yape','Plin','Transferencia') NULL,
  num_operacion    VARCHAR(60)  NULL,
  mora             DECIMAL(10,2) NULL,        -- mora cobrada (NULL si aún pendiente)
  monto_cobrado    DECIMAL(12,2) NULL,        -- cuota + mora realmente cobrado
  audit_id         VARCHAR(30)  NULL,         -- TRX-... de la tabla auditoria
  cobrado_por      VARCHAR(50)  NULL,         -- usuario que registró el cobro
  PRIMARY KEY (prestamo_id, numero),
  KEY idx_cuotas_agenda (estado, fecha_programada),
  KEY idx_cuotas_fecha_pago (fecha_pago),
  CONSTRAINT fk_cuotas_prestamo FOREIGN KEY (prestamo_id)
    REFERENCES prestamos (id) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT ck_cuotas_monto CHECK (monto > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------------------------
-- 6. AUDITORÍA (bitácora de desembolsos, cobros y eventos del sistema)
--    Protegida por triggers: no se puede modificar ni borrar registro a registro.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS auditoria (
  id            VARCHAR(30)  NOT NULL,                    -- TRX-...
  seq           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  fecha_hora    DATETIME     NOT NULL,
  fecha         DATE         NOT NULL,
  cliente       VARCHAR(150) NOT NULL DEFAULT '-',
  evento        VARCHAR(40)  NOT NULL,
  cuota_num     VARCHAR(20)  NOT NULL DEFAULT '-',
  monto         DECIMAL(12,2) NOT NULL DEFAULT 0,
  metodo        VARCHAR(30)  NOT NULL DEFAULT '-',
  num_operacion VARCHAR(60)  NOT NULL DEFAULT '-',
  usuario       VARCHAR(50)  NOT NULL DEFAULT '-',
  PRIMARY KEY (id),
  UNIQUE KEY uq_auditoria_seq (seq),
  KEY idx_auditoria_fecha (fecha_hora)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
--  TRIGGERS
--  (Si su hosting no permite triggers, el sistema funciona igual: api.php
--   aplica las mismas reglas por código. Ver README, sección "Problemas".)
-- ============================================================================
DELIMITER $$

-- Una cuota cobrada es definitiva; un cobro debe traer fecha, método y monto.
DROP TRIGGER IF EXISTS trg_cuotas_bu_validar$$
CREATE TRIGGER trg_cuotas_bu_validar BEFORE UPDATE ON cuotas
FOR EACH ROW
BEGIN
  IF OLD.estado = 'PAGADO' THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Cuota ya cobrada: no se puede modificar';
  END IF;
  IF NEW.estado = 'PAGADO' AND (NEW.fecha_pago IS NULL OR NEW.metodo_pago IS NULL OR NEW.monto_cobrado IS NULL) THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Un cobro requiere fecha, metodo de pago y monto cobrado';
  END IF;
END$$

-- Al cobrarse la última cuota pendiente, el préstamo pasa a PAGADO.
DROP TRIGGER IF EXISTS trg_cuotas_au_cerrar_prestamo$$
CREATE TRIGGER trg_cuotas_au_cerrar_prestamo AFTER UPDATE ON cuotas
FOR EACH ROW
BEGIN
  IF NEW.estado = 'PAGADO' AND OLD.estado <> 'PAGADO' THEN
    IF NOT EXISTS (SELECT 1 FROM cuotas WHERE prestamo_id = NEW.prestamo_id AND estado <> 'PAGADO') THEN
      UPDATE prestamos SET estado = 'PAGADO' WHERE id = NEW.prestamo_id;
    END IF;
  END IF;
END$$

-- La auditoría es inmutable.
DROP TRIGGER IF EXISTS trg_auditoria_bu_inmutable$$
CREATE TRIGGER trg_auditoria_bu_inmutable BEFORE UPDATE ON auditoria
FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'La auditoria es inmutable: no se puede modificar';
END$$

-- Solo se permite borrar auditoría desde "Reiniciar sistema" / "Importar respaldo"
-- (api.php activa la variable @credicochas_permitir_borrado durante esa operación).
DROP TRIGGER IF EXISTS trg_auditoria_bd_inmutable$$
CREATE TRIGGER trg_auditoria_bd_inmutable BEFORE DELETE ON auditoria
FOR EACH ROW
BEGIN
  IF @credicochas_permitir_borrado IS NULL OR @credicochas_permitir_borrado <> 1 THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'La auditoria es inmutable: no se puede borrar';
  END IF;
END$$

DELIMITER ;
