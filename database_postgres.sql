
-- ============================================================================
-- CREDICOCHA'S v3.2 — Base de datos PostgreSQL (Neon / Render / Supabase)
-- Compatible con PostgreSQL 12+
--
-- INSTALACIÓN:
-- 1. Seleccionar una base de datos vacía.
-- 2. Ejecutar este archivo completo desde el SQL Editor.
-- 3. Configurar ADMIN_PASS_INICIAL en las variables de entorno.
-- 4. El administrador se crea desde la API durante el primer acceso.
--
-- IMPORTANTE:
-- Este archivo crea la estructura, no inserta datos de prueba.
-- No elimina registros de una base de datos existente.
-- ============================================================================

SET client_encoding = 'UTF8';

-- ----------------------------------------------------------------------------
-- 1. USUARIOS DEL SISTEMA
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS usuarios (
  id                  SERIAL PRIMARY KEY,
  usuario             VARCHAR(50)  NOT NULL UNIQUE,
  password_hash       VARCHAR(255) NOT NULL,
  debe_cambiar_clave  SMALLINT     NOT NULL DEFAULT 1,
  creado_en           TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  ultimo_acceso       TIMESTAMP    NULL
);

-- ----------------------------------------------------------------------------
-- 2. SESIONES PERSISTENTES
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sesiones (
  token_hash   CHAR(64)     PRIMARY KEY,
  usuario_id   INTEGER      NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
  usuario      VARCHAR(50)  NOT NULL,
  csrf_token   VARCHAR(64)  NOT NULL,
  must_change  SMALLINT     NOT NULL DEFAULT 0,
  ip           VARCHAR(45)  NOT NULL DEFAULT '',
  user_agent   VARCHAR(255) NOT NULL DEFAULT '',
  expira_en    BIGINT       NOT NULL,
  creado_en    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_sesiones_expira ON sesiones (expira_en);
CREATE INDEX IF NOT EXISTS idx_sesiones_usuario ON sesiones (usuario_id);

-- ----------------------------------------------------------------------------
-- 3. INTENTOS DE LOGIN
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS login_intentos (
  id        BIGSERIAL   PRIMARY KEY,
  ip        VARCHAR(45) NOT NULL,
  usuario   VARCHAR(50) NOT NULL DEFAULT '',
  exito     SMALLINT    NOT NULL DEFAULT 0,
  creado_en TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_login_ip_fecha
ON login_intentos (ip, exito, creado_en);

CREATE INDEX IF NOT EXISTS idx_login_user_fecha
ON login_intentos (usuario, exito, creado_en);

-- ----------------------------------------------------------------------------
-- 4. CLIENTES
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS clientes (
  id        VARCHAR(20)  PRIMARY KEY,
  seq       BIGSERIAL    NOT NULL UNIQUE,
  nombre    VARCHAR(150) NOT NULL,
  dni       VARCHAR(11)  NOT NULL UNIQUE,
  telefono  VARCHAR(20)  NOT NULL DEFAULT '',
  direccion VARCHAR(255) NOT NULL DEFAULT '',
  creado_en TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_clientes_nombre ON clientes (nombre);

-- ----------------------------------------------------------------------------
-- 5. PRÉSTAMOS
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS prestamos (
  id              VARCHAR(20)   PRIMARY KEY,
  seq             BIGSERIAL     NOT NULL UNIQUE,
  cliente_id      VARCHAR(20)   NOT NULL
                  REFERENCES clientes(id)
                  ON DELETE RESTRICT ON UPDATE CASCADE,
  capital         NUMERIC(12,2) NOT NULL CHECK (capital > 0),
  interes_pct     NUMERIC(6,2)  NOT NULL DEFAULT 0 CHECK (interes_pct >= 0),
  total_pagar     NUMERIC(12,2) NOT NULL CHECK (total_pagar > 0),
  cuotas_count    SMALLINT      NOT NULL CHECK (cuotas_count >= 1),
  frecuencia      VARCHAR(10)   NOT NULL DEFAULT 'Diario'
                  CHECK (frecuencia IN ('Diario', 'Semanal')),
  fecha_inicio    DATE          NOT NULL,
  omitir_domingos SMALLINT      NOT NULL DEFAULT 1,
  estado          VARCHAR(10)   NOT NULL DEFAULT 'ACTIVO'
                  CHECK (estado IN ('ACTIVO', 'PAGADO')),
  creado_en       TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_prestamos_cliente ON prestamos (cliente_id);
CREATE INDEX IF NOT EXISTS idx_prestamos_estado ON prestamos (estado);

-- ----------------------------------------------------------------------------
-- 6. CUOTAS
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cuotas (
  prestamo_id      VARCHAR(20)   NOT NULL
                   REFERENCES prestamos(id)
                   ON DELETE CASCADE ON UPDATE CASCADE,
  numero           SMALLINT      NOT NULL,
  fecha_programada DATE          NOT NULL,
  monto            NUMERIC(12,2) NOT NULL CHECK (monto > 0),
  estado           VARCHAR(10)   NOT NULL DEFAULT 'PENDIENTE'
                   CHECK (estado IN ('PENDIENTE', 'PAGADO')),
  fecha_pago       DATE          NULL,
  hora_pago        TIME          NULL,
  metodo_pago      VARCHAR(20)   NULL
                   CHECK (
                     metodo_pago IS NULL OR
                     metodo_pago IN ('Efectivo', 'Yape', 'Plin', 'Transferencia')
                   ),
  num_operacion    VARCHAR(60)   NULL,
  mora             NUMERIC(10,2) NULL,
  monto_cobrado    NUMERIC(12,2) NULL,
  audit_id         VARCHAR(30)   NULL,
  mora_omitida     BOOLEAN       NOT NULL DEFAULT FALSE,
  cobrado_por      VARCHAR(50)   NULL,
  PRIMARY KEY (prestamo_id, numero)
);

CREATE INDEX IF NOT EXISTS idx_cuotas_agenda
ON cuotas (estado, fecha_programada);

CREATE INDEX IF NOT EXISTS idx_cuotas_fecha_pago
ON cuotas (fecha_pago);

-- ----------------------------------------------------------------------------
-- 7. AJUSTES DE MORA
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ajustes_mora (
  id            BIGSERIAL     PRIMARY KEY,
  prestamo_id   VARCHAR(20)   NOT NULL,
  numero        SMALLINT      NOT NULL,
  mora_anterior NUMERIC(10,2) NOT NULL,
  mora_nueva    NUMERIC(10,2) NOT NULL,
  motivo        VARCHAR(255)  NOT NULL DEFAULT '',
  usuario       VARCHAR(50)   NOT NULL,
  creado_en     TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (prestamo_id, numero)
    REFERENCES cuotas (prestamo_id, numero)
    ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_ajustes_mora_cuota
ON ajustes_mora (prestamo_id, numero);

-- ----------------------------------------------------------------------------
-- 8. MOVIMIENTOS DE CAJA
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS movimientos_caja (
  id          BIGSERIAL     PRIMARY KEY,
  fecha       DATE          NOT NULL,
  tipo        VARCHAR(10)   NOT NULL
              CHECK (tipo IN ('INGRESO', 'EGRESO')),
  categoria   VARCHAR(30)   NOT NULL,
  descripcion VARCHAR(255)  NOT NULL DEFAULT '',
  monto       NUMERIC(12,2) NOT NULL CHECK (monto > 0),
  usuario     VARCHAR(50)   NOT NULL,
  creado_en   TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_caja_fecha
ON movimientos_caja (fecha);

-- ----------------------------------------------------------------------------
-- 9. AUDITORÍA
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS auditoria (
  id            VARCHAR(30)   PRIMARY KEY,
  seq           BIGSERIAL     NOT NULL UNIQUE,
  fecha_hora    TIMESTAMP     NOT NULL,
  fecha         DATE          NOT NULL,
  cliente       VARCHAR(150)  NOT NULL DEFAULT '-',
  evento        VARCHAR(40)   NOT NULL,
  cuota_num     VARCHAR(20)   NOT NULL DEFAULT '-',
  monto         NUMERIC(12,2) NOT NULL DEFAULT 0,
  metodo        VARCHAR(30)   NOT NULL DEFAULT '-',
  num_operacion VARCHAR(60)   NOT NULL DEFAULT '-',
  usuario       VARCHAR(50)   NOT NULL DEFAULT '-'
);

CREATE INDEX IF NOT EXISTS idx_auditoria_fecha
ON auditoria (fecha_hora);

-- ============================================================================
-- TRIGGERS DE SEGURIDAD E INTEGRIDAD
-- ============================================================================

-- 1. Validación de cobros y protección de cuotas pagadas.
CREATE OR REPLACE FUNCTION fn_cuotas_bu_validar()
RETURNS TRIGGER AS $$
BEGIN
  IF OLD.estado = 'PAGADO' THEN
    RAISE EXCEPTION 'Cuota ya cobrada: no se puede modificar'
      USING ERRCODE = '45000';
  END IF;

  IF NEW.estado = 'PAGADO'
     AND (
       NEW.fecha_pago IS NULL OR
       NEW.metodo_pago IS NULL OR
       NEW.monto_cobrado IS NULL
     ) THEN
    RAISE EXCEPTION 'Un cobro requiere fecha, metodo de pago y monto cobrado'
      USING ERRCODE = '45000';
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_cuotas_bu_validar ON cuotas;

CREATE TRIGGER trg_cuotas_bu_validar
BEFORE UPDATE ON cuotas
FOR EACH ROW
EXECUTE FUNCTION fn_cuotas_bu_validar();

-- 2. Cerrar automáticamente el préstamo al pagar todas sus cuotas.
CREATE OR REPLACE FUNCTION fn_cuotas_au_cerrar_prestamo()
RETURNS TRIGGER AS $$
BEGIN
  IF NEW.estado = 'PAGADO' AND OLD.estado <> 'PAGADO' THEN
    IF NOT EXISTS (
      SELECT 1
      FROM cuotas
      WHERE prestamo_id = NEW.prestamo_id
        AND estado <> 'PAGADO'
    ) THEN
      UPDATE prestamos
      SET estado = 'PAGADO'
      WHERE id = NEW.prestamo_id;
    END IF;
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_cuotas_au_cerrar_prestamo ON cuotas;

CREATE TRIGGER trg_cuotas_au_cerrar_prestamo
AFTER UPDATE ON cuotas
FOR EACH ROW
EXECUTE FUNCTION fn_cuotas_au_cerrar_prestamo();

-- 3. Proteger la auditoría contra modificaciones.
CREATE OR REPLACE FUNCTION fn_auditoria_bu_inmutable()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'La auditoria es inmutable: no se puede modificar'
    USING ERRCODE = '45000';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_auditoria_bu_inmutable ON auditoria;

CREATE TRIGGER trg_auditoria_bu_inmutable
BEFORE UPDATE ON auditoria
FOR EACH ROW
EXECUTE FUNCTION fn_auditoria_bu_inmutable();

-- 4. Proteger la auditoría contra eliminaciones no autorizadas.
CREATE OR REPLACE FUNCTION fn_auditoria_bd_inmutable()
RETURNS TRIGGER AS $$
BEGIN
  IF current_setting('credicochas.permitir_borrado', true) IS DISTINCT FROM '1' THEN
    RAISE EXCEPTION 'La auditoria es inmutable: no se puede borrar'
      USING ERRCODE = '45000';
  END IF;

  RETURN OLD;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_auditoria_bd_inmutable ON auditoria;

CREATE TRIGGER trg_auditoria_bd_inmutable
BEFORE DELETE ON auditoria
FOR EACH ROW
EXECUTE FUNCTION fn_auditoria_bd_inmutable();
