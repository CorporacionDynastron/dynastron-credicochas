<?php
/**
 * CREDICOCHA'S v3.0 — api.php
 * Backend JSON de alta seguridad compatible con:
 *   - PostgreSQL (Neon Serverless / Render / Supabase)
 *   - MySQL / MariaDB (cPanel / VPS)
 *   - Despliegue separado (Frontend en Firebase Hosting + Backend en Render) o unificado
 *
 * Seguridad:
 *   - Consultas 100% preparadas con PDO nativo (ATTR_EMULATE_PREPARES = false) => 0% SQL Injection.
 *   - Sesiones persistentes en base de datos con token SHA-256 + Cookie HttpOnly + Bearer Token + CSRF Token.
 *   - Contraseñas con bcrypt (password_hash) y mitigación de ataques de tiempo (DUMMY_HASH).
 *   - Protección anti fuerza bruta (5 intentos / 15 min) compatible con proxies de Render y Cloudflare.
 *   - Operaciones destructivas (Reiniciar / Importar respaldo) exigen reautenticación con contraseña actual.
 *   - La mora, el cronograma en centavos y los montos cobrados los calcula SIEMPRE el servidor.
 */
declare(strict_types=1);

require __DIR__ . '/config/db.php';

const METODOS     = ['Efectivo', 'Yape', 'Plin', 'Transferencia'];
const FRECUENCIAS = ['Diario', 'Semanal'];
const DUMMY_HASH  = '$2y$10$KRMBx.HhGx/3KzUlz6ApF.KTYxnoHMi6k1M3VvZaFqTivJ9wAZG.W';

class ApiError extends Exception
{
    public $status;
    public function __construct(string $message, int $status = 400)
    {
        parent::__construct($message);
        $this->status = $status;
    }
}

// ============================================================================
//  Cabeceras de Seguridad y CORS (Firebase Hosting <-> Render)
// ============================================================================
function is_https_request(): bool
{
    return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || strtolower((string) ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')) === 'https';
}

function send_security_and_cors_headers(): void
{
    header('Content-Type: application/json; charset=utf-8');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header('Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    if (is_https_request()) {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
    }

    $origin = isset($_SERVER['HTTP_ORIGIN']) ? trim((string) $_SERVER['HTTP_ORIGIN']) : '';
    if ($origin !== '') {
        $allowedConf = trim(env('CORS_ORIGIN', '*'));
        $allowOrigin = null;
        if ($allowedConf === '*') {
            $allowOrigin = $origin;
        } else {
            $allowedList = array_filter(array_map(function ($u) {
                return rtrim(trim($u), '/');
            }, explode(',', $allowedConf)));
            if (in_array(rtrim($origin, '/'), $allowedList, true)) {
                $allowOrigin = $origin;
            }
        }
        if ($allowOrigin !== null) {
            header('Access-Control-Allow-Origin: ' . $allowOrigin);
            header('Access-Control-Allow-Credentials: true');
            header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
            header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Session-Token, X-CSRF-Token');
            header('Access-Control-Max-Age: 86400');
            header('Vary: Origin');
        }
    }

    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'OPTIONS') {
        http_response_code(204);
        exit;
    }
}

// ============================================================================
//  Utilidades
// ============================================================================
function respond(array $data, int $status = 200): void
{
    http_response_code($status);
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PARTIAL_OUTPUT_ON_ERROR);
    exit;
}

function expect_method(string $m): void
{
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== $m) {
        throw new ApiError('Método no permitido.', 405);
    }
}

function read_json(): array
{
    $raw = file_get_contents('php://input');
    if ($raw === false || $raw === '') {
        return [];
    }
    if (strlen($raw) > 30 * 1024 * 1024) {
        throw new ApiError('La solicitud es demasiado grande.', 413);
    }
    $d = json_decode($raw, true);
    if (!is_array($d)) {
        throw new ApiError('Solicitud inválida.', 400);
    }
    return $d;
}

function clean_str($v, int $max): string
{
    $s = is_scalar($v) ? trim((string) $v) : '';
    $s = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', $s) ?? $s;
    return function_exists('mb_substr') ? mb_substr($s, 0, $max, 'UTF-8') : substr($s, 0, $max);
}

function num($v): ?float
{
    if (is_int($v) || is_float($v) || (is_string($v) && is_numeric($v))) {
        $f = (float) $v;
        return is_finite($f) ? $f : null;
    }
    return null;
}

function valid_date(string $d): bool
{
    $dt = DateTime::createFromFormat('Y-m-d', $d);
    return $dt !== false && $dt->format('Y-m-d') === $d;
}

function now_dt(): DateTimeImmutable
{
    return new DateTimeImmutable('now', app_tz());
}

function today(): string
{
    return now_dt()->format('Y-m-d');
}

function tx(PDO $pdo, callable $fn)
{
    $pdo->beginTransaction();
    try {
        $r = $fn();
        $pdo->commit();
        return $r;
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        throw $e;
    }
}

/**
 * Obtiene la IP real del cliente de forma segura detrás de Render / Cloudflare.
 */
function client_ip(): string
{
    $remote = (string) ($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
    // Solo confiamos en cabeceras de proxy si REMOTE_ADDR es una IP privada/loopback del balanceador (ej. Render / Docker)
    $isTrustedProxy = filter_var(
        $remote,
        FILTER_VALIDATE_IP,
        FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
    ) === false;

    if ($isTrustedProxy) {
        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            $cf = trim((string) $_SERVER['HTTP_CF_CONNECTING_IP']);
            if (filter_var($cf, FILTER_VALIDATE_IP) !== false) {
                return substr($cf, 0, 45);
            }
        }
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $parts = array_map('trim', explode(',', (string) $_SERVER['HTTP_X_FORWARDED_FOR']));
            // Tomamos la primera IP pública válida reportada al entrar al balanceador
            foreach ($parts as $candidate) {
                if (filter_var($candidate, FILTER_VALIDATE_IP) !== false) {
                    return substr($candidate, 0, 45);
                }
            }
        }
    }
    return filter_var($remote, FILTER_VALIDATE_IP) !== false ? substr($remote, 0, 45) : '0.0.0.0';
}

// ============================================================================
//  Inicialización automática del esquema (Neon PostgreSQL / MySQL)
// ============================================================================
function ensure_schema(PDO $pdo): void
{
    $tablas = [
        'usuarios',
        'sesiones',
        'login_intentos',
        'clientes',
        'prestamos',
        'cuotas',
        'auditoria'
    ];

    try {
        foreach ($tablas as $tabla) {
            $pdo->query("SELECT 1 FROM {$tabla} LIMIT 1");
        }
        return;
    } catch (PDOException $e) {
        // Falta alguna tabla: intentar inicializar el esquema.
    }

    $sqlFile = is_pgsql()
        ? __DIR__ . '/database_postgres.sql'
        : __DIR__ . '/database.sql';

    if (!is_readable($sqlFile)) {
        throw new RuntimeException('No se encuentra el archivo de esquema de la base de datos.');
    }

    $sql = (string) file_get_contents($sqlFile);

    if (is_pgsql()) {
        $pdo->exec($sql);
    } else {
        $parts = explode('DELIMITER $$', $sql);
        $tableSql = $parts[0];

        foreach (array_filter(array_map('trim', explode(';', $tableSql))) as $stmt) {
            $clean = trim((string) preg_replace('/^\s*--.*$/m', '', $stmt));
            if ($clean !== '') {
                $pdo->exec($clean);
            }
        }
    }
}
// ============================================================================
//  Extensiones v3.1: mora por cuota, ajustes y caja
// ============================================================================
function ensure_feature_schema(PDO $pdo): void
{
    if (is_pgsql()) {
        $pdo->exec("ALTER TABLE cuotas ADD COLUMN IF NOT EXISTS mora_omitida BOOLEAN NOT NULL DEFAULT FALSE");
        $pdo->exec("CREATE TABLE IF NOT EXISTS ajustes_mora (
            id BIGSERIAL PRIMARY KEY, prestamo_id VARCHAR(20) NOT NULL, numero SMALLINT NOT NULL,
            mora_anterior NUMERIC(10,2) NOT NULL, mora_nueva NUMERIC(10,2) NOT NULL,
            motivo VARCHAR(255) NOT NULL DEFAULT '', usuario VARCHAR(50) NOT NULL, creado_en TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (prestamo_id, numero) REFERENCES cuotas(prestamo_id, numero) ON DELETE CASCADE
        )");
        $pdo->exec("CREATE TABLE IF NOT EXISTS movimientos_caja (
            id BIGSERIAL PRIMARY KEY, fecha DATE NOT NULL, tipo VARCHAR(10) NOT NULL CHECK (tipo IN ('INGRESO','EGRESO')),
            categoria VARCHAR(30) NOT NULL, descripcion VARCHAR(255) NOT NULL DEFAULT '', monto NUMERIC(12,2) NOT NULL CHECK (monto > 0),
            usuario VARCHAR(50) NOT NULL, creado_en TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )");
    } else {
        try { $pdo->exec("ALTER TABLE cuotas ADD COLUMN mora_omitida TINYINT(1) NOT NULL DEFAULT 0"); } catch (PDOException $e) { if (stripos($e->getMessage(), 'duplicate') === false && stripos($e->getMessage(), 'exists') === false) throw $e; }
        $pdo->exec("CREATE TABLE IF NOT EXISTS ajustes_mora (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY, prestamo_id VARCHAR(20) NOT NULL, numero SMALLINT UNSIGNED NOT NULL,
            mora_anterior DECIMAL(10,2) NOT NULL, mora_nueva DECIMAL(10,2) NOT NULL, motivo VARCHAR(255) NOT NULL DEFAULT '',
            usuario VARCHAR(50) NOT NULL, creado_en DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            KEY idx_ajustes_cuota(prestamo_id,numero), CONSTRAINT fk_ajustes_cuota FOREIGN KEY(prestamo_id,numero) REFERENCES cuotas(prestamo_id,numero) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        $pdo->exec("CREATE TABLE IF NOT EXISTS movimientos_caja (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY, fecha DATE NOT NULL, tipo VARCHAR(10) NOT NULL,
            categoria VARCHAR(30) NOT NULL, descripcion VARCHAR(255) NOT NULL DEFAULT '', monto DECIMAL(12,2) NOT NULL,
            usuario VARCHAR(50) NOT NULL, creado_en DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, KEY idx_caja_fecha(fecha)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    }
}

// ============================================================================
//  Sesiones Persistentes en BD + Cookie HttpOnly + Bearer Token + CSRF
// ============================================================================
function session_hours(): int
{
    return max(1, min(168, (int) env('SESSION_HOURS', '12')));
}

function set_token_cookie(string $rawToken, int $exp): void
{
    $https = is_https_request();
    $dir   = rtrim(str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '/')), '/');
    $crossOrigin = !empty($_SERVER['HTTP_ORIGIN']);
    setcookie('credicochas_sid', $rawToken, [
        'expires'  => $exp,
        'path'     => $dir === '' ? '/' : $dir . '/',
        'secure'   => $https,
        'httponly' => true,
        'samesite' => ($crossOrigin && $https) ? 'None' : 'Strict',
    ]);
}

function get_incoming_token(): string
{
    $headerToken = trim((string) ($_SERVER['HTTP_X_SESSION_TOKEN'] ?? ''));
    if (preg_match('/^[a-f0-9]{64}$/i', $headerToken)) {
        return strtolower($headerToken);
    }
    $authHeader = (string) ($_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '');
    if (preg_match('/^Bearer\s+([a-f0-9]{64})$/i', trim($authHeader), $m)) {
        return strtolower($m[1]);
    }
    $cookie = (string) ($_COOKIE['credicochas_sid'] ?? '');
    if (preg_match('/^[a-f0-9]{64}$/i', $cookie)) {
        return strtolower($cookie);
    }
    return '';
}

function load_session(PDO $pdo): ?array
{
    static $cached = false;
    static $sessionRow = null;
    if ($cached) {
        return $sessionRow;
    }
    $cached = true;

    $rawToken = get_incoming_token();
    if ($rawToken === '') {
        return null;
    }
    $tokenHash = hash('sha256', $rawToken);
    $st = $pdo->prepare('SELECT * FROM sesiones WHERE token_hash = ? LIMIT 1');
    $st->execute([$tokenHash]);
    $row = $st->fetch();
    if (!$row) {
        return null;
    }
    if ((int) $row['expira_en'] < time()) {
        $pdo->prepare('DELETE FROM sesiones WHERE token_hash = ?')->execute([$tokenHash]);
        return null;
    }
    $row['raw_token'] = $rawToken;
    $sessionRow = $row;
    return $sessionRow;
}

function require_auth(PDO $pdo): array
{
    $s = load_session($pdo);
    if ($s === null) {
        throw new ApiError('Sesión expirada. Ingrese nuevamente.', 401);
    }
    return [
        'id'          => (int) $s['usuario_id'],
        'user'        => (string) $s['usuario'],
        'csrf'        => (string) $s['csrf_token'],
        'must_change' => !empty($s['must_change']),
        'token_hash'  => (string) $s['token_hash'],
        'raw_token'   => (string) $s['raw_token'],
    ];
}

function require_csrf(array $auth): void
{
    $sent = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (!is_string($sent) || $auth['csrf'] === '' || !hash_equals($auth['csrf'], $sent)) {
        throw new ApiError('Token de seguridad inválido. Recargue la página.', 403);
    }
}

function session_info(PDO $pdo, ?array $createdSession = null): array
{
    $s = $createdSession ?? load_session($pdo);
    $auth = $s !== null;
    return [
        'ok'           => true,
        'auth'         => $auth,
        'user'         => $auth ? (string) $s['usuario'] : null,
        'mustChange'   => $auth ? !empty($s['must_change']) : false,
        'csrf'         => $auth ? (string) $s['csrf_token'] : '',
        'sessionToken' => $auth ? (string) ($s['raw_token'] ?? '') : '',
        'moraFee'      => mora_fee(),
        'timezone'     => app_tz()->getName(),
        'serverTime'   => time(),
    ];
}

// ============================================================================
//  Mapeo BD -> JSON
// ============================================================================
function map_client(array $r): array
{
    return [
        'id' => $r['id'], 'nombre' => $r['nombre'], 'dni' => $r['dni'],
        'telefono' => $r['telefono'], 'direccion' => $r['direccion'],
    ];
}

function map_cuota(array $r): array
{
    return [
        'numero'          => (int) $r['numero'],
        'fechaProgramada' => $r['fecha_programada'],
        'monto'           => (float) $r['monto'],
        'estado'          => $r['estado'],
        'fechaPago'       => $r['fecha_pago'],
        'horaPago'        => $r['hora_pago'],
        'metodoPago'      => $r['metodo_pago'],
        'numOperacion'    => $r['num_operacion'],
        'auditId'         => $r['audit_id'],
        'mora'            => $r['mora'] !== null ? (float) $r['mora'] : null,
        'montoCobrado'    => $r['monto_cobrado'] !== null ? (float) $r['monto_cobrado'] : null,
        'moraOmitida'     => in_array($r['mora_omitida'] ?? false, [true, 1, '1', 't', 'true'], true),
        'cobradoPor'      => $r['cobrado_por'] ?? null,
    ];
}

function map_audit(array $r): array
{
    $op = (string) $r['num_operacion'];
    $metodo = (string) $r['metodo'];
    if ($op !== '' && $op !== '-') {
        $metodo .= ' (Ref: ' . $op . ')';
    }
    return [
        'id'              => $r['id'],
        'timestamp'       => $r['fecha_hora'],
        'dateRaw'         => $r['fecha'],
        'cliente'         => $r['cliente'],
        'evento'          => $r['evento'],
        'cuotaNum'        => (string) $r['cuota_num'],
        'monto'           => (float) $r['monto'],
        'montoFormateado' => 'S/ ' . number_format((float) $r['monto'], 2, '.', ''),
        'metodo'          => $metodo,
        'numOperacion'    => $op,
        'usuario'         => $r['usuario'] ?? '',
    ];
}

function load_loans(PDO $pdo, ?string $onlyId = null): array
{
    if ($onlyId === null) {
        $loans = $pdo->query('SELECT * FROM prestamos ORDER BY seq')->fetchAll();
        $cuotas = $pdo->query('SELECT * FROM cuotas ORDER BY prestamo_id, numero')->fetchAll();
    } else {
        $st = $pdo->prepare('SELECT * FROM prestamos WHERE id = ?');
        $st->execute([$onlyId]);
        $loans = $st->fetchAll();
        $st = $pdo->prepare('SELECT * FROM cuotas WHERE prestamo_id = ? ORDER BY numero');
        $st->execute([$onlyId]);
        $cuotas = $st->fetchAll();
    }
    $ajustes = [];
    foreach ($pdo->query('SELECT prestamo_id, numero, mora_nueva FROM ajustes_mora ORDER BY id')->fetchAll() as $a) {
        $ajustes[$a['prestamo_id'] . ':' . $a['numero']] = (float) $a['mora_nueva'];
    }
    $byLoan = [];
    foreach ($cuotas as $c) {
        $mapped = map_cuota($c);
        $key = $c['prestamo_id'] . ':' . $c['numero'];
        if (isset($ajustes[$key])) {
            // La mora mostrada refleja la corrección vigente, pero monto_cobrado conserva
            // el importe que realmente ingresó a caja en la fecha del cobro.
            $mapped['mora'] = $ajustes[$key];
        }
        $byLoan[$c['prestamo_id']][] = $mapped;
    }
    $out = [];
    foreach ($loans as $l) {
        $out[] = [
            'id'             => $l['id'],
            'clienteId'      => $l['cliente_id'],
            'capital'        => (float) $l['capital'],
            'interesPct'     => (float) $l['interes_pct'],
            'totalPagar'     => (float) $l['total_pagar'],
            'cuotasCount'    => (int) $l['cuotas_count'],
            'frecuencia'     => $l['frecuencia'],
            'fechaInicio'    => $l['fecha_inicio'],
            'omitirDomingos' => (bool) $l['omitir_domingos'],
            'estado'         => $l['estado'],
            'cuotas'         => $byLoan[$l['id']] ?? [],
        ];
    }
    return $out;
}

// ============================================================================
//  Auditoría
// ============================================================================
function new_audit_id(PDO $pdo): string
{
    $st = $pdo->prepare('SELECT 1 FROM auditoria WHERE id = ?');
    for ($i = 0; $i < 20; $i++) {
        $id = 'TRX-' . strtoupper(base_convert((string) (int) (microtime(true) * 1000), 10, 36))
            . strtoupper(str_pad(base_convert((string) random_int(0, 1295), 10, 36), 2, '0', STR_PAD_LEFT));
        $st->execute([$id]);
        if (!$st->fetchColumn()) {
            return $id;
        }
    }
    throw new RuntimeException('No se pudo generar un ID de auditoría único.');
}

function log_audit(PDO $pdo, string $evento, string $cliente, string $cuotaNum, float $monto,
                   string $metodo, string $numOp, string $usuario, ?string $id = null): array
{
    $id  = $id ?? new_audit_id($pdo);
    $now = now_dt();
    $st = $pdo->prepare(
        'INSERT INTO auditoria (id, fecha_hora, fecha, cliente, evento, cuota_num, monto, metodo, num_operacion, usuario)
         VALUES (?,?,?,?,?,?,?,?,?,?)'
    );
    $st->execute([$id, $now->format('Y-m-d H:i:s'), $now->format('Y-m-d'), $cliente, $evento, $cuotaNum,
                  round($monto, 2), $metodo, $numOp, $usuario]);
    return map_audit([
        'id' => $id, 'fecha_hora' => $now->format('Y-m-d H:i:s'), 'fecha' => $now->format('Y-m-d'),
        'cliente' => $cliente, 'evento' => $evento, 'cuota_num' => $cuotaNum, 'monto' => round($monto, 2),
        'metodo' => $metodo, 'num_operacion' => $numOp,
    ]);
}

// ============================================================================
//  Autenticación y Verificación de Contraseña
// ============================================================================
function ensure_admin(PDO $pdo): void
{
    if ((int) $pdo->query('SELECT COUNT(*) FROM usuarios')->fetchColumn() > 0) {
        return;
    }
    $user = clean_str(env('ADMIN_USER', 'admin'), 50);
    $pass = env('ADMIN_PASS_INICIAL', '');
    if ($user === '' || strlen($pass) < 6 || $pass === 'CAMBIAR_ESTA_CLAVE') {
        throw new ApiError('Falta configurar ADMIN_USER y ADMIN_PASS_INICIAL (mínimo 6 caracteres) en el archivo .env o variables de entorno.', 500);
    }
    $nowStr = now_dt()->format('Y-m-d H:i:s');
    $st = $pdo->prepare('INSERT INTO usuarios (usuario, password_hash, debe_cambiar_clave, creado_en) VALUES (?, ?, 1, ?)');
    $st->execute([$user, password_hash($pass, PASSWORD_DEFAULT), $nowStr]);
}

function check_rate_limit(PDO $pdo, string $ip, string $usuario = ''): void
{
    $cutoff2Days = now_dt()->modify('-2 days')->format('Y-m-d H:i:s');
    $cutoff15Min = now_dt()->modify('-15 minutes')->format('Y-m-d H:i:s');

    $pdo->prepare('DELETE FROM login_intentos WHERE creado_en < ?')->execute([$cutoff2Days]);
    $pdo->prepare('DELETE FROM sesiones WHERE expira_en < ?')->execute([time()]);

    $st = $pdo->prepare('SELECT COUNT(*) FROM login_intentos WHERE ip = ? AND exito = 0 AND creado_en > ?');
    $st->execute([$ip, $cutoff15Min]);
    if ((int) $st->fetchColumn() >= 5) {
        throw new ApiError('Demasiados intentos fallidos. Por seguridad, espere 15 minutos e intente de nuevo.', 429);
    }

    if ($usuario !== '') {
        $stUser = $pdo->prepare('SELECT COUNT(*) FROM login_intentos WHERE usuario = ? AND exito = 0 AND creado_en > ?');
        $stUser->execute([$usuario, $cutoff15Min]);
        if ((int) $stUser->fetchColumn() >= 8) {
            throw new ApiError('Cuenta protegida temporalmente por múltiples intentos fallidos. Espere 15 minutos.', 429);
        }
    }
}

function verify_current_user_password(PDO $pdo, array $auth, string $password): void
{
    $ip = client_ip();
    check_rate_limit($pdo, $ip, $auth['user']);

    $st = $pdo->prepare('SELECT password_hash FROM usuarios WHERE id = ? LIMIT 1');
    $st->execute([$auth['id']]);
    $hash = $st->fetchColumn();
    $ok = ($hash !== false) && password_verify($password, (string) $hash);

    if (!$ok) {
        $nowStr = now_dt()->format('Y-m-d H:i:s');
        $pdo->prepare('INSERT INTO login_intentos (ip, usuario, exito, creado_en) VALUES (?,?,0,?)')
            ->execute([$ip, $auth['user'], $nowStr]);
        throw new ApiError('Contraseña de confirmación incorrecta.', 403);
    }
}

function do_login(PDO $pdo): void
{
    $in      = read_json();
    $usuario = clean_str($in['usuario'] ?? '', 50);
    $pass    = (isset($in['password']) && is_string($in['password'])) ? $in['password'] : '';
    $ip      = client_ip();

    check_rate_limit($pdo, $ip, $usuario);
    ensure_admin($pdo);

    $st = $pdo->prepare('SELECT * FROM usuarios WHERE usuario = ? LIMIT 1');
    $st->execute([$usuario]);
    $u  = $st->fetch();
    $ok = password_verify($pass, $u ? (string) $u['password_hash'] : DUMMY_HASH) && $u;

    $nowStr = now_dt()->format('Y-m-d H:i:s');
    $st = $pdo->prepare('INSERT INTO login_intentos (ip, usuario, exito, creado_en) VALUES (?,?,?,?)');
    $st->execute([$ip, $usuario, $ok ? 1 : 0, $nowStr]);
    if (!$ok) {
        throw new ApiError('Usuario o contraseña incorrectos.', 401);
    }

    if (password_needs_rehash((string) $u['password_hash'], PASSWORD_DEFAULT)) {
        $pdo->prepare('UPDATE usuarios SET password_hash = ? WHERE id = ?')
            ->execute([password_hash($pass, PASSWORD_DEFAULT), $u['id']]);
    }
    $pdo->prepare('UPDATE usuarios SET ultimo_acceso = ? WHERE id = ?')->execute([$nowStr, $u['id']]);
    $pdo->prepare('DELETE FROM login_intentos WHERE ip = ? AND exito = 0')->execute([$ip]);

    $rawToken  = bin2hex(random_bytes(32));
    $tokenHash = hash('sha256', $rawToken);
    $csrfToken = bin2hex(random_bytes(32));
    $exp       = time() + session_hours() * 3600;
    $mustChange = !empty($u['debe_cambiar_clave']) ? 1 : 0;
    $ua        = clean_str($_SERVER['HTTP_USER_AGENT'] ?? '', 255);

    $pdo->prepare(
        'INSERT INTO sesiones (token_hash, usuario_id, usuario, csrf_token, must_change, ip, user_agent, expira_en, creado_en)
         VALUES (?,?,?,?,?,?,?,?,?)'
    )->execute([$tokenHash, (int) $u['id'], (string) $u['usuario'], $csrfToken, $mustChange, $ip, $ua, $exp, $nowStr]);

    set_token_cookie($rawToken, $exp);

    respond(session_info($pdo, [
        'usuario_id' => (int) $u['id'],
        'usuario'    => (string) $u['usuario'],
        'csrf_token' => $csrfToken,
        'must_change'=> $mustChange,
        'raw_token'  => $rawToken,
    ]));
}

function do_logout(PDO $pdo, array $auth): void
{
    $pdo->prepare('DELETE FROM sesiones WHERE token_hash = ?')->execute([$auth['token_hash']]);
    set_token_cookie('', time() - 42000);
    respond(['ok' => true]);
}

function do_change_password(PDO $pdo, array $auth): void
{
    $in     = read_json();
    $actual = is_string($in['actual'] ?? null) ? $in['actual'] : '';
    $nueva  = is_string($in['nueva'] ?? null) ? $in['nueva'] : '';
    if (strlen($nueva) < 6 || strlen($nueva) > 200 || $nueva === '123' || $nueva === '123456' || strcasecmp($nueva, $auth['user']) === 0) {
        throw new ApiError('Por seguridad, la nueva contraseña debe tener al menos 6 caracteres y no ser igual al usuario.', 422);
    }
    $st = $pdo->prepare('SELECT * FROM usuarios WHERE id = ?');
    $st->execute([$auth['id']]);
    $u = $st->fetch();
    if (!$u) {
        throw new ApiError('Usuario no encontrado.', 404);
    }
    if (empty($u['debe_cambiar_clave'])) {
        verify_current_user_password($pdo, $auth, $actual);
    }
    $pdo->prepare('UPDATE usuarios SET password_hash = ?, debe_cambiar_clave = 0 WHERE id = ?')
        ->execute([password_hash($nueva, PASSWORD_DEFAULT), $auth['id']]);
    // Actualiza la sesión actual y cierra cualquier otra sesión abierta en otros dispositivos
    $pdo->prepare('UPDATE sesiones SET must_change = 0 WHERE token_hash = ?')->execute([$auth['token_hash']]);
    $pdo->prepare('DELETE FROM sesiones WHERE usuario_id = ? AND token_hash <> ?')->execute([$auth['id'], $auth['token_hash']]);
    log_audit($pdo, 'CLAVE_CAMBIADA', '-', '-', 0, '-', '-', $auth['user']);
    respond(['ok' => true]);
}

// ============================================================================
//  Datos
// ============================================================================
function do_bootstrap(PDO $pdo): void
{
    respond([
        'ok'        => true,
        'clients'   => array_map('map_client', $pdo->query('SELECT * FROM clientes ORDER BY seq')->fetchAll()),
        'loans'     => load_loans($pdo),
        'auditLogs' => array_map('map_audit', $pdo->query('SELECT * FROM auditoria ORDER BY seq DESC')->fetchAll()),
        'moraFee'   => mora_fee(),
        'cashMovements' => $pdo->query('SELECT * FROM movimientos_caja ORDER BY fecha DESC, id DESC')->fetchAll(),
        'moraAdjustments' => $pdo->query(
            'SELECT a.id, a.prestamo_id, a.numero, a.mora_anterior, a.mora_nueva, a.motivo, a.usuario, a.creado_en,
                    cl.nombre AS cliente, c.fecha_pago
               FROM ajustes_mora a
               JOIN prestamos p ON p.id = a.prestamo_id
               JOIN clientes cl ON cl.id = p.cliente_id
               JOIN cuotas c ON c.prestamo_id = a.prestamo_id AND c.numero = a.numero
              ORDER BY a.creado_en DESC, a.id DESC'
        )->fetchAll(),
    ]);
}

function next_client_id(PDO $pdo): string
{
    if (is_pgsql()) {
        $pdo->exec('LOCK TABLE clientes IN SHARE ROW EXCLUSIVE MODE');
        $next = (int) $pdo->query("SELECT COALESCE(MAX(CAST(SUBSTRING(id FROM 5) AS INTEGER)), 0) + 1 FROM clientes")->fetchColumn();
    } else {
        $next = (int) $pdo->query("SELECT COALESCE(MAX(CAST(SUBSTRING(id, 5) AS UNSIGNED)), 0) + 1 FROM clientes")->fetchColumn();
    }
    return 'CLI-' . $next;
}

function do_create_client(PDO $pdo, array $auth): void
{
    $in        = read_json();
    $nombre    = clean_str($in['nombre'] ?? '', 150);
    $dni       = clean_str($in['dni'] ?? '', 11);
    $telefono  = clean_str($in['telefono'] ?? '', 20);
    $direccion = clean_str($in['direccion'] ?? '', 255);

    if ($nombre === '') {
        throw new ApiError('Ingrese el nombre del cliente.', 422);
    }
    if (!preg_match('/^(\d{8}|\d{11})$/', $dni)) {
        throw new ApiError('El DNI debe tener 8 dígitos (o RUC de 11).', 422);
    }
    if ($telefono !== '' && !preg_match('/^[\d\s+\-]{6,15}$/', $telefono)) {
        throw new ApiError('Teléfono inválido.', 422);
    }

    $bloqueoId = false;

    if (!is_pgsql()) {
        $lock = (int) $pdo->query("SELECT GET_LOCK('credicochas_client_id', 10)")->fetchColumn();
        if ($lock !== 1) {
            throw new ApiError('No se pudo reservar un código de cliente. Intente nuevamente.', 503);
        }
        $bloqueoId = true;
    }

    try {
        $res = tx($pdo, function () use ($pdo, $auth, $nombre, $dni, $telefono, $direccion) {
            $st = $pdo->prepare('SELECT 1 FROM clientes WHERE dni = ?');
            $st->execute([$dni]);

            if ($st->fetchColumn()) {
                throw new ApiError('Ya existe un cliente registrado con ese DNI/RUC.', 409);
            }

            $id = next_client_id($pdo);

            $pdo->prepare('INSERT INTO clientes (id, nombre, dni, telefono, direccion) VALUES (?,?,?,?,?)')
                ->execute([$id, $nombre, $dni, $telefono, $direccion]);

            $audit = log_audit($pdo, 'CLIENTE_CREADO', $nombre, '-', 0, '-', '-', $auth['user']);

            return [
                'client' => [
                    'id' => $id,
                    'nombre' => $nombre,
                    'dni' => $dni,
                    'telefono' => $telefono,
                    'direccion' => $direccion
                ],
                'audit' => $audit
            ];
        });
    } finally {
        if ($bloqueoId) {
            $pdo->query("SELECT RELEASE_LOCK('credicochas_client_id')");
        }
    }

    respond(['ok' => true] + $res, 201);
}
/** Cronograma: reparte el total en centavos (la última cuota absorbe el resto). */
function build_schedule(float $total, int $n, string $freq, string $start, bool $omitirDomingos): array
{
    $totalCents = (int) round($total * 100);
    $base  = intdiv($totalCents, $n);
    $resto = $totalCents - $base * $n;
    $d = new DateTime($start . ' 00:00:00', app_tz());
    $out = [];
    for ($i = 1; $i <= $n; $i++) {
        if ($freq === 'Diario' && $omitirDomingos && $d->format('w') === '0') {
            $d->modify('+1 day');
        }
        $out[] = ['numero' => $i, 'fecha' => $d->format('Y-m-d'), 'monto' => ($base + ($i === $n ? $resto : 0)) / 100];
        $d->modify($freq === 'Semanal' ? '+7 days' : '+1 day');
    }
    return $out;
}

function do_create_loan(PDO $pdo, array $auth): void
{
    $in         = read_json();
    $clienteId  = clean_str($in['clienteId'] ?? '', 20);
    $capital    = num($in['capital'] ?? null);
    $interes    = num($in['interesPct'] ?? null);
    $n          = isset($in['cuotasCount']) && is_numeric($in['cuotasCount']) ? (int) $in['cuotasCount'] : 0;
    $frecuencia = clean_str($in['frecuencia'] ?? '', 10);
    $inicio     = clean_str($in['fechaInicio'] ?? '', 10);
    $omitir     = !empty($in['omitirDomingos']);

    if ($clienteId === '')                         throw new ApiError('Por favor seleccione un cliente.', 422);
    if ($capital === null || $capital <= 0 || $capital > 99999999) throw new ApiError('El monto debe ser mayor a 0.', 422);
    if ($interes === null || $interes < 0 || $interes > 1000)      throw new ApiError('El interés no puede ser negativo.', 422);
    if ($n < 1 || $n > 100)                        throw new ApiError('El N° de cuotas debe estar entre 1 y 100.', 422);
    if (!in_array($frecuencia, FRECUENCIAS, true)) throw new ApiError('Frecuencia inválida.', 422);
    if (!valid_date($inicio))                      throw new ApiError('Seleccione la fecha del primer cobro.', 422);

    $total = round($capital * (1 + $interes / 100), 2);
    if (intdiv((int) round($total * 100), $n) < 1) {
        throw new ApiError('El monto es muy pequeño para ese N° de cuotas.', 422);
    }
    $cuotas = build_schedule($total, $n, $frecuencia, $inicio, $omitir);

    $res = tx($pdo, function () use ($pdo, $auth, $clienteId, $capital, $interes, $total, $n, $frecuencia, $inicio, $omitir, $cuotas) {
        $st = $pdo->prepare('SELECT nombre FROM clientes WHERE id = ?');
        $st->execute([$clienteId]);
        $cliente = $st->fetchColumn();
        if ($cliente === false) {
            throw new ApiError('El cliente seleccionado no existe.', 404);
        }
        $st = $pdo->prepare('SELECT 1 FROM prestamos WHERE id = ?');
        $loanId = null;
        for ($i = 0; $i < 30 && $loanId === null; $i++) {
            $try = 'LOAN-' . random_int(1000, 9999);
            $st->execute([$try]);
            if (!$st->fetchColumn()) {
                $loanId = $try;
            }
        }
        if ($loanId === null) {
            $loanId = 'LOAN-' . random_int(10000, 99999999);
        }
        $pdo->prepare(
            'INSERT INTO prestamos (id, cliente_id, capital, interes_pct, total_pagar, cuotas_count, frecuencia, fecha_inicio, omitir_domingos, estado)
             VALUES (?,?,?,?,?,?,?,?,?,?)'
        )->execute([$loanId, $clienteId, $capital, $interes, $total, $n, $frecuencia, $inicio, $omitir ? 1 : 0, 'ACTIVO']);

        $ins = $pdo->prepare('INSERT INTO cuotas (prestamo_id, numero, fecha_programada, monto, estado) VALUES (?,?,?,?,?)');
        foreach ($cuotas as $c) {
            $ins->execute([$loanId, $c['numero'], $c['fecha'], $c['monto'], 'PENDIENTE']);
        }
        $audit = log_audit($pdo, 'PRESTAMO_DESEMBOLSADO', (string) $cliente, '1 a ' . $n, $capital, '-', '-', $auth['user']);
        return ['loanId' => $loanId, 'audit' => $audit];
    });
    respond(['ok' => true, 'loan' => load_loans($pdo, $res['loanId'])[0], 'audit' => $res['audit']], 201);
}

function do_pay(PDO $pdo, array $auth): void
{
    $in      = read_json();
    $loanId  = clean_str($in['loanId'] ?? '', 20);
    $numero  = isset($in['numero']) && is_numeric($in['numero']) ? (int) $in['numero'] : 0;
    $metodo  = clean_str($in['metodo'] ?? '', 20);
    $numOp   = clean_str($in['numOperacion'] ?? '', 60);
    if (!in_array($metodo, METODOS, true)) {
        throw new ApiError('Método de pago inválido.', 422);
    }
    if ($metodo === 'Efectivo' || $numOp === '') {
        $numOp = '-';
    }
    if ($loanId === '' || $numero < 1) {
        throw new ApiError('Cuota inválida.', 422);
    }

    $audit = tx($pdo, function () use ($pdo, $auth, $loanId, $numero, $metodo, $numOp) {
        $st = $pdo->prepare(
            'SELECT c.*, cl.nombre AS cliente_nombre
               FROM cuotas c
               JOIN prestamos p ON p.id = c.prestamo_id
               JOIN clientes cl ON cl.id = p.cliente_id
              WHERE c.prestamo_id = ? AND c.numero = ? FOR UPDATE'
        );
        $st->execute([$loanId, $numero]);
        $c = $st->fetch();
        if (!$c) {
            throw new ApiError('La cuota no existe.', 404);
        }
        if ($c['estado'] === 'PAGADO') {
            throw new ApiError('Esta cuota ya fue cobrada.', 409);
        }
        $now   = now_dt();
        $mora  = ($c['fecha_programada'] < $now->format('Y-m-d') && empty($c['mora_omitida'])) ? mora_fee() : 0.0;
        $total = round((float) $c['monto'] + $mora, 2);
        $auditId = new_audit_id($pdo);

        $up = $pdo->prepare(
            "UPDATE cuotas
                SET estado = 'PAGADO', fecha_pago = ?, hora_pago = ?, metodo_pago = ?, num_operacion = ?,
                    mora = ?, monto_cobrado = ?, audit_id = ?, cobrado_por = ?
              WHERE prestamo_id = ? AND numero = ? AND estado = 'PENDIENTE'"
        );
        $up->execute([$now->format('Y-m-d'), $now->format('H:i:s'), $metodo, $numOp, $mora, $total, $auditId,
                      $auth['user'], $loanId, $numero]);
        if ($up->rowCount() !== 1) {
            throw new ApiError('Esta cuota ya fue cobrada.', 409);
        }
        $pdo->prepare(
            "UPDATE prestamos SET estado = 'PAGADO'
              WHERE id = ? AND NOT EXISTS (SELECT 1 FROM cuotas WHERE prestamo_id = ? AND estado <> 'PAGADO')"
        )->execute([$loanId, $loanId]);

        return log_audit($pdo, $mora > 0 ? 'COBRO_CUOTA + MORA' : 'COBRO_CUOTA', (string) $c['cliente_nombre'],
                         (string) $numero, $total, $metodo, $numOp, $auth['user'], $auditId);
    });
    respond(['ok' => true, 'loan' => load_loans($pdo, $loanId)[0], 'audit' => $audit]);
}

// ============================================================================
//  Edición de cliente, mora y caja
// ============================================================================
function do_update_client(PDO $pdo, array $auth): void
{
    $in = read_json();
    $id = clean_str($in['id'] ?? '', 20);
    $nombre = clean_str($in['nombre'] ?? '', 150);
    $dni = clean_str($in['dni'] ?? '', 11);
    $telefono = clean_str($in['telefono'] ?? '', 20);
    $direccion = clean_str($in['direccion'] ?? '', 255);
    if ($id === '' || $nombre === '' || !preg_match('/^(\d{8}|\d{11})$/', $dni)) throw new ApiError('Datos de cliente inválidos.', 422);
    tx($pdo, function () use ($pdo,$id,$nombre,$dni,$telefono,$direccion,$auth) {
        $st=$pdo->prepare('SELECT id FROM clientes WHERE dni=? AND id<>?'); $st->execute([$dni,$id]);
        if ($st->fetchColumn()) throw new ApiError('Ya existe otro cliente con ese DNI/RUC.',409);
        $st=$pdo->prepare('UPDATE clientes SET nombre=?,dni=?,telefono=?,direccion=? WHERE id=?'); $st->execute([$nombre,$dni,$telefono,$direccion,$id]);
        if (!$st->rowCount()) { $q=$pdo->prepare('SELECT 1 FROM clientes WHERE id=?'); $q->execute([$id]); if (!$q->fetchColumn()) throw new ApiError('Cliente no encontrado.',404); }
        log_audit($pdo,'CLIENTE_EDITADO',$nombre,'-',0,'-','-',$auth['user']);
    });
    respond(['ok'=>true,'client'=>['id'=>$id,'nombre'=>$nombre,'dni'=>$dni,'telefono'=>$telefono,'direccion'=>$direccion]]);
}
function do_omit_mora(PDO $pdo, array $auth): void
{
    $in=read_json(); $loan=clean_str($in['loanId']??'',20); $n=(int)($in['numero']??0); $omit=!empty($in['omit']);
    if ($loan==='' || $n<1) throw new ApiError('Cuota inválida.',422);
    tx($pdo,function() use($pdo,$auth,$loan,$n,$omit) {
        $st=$pdo->prepare('SELECT c.estado,c.fecha_programada,cl.nombre FROM cuotas c JOIN prestamos p ON p.id=c.prestamo_id JOIN clientes cl ON cl.id=p.cliente_id WHERE c.prestamo_id=? AND c.numero=? FOR UPDATE');
        $st->execute([$loan,$n]); $c=$st->fetch(); if(!$c) throw new ApiError('Cuota no encontrada.',404);
        if($c['estado']!=='PENDIENTE') throw new ApiError('Solo puede omitir o restaurar mora de cuotas pendientes.',409);
        $up=$pdo->prepare('UPDATE cuotas SET mora_omitida=? WHERE prestamo_id=? AND numero=?'); $up->execute([$omit?1:0,$loan,$n]);
        log_audit($pdo,$omit?'MORA_OMITIDA':'MORA_RESTAURADA',(string)$c['nombre'],(string)$n,0,'-','-',$auth['user']);
    });
    respond(['ok'=>true,'loan'=>load_loans($pdo,$loan)[0]]);
}
function do_adjust_mora(PDO $pdo, array $auth): void
{
    $in=read_json(); $loan=clean_str($in['loanId']??'',20); $n=(int)($in['numero']??0); $new=num($in['mora']??null); $reason=clean_str($in['motivo']??'Corrección de mora',255);
    if($loan===''||$n<1||$new===null||$new<0||$new>1000000) throw new ApiError('Importe de mora inválido.',422);
    tx($pdo,function() use($pdo,$auth,$loan,$n,$new,$reason) {
        $st=$pdo->prepare('SELECT c.mora,c.estado,cl.nombre AS cliente,(SELECT a.mora_nueva FROM ajustes_mora a WHERE a.prestamo_id=c.prestamo_id AND a.numero=c.numero ORDER BY a.id DESC LIMIT 1) AS mora_ajustada FROM cuotas c JOIN prestamos p ON p.id=c.prestamo_id JOIN clientes cl ON cl.id=p.cliente_id WHERE c.prestamo_id=? AND c.numero=? FOR UPDATE'); $st->execute([$loan,$n]); $c=$st->fetch();
        if(!$c||$c['estado']!=='PAGADO') throw new ApiError('Solo puede corregir mora de cuotas ya cobradas.',409);
        $old=(float)($c['mora_ajustada'] ?? $c['mora'] ?? 0); $pdo->prepare('INSERT INTO ajustes_mora(prestamo_id,numero,mora_anterior,mora_nueva,motivo,usuario) VALUES(?,?,?,?,?,?)')->execute([$loan,$n,$old,$new,$reason,$auth['user']]);
        // Ledger inmutable: no se altera el pago original ni su auditoría. load_loans aplica el último ajuste al valor mostrado.
        log_audit($pdo,'MORA_CORREGIDA',(string)$c['cliente'],(string)$n,$new-$old,'-','-',$auth['user']);
    });
    respond(['ok'=>true,'loan'=>load_loans($pdo,$loan)[0]]);
}
function do_cash_movement(PDO $pdo, array $auth): void
{
    $in=read_json(); $tipo=strtoupper(clean_str($in['tipo']??'',10)); $cat=clean_str($in['categoria']??'',30); $desc=clean_str($in['descripcion']??'',255); $m=num($in['monto']??null); $fecha=clean_str($in['fecha']??today(),10);
    $cats=['APORTE','OTRO_INGRESO','GASTO_NEGOCIO','RETIRO_PERSONAL'];
    if(!in_array($tipo,['INGRESO','EGRESO'],true)||!in_array($cat,$cats,true)||$m===null||$m<=0||!valid_date($fecha)) throw new ApiError('Datos del movimiento inválidos.',422);
    if(($tipo==='INGRESO'&&!in_array($cat,['APORTE','OTRO_INGRESO'],true))||($tipo==='EGRESO'&&!in_array($cat,['GASTO_NEGOCIO','RETIRO_PERSONAL'],true))) throw new ApiError('La categoría no corresponde al tipo de movimiento.',422);
    if (is_pgsql()) { $st=$pdo->prepare('INSERT INTO movimientos_caja(fecha,tipo,categoria,descripcion,monto,usuario) VALUES(?,?,?,?,?,?) RETURNING id'); $st->execute([$fecha,$tipo,$cat,$desc,round($m,2),$auth['user']]); $id=$st->fetchColumn(); }
    else { $st=$pdo->prepare('INSERT INTO movimientos_caja(fecha,tipo,categoria,descripcion,monto,usuario) VALUES(?,?,?,?,?,?)'); $st->execute([$fecha,$tipo,$cat,$desc,round($m,2),$auth['user']]); $id=$pdo->lastInsertId(); } respond(['ok'=>true,'movement'=>['id'=>$id,'fecha'=>$fecha,'tipo'=>$tipo,'categoria'=>$cat,'descripcion'=>$desc,'monto'=>round($m,2),'usuario'=>$auth['user']]],201);
}

// ============================================================================
//  Respaldo / Reinicio (Protegidos con Contraseña Actual)
// ============================================================================
function parse_hora(string $h): ?string
{
    if (!preg_match('/^(\d{1,2}):(\d{2}):(\d{2})\s*(?:([ap])\.?\s*m\.?)?/iu', trim($h), $m)) {
        return null;
    }
    $hh = (int) $m[1];
    $ap = isset($m[4]) ? strtolower($m[4]) : '';
    if ($ap === 'p' && $hh < 12) $hh += 12;
    if ($ap === 'a' && $hh === 12) $hh = 0;
    if ($hh > 23 || (int) $m[2] > 59 || (int) $m[3] > 59) {
        return null;
    }
    return sprintf('%02d:%02d:%02d', $hh, (int) $m[2], (int) $m[3]);
}

function parse_ts(string $ts, string $dateRaw): string
{
    $ts = trim($ts);
    if (preg_match('/^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})/', $ts, $m) && checkdate((int) $m[2], (int) $m[3], (int) $m[1])) {
        return "$m[1]-$m[2]-$m[3] $m[4]:$m[5]:$m[6]";
    }
    if (preg_match('/^(\d{1,2})\/(\d{1,2})\/(\d{4}),?[\s\x{00A0}\x{202F}]+(.+)$/u', $ts, $m) && checkdate((int) $m[2], (int) $m[1], (int) $m[3])) {
        $h = parse_hora((string) preg_replace('/[\x{00A0}\x{202F}]/u', ' ', $m[4]));
        if ($h !== null) {
            return sprintf('%04d-%02d-%02d %s', (int) $m[3], (int) $m[2], (int) $m[1], $h);
        }
    }
    return $dateRaw . ' 00:00:00';
}

function split_metodo(string $metodo, string $numField): array
{
    if (preg_match('/^(.*?)\s*\(Ref:\s*(.*)\)\s*$/su', $metodo, $m)) {
        $metodo = trim($m[1]);
        $op = trim($m[2]);
    } else {
        $metodo = trim($metodo);
        $op = trim($numField);
    }
    return [$metodo === '' ? '-' : clean_str($metodo, 30), $op === '' ? '-' : clean_str($op, 60)];
}

function wipe_all(PDO $pdo): void
{
    $pgsql = is_pgsql();

    if ($pgsql) {
        $pdo->exec("SET LOCAL credicochas.permitir_borrado = '1'");
    } else {
        $pdo->exec('SET @credicochas_permitir_borrado = 1');
    }

    try {
        $pdo->exec('DELETE FROM movimientos_caja');
        $pdo->exec('DELETE FROM ajustes_mora');
        $pdo->exec('DELETE FROM cuotas');
        $pdo->exec('DELETE FROM prestamos');
        $pdo->exec('DELETE FROM clientes');
        $pdo->exec('DELETE FROM auditoria');
    } finally {
        if ($pgsql) {
            $pdo->exec("SET LOCAL credicochas.permitir_borrado = ''");
        } else {
            $pdo->exec('SET @credicochas_permitir_borrado = NULL');
        }
    }
}

function do_import_backup(PDO $pdo, array $auth): void
{
    $d = read_json();
    $password = is_string($d['password'] ?? null) ? $d['password'] : '';
    if ($password === '') {
        throw new ApiError('Debes ingresar tu contraseña para importar el respaldo.', 401);
    }
    verify_current_user_password($pdo, $auth, $password);

    $bad = function (string $why) {
        throw new ApiError("El archivo no es un respaldo válido de Credicocha's ($why).", 422);
    };
    if (($d['app'] ?? '') !== 'credicochas'
        || !isset($d['clients'], $d['loans'], $d['auditLogs'], $d['cashMovements'], $d['moraAdjustments'])
        || !is_array($d['clients']) || !is_array($d['loans']) || !is_array($d['auditLogs'])
        || !is_array($d['cashMovements']) || !is_array($d['moraAdjustments'])) {
        $bad('formato');
    }
    if (count($d['clients']) > 20000 || count($d['loans']) > 50000 || count($d['auditLogs']) > 500000) {
        $bad('demasiados registros');
    }

    $clients = []; $dnis = []; $nombresPorId = [];
    foreach ($d['clients'] as $c) {
        if (!is_array($c)) $bad('cliente');
        $id = clean_str($c['id'] ?? '', 20);
        $nombre = clean_str($c['nombre'] ?? '', 150);
        $dni = clean_str($c['dni'] ?? '', 11);
        if (!preg_match('/^CLI-\d{1,9}$/', $id) || isset($nombresPorId[$id])) $bad("cliente $id");
        if ($nombre === '' || !preg_match('/^(\d{8}|\d{11})$/', $dni) || isset($dnis[$dni])) $bad("cliente $id");
        $dnis[$dni] = true;
        $nombresPorId[$id] = $nombre;
        $clients[] = [$id, $nombre, $dni, clean_str($c['telefono'] ?? '', 20), clean_str($c['direccion'] ?? '', 255)];
    }

    $loans = []; $loanIds = [];
    foreach ($d['loans'] as $l) {
        if (!is_array($l)) $bad('préstamo');
        $id = clean_str($l['id'] ?? '', 20);
        $cid = clean_str($l['clienteId'] ?? '', 20);
        if (!preg_match('/^LOAN-\d{1,9}$/', $id) || isset($loanIds[$id]) || !isset($nombresPorId[$cid])) $bad("préstamo $id");
        $loanIds[$id] = true;
        $capital = num($l['capital'] ?? null); $interes = num($l['interesPct'] ?? null); $total = num($l['totalPagar'] ?? null);
        $frec = clean_str($l['frecuencia'] ?? '', 10); $inicio = clean_str($l['fechaInicio'] ?? '', 10);
        if ($capital === null || $capital <= 0 || $capital >= 1e10 || $interes === null || $interes < 0 || $interes > 9999
            || $total === null || $total <= 0 || $total >= 1e10 || !in_array($frec, FRECUENCIAS, true) || !valid_date($inicio)) {
            $bad("préstamo $id");
        }
        if (!isset($l['cuotas']) || !is_array($l['cuotas']) || count($l['cuotas']) < 1 || count($l['cuotas']) > 1000) $bad("cuotas de $id");
        $cuotas = []; $seen = []; $allPaid = true;
        foreach ($l['cuotas'] as $c) {
            if (!is_array($c)) $bad("cuotas de $id");
            $numero = isset($c['numero']) && is_numeric($c['numero']) ? (int) $c['numero'] : 0;
            $fp = clean_str($c['fechaProgramada'] ?? '', 10);
            $monto = num($c['monto'] ?? null);
            if ($numero < 1 || $numero > 1000 || isset($seen[$numero]) || !valid_date($fp) || $monto === null || $monto <= 0 || $monto >= 1e10) {
                $bad("cuota $numero de $id");
            }
            $seen[$numero] = true;
            $row = ['numero' => $numero, 'fp' => $fp, 'monto' => $monto, 'estado' => 'PENDIENTE', 'fecha_pago' => null, 'hora' => null,
                    'metodo' => null, 'op' => null, 'mora' => null, 'cobrado' => null, 'audit' => null, 'mora_omitida' => !empty($c['moraOmitida']), 'por' => null];
            if (($c['estado'] ?? '') === 'PAGADO') {
                $fpago = clean_str($c['fechaPago'] ?? '', 10);
                $mora  = num($c['mora'] ?? null) ?? 0.0;
                $metodo = clean_str($c['metodoPago'] ?? '', 20);
                $audit = clean_str($c['auditId'] ?? '', 30);
                $op = clean_str($c['numOperacion'] ?? '', 60);
                $row['estado'] = 'PAGADO';
                $row['fecha_pago'] = valid_date($fpago) ? $fpago : $fp;
                $row['hora'] = parse_hora(clean_str($c['horaPago'] ?? '', 30));
                $row['metodo'] = in_array($metodo, METODOS, true) ? $metodo : 'Efectivo';
                $row['op'] = $op === '' ? '-' : $op;
                $row['mora'] = ($mora >= 0 && $mora < 1e8) ? round($mora, 2) : 0.0;
                $cobrado = num($c['montoCobrado'] ?? null);
                $row['cobrado'] = ($cobrado !== null && $cobrado > 0 && $cobrado < 1e10) ? round($cobrado, 2) : round($monto + $row['mora'], 2);
                $row['audit'] = preg_match('/^[A-Za-z0-9_-]{3,30}$/', $audit) ? $audit : null;
                $cobrador = clean_str($c['cobradoPor'] ?? '', 50);
                $row['por'] = $cobrador !== '' ? $cobrador : $auth['user'];
            } else {
                $allPaid = false;
            }
            $cuotas[] = $row;
        }
        usort($cuotas, function ($a, $b) { return $a['numero'] <=> $b['numero']; });
        $loans[] = ['id' => $id, 'cid' => $cid, 'capital' => $capital, 'interes' => $interes, 'total' => $total, 'frec' => $frec,
                    'inicio' => $inicio, 'omitir' => array_key_exists('omitirDomingos', $l) ? !empty($l['omitirDomingos']) : true,
                    'estado' => $allPaid ? 'PAGADO' : 'ACTIVO', 'cuotas' => $cuotas];
    }

    $audits = []; $auditIds = [];
    foreach (array_reverse($d['auditLogs']) as $a) {
        if (!is_array($a)) $bad('auditoría');
        $id = clean_str($a['id'] ?? '', 30);
        if (!preg_match('/^[A-Za-z0-9_-]{3,30}$/', $id) || isset($auditIds[$id])) $bad("auditoría $id");
        $auditIds[$id] = true;
        $dateRaw = clean_str($a['dateRaw'] ?? '', 10);
        if (!valid_date($dateRaw)) $dateRaw = today();
        $ts = parse_ts(clean_str($a['timestamp'] ?? '', 40), $dateRaw);
        [$metodo, $op] = split_metodo(clean_str($a['metodo'] ?? '-', 60), clean_str($a['numOperacion'] ?? '-', 60));
        $monto = num($a['monto'] ?? null) ?? 0.0;
        $evento = clean_str($a['evento'] ?? '', 40);
        $audits[] = [$id, $ts, substr($ts, 0, 10), clean_str($a['cliente'] ?? '-', 150) ?: '-', $evento === '' ? 'EVENTO' : $evento,
                     clean_str($a['cuotaNum'] ?? '-', 20) ?: '-', ($monto >= 0 && $monto < 1e10) ? round($monto, 2) : 0.0, $metodo, $op, (clean_str($a['usuario'] ?? '', 50) ?: $auth['user'])];
    }

    foreach ($loans as $l) {
        foreach ($l['cuotas'] as $c) {
            if ($c['estado'] === 'PAGADO'
                && $c['audit'] !== null
                && !isset($auditIds[$c['audit']])) {
                $bad("auditoría inexistente en cuota {$c['numero']} del préstamo {$l['id']}");
            }
        }
    }

    $cashData = $d['cashMovements'];
    $moraData = $d['moraAdjustments'];

    if (!is_array($cashData) || !is_array($moraData)) {
        $bad('movimientos de caja o ajustes de mora');
    }

    if (count($cashData) > 100000 || count($moraData) > 100000) {
        $bad('demasiados movimientos o ajustes');
    }

    $cashMovements = [];
    $cashIds = [];
    foreach ($cashData as $m) {
        if (!is_array($m)) $bad('movimiento de caja');

        $id = clean_str($m['id'] ?? '', 20);
        $fecha = clean_str($m['fecha'] ?? '', 10);
        $tipo = strtoupper(clean_str($m['tipo'] ?? '', 10));
        $categoria = clean_str($m['categoria'] ?? '', 30);
        $descripcion = clean_str($m['descripcion'] ?? '', 255);
        $monto = num($m['monto'] ?? null);
        $usuario = clean_str($m['usuario'] ?? '', 50);
        $creado = clean_str($m['creado_en'] ?? '', 30);

        if (!preg_match('/^[1-9]\d{0,17}$/', $id)
            || isset($cashIds[$id])
            || !valid_date($fecha)
            || !in_array($tipo, ['INGRESO', 'EGRESO'], true)
            || $categoria === ''
            || $monto === null || $monto <= 0 || $monto >= 1e10
            || $usuario === ''
            || $creado === '' || strtotime($creado) === false) {
            $bad("movimiento de caja $id");
        }

        $cashIds[$id] = true;
        $cashMovements[] = [(int)$id, $fecha, $tipo, $categoria, $descripcion,
                            round($monto, 2), $usuario, $creado];
    }

    $cuotasValidas = [];
    foreach ($loans as $l) {
        foreach ($l['cuotas'] as $c) {
            $cuotasValidas[$l['id'] . ':' . $c['numero']] = true;
        }
    }

    $moraAdjustments = [];
    $moraIds = [];
    foreach ($moraData as $a) {
        if (!is_array($a)) $bad('ajuste de mora');

        $id = clean_str($a['id'] ?? '', 20);
        $prestamo = clean_str($a['prestamo_id'] ?? '', 20);
        $numero = isset($a['numero']) && is_numeric($a['numero']) ? (int)$a['numero'] : 0;
        $anterior = num($a['mora_anterior'] ?? null);
        $nueva = num($a['mora_nueva'] ?? null);
        $motivo = clean_str($a['motivo'] ?? '', 255);
        $usuario = clean_str($a['usuario'] ?? '', 50);
        $creado = clean_str($a['creado_en'] ?? '', 30);

        if (!preg_match('/^[1-9]\d{0,17}$/', $id)
            || isset($moraIds[$id])
            || !isset($loanIds[$prestamo])
            || $numero < 1 || !isset($cuotasValidas[$prestamo . ':' . $numero])
            || $anterior === null || $anterior < 0 || $anterior >= 1e8
            || $nueva === null || $nueva < 0 || $nueva >= 1e8
            || $usuario === ''
            || $creado === '' || strtotime($creado) === false) {
            $bad("ajuste de mora $id");
        }

        $moraIds[$id] = true;
        $moraAdjustments[] = [(int)$id, $prestamo, $numero,
                              round($anterior, 2), round($nueva, 2),
                              $motivo, $usuario, $creado];
    }

    tx($pdo, function () use ($pdo, $clients, $loans, $audits, $cashMovements, $moraAdjustments, $auth) {
        wipe_all($pdo);
        $st = $pdo->prepare('INSERT INTO clientes (id, nombre, dni, telefono, direccion) VALUES (?,?,?,?,?)');
        foreach ($clients as $r) $st->execute($r);

        $sl = $pdo->prepare('INSERT INTO prestamos (id, cliente_id, capital, interes_pct, total_pagar, cuotas_count, frecuencia, fecha_inicio, omitir_domingos, estado)
                             VALUES (?,?,?,?,?,?,?,?,?,?)');
        $sc = $pdo->prepare('INSERT INTO cuotas (prestamo_id, numero, fecha_programada, monto, estado, fecha_pago, hora_pago, metodo_pago, num_operacion, mora, monto_cobrado, audit_id, mora_omitida, cobrado_por)
                             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)');
        foreach ($loans as $l) {
            $sl->execute([$l['id'], $l['cid'], $l['capital'], $l['interes'], $l['total'], count($l['cuotas']), $l['frec'], $l['inicio'], $l['omitir'] ? 1 : 0, $l['estado']]);
            foreach ($l['cuotas'] as $c) {
                $sc->execute([$l['id'], $c['numero'], $c['fp'], $c['monto'], $c['estado'], $c['fecha_pago'], $c['hora'], $c['metodo'], $c['op'], $c['mora'], $c['cobrado'], $c['audit'], $c['mora_omitida'], $c['por']]);
            }
        }
        $sa = $pdo->prepare('INSERT INTO auditoria (id, fecha_hora, fecha, cliente, evento, cuota_num, monto, metodo, num_operacion, usuario) VALUES (?,?,?,?,?,?,?,?,?,?)');
        foreach ($audits as $r) $sa->execute($r);

        $sm = $pdo->prepare('INSERT INTO movimientos_caja
            (id, fecha, tipo, categoria, descripcion, monto, usuario, creado_en)
            VALUES (?,?,?,?,?,?,?,?)');
        foreach ($cashMovements as $r) $sm->execute($r);

        $saj = $pdo->prepare('INSERT INTO ajustes_mora
            (id, prestamo_id, numero, mora_anterior, mora_nueva, motivo, usuario, creado_en)
            VALUES (?,?,?,?,?,?,?,?)');
        foreach ($moraAdjustments as $r) $saj->execute($r);

        if (is_pgsql()) {
            $pdo->query("SELECT setval(pg_get_serial_sequence('movimientos_caja','id'),
                COALESCE(MAX(id),1), COUNT(*) > 0) FROM movimientos_caja");
            $pdo->query("SELECT setval(pg_get_serial_sequence('ajustes_mora','id'),
                COALESCE(MAX(id),1), COUNT(*) > 0) FROM ajustes_mora");
        }

        log_audit($pdo, 'RESPALDO_IMPORTADO', '-', '-', 0, '-', '-', $auth['user']);
    });
    respond(['ok' => true, 'clients' => count($clients), 'loans' => count($loans)]);
}

function do_reset(PDO $pdo, array $auth): void
{
    $in = read_json();
    if (($in['confirm'] ?? '') !== 'BORRAR') {
        throw new ApiError('Confirmación inválida.', 422);
    }
    $password = is_string($in['password'] ?? null) ? $in['password'] : '';
    if ($password === '') {
        throw new ApiError('Debes ingresar tu contraseña para reiniciar el sistema.', 401);
    }
    verify_current_user_password($pdo, $auth, $password);

    tx($pdo, function () use ($pdo, $auth) {
        wipe_all($pdo);
        log_audit($pdo, 'SISTEMA_REINICIADO', '-', '-', 0, '-', '-', $auth['user']);
    });
    respond(['ok' => true]);
}

// ============================================================================
//  Router Principal
// ============================================================================
send_security_and_cors_headers();

try {
    $action = isset($_GET['action']) ? (string) $_GET['action'] : '';
    if ($action === 'ping') {
        respond(['ok' => true, 'ts' => time()]);
    }
    if ($action === 'session' && get_incoming_token() === '') {
        expect_method('GET');
        respond([
            'ok'           => true,
            'auth'         => false,
            'user'         => null,
            'mustChange'   => false,
            'csrf'         => '',
            'sessionToken' => '',
            'moraFee'      => mora_fee(),
            'timezone'     => app_tz()->getName(),
            'serverTime'   => time(),
        ]);
    }
    $pdo = db();
    ensure_schema($pdo);
    ensure_feature_schema($pdo);

    switch ($action) {
        case 'session':
            expect_method('GET');
            respond(session_info($pdo));
        case 'login':
            expect_method('POST');
            do_login($pdo);
        case 'bootstrap':
            expect_method('GET');
            require_auth($pdo);
            do_bootstrap($pdo);
        case 'logout':
        case 'create_client':
        case 'update_client':
        case 'omit_mora':
        case 'adjust_mora':
        case 'cash_movement':
        case 'create_loan':
        case 'pay':
        case 'change_password':
        case 'import_backup':
        case 'reset':
            expect_method('POST');
            $auth = require_auth($pdo);
            require_csrf($auth);
            if ($action === 'logout') {
                do_logout($pdo, $auth);
            }
            if ($auth['must_change'] && $action !== 'change_password') {
                throw new ApiError('Debe cambiar su contraseña inicial antes de continuar.', 403);
            }
            switch ($action) {
                case 'create_client':   do_create_client($pdo, $auth);
                case 'update_client':   do_update_client($pdo, $auth);
                case 'omit_mora':       do_omit_mora($pdo, $auth);
                case 'adjust_mora':     do_adjust_mora($pdo, $auth);
                case 'cash_movement':   do_cash_movement($pdo, $auth);
                case 'create_loan':     do_create_loan($pdo, $auth);
                case 'pay':             do_pay($pdo, $auth);
                case 'change_password': do_change_password($pdo, $auth);
                case 'import_backup':   do_import_backup($pdo, $auth);
                case 'reset':           do_reset($pdo, $auth);
            }
            break;
        default:
            throw new ApiError('Acción no encontrada.', 404);
    }
} catch (ApiError $e) {
    respond(['ok' => false, 'error' => $e->getMessage()], $e->status);
} catch (DbConnectionError $e) {
    respond(['ok' => false, 'error' => $e->getMessage() . ' Revise DATABASE_URL o las variables DB_* en Render / .env.'], 500);
} catch (PDOException $e) {
    $sqlstate = (string) ($e->errorInfo[0] ?? $e->getCode());
    $driver   = (int) ($e->errorInfo[1] ?? 0);
    if ($sqlstate === '45000' || $sqlstate === 'P0001') {
        respond(['ok' => false, 'error' => (string) ($e->errorInfo[2] ?? $e->getMessage())], 409);
    }
    if ($sqlstate === '42S02' || $sqlstate === '42P01') {
        try {
            ensure_schema(db());
        } catch (Throwable $ignore) {}
        respond(['ok' => false, 'error' => 'Tablas inicializadas automáticamente. Por favor intente la acción de nuevo.'], 503);
    }
    if ($sqlstate === '23505' || ($sqlstate === '23000' && $driver === 1062)) {
        respond(['ok' => false, 'error' => 'Registro duplicado.'], 409);
    }
    error_log('[credicochas] PDOException: ' . $e->getMessage());
    respond(['ok' => false, 'error' => 'Error de base de datos.'] + (env('APP_DEBUG', 'false') === 'true' ? ['detail' => $e->getMessage()] : []), 500);
} catch (Throwable $e) {
    error_log('[credicochas] ' . $e->getMessage() . ' @ ' . $e->getFile() . ':' . $e->getLine());
    respond(['ok' => false, 'error' => 'Error interno del servidor.'] + (env('APP_DEBUG', 'false') === 'true' ? ['detail' => $e->getMessage()] : []), 500);
}
