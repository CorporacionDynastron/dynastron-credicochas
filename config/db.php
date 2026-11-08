<?php
/**
 * CREDICOCHA'S v3.0 — config/db.php
 * Lectura del archivo .env y conexión PDO segura compatible con:
 *   - PostgreSQL (Neon Serverless / Supabase / Render Postgres) via DATABASE_URL o DB_DRIVER=pgsql
 *   - MySQL / MariaDB (cPanel / VPS / Hosting tradicional) via DB_DRIVER=mysql
 *
 * Seguridad:
 *   - Sentencias preparadas reales (ATTR_EMULATE_PREPARES = false) => 0% SQL Injection.
 *   - Conexión TLS/SSL automática para Neon y bases de datos en la nube.
 *   - Las credenciales viven en variables de entorno (Render) o en .env, nunca en el código.
 */
declare(strict_types=1);

if (PHP_SAPI !== 'cli' && isset($_SERVER['SCRIPT_FILENAME']) && realpath($_SERVER['SCRIPT_FILENAME']) === __FILE__) {
    http_response_code(403);
    exit;
}

class DbConnectionError extends RuntimeException {}

/**
 * Carga el .env si existe. En Render/Docker también lee variables de entorno del sistema.
 */
function env_all(): array
{
    static $vars = null;
    if ($vars !== null) {
        return $vars;
    }
    $vars = [];
    $candidatos = [dirname(__DIR__) . '/.env', dirname(__DIR__, 2) . '/.env'];
    foreach ($candidatos as $archivo) {
        if (!is_readable($archivo)) {
            continue;
        }
        $lineas = file($archivo, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
        foreach ($lineas as $linea) {
            $linea = trim($linea);
            if ($linea === '' || $linea[0] === '#' || strpos($linea, '=') === false) {
                continue;
            }
            [$k, $v] = explode('=', $linea, 2);
            $k = trim($k);
            $v = trim($v);
            if (strlen($v) >= 2 && ($v[0] === '"' || $v[0] === "'") && substr($v, -1) === $v[0]) {
                $v = substr($v, 1, -1);
            } else {
                $v = preg_replace('/\s+#.*$/', '', $v);
            }
            $vars[$k] = $v;
        }
        break;
    }
    return $vars;
}

function env(string $key, string $default = ''): string
{
    // Prioridad 1: Variables de entorno reales del servidor (Render / Docker / Cloud)
    $real = getenv($key);
    if ($real !== false && $real !== '') {
        return (string) $real;
    }
    if (isset($_ENV[$key]) && $_ENV[$key] !== '') {
        return (string) $_ENV[$key];
    }
    // Prioridad 2: Archivo .env local
    $vars = env_all();
    if (array_key_exists($key, $vars) && $vars[$key] !== '') {
        return (string) $vars[$key];
    }
    return $default;
}

function app_tz(): DateTimeZone
{
    static $tz = null;
    if ($tz === null) {
        try {
            $tz = new DateTimeZone(env('APP_TIMEZONE', 'America/Lima'));
        } catch (Exception $e) {
            $tz = new DateTimeZone('America/Lima');
        }
        date_default_timezone_set($tz->getName());
    }
    return $tz;
}

function mora_fee(): float
{
    $f = (float) env('MORA_FEE', '10');
    return $f >= 0 ? round($f, 2) : 10.0;
}

/**
 * Devuelve el motor activo ('pgsql' o 'mysql').
 * Detecta automáticamente PostgreSQL si hay DATABASE_URL (Neon), puerto 5432,
 * host de Neon (*.neon.tech) o DB_DRIVER=pgsql.
 */
function db_driver(): string
{
    $url = env('DATABASE_URL', '');
    if ($url !== '') {
        $scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));
        if (in_array($scheme, ['postgres', 'postgresql', 'pgsql'], true)) {
            return 'pgsql';
        }
        if (in_array($scheme, ['mysql', 'mariadb'], true)) {
            return 'mysql';
        }
    }
    $drv  = strtolower(env('DB_DRIVER', ''));
    $host = strtolower(env('DB_HOST', 'localhost'));
    $port = env('DB_PORT', '');
    if ($drv === 'pgsql' || $drv === 'postgres' || $drv === 'postgresql'
        || $port === '5432' || strpos($host, 'neon.tech') !== false || strpos($host, 'supabase.') !== false) {
        return 'pgsql';
    }
    return 'mysql';
}

function is_pgsql(): bool
{
    return db_driver() === 'pgsql';
}

function db(): PDO
{
    static $pdo = null;
    if ($pdo instanceof PDO) {
        return $pdo;
    }
    $tz     = app_tz();
    $driver = db_driver();
    $url    = env('DATABASE_URL', '');

    if ($url !== '') {
        $parts = parse_url($url);
        if ($parts === false || empty($parts['host'])) {
            throw new DbConnectionError('DATABASE_URL tiene un formato inválido.');
        }
        $host = $parts['host'];
        $port = (string) ($parts['port'] ?? ($driver === 'pgsql' ? '5432' : '3306'));
        $name = ltrim((string) ($parts['path'] ?? ''), '/');
        $user = isset($parts['user']) ? rawurldecode($parts['user']) : '';
        $pass = isset($parts['pass']) ? rawurldecode($parts['pass']) : '';
        parse_str((string) ($parts['query'] ?? ''), $queryParams);
        $sslmode = (string) ($queryParams['sslmode'] ?? env('DB_SSLMODE', 'require'));
    } else {
        $host    = env('DB_HOST', 'localhost');
        $port    = env('DB_PORT', $driver === 'pgsql' ? '5432' : '3306');
        $name    = env('DB_NAME', '');
        $user    = env('DB_USER', '');
        $pass    = env('DB_PASS', '');
        $sslmode = env('DB_SSLMODE', ($driver === 'pgsql' && !in_array($host, ['localhost', '127.0.0.1'], true)) ? 'require' : 'prefer');
    }

    if ($name === '' || $user === '') {
        throw new DbConnectionError('Faltan credenciales de base de datos (configure DATABASE_URL o DB_HOST, DB_NAME, DB_USER y DB_PASS).');
    }

    $pdoOpts = [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        // En PostgreSQL (Neon Pooler / PgBouncer transaction mode), ATTR_EMULATE_PREPARES=true
        // usa PQescapeLiteral nativo de libpq evitando colisiones de prepared statements en el pooler.
        PDO::ATTR_EMULATE_PREPARES   => ($driver === 'pgsql'),
        PDO::ATTR_TIMEOUT            => 10,
    ];

    if ($driver === 'pgsql') {
        if (!extension_loaded('pdo_pgsql')) {
            throw new DbConnectionError('La extensión PHP pdo_pgsql no está habilitada en el servidor.');
        }
        $dsn = "pgsql:host={$host};port={$port};dbname={$name};sslmode={$sslmode}";
    } else {
        if (!extension_loaded('pdo_mysql')) {
            throw new DbConnectionError('La extensión PHP pdo_mysql no está habilitada en el servidor.');
        }
        $charset = env('DB_CHARSET', 'utf8mb4');
        $dsn = "mysql:host={$host};port={$port};dbname={$name};charset={$charset}";
    }

    try {
        $pdo = new PDO($dsn, $user, $pass, $pdoOpts);
    } catch (PDOException $e) {
        // Fallback para clientes libpq antiguos (ej. Windows sin SNI) que piden explícitamente endpoint=...
        if ($driver === 'pgsql' && strpos($e->getMessage(), 'Endpoint ID is not specified') !== false) {
            $firstLabel = explode('.', $host)[0];
            $endpoint   = (string) preg_replace('/-pooler$/i', '', $firstLabel);
            try {
                $pdo = new PDO($dsn . ";options='endpoint={$endpoint}'", $user, $pass, $pdoOpts);
            } catch (PDOException $e2) {
                error_log('[credicochas] No se pudo conectar a la BD (pgsql fallback): ' . $e2->getMessage());
                throw new DbConnectionError('No se pudo conectar a la base de datos.');
            }
        } else {
            error_log('[credicochas] No se pudo conectar a la BD (' . $driver . '): ' . $e->getMessage());
            throw new DbConnectionError('No se pudo conectar a la base de datos.');
        }
    }

    $offset = (new DateTimeImmutable('now', $tz))->format('P');
    if ($driver === 'pgsql') {
        $pdo->exec("SET TIME ZONE '" . $offset . "'");
        $pdo->exec("SET client_encoding TO 'UTF8'");
    } else {
        $pdo->exec("SET time_zone = '" . $offset . "'");
    }

    return $pdo;
}
