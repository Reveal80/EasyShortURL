<?php
ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_samesite', 'Strict');
session_start();

$nonce = base64_encode(random_bytes(16));

// --- Cabeceras de seguridad ---
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
header("Content-Security-Policy: default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com 'nonce-{$nonce}'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'");

// --- Funciones de IP y rate limiting ---
function getClientIp(): string {
    return filter_var($_SERVER['REMOTE_ADDR'] ?? 'unknown', FILTER_VALIDATE_IP) ?: 'unknown';
}

function writeJson(string $file, array $data): bool {
    $fp = fopen($file, 'c+');
    if (!$fp) return false;
    if (!flock($fp, LOCK_EX)) { fclose($fp); return false; }
    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, json_encode($data, JSON_PRETTY_PRINT));
    flock($fp, LOCK_UN);
    fclose($fp);
    return true;
}

function checkRedirectRateLimit(string $ip): bool {
    $file = __DIR__ . '/data/redirect_limits.json';
    $fp   = fopen($file, 'c+');
    if (!$fp) return true;
    flock($fp, LOCK_EX);
    $raw  = stream_get_contents($fp);
    $data = json_decode($raw, true) ?? [];
    $now  = time();
    foreach (array_keys($data) as $k) {
        if ($now - ($data[$k]['window_start'] ?? 0) >= 60) unset($data[$k]);
    }
    if (!isset($data[$ip])) {
        $data[$ip] = ['count' => 1, 'window_start' => $now];
        $allow = true;
    } else {
        $entry = &$data[$ip];
        if ($now - $entry['window_start'] >= 60) {
            $entry['count'] = 1;
            $entry['window_start'] = $now;
            $allow = true;
        } else {
            $entry['count']++;
            $allow = $entry['count'] <= 60;
        }
    }
    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, json_encode($data, JSON_PRETTY_PRINT));
    flock($fp, LOCK_UN);
    fclose($fp);
    return $allow;
}

// --- Manejar redirecciones de URLs cortas ---
$requestPath  = trim(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH), '/');
$reservedPaths = ['index.php', 'dashboard.php', 'logout.php', 'redirect.php', ''];

if (!empty($requestPath) && !in_array($requestPath, $reservedPaths) && preg_match('/^[a-zA-Z0-9]{3,12}$/', $requestPath)) {
    $dataFile = __DIR__ . '/data/urls.json';
    if (file_exists($dataFile)) {
        $urls = json_decode(file_get_contents($dataFile), true) ?? [];
        if (isset($urls[$requestPath])) {
            $target = $urls[$requestPath]['url'];
            if (!preg_match('#^https?://#i', $target)) {
                http_response_code(400);
                exit('URL de destino no válida.');
            }
            if (!checkRedirectRateLimit(getClientIp())) {
                http_response_code(429);
                exit('Too Many Requests. Please try again later.');
            }
            $urls[$requestPath]['clicks']    = ($urls[$requestPath]['clicks'] ?? 0) + 1;
            $urls[$requestPath]['last_used'] = date('Y-m-d H:i:s');
            writeJson($dataFile, $urls);
            header('Location: ' . $target, true, 302);
            exit;
        }
    }
    http_response_code(404);
    echo '<!DOCTYPE html><html lang="es"><body style="font-family:sans-serif;text-align:center;padding:80px;background:#0a0e1a;color:#f9fafb"><h1 style="font-size:4rem;margin:0">404</h1><p>URL no encontrada</p><a href="/" style="color:#06b6d4">Inicio</a></body></html>';
    exit;
}

// --- Redirigir si ya está autenticado ---
if (isset($_SESSION['logged_in'])) {
    if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > 7200) {
        $_SESSION = [];
        session_regenerate_id(true);
        session_destroy();
        header('Location: index.php');
        exit;
    }
    header('Location: dashboard.php');
    exit;
}

// --- Funciones de seguridad ---
function loadEnv(): array {
    $env  = [];
    $file = __DIR__ . '/.env';
    if (!file_exists($file)) return $env;
    foreach (file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        if (strpos(trim($line), '#') === 0 || strpos($line, '=') === false) continue;
        [$k, $v] = explode('=', $line, 2);
        $env[trim($k)] = trim($v);
    }
    return $env;
}

function getAttemptsFile(): string {
    return __DIR__ . '/data/attempts.json';
}

function getAttempts(string $ip): array {
    $file = getAttemptsFile();
    $data = file_exists($file) ? (json_decode(file_get_contents($file), true) ?? []) : [];
    return $data[$ip] ?? ['count' => 0, 'locked_until' => null];
}

function saveAttempts(string $ip, array $entry): void {
    $file = getAttemptsFile();
    $fp   = fopen($file, 'c+');
    if (!$fp) return;
    flock($fp, LOCK_EX);
    $data     = json_decode(stream_get_contents($fp), true) ?? [];
    $data[$ip] = $entry;
    // Limpiar entradas cuyo bloqueo expiró hace más de 24h
    $now = time();
    foreach (array_keys($data) as $k) {
        $e = $data[$k];
        if ($k !== $ip && ($e['locked_until'] === null || $e['locked_until'] < $now - 86400)) {
            unset($data[$k]);
        }
    }
    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, json_encode($data, JSON_PRETTY_PRINT));
    flock($fp, LOCK_UN);
    fclose($fp);
}

function logSecurity(string $msg): void {
    $log  = __DIR__ . '/data/security.log';
    $ip   = getClientIp();
    file_put_contents($log, date('[Y-m-d H:i:s]') . " IP:$ip $msg\n", FILE_APPEND);
    if (file_exists($log)) {
        $lines = file($log);
        if (count($lines) > 500) {
            file_put_contents($log, implode('', array_slice($lines, -500)));
        }
    }
}

// --- Idioma ---
if (isset($_GET['lang']) && in_array($_GET['lang'], ['es', 'en'])) {
    $_SESSION['lang'] = $_GET['lang'];
    header('Location: index.php');
    exit;
}
$lang = $_SESSION['lang'] ?? 'es';
$tr = [
    'es' => ['title' => 'Acortador de URLs', 'user' => 'Usuario', 'pass' => 'Contraseña', 'login' => 'Iniciar sesión'],
    'en' => ['title' => 'URL Shortener',      'user' => 'Username', 'pass' => 'Password',   'login' => 'Log in'],
][$lang];

// --- Generar token CSRF ---
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$error = '';
$ip    = getClientIp();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    if (!hash_equals($_SESSION['csrf_token'] ?? '', $_POST['csrf_token'] ?? '')) {
        logSecurity('CSRF token inválido en login');
        http_response_code(403);
        exit('Solicitud no válida.');
    }

    $attempts = getAttempts($ip);
    if ($attempts['locked_until'] && time() < $attempts['locked_until']) {
        $wait  = ceil(($attempts['locked_until'] - time()) / 60);
        $error = "Demasiados intentos fallidos. Espera {$wait} minuto(s).";
    } else {
        $username = mb_substr($_POST['username'] ?? '', 0, 64);
        $password = mb_substr($_POST['password'] ?? '', 0, 128);

        $env       = loadEnv();
        $validUser = ($username === ($env['APP_USER'] ?? ''));
        $validPass = password_verify($password, $env['APP_PASSWORD'] ?? '');

        if ($validUser && $validPass) {
            saveAttempts($ip, ['count' => 0, 'locked_until' => null]);
            session_regenerate_id(true);
            $_SESSION['logged_in']     = true;
            $_SESSION['username']      = $username;
            $_SESSION['last_activity'] = time();
            $_SESSION['csrf_token']    = bin2hex(random_bytes(32));
            logSecurity("Login exitoso: $username");
            header('Location: dashboard.php');
            exit;
        } else {
            $attempts['count']++;
            if ($attempts['count'] >= 5) {
                $attempts['locked_until'] = time() + 900;
                logSecurity("IP bloqueada tras 5 intentos fallidos");
                $error = 'Demasiados intentos fallidos. Espera 15 minutos.';
            } else {
                $remaining = 5 - $attempts['count'];
                $error     = "Credenciales incorrectas. Intentos restantes: {$remaining}";
                logSecurity("Login fallido para usuario: $username ({$attempts['count']}/5)");
            }
            saveAttempts($ip, $attempts);
        }
    }
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EasyShort — Iniciar sesión</title>
    <style>
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: #0a0e1a;
            color: #f9fafb;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 1rem;
        }

        .login-wrap { width: 100%; max-width: 400px; }

        .logo { text-align: center; margin-bottom: 2rem; }

        .logo h1 {
            font-size: 1.8rem;
            font-weight: 700;
            background: linear-gradient(135deg, #06b6d4, #3b82f6);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .logo p { color: #6b7280; font-size: 0.9rem; margin-top: 0.25rem; }

        .card {
            background: #111827;
            border: 1px solid #1f2937;
            border-radius: 16px;
            padding: 2rem;
        }

        .error-msg {
            background: rgba(239,68,68,0.1);
            border: 1px solid rgba(239,68,68,0.3);
            color: #f87171;
            padding: 0.75rem 1rem;
            border-radius: 8px;
            margin-bottom: 1.5rem;
            font-size: 0.9rem;
        }

        label { display: block; font-size: 0.85rem; font-weight: 500; color: #9ca3af; margin-bottom: 0.4rem; }

        input[type="text"], input[type="password"] {
            width: 100%;
            background: #1f2937;
            border: 1px solid #374151;
            color: #f9fafb;
            padding: 0.75rem 1rem;
            border-radius: 8px;
            font-size: 1rem;
            outline: none;
            transition: border-color 0.2s;
        }

        input:focus { border-color: #06b6d4; }
        .form-group { margin-bottom: 1.25rem; }

        .btn-primary {
            width: 100%;
            background: linear-gradient(135deg, #06b6d4, #3b82f6);
            color: #fff;
            border: none;
            padding: 0.85rem;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            margin-top: 0.5rem;
            transition: opacity 0.2s;
        }

        .btn-primary:hover { opacity: 0.9; }

        .lang-switcher {
            display: flex;
            gap: 0.25rem;
            justify-content: center;
            margin-top: 1.25rem;
        }

        .lang-switcher a {
            font-size: 0.75rem;
            font-weight: 600;
            padding: 0.25rem 0.65rem;
            border-radius: 4px;
            text-decoration: none;
            color: #6b7280;
            border: 1px solid #1f2937;
            transition: all 0.15s;
        }

        .lang-switcher a.active {
            background: #06b6d4;
            border-color: #06b6d4;
            color: #000;
        }

        .lang-switcher a:not(.active):hover { color: #f9fafb; border-color: #374151; }
    </style>
</head>
<body>
    <div class="login-wrap">
        <div class="logo">
            <h1>Easy Short URL</h1>
            <p><?= $tr['title'] ?></p>
        </div>
        <div class="card">
            <?php if ($error): ?>
            <div class="error-msg"><?= htmlspecialchars($error) ?></div>
            <?php endif; ?>
            <form method="POST" autocomplete="on">
                <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
                <div class="form-group">
                    <label for="username"><?= $tr['user'] ?></label>
                    <input type="text" id="username" name="username" required maxlength="64"
                           autocomplete="username" placeholder="admin">
                </div>
                <div class="form-group">
                    <label for="password"><?= $tr['pass'] ?></label>
                    <input type="password" id="password" name="password" required maxlength="128"
                           autocomplete="current-password" placeholder="••••••••">
                </div>
                <button type="submit" class="btn-primary"><?= $tr['login'] ?></button>
            </form>
        </div>
        <div class="lang-switcher">
            <a href="?lang=es" class="<?= $lang === 'es' ? 'active' : '' ?>">ES</a>
            <a href="?lang=en" class="<?= $lang === 'en' ? 'active' : '' ?>">EN</a>
        </div>
    </div>
</body>
</html>
