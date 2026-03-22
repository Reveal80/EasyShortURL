<?php
ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_samesite', 'Strict');
session_start();

$nonce = base64_encode(random_bytes(16));

// Cabeceras de seguridad
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
header("Content-Security-Policy: default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com 'nonce-{$nonce}'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'");

if (!isset($_SESSION['logged_in'])) {
    header('Location: index.php');
    exit;
}

// --- Helper functions ---
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

// Session expiry check (7200 seconds = 2 hours)
if (!isset($_SESSION['last_activity']) || (time() - $_SESSION['last_activity']) > 7200) {
    $_SESSION = [];
    session_regenerate_id(true);
    session_destroy();
    header('Location: index.php');
    exit;
}
$_SESSION['last_activity'] = time();

// CSRF token
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrfToken = $_SESSION['csrf_token'];

const MAX_URLS  = 500;
const MAX_BATCH = 20;

// Idioma
if (isset($_GET['lang']) && in_array($_GET['lang'], ['es', 'en'])) {
    $_SESSION['lang'] = $_GET['lang'];
    header('Location: dashboard.php');
    exit;
}
$lang = $_SESSION['lang'] ?? 'es';

$t = [
    'es' => [
        'panel'         => 'Panel de control',
        'create_btn'    => 'Crear Short',
        'my_urls'       => 'Mis URLs',
        'no_urls'       => 'Aún no tienes URLs acortadas.',
        'short_url'     => 'URL corta',
        'destination'   => 'Destino',
        'created'       => 'Creada',
        'last_use'      => 'Último uso',
        'clicks'        => 'Clics',
        'actions'       => 'Acciones',
        'no_use'        => 'Sin uso',
        'logout'        => 'Cerrar sesión',
        'modal_title'   => 'Crear nuevo Short',
        'url_label'     => 'URL de destino',
        'code_label'    => 'Código personalizado',
        'code_ph'       => 'Vacío = automático',
        'add_url'       => '+ Añadir otra URL',
        'cancel'        => 'Cancelar',
        'create'        => 'Crear',
        'edit_title'    => 'Editar destino',
        'new_url_label' => 'Nueva URL de destino',
        'save'          => 'Guardar',
        'qr_title'      => 'Código QR',
        'confirm_del'   => '¿Eliminar /',
        'visits'        => 'Visitas',
        'copy_title'    => 'Copiar enlace',
        'edit_title2'   => 'Editar destino',
        'delete_title'  => 'Eliminar',
        'remove_row'    => 'Eliminar fila',
        'code_lbl'      => 'Código',
        'new_url_ph'    => 'https://nuevo-destino.com',
        'url_ph'        => 'ejemplo.com/url-larga',
        'code_ph_js'    => 'Vacío = automático',
        'err_limit'     => 'Límite de ' . MAX_URLS . ' URLs alcanzado.',
        'err_url'       => ': URL inválida',
        'err_code'      => ': código inválido (solo letras/números, 3–12 caracteres)',
        'err_reserved'  => ': el código "%s" está reservado',
        'err_used'      => ': el código "%s" ya está en uso',
        'ok_created1'   => 'URL acortada creada con éxito',
        'ok_created_n'  => '%d URLs creadas con éxito',
        'err_scheme'    => 'URL inválida: debe comenzar por http:// o https://',
        'err_url2'      => 'URL inválida',
        'err_code404'   => 'Código no encontrado',
        'ok_updated'    => 'URL actualizada con éxito',
        'ok_deleted'    => 'URL eliminada',
        'row_prefix'    => 'Fila ',
    ],
    'en' => [
        'panel'         => 'Dashboard',
        'create_btn'    => 'Create Short',
        'my_urls'       => 'My URLs',
        'no_urls'       => 'You have no shortened URLs yet.',
        'short_url'     => 'Short URL',
        'destination'   => 'Destination',
        'created'       => 'Created',
        'last_use'      => 'Last used',
        'clicks'        => 'Clicks',
        'actions'       => 'Actions',
        'no_use'        => 'Never used',
        'logout'        => 'Log out',
        'modal_title'   => 'Create new Short',
        'url_label'     => 'Destination URL',
        'code_label'    => 'Custom code',
        'code_ph'       => 'Empty = auto-generated',
        'add_url'       => '+ Add another URL',
        'cancel'        => 'Cancel',
        'create'        => 'Create',
        'edit_title'    => 'Edit destination',
        'new_url_label' => 'New destination URL',
        'save'          => 'Save',
        'qr_title'      => 'QR Code',
        'confirm_del'   => 'Delete /',
        'visits'        => 'Visits',
        'copy_title'    => 'Copy link',
        'edit_title2'   => 'Edit destination',
        'delete_title'  => 'Delete',
        'remove_row'    => 'Remove row',
        'code_lbl'      => 'Code',
        'new_url_ph'    => 'https://new-destination.com',
        'url_ph'        => 'example.com/long-url',
        'code_ph_js'    => 'Empty = auto-generated',
        'err_limit'     => 'Limit of ' . MAX_URLS . ' URLs reached.',
        'err_url'       => ': invalid URL',
        'err_code'      => ': invalid code (letters/numbers only, 3–12 characters)',
        'err_reserved'  => ': code "%s" is reserved',
        'err_used'      => ': code "%s" is already in use',
        'ok_created1'   => 'Short URL created successfully',
        'ok_created_n'  => '%d short URLs created successfully',
        'err_scheme'    => 'Invalid URL: must start with http:// or https://',
        'err_url2'      => 'Invalid URL',
        'err_code404'   => 'Code not found',
        'ok_updated'    => 'URL updated successfully',
        'ok_deleted'    => 'URL deleted',
        'row_prefix'    => 'Row ',
    ],
];
$tr = $t[$lang];

$dataFile = __DIR__ . '/data/urls.json';
$urls = [];
if (file_exists($dataFile)) {
    $urls = json_decode(file_get_contents($dataFile), true) ?? [];
}

// Flash message (PRG pattern)
$message     = '';
$messageType = '';
if (!empty($_SESSION['flash'])) {
    $message     = $_SESSION['flash']['message'];
    $messageType = $_SESSION['flash']['type'];
    unset($_SESSION['flash']);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Validar CSRF
    if (!hash_equals($_SESSION['csrf_token'] ?? '', $_POST['csrf_token'] ?? '')) {
        http_response_code(403);
        exit('Solicitud no válida.');
    }

    $action = $_POST['action'] ?? '';

    if ($action === 'create') {
        $rawUrls     = array_slice((array)($_POST['url']         ?? []), 0, MAX_BATCH);
        $rawCodes    = array_slice((array)($_POST['custom_code'] ?? []), 0, MAX_BATCH);
        $targetUrls  = array_map(fn($u) => mb_substr(trim($u), 0, 2048), $rawUrls);
        $customCodes = array_map(fn($c) => mb_substr(trim($c), 0, 12),   $rawCodes);
        $chars       = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        $reservedCodes = ['admin','test','login','logout','dashboard','api','www','mail','data','public','static','assets','help','about','index','null'];
        $errors  = [];
        $newCodes = [];

        if (count($urls) >= MAX_URLS) {
            $_SESSION['flash'] = ['message' => $tr['err_limit'], 'type' => 'error'];
        } else {
            foreach ($targetUrls as $i => $targetUrl) {
                if (empty($targetUrl)) continue;
                if (!preg_match('#^https?://#i', $targetUrl)) {
                    $targetUrl = 'https://' . $targetUrl;
                }
                if (!filter_var($targetUrl, FILTER_VALIDATE_URL)) {
                    $errors[] = $tr['row_prefix'] . ($i + 1) . $tr['err_url'];
                    continue;
                }
                $customCode = $customCodes[$i] ?? '';
                $code = '';
                if (!empty($customCode)) {
                    if (!preg_match('/^[a-zA-Z0-9]{3,12}$/', $customCode)) {
                        $errors[] = $tr['row_prefix'] . ($i + 1) . $tr['err_code'];
                        continue;
                    } elseif (in_array(strtolower($customCode), $reservedCodes)) {
                        $errors[] = $tr['row_prefix'] . ($i + 1) . sprintf($tr['err_reserved'], htmlspecialchars($customCode));
                        continue;
                    } elseif (isset($urls[$customCode])) {
                        $errors[] = $tr['row_prefix'] . ($i + 1) . sprintf($tr['err_used'], htmlspecialchars($customCode));
                        continue;
                    }
                    $code = $customCode;
                } else {
                    do {
                        $code = '';
                        for ($j = 0; $j < 10; $j++) {
                            $code .= $chars[random_int(0, strlen($chars) - 1)];
                        }
                    } while (isset($urls[$code]));
                }
                $urls[$code] = ['url' => $targetUrl, 'created' => date('Y-m-d H:i:s'), 'clicks' => 0];
                $newCodes[] = $code;

                if (count($urls) >= MAX_URLS) break;
            }

            if (!empty($newCodes)) {
                writeJson($dataFile, $urls);
            }
            if (!empty($errors)) {
                $_SESSION['flash'] = ['message' => implode('<br>', $errors), 'type' => 'error'];
            } elseif (!empty($newCodes)) {
                $_SESSION['flash'] = ['message' => count($newCodes) === 1 ? $tr['ok_created1'] : sprintf($tr['ok_created_n'], count($newCodes)), 'type' => 'success'];
            }
        }
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        header('Location: dashboard.php');
        exit;

    } elseif ($action === 'edit') {
        $code   = $_POST['code'] ?? '';
        $newUrl = mb_substr(trim($_POST['new_url'] ?? ''), 0, 2048);

        if (!preg_match('#^https?://#i', $newUrl)) {
            $_SESSION['flash'] = ['message' => $tr['err_scheme'], 'type' => 'error'];
        } elseif (!filter_var($newUrl, FILTER_VALIDATE_URL)) {
            $_SESSION['flash'] = ['message' => $tr['err_url2'], 'type' => 'error'];
        } elseif (!isset($urls[$code])) {
            $_SESSION['flash'] = ['message' => $tr['err_code404'], 'type' => 'error'];
        } else {
            $urls[$code]['url'] = $newUrl;
            writeJson($dataFile, $urls);
            $_SESSION['flash'] = ['message' => $tr['ok_updated'], 'type' => 'success'];
        }
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        header('Location: dashboard.php');
        exit;

    } elseif ($action === 'delete') {
        $code = $_POST['code'] ?? '';
        if (isset($urls[$code])) {
            unset($urls[$code]);
            writeJson($dataFile, $urls);
            $_SESSION['flash'] = ['message' => $tr['ok_deleted'], 'type' => 'error'];
        }
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        header('Location: dashboard.php');
        exit;
    }
}

// Estadísticas para el navbar
$totalUrls   = count($urls);
$totalClicks = array_sum(array_column($urls, 'clicks'));

// Sort by created desc
uasort($urls, fn($a, $b) => strcmp($b['created'] ?? '', $a['created'] ?? ''));

$protocol = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ? 'https' : 'http';
$rawHost  = $_SERVER['HTTP_HOST'] ?? 'localhost';
$safeHost = preg_replace('/[^a-zA-Z0-9\-\.\:]/', '', $rawHost);
$baseUrl  = $protocol . '://' . $safeHost;

// Paginación
$perPage    = 10;
$totalItems = count($urls);
$totalPages = max(1, (int)ceil($totalItems / $perPage));
$page       = max(1, min($totalPages, (int)($_GET['page'] ?? 1)));
$pagedUrls  = array_slice($urls, ($page - 1) * $perPage, $perPage, true);
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Shorts URL</title>
    <script nonce="<?= $nonce ?>" src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
    <style>
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

        :root {
            --bg:      #0a0e1a;
            --surface: #111827;
            --border:  #1f2937;
            --border2: #374151;
            --accent:  #06b6d4;
            --accent2: #3b82f6;
            --text:    #f9fafb;
            --muted:   #9ca3af;
            --success: #10b981;
            --error:   #ef4444;
        }

        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
        }

        /* NAV */
        nav {
            background: var(--surface);
            border-bottom: 1px solid var(--border);
            padding: 0 1.5rem;
            height: 60px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            position: sticky;
            top: 0;
            z-index: 100;
        }

        .nav-brand {
            display: flex;
            align-items: center;
            gap: 0.6rem;
            font-weight: 700;
            font-size: 1.2rem;
            background: linear-gradient(135deg, var(--accent), var(--accent2));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .nav-stats {
            display: flex;
            gap: 0.25rem;
            position: absolute;
            left: 50%;
            transform: translateX(-50%);
        }

        .stat-pill {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            background: rgba(255,255,255,0.05);
            border: 1px solid var(--border);
            border-radius: 20px;
            padding: 0.3rem 0.9rem;
            font-size: 0.82rem;
            white-space: nowrap;
        }

        .stat-pill .stat-icon { font-size: 0.9rem; }
        .stat-pill .stat-num { font-weight: 700; color: var(--accent); }
        .stat-pill .stat-label { color: var(--muted); }

        .nav-right {
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .nav-user { color: var(--muted); font-size: 0.85rem; }

        .btn-logout {
            background: transparent;
            border: 1px solid var(--border2);
            color: var(--muted);
            padding: 0.4rem 0.9rem;
            border-radius: 6px;
            font-size: 0.85rem;
            cursor: pointer;
            text-decoration: none;
            transition: all 0.2s;
        }

        .btn-logout:hover { border-color: var(--error); color: var(--error); }

        .lang-switcher {
            display: flex;
            gap: 0.25rem;
            background: rgba(255,255,255,0.05);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 0.2rem;
        }

        .lang-switcher a {
            font-size: 0.75rem;
            font-weight: 600;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            text-decoration: none;
            color: var(--muted);
            transition: all 0.15s;
        }

        .lang-switcher a.active { background: var(--accent); color: #000; }
        .lang-switcher a:not(.active):hover { color: var(--text); }

        /* MAIN */
        main {
            width: 80%;
            max-width: 1600px;
            margin: 0 auto;
            padding: 2rem 1.5rem;
        }

        .page-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 1.5rem;
        }

        .page-title { font-size: 1.5rem; font-weight: 700; }

        /* TOAST */
        .toast-wrap {
            position: fixed;
            top: 70px;
            left: 1.5rem;
            z-index: 300;
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
            pointer-events: none;
        }

        .toast {
            pointer-events: all;
            padding: 0.85rem 1.1rem;
            border-radius: 10px;
            font-size: 0.88rem;
            max-width: 340px;
            box-shadow: 0 8px 24px rgba(0,0,0,0.4);
            animation: toast-in 0.25s ease;
        }

        @keyframes toast-in {
            from { opacity: 0; transform: translateX(-30px); }
            to   { opacity: 1; transform: translateX(0); }
        }

        .toast-out { animation: toast-out 0.3s ease forwards; }

        @keyframes toast-out {
            to { opacity: 0; transform: translateX(-30px); }
        }

        .toast-success { background: #0d2b1f; border: 1px solid rgba(16,185,129,0.4); color: #6ee7b7; }
        .toast-error   { background: #2b0d0d; border: 1px solid rgba(239,68,68,0.4);  color: #f87171; }

        /* CARD */
        .card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }

        .card-title { font-size: 1rem; font-weight: 600; margin-bottom: 1.25rem; }

        label { font-size: 0.8rem; font-weight: 500; color: var(--muted); }

        input[type="text"],
        input[type="url"] {
            background: #1f2937;
            border: 1px solid var(--border2);
            color: var(--text);
            padding: 0.7rem 1rem;
            border-radius: 8px;
            font-size: 0.95rem;
            outline: none;
            transition: border-color 0.2s;
            width: 100%;
        }

        input:focus { border-color: var(--accent); }

        .btn {
            padding: 0.7rem 1.25rem;
            border-radius: 8px;
            border: none;
            font-size: 0.95rem;
            font-weight: 600;
            cursor: pointer;
            transition: opacity 0.2s, transform 0.1s;
            white-space: nowrap;
        }

        .btn:active { transform: scale(0.98); }

        .btn-primary {
            background: linear-gradient(135deg, var(--accent), var(--accent2));
            color: #fff;
        }

        .btn-primary:hover { opacity: 0.88; }

        .btn-sm { padding: 0.35rem 0.75rem; font-size: 0.8rem; border-radius: 6px; }

        .btn-secondary {
            background: transparent;
            border: 1px solid var(--border2);
            color: var(--muted);
        }

        .btn-secondary:hover { border-color: var(--text); color: var(--text); }

        /* TABLE */
        .table-wrap { overflow-x: auto; }

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.88rem;
            table-layout: fixed;
        }

        thead th {
            text-align: center;
            padding: 0.6rem 0.75rem;
            color: var(--muted);
            font-weight: 500;
            border-bottom: 1px solid var(--border);
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        thead th:nth-child(1) { width: 10%; text-align: left; }
        thead th:nth-child(2) { width: 44%; text-align: left; }
        thead th:nth-child(3) { width: 12%; }
        thead th:nth-child(4) { width: 12%; }
        thead th:nth-child(5) { width: 4%; }
        thead th:nth-child(6) { width: 18%; }

        tbody td:nth-child(3),
        tbody td:nth-child(4),
        tbody td:nth-child(5),
        tbody td:nth-child(6) { text-align: right; }

        tbody tr { border-bottom: 1px solid var(--border); transition: background 0.15s; }
        tbody tr:last-child { border-bottom: none; }
        tbody tr:hover { background: rgba(255,255,255,0.02); }

        td { padding: 0.75rem; vertical-align: middle; }

        .short-link {
            font-family: monospace;
            color: var(--accent);
            text-decoration: none;
            font-size: 0.9rem;
        }

        .short-link:hover { text-decoration: underline; }

        .dest-url {
            color: var(--muted);
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            display: block;
            max-width: 100%;
        }

        .badge-clicks {
            background: rgba(6,182,212,0.12);
            color: var(--accent);
            padding: 0.2rem 0.6rem;
            border-radius: 20px;
            font-size: 0.78rem;
            font-weight: 600;
        }

        .actions { display: flex; gap: 0.4rem; flex-wrap: nowrap; align-items: center; justify-content: flex-end; }

        .btn-icon {
            width: 32px;
            height: 32px;
            padding: 0;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            border-radius: 6px;
            border: 1px solid transparent;
            cursor: pointer;
            transition: all 0.15s;
            flex-shrink: 0;
            background: none;
        }

        .btn-icon svg { display: block; }

        .btn-icon.btn-copy   { background: rgba(16,185,129,0.1);  border-color: rgba(16,185,129,0.25); color: #6ee7b7; }
        .btn-icon.btn-qr     { background: rgba(6,182,212,0.1);   border-color: rgba(6,182,212,0.25);  color: #67e8f9; }
        .btn-icon.btn-edit   { background: rgba(59,130,246,0.15); border-color: rgba(59,130,246,0.3);  color: #93c5fd; }
        .btn-icon.btn-delete { background: rgba(239,68,68,0.1);   border-color: rgba(239,68,68,0.25);  color: #f87171; }

        .btn-icon.btn-copy:hover   { background: rgba(16,185,129,0.25); }
        .btn-icon.btn-qr:hover     { background: rgba(6,182,212,0.25); }
        .btn-icon.btn-edit:hover   { background: rgba(59,130,246,0.3); }
        .btn-icon.btn-delete:hover { background: rgba(239,68,68,0.22); }

        .empty-state { text-align: center; padding: 3rem 1rem; color: var(--muted); }
        .empty-state .icon { font-size: 3rem; margin-bottom: 0.75rem; }

        /* MODAL */
        .modal-overlay {
            display: none;
            position: fixed;
            inset: 0;
            background: rgba(0,0,0,0.7);
            z-index: 200;
            align-items: center;
            justify-content: center;
            padding: 1rem;
        }

        .modal-overlay.open { display: flex; }

        .modal {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 1.75rem;
            width: 100%;
            max-width: 420px;
        }

        .modal-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 1.25rem;
        }

        .modal-title { font-size: 1.1rem; font-weight: 600; }

        .modal-close {
            background: transparent;
            border: none;
            color: var(--muted);
            font-size: 1.4rem;
            cursor: pointer;
            line-height: 1;
            padding: 0;
        }

        .modal-close:hover { color: var(--text); }

        /* QR */
        #qr-container { display: flex; justify-content: center; margin: 1rem 0; }

        #qr-container canvas,
        #qr-container img { border-radius: 8px; border: 8px solid #fff; }

        .qr-url-row {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            margin-top: 0.75rem;
            background: rgba(6,182,212,0.06);
            border: 1px solid rgba(6,182,212,0.15);
            border-radius: 8px;
            padding: 0.5rem 0.75rem;
        }

        .qr-url {
            font-family: monospace;
            font-size: 0.85rem;
            color: var(--accent);
            word-break: break-all;
            flex: 1;
        }

        /* EDIT MODAL */
        #edit-form .form-group { margin-bottom: 1rem; display: flex; flex-direction: column; gap: 0.35rem; }

        #edit-form input {
            background: #1f2937;
            border: 1px solid var(--border2);
            color: var(--text);
            padding: 0.7rem 1rem;
            border-radius: 8px;
            font-size: 0.95rem;
            outline: none;
            width: 100%;
        }

        #edit-form input:focus { border-color: var(--accent); }

        .modal-footer {
            display: flex;
            gap: 0.75rem;
            justify-content: flex-start;
            margin-top: 1.25rem;
        }

        .create-header-row {
            display: flex;
            gap: 0.5rem;
            margin-bottom: 0.4rem;
            align-items: center;
        }

        .create-col-label { font-size: 0.78rem; font-weight: 500; color: var(--muted); }

        .url-row {
            display: flex;
            gap: 0.5rem;
            align-items: center;
            margin-bottom: 0.5rem;
        }

        .url-row input[name="url[]"]         { flex: 1; }
        .url-row input[name="custom_code[]"] { width: 220px; flex-shrink: 0; }

        .btn-remove-row {
            background: transparent;
            border: 1px solid var(--border2);
            color: var(--muted);
            width: 32px;
            height: 36px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 1rem;
            flex-shrink: 0;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.15s;
        }

        .btn-remove-row:hover { border-color: var(--error); color: var(--error); }

        /* PAGINATION */
        .pagination {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.4rem;
            padding: 1.25rem 0 0.25rem;
            flex-wrap: wrap;
        }

        .page-info {
            font-size: 0.8rem;
            color: var(--muted);
            margin: 0 0.5rem;
            white-space: nowrap;
        }

        .page-btn {
            min-width: 34px;
            height: 34px;
            padding: 0 0.5rem;
            border-radius: 6px;
            border: 1px solid var(--border2);
            background: transparent;
            color: var(--muted);
            font-size: 0.85rem;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            text-decoration: none;
            transition: all 0.15s;
        }

        .page-btn:hover { border-color: var(--accent); color: var(--accent); }

        .page-btn.active {
            background: var(--accent);
            border-color: var(--accent);
            color: #000;
            font-weight: 700;
            cursor: default;
        }

        .page-btn.disabled {
            opacity: 0.3;
            cursor: not-allowed;
            pointer-events: none;
        }

        @media (max-width: 768px) { .nav-stats { display: none; } }

        @media (max-width: 600px) {
            .btn { width: 100%; }
            .dest-url { max-width: 100%; }
        }
    </style>
</head>
<body>

<div class="toast-wrap" id="toast-wrap">
    <?php if ($message): ?>
    <div class="toast toast-<?= $messageType ?>" id="php-toast">
        <?= $message ?>
    </div>
    <?php endif; ?>
</div>

<nav>
    <div class="nav-brand">Easy Short URL</div>

    <div class="nav-stats">
        <div class="stat-pill">
            <span class="stat-icon">🔗</span>
            <span class="stat-num"><?= $totalUrls ?></span>
            <span class="stat-label">URLs</span>
        </div>
        <div class="stat-pill">
            <span class="stat-icon">👁</span>
            <span class="stat-num"><?= $totalClicks ?></span>
            <span class="stat-label"><?= $tr['visits'] ?></span>
        </div>
    </div>

    <div class="nav-right">
        <span class="nav-user">👤 <?= htmlspecialchars($_SESSION['username'] ?? 'admin') ?></span>
        <div class="lang-switcher">
            <a href="?lang=es" class="<?= $lang === 'es' ? 'active' : '' ?>">ES</a>
            <a href="?lang=en" class="<?= $lang === 'en' ? 'active' : '' ?>">EN</a>
        </div>
        <a href="logout.php" class="btn-logout"><?= $tr['logout'] ?></a>
    </div>
</nav>

<main>
    <div class="page-header">
        <h1 class="page-title"><?= $tr['panel'] ?></h1>
        <button id="btn-open-create" class="btn btn-primary"><?= $tr['create_btn'] ?></button>
    </div>

    <!-- URLS LIST -->
    <div class="card">
        <div class="card-title">🔗 <?= $tr['my_urls'] ?></div>

        <?php if (empty($urls)): ?>
        <div class="empty-state">
            <div class="icon">🔗</div>
            <p><?= $tr['no_urls'] ?></p>
        </div>
        <?php else: ?>
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th><?= $tr['short_url'] ?></th>
                        <th><?= $tr['destination'] ?></th>
                        <th><?= $tr['created'] ?></th>
                        <th><?= $tr['last_use'] ?></th>
                        <th><?= $tr['clicks'] ?></th>
                        <th><?= $tr['actions'] ?></th>
                    </tr>
                </thead>
                <tbody id="url-tbody">
                <?php foreach ($pagedUrls as $code => $data): ?>
                    <tr>
                        <td>
                            <a href="<?= $baseUrl . '/' . htmlspecialchars($code) ?>"
                               class="short-link" target="_blank">
                                /<?= htmlspecialchars($code) ?>
                            </a>
                        </td>
                        <td>
                            <span class="dest-url" title="<?= htmlspecialchars($data['url']) ?>">
                                <?= htmlspecialchars($data['url']) ?>
                            </span>
                        </td>
                        <td style="color:var(--muted);white-space:nowrap">
                            <?= htmlspecialchars($data['created'] ?? '—') ?>
                        </td>
                        <td style="color:var(--muted);white-space:nowrap">
                            <?= isset($data['last_used']) ? htmlspecialchars($data['last_used']) : '<span style="opacity:0.4">' . $tr['no_use'] . '</span>' ?>
                        </td>
                        <td>
                            <span class="badge-clicks"><?= (int)($data['clicks'] ?? 0) ?></span>
                        </td>
                        <td>
                            <div class="actions">
                                <button class="btn-icon btn-copy"
                                        data-action="copy"
                                        data-url="<?= htmlspecialchars($baseUrl . '/' . $code) ?>"
                                        title="<?= $tr['copy_title'] ?>">
                                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                                </button>
                                <button class="btn-icon btn-qr"
                                        data-action="qr"
                                        data-url="<?= htmlspecialchars($baseUrl . '/' . $code) ?>"
                                        title="Ver QR">
                                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="3" height="3"/><rect x="18" y="14" width="3" height="3"/><rect x="14" y="18" width="3" height="3"/><rect x="18" y="18" width="3" height="3"/></svg>
                                </button>
                                <button class="btn-icon btn-edit"
                                        data-action="edit"
                                        data-code="<?= htmlspecialchars($code) ?>"
                                        data-url="<?= htmlspecialchars($data['url']) ?>"
                                        title="<?= $tr['edit_title2'] ?>">
                                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
                                </button>
                                <form method="POST" style="display:inline"
                                      data-confirm="<?= htmlspecialchars($tr['confirm_del'] . $code . '?') ?>">
                                    <input type="hidden" name="action" value="delete">
                                    <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                                    <input type="hidden" name="code" value="<?= htmlspecialchars($code) ?>">
                                    <button type="submit" class="btn-icon btn-delete" title="<?= $tr['delete_title'] ?>">
                                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3,6 5,6 21,6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>
                                    </button>
                                </form>
                            </div>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>

        <?php if ($totalPages > 1): ?>
        <div class="pagination">
            <a href="?page=<?= $page - 1 ?>"
               class="page-btn<?= $page <= 1 ? ' disabled' : '' ?>"
               aria-label="Anterior">&#8249;</a>

            <?php
            // Mostrar hasta 7 botones de página con elipsis
            $range = 2;
            $start = max(1, $page - $range);
            $end   = min($totalPages, $page + $range);
            if ($start > 1): ?>
                <a href="?page=1" class="page-btn">1</a>
                <?php if ($start > 2): ?><span class="page-info">…</span><?php endif; ?>
            <?php endif; ?>

            <?php for ($p = $start; $p <= $end; $p++): ?>
                <a href="?page=<?= $p ?>"
                   class="page-btn<?= $p === $page ? ' active' : '' ?>"><?= $p ?></a>
            <?php endfor; ?>

            <?php if ($end < $totalPages): ?>
                <?php if ($end < $totalPages - 1): ?><span class="page-info">…</span><?php endif; ?>
                <a href="?page=<?= $totalPages ?>" class="page-btn"><?= $totalPages ?></a>
            <?php endif; ?>

            <a href="?page=<?= $page + 1 ?>"
               class="page-btn<?= $page >= $totalPages ? ' disabled' : '' ?>"
               aria-label="Siguiente">&#8250;</a>

            <span class="page-info">
                <?= $lang === 'en' ? 'Page' : 'Pág.' ?> <?= $page ?> <?= $lang === 'en' ? 'of' : 'de' ?> <?= $totalPages ?>
                &nbsp;·&nbsp; <?= $totalItems ?> URLs
            </span>
        </div>
        <?php endif; ?>

        <?php endif; ?>
    </div>
</main>

<!-- CREATE MODAL -->
<div class="modal-overlay" id="create-modal">
    <div class="modal" style="max-width:816px;width:95%">
        <div class="modal-header">
            <div class="modal-title"><?= $tr['modal_title'] ?></div>
            <button class="modal-close" data-close="create-modal">×</button>
        </div>
        <form method="POST" id="create-form">
            <input type="hidden" name="action" value="create">
            <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
            <div class="create-header-row">
                <span class="create-col-label" style="flex:1"><?= $tr['url_label'] ?></span>
                <span class="create-col-label" style="width:220px"><?= $tr['code_label'] ?></span>
                <span></span>
            </div>
            <div id="url-rows"></div>
            <div style="margin-top:0.75rem">
                <button type="button" id="btn-add-row" class="btn btn-sm btn-secondary"><?= $tr['add_url'] ?></button>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-sm btn-secondary" data-close="create-modal"><?= $tr['cancel'] ?></button>
                <button type="submit" class="btn btn-sm btn-primary"><?= $tr['create'] ?></button>
            </div>
        </form>
    </div>
</div>

<!-- QR MODAL -->
<div class="modal-overlay" id="qr-modal">
    <div class="modal">
        <div class="modal-header">
            <div class="modal-title"><?= $tr['qr_title'] ?></div>
            <button class="modal-close" data-close="qr-modal">×</button>
        </div>
        <div id="qr-container"></div>
        <div class="qr-url-row">
            <span class="qr-url" id="qr-url-text"></span>
            <button class="btn-icon btn-copy" id="qr-copy-btn" title="Copiar URL">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
            </button>
        </div>
    </div>
</div>

<!-- EDIT MODAL -->
<div class="modal-overlay" id="edit-modal">
    <div class="modal">
        <div class="modal-header">
            <div class="modal-title"><?= $tr['edit_title'] ?></div>
            <button class="modal-close" data-close="edit-modal">×</button>
        </div>
        <form method="POST" id="edit-form">
            <input type="hidden" name="action" value="edit">
            <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
            <input type="hidden" name="code" id="edit-code">
            <div class="form-group">
                <label><?= $tr['code_lbl'] ?></label>
                <input type="text" id="edit-code-display" disabled style="opacity:0.5">
            </div>
            <div class="form-group">
                <label for="edit-new-url"><?= $tr['new_url_label'] ?></label>
                <input type="url" id="edit-new-url" name="new_url" required
                       placeholder="<?= $tr['new_url_ph'] ?>">
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-sm btn-secondary" data-close="edit-modal"><?= $tr['cancel'] ?></button>
                <button type="submit" class="btn btn-sm btn-primary"><?= $tr['save'] ?></button>
            </div>
        </form>
    </div>
</div>

<script nonce="<?= $nonce ?>">
'use strict';

// ---- Utilidades ----
function dismissToast(el) {
    el.classList.add('toast-out');
    el.addEventListener('animationend', () => el.remove());
}

function randomCode() {
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let code = '';
    for (let i = 0; i < 10; i++) code += chars[Math.floor(Math.random() * chars.length)];
    return code;
}

function copyUrl(url, btn) {
    const done = () => {
        const orig = btn.innerHTML;
        btn.innerHTML = '✓';
        setTimeout(() => btn.innerHTML = orig, 1800);
    };
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(url).then(done);
    } else {
        const ta = document.createElement('textarea');
        ta.value = url;
        ta.style.cssText = 'position:fixed;opacity:0';
        document.body.appendChild(ta);
        ta.focus(); ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        done();
    }
}

function openModal(id) { document.getElementById(id).classList.add('open'); }
function closeModal(id) { document.getElementById(id).classList.remove('open'); }

// ---- Modal de crear ----
function addUrlRow() {
    const container = document.getElementById('url-rows');
    const row = document.createElement('div');
    row.className = 'url-row';
    row.innerHTML =
        '<input type="text" name="url[]" placeholder="<?= htmlspecialchars($tr['url_ph']) ?>" required>' +
        '<input type="text" name="custom_code[]" placeholder="<?= htmlspecialchars($tr['code_ph_js']) ?>" pattern="[a-zA-Z0-9]{3,12}">' +
        '<button type="button" class="btn btn-secondary btn-sm btn-random" style="flex-shrink:0;font-size:0.85rem">⇄</button>' +
        '<button type="button" class="btn-remove-row" title="<?= htmlspecialchars($tr['remove_row']) ?>">×</button>';
    container.appendChild(row);
    row.querySelector('input').focus();
    updateRemoveButtons();
}

function updateRemoveButtons() {
    const rows = document.querySelectorAll('#url-rows .url-row');
    rows.forEach(r => {
        r.querySelector('.btn-remove-row').style.display = rows.length > 1 ? 'flex' : 'none';
    });
}

function openCreateModal() {
    document.getElementById('url-rows').innerHTML = '';
    addUrlRow();
    openModal('create-modal');
}

// ---- Modal QR ----
let currentQrUrl = '';

function showQr(url) {
    const container = document.getElementById('qr-container');
    container.innerHTML = '';
    currentQrUrl = url;
    document.getElementById('qr-url-text').textContent = url;
    new QRCode(container, {
        text: url,
        width: 220,
        height: 220,
        colorDark: '#000000',
        colorLight: '#ffffff',
        correctLevel: QRCode.CorrectLevel.H
    });
    document.getElementById('qr-copy-btn').dataset.url = url;
    openModal('qr-modal');
}

// ---- Modal editar ----
function openEdit(code, url) {
    document.getElementById('edit-code').value = code;
    document.getElementById('edit-code-display').value = '/' + code;
    document.getElementById('edit-new-url').value = url;
    openModal('edit-modal');
    setTimeout(() => document.getElementById('edit-new-url').focus(), 100);
}

// ---- Event delegation: tabla ----
document.addEventListener('click', function(e) {
    const btn = e.target.closest('[data-action]');
    if (!btn) return;
    const action = btn.dataset.action;
    if (action === 'copy') { copyUrl(btn.dataset.url, btn); return; }
    if (action === 'qr')   { showQr(btn.dataset.url); return; }
    if (action === 'edit') { openEdit(btn.dataset.code, btn.dataset.url); return; }
});

// ---- Event delegation: botones de cerrar modal ----
document.addEventListener('click', function(e) {
    const btn = e.target.closest('[data-close]');
    if (btn) closeModal(btn.dataset.close);
});

// ---- QR copy button ----
document.getElementById('qr-copy-btn').addEventListener('click', function() {
    copyUrl(this.dataset.url, this);
});

// ---- Crear short button ----
document.getElementById('btn-open-create').addEventListener('click', openCreateModal);

// ---- Añadir fila ----
document.getElementById('btn-add-row').addEventListener('click', addUrlRow);

// ---- Event delegation: url-rows (⇄ y ×) ----
document.getElementById('url-rows').addEventListener('click', function(e) {
    if (e.target.closest('.btn-random')) {
        const row = e.target.closest('.url-row');
        row.querySelector('[name="custom_code[]"]').value = randomCode();
        return;
    }
    if (e.target.closest('.btn-remove-row')) {
        e.target.closest('.url-row').remove();
        updateRemoveButtons();
    }
});

// ---- Delete form confirmation ----
document.addEventListener('submit', function(e) {
    const form = e.target.closest('form[data-confirm]');
    if (form && !confirm(form.dataset.confirm)) {
        e.preventDefault();
    }
});

// ---- Cerrar modales (clic en overlay, excepto crear) ----
document.querySelectorAll('.modal-overlay:not(#create-modal)').forEach(overlay => {
    overlay.addEventListener('click', e => {
        if (e.target === overlay) overlay.classList.remove('open');
    });
});

// ---- Escape ----
document.addEventListener('keydown', e => {
    if (e.key === 'Escape') {
        document.querySelectorAll('.modal-overlay.open').forEach(m => m.classList.remove('open'));
    }
});

// ---- Auto-dismiss toasts ----
document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.toast').forEach(t => setTimeout(() => dismissToast(t), 4000));
});
</script>

</body>
</html>
