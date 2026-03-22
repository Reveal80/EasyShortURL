<?php
$code = $_GET['code'] ?? '';

if (empty($code)) {
    header('Location: index.php');
    exit;
}

$dataFile = __DIR__ . '/data/urls.json';

if (!file_exists($dataFile)) {
    http_response_code(404);
    echo '<!DOCTYPE html><html lang="es"><body style="font-family:sans-serif;text-align:center;padding:80px;background:#0a0e1a;color:#f9fafb"><h1 style="font-size:4rem;margin:0">404</h1><p>URL no encontrada</p><a href="/" style="color:#06b6d4">Volver al inicio</a></body></html>';
    exit;
}

$urls = json_decode(file_get_contents($dataFile), true) ?? [];

if (!isset($urls[$code])) {
    http_response_code(404);
    echo '<!DOCTYPE html><html lang="es"><body style="font-family:sans-serif;text-align:center;padding:80px;background:#0a0e1a;color:#f9fafb"><h1 style="font-size:4rem;margin:0">404</h1><p>URL no encontrada</p><a href="/" style="color:#06b6d4">Volver al inicio</a></body></html>';
    exit;
}

// Incrementar contador de clics y guardar último uso
$urls[$code]['clicks']    = ($urls[$code]['clicks'] ?? 0) + 1;
$urls[$code]['last_used'] = date('Y-m-d H:i:s');
file_put_contents($dataFile, json_encode($urls, JSON_PRETTY_PRINT));

header('Location: ' . $urls[$code]['url'], true, 301);
exit;
