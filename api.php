<?php

declare(strict_types=1);

session_set_cookie_params([
    'httponly' => true,
    'samesite' => 'Lax',
    'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
]);
session_start();

require __DIR__ . '/vendor/autoload.php';

use phpseclib3\Math\BigInteger;

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

const SRP_N_LEGACY = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF';
const SRP_G = '02';
const SRP_K = '03';

function readJsonBody(): array
{
    $raw = file_get_contents('php://input');
    if ($raw === false || trim($raw) === '') {
        return [];
    }

    $decoded = json_decode($raw, true);
    return is_array($decoded) ? $decoded : [];
}

function dbPath(): string
{
    $containerPath = __DIR__ . '/data/db.json';
    return is_dir(__DIR__ . '/data') ? $containerPath : __DIR__ . '/db.json';
}

function loadDb(): array
{
    $path = dbPath();
    if (!is_file($path)) {
        if (file_put_contents($path, "[]\n", LOCK_EX) === false) {
            errorJson('No se pudo inicializar el almacenamiento.', 500);
        }
        return [];
    }

    $raw = file_get_contents($path);
    if ($raw === false || trim($raw) === '') {
        return [];
    }

    try {
        $decoded = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
    } catch (JsonException) {
        errorJson('El almacenamiento contiene JSON inválido.', 500);
    }

    if (!is_array($decoded)) {
        errorJson('El almacenamiento tiene un formato inválido.', 500);
    }

    return $decoded;
}

function saveDb(array $db): void
{
    $path = dbPath();
    $json = json_encode($db, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . PHP_EOL;
    $tempPath = tempnam(dirname($path), 'db-');

    if ($tempPath === false || file_put_contents($tempPath, $json, LOCK_EX) === false || !rename($tempPath, $path)) {
        if ($tempPath !== false && is_file($tempPath)) {
            unlink($tempPath);
        }
        errorJson('No se pudo guardar el almacenamiento.', 500);
    }
}

function errorJson(string $message, int $status = 400): void
{
    http_response_code($status);
    echo json_encode(['success' => false, 'error' => $message], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit;
}

function normalizeHex(string $hex): string
{
    $hex = trim($hex);
    if (str_starts_with(strtolower($hex), '0x')) {
        $hex = substr($hex, 2);
    }

    return $hex !== '' && preg_match('/\A[0-9a-fA-F]+\z/', $hex) && strlen($hex) % 2 === 0
        ? strtoupper($hex)
        : '';
}

function hexToBin(string $hex): string
{
    $hex = normalizeHex($hex);
    if ($hex === '') {
        return '';
    }

    $bin = hex2bin($hex);
    return $bin === false ? '' : $bin;
}

function bigIntFromHex(string $hex): BigInteger
{
    return new BigInteger(normalizeHex($hex), 16);
}

function bigIntFromBytes(string $bytes): BigInteger
{
    return new BigInteger($bytes, 256);
}

function bigIntMod(BigInteger $value, BigInteger $modulus): BigInteger
{
    [$quotient, $remainder] = $value->divide($modulus);
    return $remainder;
}

function bigIntToHex(BigInteger $value): string
{
    $hex = $value->toHex();
    return strlen($hex) % 2 === 0 ? $hex : '0' . $hex;
}

function validGroupElement(string $hex, BigInteger $N): bool
{
    if ($hex === '') {
        return false;
    }

    $value = bigIntFromHex($hex);
    return $value->compare(new BigInteger(1)) > 0 && $value->compare($N) < 0;
}

function findUserByName(string $username, ?array $db = null): ?array
{
    foreach ($db ?? loadDb() as $user) {
        if (($user['username'] ?? '') === $username) {
            return $user;
        }
    }

    return null;
}

function computeU(string $AHex, string $BHex): string
{
    return hash('sha256', hexToBin($AHex) . hexToBin($BHex), true);
}

function computeSecretServer(string $AHex, string $BHex, string $bHex, string $verifierHex): string
{
    $N = bigIntFromHex(SRP_N_LEGACY);
    $A = bigIntFromHex($AHex);
    $v = bigIntFromHex($verifierHex);
    $u = bigIntFromBytes(computeU($AHex, $BHex));
    $b = bigIntFromHex($bHex);

    $tmp = $A->multiply($v->powMod($u, $N));
    $secret = bigIntMod($tmp, $N);
    $secret = $secret->powMod($b, $N);
    return bigIntToHex($secret);
}

function computeM1(string $AHex, string $BHex, string $secretHex): string
{
    $input = hexToBin($AHex) . hexToBin($BHex) . hexToBin($secretHex);
    return hash('sha256', $input, false);
}

$action = $_GET['action'] ?? $_POST['action'] ?? '';

if ($action === 'register') {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        errorJson('Método no permitido.', 405);
    }

    $payload = readJsonBody();
    $username = trim((string)($payload['username'] ?? ''));
    $saltHex = normalizeHex((string)($payload['salt'] ?? ''));
    $verifierHex = normalizeHex((string)($payload['verifier'] ?? ''));
    $N = bigIntFromHex(SRP_N_LEGACY);

    if (!preg_match('/\A[A-Za-z0-9_.-]{3,64}\z/', $username)) {
        errorJson('El usuario debe tener entre 3 y 64 caracteres válidos.', 422);
    }

    if (strlen($saltHex) !== 32 || $verifierHex === '' || !validGroupElement($verifierHex, $N)) {
        errorJson('Se requieren username, salt y verifier.', 422);
    }

    $db = loadDb();
    if (findUserByName($username, $db) !== null) {
        errorJson('El usuario ya existe.', 409);
    }

    $db[] = [
        'username' => $username,
        'salt' => $saltHex,
        'verifier' => $verifierHex,
    ];

    saveDb($db);

    echo json_encode([
        'success' => true,
        'message' => 'Usuario registrado correctamente.',
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit;
}

if ($action === 'challenge') {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        errorJson('Método no permitido.', 405);
    }

    $payload = readJsonBody();
    $username = trim((string)($payload['username'] ?? ''));
    $AHex = normalizeHex((string)($payload['A'] ?? ''));
    $N = bigIntFromHex(SRP_N_LEGACY);

    if (!preg_match('/\A[A-Za-z0-9_.-]{3,64}\z/', $username) || !validGroupElement($AHex, $N)) {
        errorJson('Se requieren username y A.', 422);
    }

    $user = findUserByName($username);
    if ($user === null) {
        errorJson('Usuario no encontrado.', 404);
    }

    $saltHex = (string)($user['salt'] ?? '');
    $verifierHex = (string)($user['verifier'] ?? '');

    $g = bigIntFromHex(SRP_G);
    $b = new BigInteger(bin2hex(random_bytes(32)), 16);
    $v = bigIntFromHex($verifierHex);
    $k = bigIntFromHex((string)SRP_K);

    $B = $k->multiply($v);
    $B = $B->add($g->powMod($b, $N));
    $B = bigIntMod($B, $N);
    $BHex = bigIntToHex($B);

    $_SESSION['srp'] = [
        'username' => $username,
        'A' => $AHex,
        'B' => $BHex,
        'b' => bigIntToHex($b),
        'salt' => $saltHex,
        'verifier' => $verifierHex,
    ];

    echo json_encode([
        'success' => true,
        'salt' => $saltHex,
        'B' => $BHex,
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit;
}

if ($action === 'verify') {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        errorJson('Método no permitido.', 405);
    }

    $payload = readJsonBody();
    $username = trim((string)($payload['username'] ?? ''));
    $m1ClientHex = normalizeHex((string)($payload['M1'] ?? ''));

    if (!preg_match('/\A[A-Za-z0-9_.-]{3,64}\z/', $username) || $m1ClientHex === '' || strlen($m1ClientHex) !== 64) {
        errorJson('Se requieren username y M1 válidos.', 422);
    }

    $session = $_SESSION['srp'] ?? null;
    unset($_SESSION['srp']);
    if (!is_array($session) || ($session['username'] ?? '') !== $username) {
        errorJson('Sesión SRP no válida o expirada.', 401);
    }

    $AHex = (string)($session['A'] ?? '');
    $BHex = (string)($session['B'] ?? '');
    $bHex = (string)($session['b'] ?? '');
    $saltHex = (string)($session['salt'] ?? '');
    $verifierHex = (string)($session['verifier'] ?? '');

    $secretHex = computeSecretServer($AHex, $BHex, $bHex, $verifierHex);
    $expectedM1 = computeM1($AHex, $BHex, $secretHex);
    if (!hash_equals(strtolower($expectedM1), strtolower($m1ClientHex))) {
        errorJson('Verificación SRP fallida.', 401);
    }

    session_regenerate_id(true);
    $_SESSION['auth'] = [
        'username' => $username,
        'token' => bin2hex(random_bytes(16)),
        'issuedAt' => time(),
    ];

    echo json_encode([
        'success' => true,
        'message' => 'Autenticación SRP verificada correctamente.',
        'token' => $_SESSION['auth']['token'],
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit;
}

errorJson('Acción no soportada.', 400);
