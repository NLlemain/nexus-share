<?php
/**
 * Day 3: PHP Central Auth & Directory Server (server.php)
 *
 * Dual mode:
 * - Web mode (PHP-FPM/Apache): JSON API for hosted central server endpoints.
 * - CLI mode: legacy TCP socket daemon for local development/tests.
 */

error_reporting(E_ALL);
ini_set('display_errors', PHP_SAPI === 'cli' ? '1' : '0');

$dataDir = __DIR__ . '/nexus_data';

if (!is_dir($dataDir) && !@mkdir($dataDir, 0700, true) && !is_dir($dataDir)) {
    throw new RuntimeException('Unable to create the local data directory.');
}

$userDbFile = $dataDir . '/users.db.json';
$sessionDbFile = $dataDir . '/sessions.db.json';
$authStateFile = $dataDir . '/auth_state.db.json';

if (!file_exists($userDbFile)) {
    file_put_contents($userDbFile, json_encode([]));
    @chmod($userDbFile, 0600);
}
if (!file_exists($sessionDbFile)) {
    file_put_contents($sessionDbFile, json_encode([]));
    @chmod($sessionDbFile, 0600);
}

function loadJsonFile(string $filePath, array $fallback = []): array {
    if (!file_exists($filePath)) {
        return $fallback;
    }

    $fp = @fopen($filePath, 'rb');
    if ($fp === false) {
        return $fallback;
    }

    $raw = '';
    if (@flock($fp, LOCK_SH)) {
        $read = stream_get_contents($fp);
        $raw = $read === false ? '' : $read;
        @flock($fp, LOCK_UN);
    }
    fclose($fp);

    if ($raw === false || $raw === '') {
        return $fallback;
    }

    $decoded = json_decode($raw, true);
    return is_array($decoded) ? $decoded : $fallback;
}

function saveJsonFile(string $filePath, array $data): void {
    $dir = dirname($filePath);
    if (!is_dir($dir)) {
        @mkdir($dir, 0700, true);
    }

    $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    if ($json === false) {
        return;
    }

    $tmpFile = $filePath . '.tmp';
    $fp = @fopen($tmpFile, 'wb');
    if ($fp === false) {
        return;
    }

    $bytesWritten = 0;
    if (@flock($fp, LOCK_EX)) {
        $bytesWritten = fwrite($fp, $json);
        fflush($fp);
        @flock($fp, LOCK_UN);
    }
    fclose($fp);

    if ($bytesWritten === strlen($json)) {
        @rename($tmpFile, $filePath);
        @chmod($filePath, 0600);
    } else {
        @unlink($tmpFile);
        serverLog("Fout bij opslaan database: Schrijven naar tijdelijk bestand is mislukt (mogelijke schijf vol). Bewerking afgebroken.");
    }
}

function serverLog(string $msg): void {
    if (PHP_SAPI === 'cli') {
        echo $msg . "\n";
    } else {
        error_log($msg);
    }
}

function releaseDbLock($lockFp): void {
    if ($lockFp) {
        flock($lockFp, LOCK_UN);
        fclose($lockFp);
    }
}

function jsonResponse(array $data, int $statusCode = 200): void {
    http_response_code($statusCode);
    header('Content-Type: application/json; charset=utf-8');
    header('X-Content-Type-Options: nosniff');
    header('Cache-Control: no-store');
    header('Content-Security-Policy: default-src \'none\'; frame-ancestors \'none\';');
    header('X-Frame-Options: DENY');
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n";
}

function enforceRateLimit(string $ip, string $authStateFile): ?array {
    $state = loadJsonFile($authStateFile, []);
    $now = time();

    foreach ($state as $key => $entry) {
        $windowStart = isset($entry['window_start']) ? (int)$entry['window_start'] : $now;
        $blockedUntil = isset($entry['blocked_until']) ? (int)$entry['blocked_until'] : 0;
        if (($now - $windowStart) > 86400 && $blockedUntil < $now) {
            unset($state[$key]);
        }
    }

    if (!isset($state[$ip])) {
        $state[$ip] = [
            'window_start' => $now,
            'count' => 0,
            'failed_logins' => 0,
            'blocked_until' => 0,
        ];
    }

    $entry = &$state[$ip];
    if (!empty($entry['blocked_until']) && (int)$entry['blocked_until'] > $now) {
        saveJsonFile($authStateFile, $state);
        return ['status' => 'error', 'message' => 'IP-adres is tijdelijk geblokkeerd wegens misbruik.'];
    }

    if (($now - (int)$entry['window_start']) >= 60) {
        $entry['window_start'] = $now;
        $entry['count'] = 0;
    }

    $entry['count'] = ((int)$entry['count']) + 1;
    if ((int)$entry['count'] > 60) {
        $entry['blocked_until'] = $now + 60;
        saveJsonFile($authStateFile, $state);
        return ['status' => 'error', 'message' => 'Te veel verzoeken. Probeer over 1 minuut opnieuw.'];
    }

    saveJsonFile($authStateFile, $state);
    return null;
}

function recordLoginResult(string $ip, bool $success, string $authStateFile, string $username = ''): void {
    $state = loadJsonFile($authStateFile, []);
    $now = time();

    if (!isset($state[$ip])) {
        $state[$ip] = [
            'window_start' => $now,
            'count' => 0,
            'failed_logins' => 0,
            'blocked_until' => 0,
        ];
    }

    if ($success) {
        $state[$ip]['failed_logins'] = 0;
    } else {
        $failed = (int)($state[$ip]['failed_logins'] ?? 0) + 1;
        $state[$ip]['failed_logins'] = $failed;
        if ($failed >= 5) {
            $state[$ip]['blocked_until'] = $now + 900;
            $state[$ip]['failed_logins'] = 0;
            serverLog("[$ip] [HACK POGING] Brute-force gedetecteerd voor gebruiker: $username. IP geblokkeerd voor 15 minuten.");
        }
    }

    saveJsonFile($authStateFile, $state);
}

function valideerSessie(string $token, array $sessies): bool {
    foreach ($sessies as $info) {
        if (isset($info['token']) && hash_equals((string)$info['token'], $token)) {
            return true;
        }
    }
    return false;
}

function verwerkActie(array $data, string $ip, array &$gebruikers, array &$sessies): array {
    // Validate the username field when supplied.
    if (isset($data['username'])) {
        $checkUser = trim((string)$data['username']);
        if ($checkUser !== '' && !preg_match('/^[a-zA-Z0-9_\-]+$/', $checkUser)) {
            serverLog("[$ip] [HACK POGING] Verdachte/ongeldige tekens in gebruikersnaam: '$checkUser'");
            return ['status' => 'error', 'message' => 'Gebruikersnaam bevat ongeldige tekens'];
        }
    }

    // Validate the session token field when supplied.
    if (isset($data['session_token'])) {
        $checkToken = trim((string)$data['session_token']);
        if ($checkToken !== '' && !preg_match('/^[0-9a-fA-F]{32}$/', $checkToken)) {
            serverLog("[$ip] [HACK POGING] Ongeldig sessietoken formaat gedetecteerd: '$checkToken'");
            return ['status' => 'error', 'message' => 'Ongeldig sessietoken'];
        }
    }

    // Reject potentially unsafe characters in the address field when supplied.
    if (isset($data['address'])) {
        $checkAddress = trim((string)$data['address']);
        if ($checkAddress !== '' && preg_match('/[\'"<>;()\\$]/', $checkAddress)) {
            serverLog("[$ip] [HACK POGING] Mogelijk injectie-payload in adres gedetecteerd: '$checkAddress'");
            return ['status' => 'error', 'message' => 'Ongeldig adresformaat'];
        }
    }

    if (!isset($data['action'])) {
        return ['status' => 'error', 'message' => 'Ongeldig verzoekformaat'];
    }

    $actie = (string)$data['action'];

    switch ($actie) {
        case 'register':
            $user = trim((string)($data['username'] ?? ''));
            $pass = (string)($data['password'] ?? '');

            if ($user === '' || $pass === '') {
                return ['status' => 'error', 'message' => 'Gebruikersnaam en wachtwoord zijn verplicht'];
            }

            if (strlen($user) < 3 || strlen($user) > 32) {
                return ['status' => 'error', 'message' => 'Gebruikersnaam moet tussen 3 en 32 tekens bevatten'];
            }

            $gereserveerd = ['admin', 'root', 'system', 'anonymous', 'administrator', 'nexus', 'server', 'directory'];
            if (in_array(strtolower($user), $gereserveerd, true)) {
                return ['status' => 'error', 'message' => 'Gereserveerde gebruikersnaam is niet toegestaan'];
            }

            if (isset($gebruikers[$user])) {
                return ['status' => 'error', 'message' => 'Gebruikersnaam bestaat al'];
            }

            $gebruikers[$user] = password_hash($pass, PASSWORD_BCRYPT);
            return ['status' => 'success', 'message' => 'Account aangemaakt'];

        case 'login':
            $user = trim((string)($data['username'] ?? ''));
            $pass = (string)($data['password'] ?? '');
            $adres = trim((string)($data['address'] ?? ''));

            $dummyHash = '$2y$10$reZ1lKex5oG1U1W1E1E1Eu1V1E1E1E1E1E1E1E1E1E1E1E1E1E1E1';
            $userExists = isset($gebruikers[$user]);
            $hashToVerify = $userExists ? (string)$gebruikers[$user] : $dummyHash;

            if (!password_verify($pass, $hashToVerify) || !$userExists) {
                serverLog("[$ip] Mislukte inlogpoging voor: $user");
                return ['status' => 'error', 'message' => 'Ongeldige inloggegevens'];
            }

            if ($adres !== '' && !preg_match('/^[a-z2-7]{52}\.b32\.i2p$/', $adres)) {
                serverLog("[$ip] [HACK POGING] Update adres mislukt: adres is leeg of is geen geldig I2P Base32 adres: '$adres'");
                return ['status' => 'error', 'message' => 'Ongeldig I2P-adres formaat'];
            }

            $token = bin2hex(random_bytes(16));
            $sessies[$user] = [
                'address' => $adres,
                'token' => $token,
                'updated_at' => time(),
                'ip' => $ip,
            ];

            return [
                'status' => 'success',
                'session_token' => $token,
            ];

        case 'update_address':
            $mijnToken = (string)($data['session_token'] ?? '');
            $adres = trim((string)($data['address'] ?? ''));

            if (!valideerSessie($mijnToken, $sessies)) {
                return ['status' => 'error', 'message' => 'Sessie is ongeldig of verlopen'];
            }

            if ($adres === '' || !preg_match('/^[a-z2-7]{52}\.b32\.i2p$/', $adres)) {
                serverLog("[$ip] [HACK POGING] Update adres mislukt: adres is leeg of is geen geldig I2P Base32 adres: '$adres'");
                return ['status' => 'error', 'message' => 'Geldig I2P Base32 adres (.b32.i2p) is verplicht'];
            }

            foreach ($sessies as &$info) {
                if (isset($info['token']) && hash_equals((string)$info['token'], $mijnToken)) {
                    $info['address'] = $adres;
                    $info['updated_at'] = time();
                    return ['status' => 'success', 'message' => 'Adres succesvol bijgewerkt'];
                }
            }
            unset($info);

            return ['status' => 'error', 'message' => 'Sessie niet gevonden'];

        case 'lookup':
            $mijnToken = (string)($data['session_token'] ?? '');
            $doelGebruiker = trim((string)($data['target'] ?? ''));

            if ($doelGebruiker === '' || !preg_match('/^[a-zA-Z0-9_\-]+$/', $doelGebruiker)) {
                return ['status' => 'error', 'message' => 'Gebruikersnaam bevat ongeldige tekens'];
            }

            if (!valideerSessie($mijnToken, $sessies)) {
                return ['status' => 'error', 'message' => 'Sessie is ongeldig of verlopen'];
            }

            if (!isset($sessies[$doelGebruiker]) || empty($sessies[$doelGebruiker]['address'])) {
                return ['status' => 'error', 'message' => "Gebruiker '$doelGebruiker' is offline of I2P is nog niet gereed"];
            }

            $sessies[$doelGebruiker]['updated_at'] = time();

            return [
                'status' => 'success',
                'address' => $sessies[$doelGebruiker]['address'],
            ];

        case 'verify_session':
            $mijnToken = (string)($data['session_token'] ?? '');
            $checkGebruiker = trim((string)($data['username'] ?? ''));

            if ($checkGebruiker === '' || !preg_match('/^[a-zA-Z0-9_\-]+$/', $checkGebruiker)) {
                serverLog("[$ip] [HACK POGING] Sessie verificatie mislukt: gebruikersnaam bevat ongeldige tekens: '$checkGebruiker'");
                return ['status' => 'error', 'message' => 'Gebruikersnaam bevat ongeldige tekens'];
            }

            if (!valideerSessie($mijnToken, $sessies)) {
                serverLog("[$ip] [HACK POGING] Sessie verificatie mislukt: token '$mijnToken' is ongeldig of verlopen voor gebruiker '$checkGebruiker'");
                return ['status' => 'error', 'message' => 'Sessie is ongeldig of verlopen'];
            }

            // Check if token belongs to the given username
            if (!isset($sessies[$checkGebruiker]) || !hash_equals((string)$sessies[$checkGebruiker]['token'], $mijnToken)) {
                serverLog("[$ip] [HACK POGING] Sessie verificatie mislukt: token '$mijnToken' komt niet overeen met gebruiker '$checkGebruiker'");
                return ['status' => 'error', 'message' => 'Sessie komt niet overeen met gebruiker'];
            }

            return ['status' => 'success', 'message' => 'Sessie is geldig'];

        case 'report_offline':
            $mijnToken = (string)($data['session_token'] ?? '');
            $doelGebruiker = trim((string)($data['target'] ?? ''));

            if ($doelGebruiker === '' || !preg_match('/^[a-zA-Z0-9_\-]+$/', $doelGebruiker)) {
                return ['status' => 'error', 'message' => 'Gebruikersnaam bevat ongeldige tekens'];
            }

            if (!valideerSessie($mijnToken, $sessies)) {
                return ['status' => 'error', 'message' => 'Sessie is ongeldig of verlopen'];
            }

            // Security: a user may only mark their own session as offline.
            if (isset($sessies[$doelGebruiker])) {
                if (!hash_equals((string)$sessies[$doelGebruiker]['token'], $mijnToken)) {
                    serverLog("[$ip] [HACK POGING] Ongeautoriseerde poging om gebruiker '$doelGebruiker' offline te melden.");
                    return ['status' => 'error', 'message' => 'Ongeautoriseerd'];
                }
                unset($sessies[$doelGebruiker]);
                serverLog("[$ip] Gebruiker '$doelGebruiker' offline gemeld.");
            }

            return ['status' => 'success', 'message' => 'Gebruiker offline gemeld en verwijderd'];

        default:
            return ['status' => 'error', 'message' => 'Onbekende actie'];
    }
}

// ---------------------------
// Web mode: hosted JSON API
// ---------------------------
if (PHP_SAPI !== 'cli') {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

    $lockFile = $dataDir . '/db.lock';
    $lockFp = fopen($lockFile, 'c');
    if ($lockFp) {
        flock($lockFp, LOCK_EX);
    }

    $rateError = enforceRateLimit($ip, $authStateFile);
    if ($rateError !== null) {
        releaseDbLock($lockFp);
        jsonResponse($rateError, 429);
        exit;
    }

    if ($method !== 'POST') {
        releaseDbLock($lockFp);
        jsonResponse([
            'status' => 'error',
            'message' => 'Gebruik POST met JSON payload.'
        ], 405);
        exit;
    }

    $raw = file_get_contents('php://input');
    if ($raw !== false && strlen($raw) > 8192) {
        releaseDbLock($lockFp);
        jsonResponse(['status' => 'error', 'message' => 'Payload te groot'], 413);
        exit;
    }
    $data = json_decode($raw ?? '', true);

    if (!is_array($data)) {
        serverLog("[$ip] [HACK POGING] Ongeldige JSON-payload of HTTP-probe ontvangen: " . json_encode($raw));
        releaseDbLock($lockFp);
        jsonResponse(['status' => 'error', 'message' => 'Ongeldig JSON-formaat'], 400);
        exit;
    }

    $gebruikers = loadJsonFile($userDbFile, []);
    $sessies = loadJsonFile($sessionDbFile, []);

    // Remove inactive sessions after three minutes.
    $now = time();
    foreach ($sessies as $user => $info) {
        $updatedAt = isset($info['updated_at']) ? (int)$info['updated_at'] : 0;
        if ($updatedAt > 0 && ($now - $updatedAt) > 180) {
            unset($sessies[$user]);
        }
    }

    $response = verwerkActie($data, $ip, $gebruikers, $sessies);

    $actie = isset($data['action']) ? (string)$data['action'] : '';
    if ($actie === 'login') {
        $user = trim((string)($data['username'] ?? ''));
        recordLoginResult($ip, (($response['status'] ?? 'error') === 'success'), $authStateFile, $user);
    }

    saveJsonFile($userDbFile, $gebruikers);
    saveJsonFile($sessionDbFile, $sessies);

    releaseDbLock($lockFp);
    jsonResponse($response, $response['status'] === 'success' ? 200 : 400);
    exit;
}

// ---------------------------------
// CLI mode: legacy socket auth node
// ---------------------------------
if (!extension_loaded('sockets')) {
    fwrite(STDERR, "PHP sockets extensie ontbreekt in CLI mode.\n");
    exit(1);
}

$poort = isset($argv[1]) ? (int)$argv[1] : 8000;
$actieveSessies = [];

$server = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
if ($server === false) {
    die("Kan socket niet maken: " . socket_strerror(socket_last_error()) . "\n");
}

socket_set_option($server, SOL_SOCKET, SO_REUSEADDR, 1);

if (socket_bind($server, '0.0.0.0', $poort) === false) {
    die("Kan socket niet binden op poort $poort: " . socket_strerror(socket_last_error($server)) . "\n");
}

if (socket_listen($server, 10) === false) {
    die("Kan niet luisteren op socket: " . socket_strerror(socket_last_error($server)) . "\n");
}

echo "Centrale PHP Directory Server gestart op poort $poort...\n";

while (true) {
    $clientSocket = socket_accept($server);
    if ($clientSocket === false) {
        continue;
    }

    socket_getpeername($clientSocket, $clientIp);
    socket_set_option($clientSocket, SOL_SOCKET, SO_RCVTIMEO, ['sec' => 5, 'usec' => 0]);
    socket_set_option($clientSocket, SOL_SOCKET, SO_SNDTIMEO, ['sec' => 5, 'usec' => 0]);

    try {
        behandelVerbinding($clientSocket, (string)$clientIp, $userDbFile, $actieveSessies);
    } catch (Exception $e) {
        echo "Fout bij afhandeling: " . $e->getMessage() . "\n";
        socket_close($clientSocket);
    }
}

function behandelVerbinding(mixed $socket, string $ip, string $dbFile, array &$sessies): void {
    global $authStateFile;
    global $dataDir;

    // Remove inactive sessions after three minutes to prevent unbounded memory use.
    $now = time();
    foreach ($sessies as $user => $info) {
        $updatedAt = isset($info['updated_at']) ? (int)$info['updated_at'] : 0;
        if ($updatedAt > 0 && ($now - $updatedAt) > 180) {
            unset($sessies[$user]);
        }
    }

    $lockFile = $dataDir . '/db.lock';
    $lockFp = fopen($lockFile, 'c');
    if ($lockFp) {
        flock($lockFp, LOCK_EX);
    }

    $rateError = enforceRateLimit($ip, $authStateFile);
    if ($rateError !== null) {
        releaseDbLock($lockFp);
        stuurAntwoord($socket, $rateError);
        socket_close($socket);
        return;
    }

    $verzoek = leesRegel($socket);
    if ($verzoek === false) {
        releaseDbLock($lockFp);
        socket_close($socket);
        return;
    }

    $data = json_decode($verzoek, true);
    if (!is_array($data)) {
        serverLog("[$ip] [HACK POGING] Ongeldige JSON-payload of HTTP-probe ontvangen: " . json_encode($verzoek));
        releaseDbLock($lockFp);
        stuurAntwoord($socket, ['status' => 'error', 'message' => 'Ongeldig JSON-formaat']);
        socket_close($socket);
        return;
    }

    $gebruikers = loadJsonFile($dbFile, []);
    $response = verwerkActie($data, $ip, $gebruikers, $sessies);
    saveJsonFile($dbFile, $gebruikers);

    $actie = isset($data['action']) ? (string)$data['action'] : '';
    if ($actie === 'login') {
        $user = trim((string)($data['username'] ?? ''));
        recordLoginResult($ip, (($response['status'] ?? 'error') === 'success'), $authStateFile, $user);
    }

    releaseDbLock($lockFp);
    stuurAntwoord($socket, $response);
    socket_close($socket);
}

function leesRegel(mixed $socket): string|false {
    $buffer = '';
    $maxLen = 4096;

    while (strlen($buffer) < $maxLen) {
        $chunk = @socket_read($socket, 1024);
        if ($chunk === false || $chunk === '') {
            return false;
        }

        $buffer .= $chunk;
        $nlPos = strpos($buffer, "\n");
        if ($nlPos !== false) {
            return substr($buffer, 0, $nlPos);
        }
    }

    return false;
}

function stuurAntwoord(mixed $socket, array $data): void {
    $res = json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n";
    @socket_write($socket, $res);
}
?>
