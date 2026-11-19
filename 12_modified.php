<?php
/**
 * SAKURA DREAM — Adaptive Prediction Engine
 * Multi-model ensemble + adaptive learning + anti-rig detection
 * Auto bet engine (WebSocket, martingale, history, session)
 */

$CFG = [
    'game' => [
        'login_url'    => 'https://apifo88daigia.tele68.com/api?c=3&un={USER}&pw={PASS_MD5}&cp=R&cl=R&pf=web&at=',
        'lobby_url'    => 'https://wlb.tele68.com/v1/lobby/auth/login?cp=R&cl=R&pf=web&at=',
        'ws_host'      => 'wtxmd52.tele68.com',
        'ws_path'      => '/txmd5/',
        'sessions_api' => 'https://wtxmd52.tele68.com/v1/txmd5/sessions',
    ],
    'security' => [
        'hmac_secret' => 'SAKURA_PRO_AUTH_HMAC_v2',
        'session_ttl' => 2592000,
    ],
    'worker' => [
        'loop_sleep'     => 1,
        'resume_timeout' => 90,
        'max_runtime'    => 3600,
        'respawn_buffer' => 60,
    ],
    'default_config' => [
        'base_bet'    => 0,
        'profit_stop' => 0,
        'auto'        => false,
        'paused'      => false,
        'lose_streak' => 0,
        'bet_streak'  => 0,
        'onboarded'   => false,
    ],
    'max_history' => 500,
];

const DATA_DIR = __DIR__ . '/.data';
const KEY_DIR  = DATA_DIR . '/by_key';

header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Cache-Control: no-store');

if (!is_dir(DATA_DIR)) @mkdir(DATA_DIR, 0700, true);
if (!is_dir(KEY_DIR))  @mkdir(KEY_DIR, 0700, true);
@file_put_contents(DATA_DIR . '/.htaccess', "Require all denied\nDeny from all\n");
@file_put_contents(DATA_DIR . '/index.html', '');
@file_put_contents(KEY_DIR  . '/.htaccess', "Require all denied\nDeny from all\n");
@file_put_contents(KEY_DIR  . '/index.html', '');

// ═══════ AUTH ═══════
function hmac_sign(string $p): string { global $CFG; return hash_hmac('sha256', $p, $CFG['security']['hmac_secret']); }
function issue_token(string $u): string {
    $exp = time() + ($GLOBALS['CFG']['security']['session_ttl'] ?? 2592000);
    return base64_encode($u . '|' . $exp . '|' . hmac_sign($u . '|' . $exp));
}
function verify_token(string $tok, string $u): bool {
    $d = base64_decode($tok, true); if ($d === false) return false;
    $p = explode('|', $d); if (count($p) !== 3) return false;
    [$uu, $exp, $sig] = $p;
    if ($uu !== $u || (int)$exp < time()) return false;
    return hash_equals(hmac_sign($uu . '|' . $exp), $sig);
}
function require_auth(string $u, string $tok): bool {
    if (!$u || !$tok || !verify_token($tok, $u)) return false;
    return (bool)key_load_by_user($u);
}

// ═══════ STORAGE ═══════
function key_path(string $key): string { return KEY_DIR . '/' . hash('sha256', strtolower(trim($key))) . '.json'; }
function key_load(string $key): array {
    $p = key_path($key); if (!is_file($p)) return [];
    $j = json_decode(file_get_contents($p), true); return is_array($j) ? $j : [];
}
function key_save(string $key, array $d): void {
    $p = key_path($key); $t = $p . '.tmp';
    file_put_contents($t, json_encode($d, JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT), LOCK_EX);
    rename($t, $p); @chmod($p, 0600);
}
function key_update(string $key, callable $f): array {
    $p = key_path($key); $fp = @fopen($p, 'c+');
    if (!$fp) { $d = key_load($key); $f($d); return $d; }
    @flock($fp, LOCK_EX);
    $d = json_decode(stream_get_contents($fp) ?: '{}', true);
    if (!is_array($d)) $d = [];
    $n = $f($d); if (is_array($n)) $d = $n;
    ftruncate($fp, 0); rewind($fp);
    fwrite($fp, json_encode($d, JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT));
    fflush($fp); @flock($fp, LOCK_UN); fclose($fp); @chmod($p, 0600);
    return $d;
}
function key_log(string $key, string $lvl, string $msg): void {
    key_update($key, function($d) use ($lvl, $msg) {
        $d['logs'] = $d['logs'] ?? [];
        array_unshift($d['logs'], ['ts'=>date('H:i:s d/m'), 'level'=>$lvl, 'msg'=>$msg]);
        $d['logs'] = array_slice($d['logs'], 0, 300); return $d;
    });
}
function key_load_by_user(string $user): array {
    $idx = DATA_DIR . '/user_index.json'; if (!is_file($idx)) return [];
    $m = json_decode(file_get_contents($idx), true) ?: [];
    $k = $m[strtolower($user)] ?? null; return $k ? key_load($k) : [];
}
function key_save_by_user(string $user, string $key): void {
    $idx = DATA_DIR . '/user_index.json';
    $m = is_file($idx) ? (json_decode(file_get_contents($idx), true) ?: []) : [];
    $m[strtolower($user)] = $key;
    file_put_contents($idx, json_encode($m, JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT), LOCK_EX);
}
function key_resolve(string $u): string {
    $idx = DATA_DIR . '/user_index.json';
    if (is_file($idx)) { $m = json_decode(file_get_contents($idx), true) ?: [];
        if (isset($m[strtolower($u)])) return $m[strtolower($u)]; }
    return $u;
}

// ═══════ GAME LOGIN ═══════
function game_login(string $u, string $p): array {
    global $CFG;
    $url = str_replace(['{USER}','{PASS_MD5}'], [urlencode($u), md5($p)], $CFG['game']['login_url']);
    $ctx = stream_context_create(['http'=>['timeout'=>15,'ignore_errors'=>true,'header'=>"User-Agent: Mozilla/5.0\r\n"]]);
    $raw = @file_get_contents($url, false, $ctx);
    if (!$raw) return ['_error'=>'Không kết nối server'];
    $d = json_decode($raw, true);
    if (!is_array($d) || empty($d['success'])) return ['_error'=>'Đăng nhập thất bại: ' . ($d['message'] ?? 'Sai TK/MK')];
    $sk = $d['sessionKey'] ?? ''; $sk .= str_repeat('=', (4 - strlen($sk) % 4) % 4);
    $sess = json_decode(base64_decode($sk), true) ?: [];
    $nick = $sess['nickname'] ?? $sess['nickName'] ?? '';
    $body = json_encode(['nickName'=>$nick,'accessToken'=>$d['accessToken'] ?? '']);
    $ctx2 = stream_context_create(['http'=>['method'=>'POST','header'=>"Content-Type: application/json\r\nUser-Agent: Mozilla/5.0\r\n",'content'=>$body,'timeout'=>15,'ignore_errors'=>true]]);
    $raw2 = @file_get_contents($CFG['game']['lobby_url'], false, $ctx2);
    $lb = json_decode($raw2 ?: '', true) ?: [];
    if (empty($lb['token'])) return ['_error'=>'Lobby không trả JWT'];
    $money = $lb['loginResp']['money'] ?? $lb['remoteLoginResp']['money'] ?? 0;
    return ['token'=>$lb['token'],'nickname'=>$nick,'money'=>$money];
}
function fetch_sessions_api(): ?array {
    global $CFG;
    $ctx = stream_context_create([
        'http'=>['timeout'=>5,'ignore_errors'=>true,'header'=>"User-Agent: Mozilla/5.0\r\nAccept: application/json\r\n"],
        'ssl'=>['verify_peer'=>false,'verify_peer_name'=>false],
    ]);
    $raw = @file_get_contents($CFG['game']['sessions_api'], false, $ctx);
    if (!$raw) return null;
    $j = json_decode($raw, true);
    return (is_array($j) && isset($j['list'])) ? $j : null;
}

// ═══════ HELPERS ═══════
function map_result(string $raw): ?string {
    $map = ['Tài'=>'TAI','Xỉu'=>'XIU','tai'=>'TAI','xiu'=>'XIU','TAI'=>'TAI','XIU'=>'XIU','TÀI'=>'TAI','XỈU'=>'XIU'];
    return $map[$raw] ?? null;
}
function find_session(array $sessions, int $targetId): ?array {
    foreach ($sessions as $row) if ((int)$row['id'] === $targetId) return $row;
    return null;
}
function detect_jackpot(array $found, array $dices): bool {
    foreach (['isJackpot','jackpot','isJackPot','isBaoLoc','baoloc','noHu','nohu','jackpotResult','isJackpotResult','is_baoloc','is_jackpot'] as $f) {
        if (isset($found[$f])) { $v = $found[$f];
            if ($v === true || $v === 1 || $v === '1' || $v === 'true') return true; }
    }
    if (count($dices) === 3) {
        $u = array_unique($dices);
        if (count($u) === 1 && $dices[0] >= 1 && $dices[0] <= 6) return true;
    }
    return false;
}

// ═══════════════════════════════════════════════════════════════
// PREDICTION ENGINE — multi-model ensemble (internal, hidden)
// ═══════════════════════════════════════════════════════════════
class ModelA {
    public function predict(array $h): ?array {
        $n = count($h);
        if ($n < 3) return null;
        $sT = 0.0; $sX = 0.0;

        // streak continuation
        $stk = 1;
        for ($i = 1; $i < $n; $i++) { if ($h[$i] === $h[0]) $stk++; else break; }
        if ($stk >= 3) { if ($h[0] === 'T') $sT += 0.25; else $sX += 0.25; }

        // alternation pressure
        $alt = 0;
        $lim = min(7, $n);
        for ($i = 1; $i < $lim; $i++) if ($h[$i] !== $h[$i-1]) $alt++;
        if ($alt >= 4) { if ($h[0] === 'T') $sX += 0.30; else $sT += 0.30; }

        // long-term frequency
        $t = 0; $lim2 = min(20, $n);
        for ($i = 0; $i < $lim2; $i++) if ($h[$i] === 'T') $t++;
        $rate = $t / $lim2;
        if ($rate > 0.62) $sX += 0.20;
        elseif ($rate < 0.38) $sT += 0.20;

        // 2-2 pattern
        if ($n >= 4 && $h[0] === $h[1] && $h[2] === $h[3] && $h[0] !== $h[2]) {
            if ($h[0] === 'X') $sT += 0.15; else $sX += 0.15;
        }
        // 1-1 pattern
        if ($n >= 4 && $h[0] === $h[2] && $h[1] === $h[3] && $h[0] !== $h[1]) {
            if ($h[0] === 'T') $sX += 0.15; else $sT += 0.15;
        }
        // recent 3 momentum
        if ($n >= 5) {
            $t3 = 0; for ($i = 0; $i < 3; $i++) if ($h[$i] === 'T') $t3++;
            if ($t3 >= 2) $sT += 0.10; else $sX += 0.10;
        }

        $pred = $sT >= $sX ? 'T' : 'X';
        $tot = $sT + $sX;
        $conf = $tot > 0 ? round(55 + abs($sT - $sX) / $tot * 30) : 55;
        return ['p'=>$pred, 'c'=>max(55, min(90, (int)$conf))];
    }
}
class ModelB {
    public function predict(array $h): ?array {
        $n = count($h);
        if ($n < 5) return null;

        $trans = ['T'=>['T'=>0,'X'=>0], 'X'=>['T'=>0,'X'=>0]];
        for ($i = 0; $i < $n - 1; $i++) {
            $prev = $h[$i+1]; $next = $h[$i];
            if (isset($trans[$prev][$next])) $trans[$prev][$next]++;
        }
        $last = $h[0];
        $tT = $trans[$last]['T']; $tX = $trans[$last]['X'];
        $sum = $tT + $tX;
        if ($sum < 2) return null;

        $pred = $tT >= $tX ? 'T' : 'X';
        $conf = round(50 + abs($tT - $tX) / $sum * 35);
        $conf = max(50, min(85, (int)$conf));

        // 2nd order corroboration
        if ($n >= 8) {
            $k2 = $h[1] . $h[0];
            $n2 = ['T'=>0, 'X'=>0];
            for ($i = 0; $i < $n - 2; $i++) {
                if ($h[$i+2] . $h[$i+1] === $k2) $n2[$h[$i]]++;
            }
            $s2 = $n2['T'] + $n2['X'];
            if ($s2 >= 2) {
                $p2 = $n2['T'] >= $n2['X'] ? 'T' : 'X';
                if ($p2 === $pred) $conf = min(90, $conf + 4);
                else $conf = max(50, $conf - 6);
            }
        }
        return ['p'=>$pred, 'c'=>$conf];
    }
}
class Ensemble {
    private $a; private $b;
    public function __construct() { $this->a = new ModelA(); $this->b = new ModelB(); }
    public function predict(array $h): array {
        $ra = $this->a->predict($h);
        $rb = $this->b->predict($h);
        if ($ra && !$rb) return ['p'=>$ra['p'], 'c'=>$ra['c']];
        if (!$ra && $rb) return ['p'=>$rb['p'], 'c'=>$rb['c']];
        if ($ra && $rb) {
            if ($ra['p'] === $rb['p']) {
                $c = min(98, round(($ra['c'] + $rb['c']) / 1.8));
                return ['p'=>$ra['p'], 'c'=>(int)$c];
            }
            $sa = $ra['c'] * 0.6; $sb = $rb['c'] * 0.4;
            return ($sa >= $sb) ? ['p'=>$ra['p'], 'c'=>$ra['c']] : ['p'=>$rb['p'], 'c'=>$rb['c']];
        }
        $last = $h[0] ?? 'T';
        return ['p'=>($last === 'T' ? 'X' : 'T'), 'c'=>60];
    }
}
class AntiRig {
    public $prob = 0;
    public function check(array $log): string {
        $recent = array_slice($log, 0, 10);
        if (count($recent) < 5) { $this->prob = 0; return 'normal'; }
        $ok = 0; $tot = 0;
        foreach ($recent as $r) {
            if (!isset($r['base'], $r['actual'])) continue;
            $tot++;
            if ($r['base'] === $r['actual']) $ok++;
        }
        if ($tot < 5) { $this->prob = 0; return 'normal'; }
        $acc = $ok / $tot;
        if ($acc < 0.30) { $this->prob = 0.85; return 'reverse'; }
        if ($acc < 0.40) { $this->prob = 0.60; return 'caution'; }
        if ($acc < 0.50) { $this->prob = 0.40; return 'reduce_confidence'; }
        $this->prob = 0;
        return 'normal';
    }
}

function engine_predict(string $key, array $sessions): ?array {
    // extract history (newest first)
    $hist = [];
    foreach ($sessions as $row) {
        $r = map_result((string)($row['resultTruyenThong'] ?? ''));
        if ($r !== null) $hist[] = $r === 'TAI' ? 'T' : 'X';
    }
    if (count($hist) < 10) return null;

    $s = key_load($key);
    $log = $s['pred_log'] ?? [];
    $reverseMode = (bool)($s['self_learning']['reverse_mode'] ?? false);

    $rig = new AntiRig();
    $advice = $rig->check($log);

    $ens = new Ensemble();
    $r = $ens->predict($hist);
    $base = $r['p'];
    $pred = $base;
    $conf = $r['c'];

    $badge = '';
    if ($advice === 'reverse') {
        $pred = $base === 'T' ? 'X' : 'T';
        $conf = min(98, $conf + 5);
        $badge = 'shield';
    } elseif ($advice === 'caution') {
        $conf = max(70, $conf - 3);
    } elseif ($advice === 'reduce_confidence') {
        $conf = max(65, $conf - 5);
    }

    if ($reverseMode) {
        $pred = $pred === 'T' ? 'X' : 'T';
        $conf = max(60, $conf - 5);
        $badge = $badge ?: 'reverse';
    }
    if ($conf >= 85) $badge = $badge ?: 'high';

    return [
        'prediction'   => $pred === 'T' ? 'TAI' : 'XIU',
        'base'         => $base,
        'final_sym'    => $pred,
        'confidence'   => (int)$conf,
        'cheat'        => $advice !== 'normal',
        'reverse_mode' => $reverseMode,
        'badge'        => $badge,
        'history_count'=> count($hist),
    ];
}

// ═══════ TINY WS ═══════
class TinyWS {
    public $sock; public $error = '';
    private $h, $p, $path, $headers;
    public function __construct($h, $p, $path, $headers = []) {
        $this->h = $h; $this->p = $p; $this->path = $path; $this->headers = $headers;
    }
    public function connect(): bool {
        $ctx = stream_context_create(['ssl'=>['verify_peer'=>false,'verify_peer_name'=>false,'allow_self_signed'=>true]]);
        $this->sock = @stream_socket_client("tls://{$this->h}:{$this->p}", $en, $es, 8, STREAM_CLIENT_CONNECT, $ctx);
        if (!$this->sock) { $this->error = "TCP: $en:$es"; return false; }
        stream_set_timeout($this->sock, 10); stream_set_blocking($this->sock, true);
        $key = base64_encode(random_bytes(16));
        $req = "GET {$this->path} HTTP/1.1\r\nHost: {$this->h}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {$key}\r\nSec-WebSocket-Version: 13\r\nOrigin: https://{$this->h}\r\nUser-Agent: Mozilla/5.0\r\n";
        foreach ($this->headers as $hd) $req .= $hd . "\r\n";
        $req .= "\r\n";
        fwrite($this->sock, $req);
        $resp = ''; $dl = microtime(true) + 8;
        while (!str_contains($resp, "\r\n\r\n") && microtime(true) < $dl) {
            $c = fread($this->sock, 2048);
            if ($c === false || $c === '') { $this->error = 'Handshake no data'; return false; }
            $resp .= $c;
        }
        if (stripos($resp, ' 101') === false) { $this->error = 'Handshake: '.substr($resp,0,100); return false; }
        return true;
    }
    public function sendRaw(string $p): void {
        if (!$this->sock) return;
        $len = strlen($p); $f = chr(0x81);
        if ($len < 126) $f .= chr(0x80 | $len);
        elseif ($len < 65536) $f .= chr(0x80 | 126) . pack('n', $len);
        else $f .= chr(0x80 | 127) . pack('J', $len);
        $m = random_bytes(4); $f .= $m;
        for ($i = 0; $i < $len; $i++) $f .= $p[$i] ^ $m[$i % 4];
        @fwrite($this->sock, $f);
    }
    public function readOneFrame(int $to = 1): ?array {
        if (!$this->sock) return null;
        $r = [$this->sock]; $w = null; $e = null;
        $n = @stream_select($r, $w, $e, $to, 0);
        if ($n === false) return null;
        if ($n === 0) return [];
        $hdr = @fread($this->sock, 2);
        if ($hdr === false || strlen($hdr) < 2) return null;
        $b1 = ord($hdr[0]); $b2 = ord($hdr[1]);
        $op = $b1 & 0x0f; $masked = ($b2 & 0x80) !== 0; $len = $b2 & 0x7f;
        if ($len === 126) { $ext = @fread($this->sock, 2); if (strlen($ext) < 2) return null; $len = unpack('n', $ext)[1]; }
        elseif ($len === 127) { $ext = @fread($this->sock, 8); if (strlen($ext) < 8) return null; $len = unpack('J', $ext)[1]; }
        $mask = null;
        if ($masked) { $mask = @fread($this->sock, 4); if (strlen($mask) < 4) return null; }
        $data = '';
        while (strlen($data) < $len) {
            $c = @fread($this->sock, $len - strlen($data));
            if ($c === false || $c === '') return null;
            $data .= $c;
        }
        if ($mask) { $u = ''; for ($i = 0; $i < $len; $i++) $u .= $data[$i] ^ $mask[$i % 4]; $data = $u; }
        if ($op === 0x8) return null;
        if ($op === 0x9) { $this->sendPong($data); return []; }
        if ($op === 0xA) return [];
        if ($op === 0x0 || $op === 0x1) return [$data];
        return [];
    }
    private function sendPong(string $pl): void {
        if (!$this->sock) return;
        $len = strlen($pl); $f = chr(0x8A);
        if ($len < 126) $f .= chr(0x80 | $len);
        elseif ($len < 65536) $f .= chr(0x80 | 126) . pack('n', $len);
        else $f .= chr(0x80 | 127) . pack('J', $len);
        $m = random_bytes(4); $f .= $m;
        for ($i = 0; $i < $len; $i++) $f .= $pl[$i] ^ $m[$i % 4];
        @fwrite($this->sock, $f);
    }
    public function close(): void { if ($this->sock) @fclose($this->sock); $this->sock = null; }
}

// ═══════ WS BET ═══════
function do_ws_bet(string $key, array $s, array &$actions): array {
    global $CFG;
    if (empty($s['token'])) return ['ok'=>false, 'reason'=>'Missing token'];
    $pred = $s['pending_pred'] ?? null;
    if (!$pred) return ['ok'=>false, 'reason'=>'No pending_pred'];
    $side = 'XIU';
    if ($pred === 'Tài' || $pred === 'T' || $pred === 'TAI') $side = 'TAI';
    $ps = (int)($s['pending_session'] ?? 0);
    $amount = (int)($s['pending_bet_amount'] ?? 10000);
    if ($amount < 1000) $amount = 1000;

    $wsPath = rtrim($CFG['game']['ws_path'], '/') . '/?EIO=4&transport=websocket';
    $ws = new TinyWS($CFG['game']['ws_host'], 443, $wsPath, ['Authorization: Bearer ' . $s['token']]);
    if (!$ws->connect()) {
        key_log($key, 'error', '❌ WS connect: ' . $ws->error);
        return ['ok'=>false, 'reason'=>'Connect: '.$ws->error];
    }
    key_log($key, 'info', '✅ WS connected');

    $auth = json_encode(['token'=>$s['token']], JSON_UNESCAPED_UNICODE);
    $stage = 'wait_open';
    $joined = false; $done = false;
    $sawBetting = false; $lastTickState = '';
    $deadline = microtime(true) + 8;

    while (microtime(true) < $deadline) {
        $frames = $ws->readOneFrame(1);
        if ($frames === null) {
            $ws->close();
            return ['ok'=>false, 'reason'=>'WS closed at: '.$stage];
        }
        if ($frames === []) continue;
        foreach ($frames as $pkt) {
            if ($pkt === '' || $pkt === null) continue;
            if (str_starts_with($pkt, '0{')) {
                $stage = 'auth_sent';
                $ws->sendRaw('40/txmd5,' . $auth);
                continue;
            }
            if ($pkt === '2') { $ws->sendRaw('3'); continue; }
            if ($pkt === '3' || $pkt === '6') continue;
            if ($pkt === '1') { $ws->close(); return ['ok'=>false, 'reason'=>'Engine.IO close']; }
            if (!str_starts_with($pkt, '4')) continue;
            $sio = substr($pkt, 1);
            if (str_starts_with($sio, '0/txmd5,')) { $stage = 'joined'; $joined = true; continue; }
            if (str_starts_with($sio, '1')) { $ws->close(); return ['ok'=>false, 'reason'=>'SIO disconnect']; }
            if (str_starts_with($sio, '4')) { $ws->close(); return ['ok'=>false, 'reason'=>'CONNECT_ERROR: '.substr($sio,0,80)]; }
            if (!str_starts_with($sio, '2')) continue;

            $body = substr($sio, 1);
            if (str_starts_with($body, '/txmd5,')) $body = substr($body, strlen('/txmd5,'));
            $msg = json_decode($body, true);
            if (!is_array($msg) || count($msg) < 1) continue;
            $ev = $msg[0] ?? ''; $d = $msg[1] ?? [];

            if ($ev === 'tick-update') {
                $state = $d['state'] ?? '';
                $tickSid = isset($d['id']) ? (int)$d['id'] : (isset($d['sessionId']) ? (int)$d['sessionId'] : null);
                if ($state !== $lastTickState) $lastTickState = $state;
                if ($state === 'BETTING' && $joined && !$done) {
                    if ($tickSid !== null && $tickSid < $ps) continue;
                    $sawBetting = true;
                    $stage = 'bet_sent';
                    $ws->sendRaw('42/txmd5,' . json_encode(['bet', ['type'=>$side, 'amount'=>$amount]], JSON_UNESCAPED_UNICODE));
                    $done = true;
                    key_log($key, 'success', '💰 Bet: #'.$ps.' '.$side.' '.number_format($amount));
                    $actions[] = ['type'=>'bet', 'msg'=>"Bet #$ps $side $amount"];
                    key_update($key, function($dd) use ($ps, $amount) {
                        $dd['bet_session'] = $ps;
                        $dd['bet_amount'] = $amount;
                        return $dd;
                    });
                    $wait = microtime(true) + 2;
                    while (microtime(true) < $wait) {
                        $more = $ws->readOneFrame(1);
                        if ($more === null || $more === []) continue;
                        foreach ($more as $p2) {
                            if ($p2 === '2') { $ws->sendRaw('3'); continue; }
                            if (!str_starts_with($p2, '4')) continue;
                            $s2 = substr($p2, 1);
                            if (!str_starts_with($s2, '2')) continue;
                            $b2 = substr($s2, 1);
                            if (str_starts_with($b2, '/txmd5,')) $b2 = substr($b2, strlen('/txmd5,'));
                            $m2 = json_decode($b2, true);
                            if (!is_array($m2)) continue;
                            if (($m2[0] ?? '') === 'bet-result') {
                                key_log($key, 'success', '✅ Bet ACK');
                                if (isset($m2[1]['postBalance'])) {
                                    key_update($key, function($dd) use ($m2) {
                                        $dd['last_post_balance'] = $m2[1]['postBalance'];
                                        return $dd;
                                    });
                                }
                            }
                        }
                    }
                    $ws->close();
                    return ['ok'=>true, 'reason'=>'Bet sent + ack'];
                }
            }
            if ($ev === 'session-result') { $ws->close(); return ['ok'=>false, 'reason'=>'Session settled before bet']; }
        }
    }
    $ws->close();
    $reason = 'Timeout 8s — stage='.$stage;
    if ($joined && !$sawBetting) $reason .= ' (no BETTING)';
    key_log($key, 'error', '❌ ' . $reason);
    return ['ok'=>false, 'reason'=>$reason];
}

// ═══════ WORKER ═══════
function worker_step(string $key): array {
    $actions = [];
    $s = key_load($key);
    if (!$s) return $actions;
    $cfg = $s['config'] ?? [];
    if (empty($cfg['auto']) || !empty($cfg['paused'])) return $actions;

    $pTarget = (int)($cfg['profit_stop'] ?? 0);
    if ($pTarget > 0 && (int)($s['profit_total'] ?? 0) >= $pTarget && empty($s['pending_pred'])) {
        key_update($key, function($d) { $d['config']['auto'] = false; $d['config']['paused'] = true; return $d; });
        key_log($key, 'success', '🎉 ĐẠT MỤC TIÊU');
        return $actions;
    }

    $data = fetch_sessions_api();
    if (!$data || empty($data['list'])) {
        if (($s['last_api_fail_log'] ?? 0) < time() - 60) {
            key_log($key, 'warn', '⚠️ sessions API fail');
            key_update($key, fn($d) => array_merge($d, ['last_api_fail_log' => time()]));
        }
        return $actions;
    }
    $sessions = $data['list'];

    $latestId = 0;
    foreach ($sessions as $row) {
        if (map_result((string)($row['resultTruyenThong'] ?? '')) !== null) {
            $latestId = (int)$row['id']; break;
        }
    }
    if ($latestId === 0) { key_log($key, 'warn', 'Không có phiên có KQ'); return $actions; }

    $lastId = (int)($s['last_session_id'] ?? 0);

    if ($lastId === 0) {
        key_update($key, fn($d) => array_merge($d, ['last_session_id'=>$latestId]));
        key_log($key, 'info', '📡 Baseline #'.$latestId);
        return $actions;
    }

    if ($latestId > $lastId) {
        for ($sid = $lastId + 1; $sid <= $latestId; $sid++) {
            $found = find_session($sessions, $sid);
            if (!$found) continue;
            $result = map_result((string)($found['resultTruyenThong'] ?? ''));
            if ($result === null) continue;
            $dices = $found['dices'] ?? [0,0,0];
            $tong = 0; foreach ($dices as $v) $tong += (int)$v;
            $jackpot = detect_jackpot($found, $dices);

            if ((int)($s['pending_session'] ?? 0) === $sid && !empty($s['pending_pred'])) {
                $pred = $s['pending_pred'];
                $betPlaced = ((int)($s['bet_session'] ?? 0) === $sid);

                if (!$betPlaced) {
                    key_log($key, 'error', '⚠️ #'.$sid.' không đặt được cược — clear pending');
                    key_update($key, function($d) {
                        $d['pending_pred']=null; $d['pending_session']=null;
                        $d['pending_bet_amount']=null; $d['bet_session']=null; $d['bet_amount']=0;
                        $d['pending_conf']=null; $d['pending_base']=null; $d['pending_final']=null;
                        return $d;
                    });
                    $s = key_load($key);
                    continue;
                }

                $win = (($pred==='Tài'||$pred==='T') && $result==='TAI') || (($pred==='Xỉu'||$pred==='X') && $result==='XIU');

                $actualSym = $result === 'TAI' ? 'T' : 'X';
                $baseSym = $s['pending_base'] ?? ($pred === 'Tài' ? 'T' : 'X');
                $finalSym = $s['pending_final'] ?? ($pred === 'Tài' ? 'T' : 'X');
                $pendingConf = (int)($s['pending_conf'] ?? 0);

                key_update($key, function($d) use ($sid, $pred, $result, $dices, $win, $jackpot, $tong, $actualSym, $baseSym, $finalSym, $pendingConf) {
                    $c = $d['config'];
                    $st = (int)($c['lose_streak'] ?? 0);
                    $bSt = (int)($c['bet_streak'] ?? 0);

                    if ($win) {
                        $st = 0; $bSt = 0;
                        $d['win_count_total'] = (int)($d['win_count_total'] ?? 0) + 1;
                    } else {
                        $d['loss_count_total'] = (int)($d['loss_count_total'] ?? 0) + 1;
                        $st++; $bSt++;
                    }
                    $c['lose_streak'] = $st;
                    $c['bet_streak'] = $bSt;

                    $betAmt = (int)($d['bet_amount'] ?? 0);
                    $bal = (int)($d['balance'] ?? 0);
                    $delta = $win ? intval($betAmt * 0.98) : -$betAmt;
                    $bal += $delta;
                    if ($bal < 0) $bal = 0;
                    $d['balance'] = $bal;
                    $d['profit_total'] = (int)($d['profit_total'] ?? 0) + $delta;

                    $d['history'] = $d['history'] ?? [];
                    array_unshift($d['history'], [
                        'ts'=>date('H:i:s d/m'),'session'=>$sid,'pred'=>$pred,'result'=>$result,
                        'dices'=>$dices,'tong'=>$tong,'win'=>$win,'amount'=>$betAmt,
                        'balance_after'=>$bal,'streak'=>$st,'bet_streak'=>$bSt,
                        'jackpot'=>$jackpot,'conf'=>$pendingConf,
                    ]);
                    $d['history'] = array_slice($d['history'], 0, 500);

                    // adaptive learning
                    $predLog = $d['pred_log'] ?? [];
                    array_unshift($predLog, ['base'=>$baseSym, 'final'=>$finalSym, 'actual'=>$actualSym, 'ts'=>time()]);
                    $predLog = array_slice($predLog, 0, 30);
                    $d['pred_log'] = $predLog;

                    $recent = array_slice($predLog, 0, 8);
                    if (count($recent) >= 6) {
                        $baseOk = 0;
                        foreach ($recent as $r) if (($r['base'] ?? '') === ($r['actual'] ?? '')) $baseOk++;
                        $baseAcc = $baseOk / count($recent);
                        $sl = $d['self_learning'] ?? ['reverse_mode' => false];
                        if ($baseAcc < 0.30 && empty($sl['reverse_mode'])) $sl['reverse_mode'] = true;
                        elseif ($baseAcc > 0.55 && !empty($sl['reverse_mode'])) $sl['reverse_mode'] = false;
                        $d['self_learning'] = $sl;
                    }

                    $d['pending_pred']=null; $d['pending_session']=null;
                    $d['pending_bet_amount']=null; $d['bet_session']=null; $d['bet_amount']=0;
                    $d['pending_conf']=null; $d['pending_base']=null; $d['pending_final']=null;

                    $sym = ($result==='TAI')?'T':'X';
                    $p10 = ($d['pattern_10'] ?? '') . $sym;
                    if (strlen($p10) > 10) $p10 = substr($p10, -10);
                    $d['pattern_10'] = $p10;

                    $d['config'] = $c;
                    $pS = (int)($c['profit_stop'] ?? 0);
                    if ($pS > 0 && (int)$d['profit_total'] >= $pS) { $c['auto']=false; $c['paused']=true; $d['config']=$c; }
                    return $d;
                });
                $icon = $win ? '✅' : '❌';
                $confTxt = $pendingConf > 0 ? " ({$pendingConf}%)" : '';
                $log = "$icon #$sid: $pred$confTxt → $result (".implode('-',$dices).")".($jackpot?' 🎰':'');
                key_log($key, $win?'success':'error', $log);
                $actions[] = ['type'=>'result', 'msg'=>$log];
                $s = key_load($key);
            }
        }
        key_update($key, fn($d) => array_merge($d, ['last_session_id'=>$latestId]));
        $s = key_load($key);
    }

    if (!empty($s['pending_session']) && (int)$s['pending_session'] <= $latestId) {
        key_update($key, function($d) {
            $d['pending_pred']=null; $d['pending_session']=null;
            $d['pending_bet_amount']=null; $d['bet_session']=null; $d['bet_amount']=0;
            $d['pending_conf']=null; $d['pending_base']=null; $d['pending_final']=null;
            return $d;
        });
        $s = key_load($key);
    }

    $cfg = $s['config'];
    if (!empty($cfg['auto']) && empty($cfg['paused']) && empty($s['pending_pred'])) {
        $lastComputeId = (int)($s['last_compute_id'] ?? 0);
        $shouldLog = ($lastComputeId !== $latestId);

        $predictionInfo = engine_predict($key, $sessions);
        if ($predictionInfo === null) {
            if ($shouldLog) {
                key_log($key, 'info', '⏭ #'.($latestId+1).' — chưa đủ dữ liệu');
                key_update($key, fn($d) => array_merge($d, ['last_compute_id'=>$latestId]));
            }
            return $actions;
        }

        $predStr = ($predictionInfo['prediction'] === 'TAI') ? 'Tài' : 'Xỉu';
        $conf = (int)$predictionInfo['confidence'];

        // Sau 2 lần thua liên tiếp: đảo dự đoán nội bộ từ tay thứ 3
        // và tiếp tục đảo cho đến khi thắng; khi thắng lose_streak được reset về 0.
        if ((int)($cfg['lose_streak'] ?? 0) >= 2) {
            $predStr = ($predStr === 'Tài') ? 'Xỉu' : 'Tài';
        }

        $betStreak = (int)($cfg['bet_streak'] ?? 0);
        $baseBet = max(1000, (int)($cfg['base_bet'] ?? 10000));
        $bal = (int)($s['balance'] ?? 0);
        $mult = (int)pow(2, min($betStreak, 62));
        $betAmt = $baseBet * $mult;
        if ($bal > 0 && $betAmt > $bal) $betAmt = $bal;
        if ($betAmt < 1000) $betAmt = 1000;

        if ($bal < 1000) {
            key_update($key, function($d) { $d['config']['auto']=false; $d['config']['paused']=true; return $d; });
            key_log($key, 'error', '🛑 Balance < 1000đ — dừng');
            return $actions;
        }

        key_update($key, function($d) use ($predStr, $latestId, $betAmt, $predictionInfo, $conf) {
            $d['pending_pred'] = $predStr;
            $d['pending_session'] = $latestId + 1;
            $d['pending_bet_amount'] = $betAmt;
            $d['pending_conf'] = $conf;
            $d['pending_base'] = $predictionInfo['base'];
            $d['pending_final'] = $predictionInfo['final_sym'];
            $d['last_compute_id'] = $latestId;
            return $d;
        });

        if ($shouldLog) {
            $badges = [];
            if ($predictionInfo['cheat']) $badges[] = '🛡️';
            if ($predictionInfo['reverse_mode']) $badges[] = '🔄';
            if ($conf >= 85) $badges[] = '⚡';
            $badgeStr = $badges ? ' '.implode('', $badges) : '';
            $log = "🌸 #".($latestId+1)." → $predStr ({$conf}%){$badgeStr} | Bet: ".number_format($betAmt)."đ x$mult";
            key_log($key, 'info', $log);
            $actions[] = ['type'=>'predict', 'msg'=>$log];
        }
        $s = key_load($key);
    }

    $cfg = $s['config'];
    if (!empty($s['pending_pred']) && !empty($cfg['auto']) && empty($cfg['paused'])) {
        if ((int)($s['bet_session'] ?? 0) !== (int)($s['pending_session'] ?? 0)) {
            $betResult = do_ws_bet($key, $s, $actions);
            if (!$betResult['ok']) {
                key_update($key, fn($d) => array_merge($d, ['last_ws_error' => $betResult['reason']]));
            }
        }
    }
    return $actions;
}

function worker_heartbeat(string $key, string $status = 'running'): void {
    key_update($key, function($d) use ($status) {
        $start = $d['worker']['started_at'] ?? time();
        $d['worker'] = ['last_beat'=>time(),'pid'=>getmypid(),'status'=>$status,'started_at'=>$start];
        return $d;
    });
}
function worker_alive(string $key): bool {
    global $CFG;
    $s = key_load($key);
    $w = $s['worker'] ?? [];
    if (empty($w['last_beat'])) return false;
    return (time() - (int)$w['last_beat']) < ($CFG['worker']['resume_timeout'] ?? 90);
}
function worker_lock(string $key): bool {
    $lp = KEY_DIR . '/' . hash('sha256', strtolower($key)) . '.lock';
    if (is_file($lp)) {
        $pid = (int)trim(@file_get_contents($lp));
        if ($pid > 0 && function_exists('posix_kill') && @posix_kill($pid, 0)) return false;
        @unlink($lp);
    }
    $fp = @fopen($lp, 'c+');
    if (!$fp) return false;
    if (!flock($fp, LOCK_EX | LOCK_NB)) { fclose($fp); return false; }
    ftruncate($fp, 0); rewind($fp); fwrite($fp, (string)getmypid()); fflush($fp);
    register_shutdown_function(function() use ($fp, $lp) {
        @flock($fp, LOCK_UN); @fclose($fp); @unlink($lp);
    });
    return true;
}
function run_worker_daemon(string $key, int $max): void {
    global $CFG;
    if (function_exists('fastcgi_finish_request')) @fastcgi_finish_request();
    else { @ob_end_clean(); header('Connection: close'); header('Content-Length: 0'); @flush(); @ob_end_flush(); }
    @ignore_user_abort(true); @set_time_limit(0); @ini_set('memory_limit', '256M');
    if (!worker_lock($key)) return;
    $sleep = (int)($CFG['worker']['loop_sleep'] ?? 1);
    $deadline = time() + $max; $lastBeat = 0;
    $buf = (int)($CFG['worker']['respawn_buffer'] ?? 60);
    worker_heartbeat($key, 'running');
    key_log($key, 'info', '🚀 Worker started PID='.getmypid());
    while (time() < $deadline) {
        $s = key_load($key);
        if (!$s) break;
        try { worker_step($key); }
        catch (Throwable $e) { key_log($key, 'error', '💥 '.$e->getMessage()); }
        if (time() - $lastBeat >= 10) { worker_heartbeat($key, 'running'); $lastBeat = time(); }
        if ((time() + $buf) >= $deadline) {
            $s2 = key_load($key);
            if (!empty($s2['config']['auto']) && empty($s2['config']['paused'])) {
                @unlink(KEY_DIR . '/' . hash('sha256', strtolower($key)) . '.lock');
                spawn_worker_async($key);
            }
            break;
        }
        sleep($sleep);
    }
    worker_heartbeat($key, 'stopped');
}
function spawn_worker_async(string $key): void {
    $lp = KEY_DIR . '/' . hash('sha256', strtolower($key)) . '.lock';
    if (is_file($lp)) {
        $pid = (int)trim(@file_get_contents($lp));
        if ($pid > 0 && function_exists('posix_kill')) {
            @posix_kill($pid, SIGTERM);
            usleep(200000);
            if (@posix_kill($pid, 0)) @posix_kill($pid, SIGKILL);
        }
        @unlink($lp);
    }
    $scheme = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $path = $_SERVER['SCRIPT_NAME'] ?? '/index.php';
    $url = "$scheme://$host$path?action=worker&key=" . urlencode($key) . "&max=3600";

    $spawned = false; $method = '';
    if (function_exists('exec') && !in_array('exec', array_map('trim', explode(',',(string)ini_get('disable_functions'))))) {
        $php = PHP_BINARY ?: 'php';
        $code = 'ignore_user_abort(true);set_time_limit(0);@file_get_contents(' . var_export($url, true) . ');';
        @exec(sprintf('%s -r %s > /dev/null 2>&1 &', escapeshellarg($php), escapeshellarg($code)));
        $spawned = true; $method = 'exec';
    } elseif (function_exists('shell_exec') && !in_array('shell_exec', array_map('trim', explode(',',(string)ini_get('disable_functions'))))) {
        @shell_exec("curl -s --max-time 2 " . escapeshellarg($url) . " > /dev/null 2>&1 &");
        $spawned = true; $method = 'shell_exec';
    } elseif (function_exists('fsockopen')) {
        $parsed = parse_url($url);
        $h = $parsed['host'] ?? $host;
        $port = ($parsed['scheme'] ?? 'http') === 'https' ? 443 : 80;
        $fp = @fsockopen($h, $port, $en, $es, 1);
        if ($fp) {
            stream_set_timeout($fp, 1);
            $p = ($parsed['path'] ?? '/') . '?' . ($parsed['query'] ?? '');
            @fwrite($fp, "GET {$p} HTTP/1.1\r\nHost: {$h}\r\nConnection: Close\r\n\r\n");
            @fclose($fp);
            $spawned = true; $method = 'fsockopen';
        }
    } else {
        try {
            $ctx = stream_context_create(['http'=>['timeout'=>0.5]]);
            @file_get_contents($url, false, $ctx);
            $spawned = true; $method = 'fgc';
        } catch (Throwable $e) {}
    }
    key_log($key, $spawned ? 'info' : 'error', 'Spawn: '.($spawned ? $method : 'FAILED'));
}

// ═══════ ROUTER ═══════
$action = $_GET['action'] ?? $_POST['action'] ?? '';
if ($action === '') { render_ui(); exit; }

if ($action === 'worker') {
    $key = trim($_GET['key'] ?? '');
    if (!$key) { http_response_code(400); echo 'missing'; exit; }
    run_worker_daemon($key, (int)($_GET['max'] ?? 3600));
    exit;
}
if ($action === 'keepalive') { header('Content-Type: application/json'); echo json_encode(['ok'=>true,'ts'=>time()]); exit; }

header('Content-Type: application/json; charset=utf-8');
try {
    switch ($action) {
        case 'verify':
            $u = trim($_POST['user'] ?? ''); $p = trim($_POST['pass'] ?? '');
            $dev = trim($_POST['device'] ?? 'WEB');
            if (!$u || !$p) { echo json_encode(['ok'=>false,'msg'=>'Thiếu TK/MK']); exit; }
            $key = $u;
            $existing = key_load($key);
            $canResume = !empty($existing['user']) && !empty($existing['token']);
            $gl = game_login($u, $p);
            if (isset($gl['_error'])) {
                if ($canResume) { $gl = ['nickname'=>$existing['nickname']??$u,'token'=>$existing['token'],'money'=>$existing['balance']??0];
                    key_log($key, 'info', '♻️ Resume'); }
                else { echo json_encode(['ok'=>false,'msg'=>$gl['_error']]); exit; }
            }
            $s = $existing ?: [];
            $s['user']=$u; $s['key']=$key; $s['device']=$dev;
            $s['nickname']=$gl['nickname']??$u; $s['token']=$gl['token']??'';
            $s['balance']=$gl['money']??($s['balance']??0);
            if (!isset($s['history'])) $s['history']=[];
            if (!isset($s['logs'])) $s['logs']=[];
            if (!isset($s['pred_log'])) $s['pred_log']=[];
            if (!isset($s['self_learning'])) $s['self_learning']=['reverse_mode'=>false];
            $s['config'] = array_merge($CFG['default_config'], $s['config']??[]);
            foreach (['win_count_total','loss_count_total','profit_total','last_session_id'] as $k) if (!isset($s[$k])) $s[$k]=0;
            foreach (['pending_pred','pending_session','pending_bet_amount','bet_session','pending_conf','pending_base','pending_final'] as $k) if (!array_key_exists($k, $s)) $s[$k]=null;
            if (!isset($s['bet_amount'])) $s['bet_amount']=0;
            if (!isset($s['pattern_10'])) $s['pattern_10']='';
            key_save($key, $s); key_save_by_user($u, $key);
            key_log($key, 'info', '🔐 Login — '.$dev);
            if (!worker_alive($key)) spawn_worker_async($key);
            echo json_encode(['ok'=>true,'user'=>$u,'nickname'=>$s['nickname'],'balance'=>$s['balance'],
                'config'=>$s['config'],'history'=>$s['history'],
                'auth_token'=>issue_token($u),'worker_alive'=>worker_alive($key),'resumed'=>$canResume]);
            exit;

        case 'resume':
            $u = trim($_POST['user'] ?? ''); $tk = trim($_POST['auth_token'] ?? '');
            if (!verify_token($tk, $u)) { echo json_encode(['ok'=>false,'msg'=>'Token expired']); exit; }
            $key = key_resolve($u); $s = key_load($key);
            if (!$s || empty($s['token'])) { echo json_encode(['ok'=>false,'msg'=>'Session lost']); exit; }
            if (!empty($s['config']['auto']) && empty($s['config']['paused']) && !worker_alive($key)) {
                @unlink(KEY_DIR.'/'.hash('sha256',strtolower($key)).'.lock');
                spawn_worker_async($key);
            }
            $wins = (int)($s['win_count_total']??0); $losses = (int)($s['loss_count_total']??0);
            $tot = $wins+$losses; $wr = $tot>0 ? round($wins/$tot*100,1) : 0;
            $profit = (int)($s['profit_total']??0);
            echo json_encode(['ok'=>true,'user'=>$u,'nickname'=>$s['nickname']??'','balance'=>$s['balance']??0,
                'config'=>$s['config']??[],'history'=>array_slice($s['history']??[],0,100),
                'auth_token'=>issue_token($u),'worker_alive'=>worker_alive($key),
                'pending_pred'=>$s['pending_pred']??null,'pending_session'=>$s['pending_session']??null,
                'pending_bet_amount'=>$s['pending_bet_amount']??null,'pending_conf'=>$s['pending_conf']??null,
                'reverse_mode'=>$s['self_learning']['reverse_mode']??false,
                'last_session_id'=>$s['last_session_id']??0,'pattern_10'=>$s['pattern_10']??'',
                'win_count_total'=>$wins,'loss_count_total'=>$losses,'profit_total'=>$profit,
                'stats'=>['wins'=>$wins,'losses'=>$losses,'total'=>$tot,'winrate'=>$wr,'profit'=>$profit],
                'ts'=>time()]);
            exit;

        case 'setup':
            $u = trim($_POST['user'] ?? ''); $tk = trim($_POST['auth_token'] ?? '');
            if (!require_auth($u, $tk)) { echo json_encode(['ok'=>false,'msg'=>'Unauthorized']); exit; }
            $key = key_resolve($u); $s = key_load($key);
            $c = $s['config'];
            $c['base_bet'] = max(1000, (int)($_POST['base_bet']??10000));
            $c['profit_stop'] = max(0, (int)($_POST['profit_stop']??0));
            $c['onboarded'] = true; $c['auto'] = true; $c['paused'] = false;
            $c['bet_streak'] = 0; $c['lose_streak'] = 0;
            $s['config'] = $c;
            $s['pending_pred']=null; $s['pending_session']=null; $s['pending_bet_amount']=null;
            $s['bet_session']=null; $s['bet_amount']=0; $s['last_compute_id']=0;
            $s['last_ws_error']=null; $s['last_session_id'] = 0;
            $s['pending_conf']=null; $s['pending_base']=null; $s['pending_final']=null;
            key_save($key, $s);
            $lp = KEY_DIR.'/'.hash('sha256',strtolower($key)).'.lock';
            if (is_file($lp)) {
                $pid = (int)trim(@file_get_contents($lp));
                if ($pid > 0 && function_exists('posix_kill')) { @posix_kill($pid, SIGTERM); usleep(200000); }
                @unlink($lp);
            }
            spawn_worker_async($key);
            key_log($key, 'success', '▶ AUTO ON — base='.number_format($c['base_bet']).' target='.number_format($c['profit_stop']));
            echo json_encode(['ok'=>true,'config'=>$c,'worker_alive'=>worker_alive($key)]);
            exit;

        case 'kill':
            $u = trim($_POST['user'] ?? ''); $tk = trim($_POST['auth_token'] ?? '');
            if (!require_auth($u, $tk)) { echo json_encode(['ok'=>false,'msg'=>'Unauthorized']); exit; }
            $key = key_resolve($u);
            key_update($key, function($d) {
                $d['config']['auto']=false; $d['config']['paused']=true;
                $d['config']['lose_streak']=0; $d['config']['bet_streak']=0;
                $d['pending_pred']=null; $d['pending_session']=null; $d['pending_bet_amount']=null;
                $d['bet_session']=null; $d['bet_amount']=0;
                $d['pending_conf']=null; $d['pending_base']=null; $d['pending_final']=null;
                return $d;
            });
            $lp = KEY_DIR.'/'.hash('sha256',strtolower($key)).'.lock';
            if (is_file($lp)) {
                $pid = (int)trim(@file_get_contents($lp));
                if ($pid > 0 && function_exists('posix_kill')) @posix_kill($pid, SIGTERM);
                @unlink($lp);
            }
            key_log($key, 'warn', '🛑 KILL');
            echo json_encode(['ok'=>true]);
            exit;

        case 'reset_adaptive':
            $u = trim($_POST['user'] ?? ''); $tk = trim($_POST['auth_token'] ?? '');
            if (!require_auth($u, $tk)) { echo json_encode(['ok'=>false,'msg'=>'Unauthorized']); exit; }
            $key = key_resolve($u);
            key_update($key, function($d) {
                $d['self_learning'] = ['reverse_mode'=>false];
                $d['pred_log'] = [];
                return $d;
            });
            key_log($key, 'info', '🔄 Reset adaptive learning');
            echo json_encode(['ok'=>true]);
            exit;

        case 'status':
            $u = trim($_GET['user'] ?? ''); $tk = trim($_GET['auth_token'] ?? '');
            if (!verify_token($tk, $u)) { echo json_encode(['ok'=>false,'msg'=>'Unauthorized']); exit; }
            $key = key_resolve($u); $s = key_load($key);
            if (!empty($s['config']['auto']) && empty($s['config']['paused']) && !worker_alive($key)) {
                @unlink(KEY_DIR.'/'.hash('sha256',strtolower($key)).'.lock');
                spawn_worker_async($key);
            }
            $wins = (int)($s['win_count_total']??0); $losses = (int)($s['loss_count_total']??0);
            $tot = $wins+$losses; $wr = $tot>0 ? round($wins/$tot*100,1) : 0;
            $profit = (int)($s['profit_total']??0);
            echo json_encode(['ok'=>true,'nickname'=>$s['nickname']??'','balance'=>$s['balance']??0,
                'config'=>$s['config']??[],'history'=>array_slice($s['history']??[],0,100),
                'pending_pred'=>$s['pending_pred']??null,'pending_session'=>$s['pending_session']??null,
                'pending_bet_amount'=>$s['pending_bet_amount']??null,'pending_conf'=>$s['pending_conf']??null,
                'reverse_mode'=>$s['self_learning']['reverse_mode']??false,
                'last_session_id'=>$s['last_session_id']??0,'pattern_10'=>$s['pattern_10']??'',
                'win_count_total'=>$wins,'loss_count_total'=>$losses,'profit_total'=>$profit,
                'stats'=>['wins'=>$wins,'losses'=>$losses,'total'=>$tot,'winrate'=>$wr,'profit'=>$profit],
                'worker_alive'=>worker_alive($key),
                'last_ws_error'=>$s['last_ws_error']??null,
                'last_post_balance'=>$s['last_post_balance']??null,
                'logs'=>array_slice($s['logs']??[],0,25),
                'ts'=>time()]);
            exit;

        case 'tick':
            $u = trim($_POST['user'] ?? ''); $tk = trim($_POST['auth_token'] ?? '');
            if (!verify_token($tk, $u)) { echo json_encode(['ok'=>false,'msg'=>'Unauthorized']); exit; }
            $key = key_resolve($u);
            $s = key_load($key);
            if (!empty($s['config']['auto']) && empty($s['config']['paused']) && !worker_alive($key)) {
                @unlink(KEY_DIR.'/'.hash('sha256',strtolower($key)).'.lock');
                spawn_worker_async($key);
            }
            $s2 = key_load($key);
            echo json_encode(['ok'=>true,'worker_alive'=>worker_alive($key),
                'pending_pred'=>$s2['pending_pred']??null,'pending_session'=>$s2['pending_session']??null,
                'pending_conf'=>$s2['pending_conf']??null,
                'reverse_mode'=>$s2['self_learning']['reverse_mode']??false,
                'last_ws_error'=>$s2['last_ws_error']??null]);
            exit;

        case 'logout':
            $u = trim($_POST['user'] ?? ''); $tk = trim($_POST['auth_token'] ?? '');
            if (!verify_token($tk, $u)) { echo json_encode(['ok'=>false,'msg'=>'Unauthorized']); exit; }
            $key = key_resolve($u);
            @unlink(key_path($key));
            $lp = KEY_DIR.'/'.hash('sha256',strtolower($key)).'.lock';
            if (is_file($lp)) {
                $pid = (int)trim(@file_get_contents($lp));
                if ($pid > 0 && function_exists('posix_kill')) @posix_kill($pid, SIGTERM);
                @unlink($lp);
            }
            echo json_encode(['ok'=>true]);
            exit;

        case 'debug':
            $u = trim($_GET['user'] ?? ''); $tk = trim($_GET['auth_token'] ?? '');
            if (!verify_token($tk, $u)) { echo json_encode(['ok'=>false,'msg'=>'Unauthorized']); exit; }
            $key = key_resolve($u); $s = key_load($key);
            $data = fetch_sessions_api();
            $sessInfo = ['count'=>0, 'latestId'=>0, 'sessions'=>[]];
            $prediction = null;
            if ($data && !empty($data['list'])) {
                $sessions = $data['list'];
                $sessInfo['count'] = count($sessions);
                $latestId = 0;
                foreach ($sessions as $row) {
                    if (map_result((string)($row['resultTruyenThong'] ?? '')) !== null) {
                        $latestId = (int)$row['id']; break;
                    }
                }
                $sessInfo['latestId'] = $latestId;
                $sessInfo['sessions'] = array_slice(array_map(function($r) {
                    return ['id'=>(int)$r['id'], 'result'=>$r['resultTruyenThong']??'', 'dices'=>$r['dices']??[]];
                }, $sessions), 0, 30);
                if ($latestId > 0) $prediction = engine_predict($key, $sessions);
            }
            $cfg = $s['config'] ?? [];
            $betStreak = (int)($cfg['bet_streak'] ?? 0);
            $baseBet = (int)($cfg['base_bet'] ?? 0);
            $bal = (int)($s['balance'] ?? 0);
            $mult = (int)pow(2, min($betStreak, 62));
            $nextBetAmt = $baseBet * $mult;
            if ($bal > 0 && $nextBetAmt > $bal) $nextBetAmt = $bal;

            $recentLog = array_slice($s['pred_log'] ?? [], 0, 10);
            $baseOk = 0; $totLog = 0;
            foreach ($recentLog as $r) {
                if (!isset($r['base'], $r['actual'])) continue;
                $totLog++;
                if ($r['base'] === $r['actual']) $baseOk++;
            }

            echo json_encode([
                'ok'=>true, 'table'=>'MD5',
                'ws_host'=>$CFG['game']['ws_host'],
                'config'=>$cfg,
                'state'=>[
                    'balance'=>$bal,
                    'bet_streak'=>$betStreak,
                    'lose_streak'=>(int)($cfg['lose_streak'] ?? 0),
                    'last_session_id'=>$s['last_session_id']??0,
                    'last_compute_id'=>$s['last_compute_id']??0,
                    'pending_pred'=>$s['pending_pred']??null,
                    'pending_session'=>$s['pending_session']??null,
                    'pending_bet_amount'=>$s['pending_bet_amount']??null,
                    'pending_conf'=>$s['pending_conf']??null,
                    'bet_session'=>$s['bet_session']??null,
                    'last_ws_error'=>$s['last_ws_error']??null,
                    'reverse_mode'=>$s['self_learning']['reverse_mode']??false,
                    'worker'=>['alive'=>worker_alive($key), 'info'=>$s['worker']??null],
                ],
                'next_bet_simulation'=>[
                    'base_bet'=>$baseBet,
                    'bet_streak'=>$betStreak,
                    'multiplier'=>$mult,
                    'bet_amount'=>$nextBetAmt,
                    'balance_cap'=>$bal,
                ],
                'learning'=>[
                    'samples'=>count($s['pred_log'] ?? []),
                    'recent_base_accuracy'=> $totLog > 0 ? round($baseOk/$totLog*100, 1) : null,
                    'reverse_mode'=>$s['self_learning']['reverse_mode']??false,
                ],
                'sessions_api_result'=>$sessInfo,
                'prediction'=>$prediction,
            ]);
            exit;
    }
    echo json_encode(['ok'=>false,'msg'=>'Action lạ']);
} catch (Throwable $e) {
    echo json_encode(['ok'=>false,'msg'=>'Lỗi: '.$e->getMessage()]);
}
exit;

// ═══════ UI ═══════
function render_ui(): void { ?>
<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no,viewport-fit=cover">
<meta name="theme-color" content="#ffd0e6">
<title>SAKURA · AI</title>
<style>
:root{
  --bg-1:#ffe4f0;--bg-2:#ffd0e6;--bg-3:#ffc0dd;
  --pink-1:#ff6ba8;--pink-2:#ff4d94;--pink-3:#ff8fc3;
  --rose:#e63980;--rose-deep:#c2185b;
  --gold:#ffb84d;--gold-bright:#ffd966;
  --mint:#4ecca3;--cyan:#5ec8ff;--violet:#a78bfa;
  --aurora:#7ee8c7;
  --text:#3d1e2e;--text-dim:#8a5a72;--muted:#b890a5;
  --white:#ffffff;
  --glass-bg:rgba(255,255,255,0.72);
  --glass-border:rgba(255,109,168,0.35);
}
*{margin:0;padding:0;box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html{height:100dvh;overflow:hidden;font-size:16px}
body{
  height:100dvh;overflow:hidden;position:fixed;inset:0;
  background:linear-gradient(135deg,var(--bg-1) 0%,var(--bg-2) 50%,var(--bg-3) 100%);
  background-attachment:fixed;color:var(--text);
  font-family:-apple-system,BlinkMacSystemFont,"Noto Sans JP","Segoe UI",system-ui,sans-serif;
  user-select:none;touch-action:manipulation;overscroll-behavior:none;
}
.bg-layer{position:fixed;inset:-20%;z-index:0;pointer-events:none;
  background:
    radial-gradient(circle at 20% 30%,rgba(255,109,168,0.55),transparent 40%),
    radial-gradient(circle at 80% 20%,rgba(255,180,220,0.6),transparent 45%),
    radial-gradient(circle at 60% 80%,rgba(167,139,250,0.35),transparent 40%),
    radial-gradient(circle at 30% 90%,rgba(255,217,102,0.35),transparent 45%),
    radial-gradient(circle at 50% 50%,rgba(126,232,199,0.25),transparent 50%);
  animation:meshRotate 30s linear infinite;filter:blur(40px);opacity:0.9;}
@keyframes meshRotate{to{transform:rotate(360deg)}}
.aurora{position:fixed;inset:0;z-index:0;pointer-events:none;opacity:0.55;
  background:linear-gradient(115deg,transparent 30%,rgba(126,232,199,0.35) 45%,transparent 60%);
  background-size:300% 100%;
  animation:auroraSlide 8s linear infinite;filter:blur(30px);mix-blend-mode:screen;}
@keyframes auroraSlide{0%{background-position:0% 0}100%{background-position:300% 0}}
#particles{position:fixed;inset:0;z-index:1;pointer-events:none;opacity:0.9}
.petal{position:fixed;width:14px;height:14px;z-index:1;pointer-events:none;
  background:radial-gradient(ellipse at 30% 30%,#fff,#ff9dcc 60%,#ff6ba8 90%);
  border-radius:50% 0 50% 50%;opacity:0.6;
  animation:petalFall linear infinite;
  filter:drop-shadow(0 0 6px rgba(255,109,168,0.7));}
@keyframes petalFall{0%{transform:translateY(-30px) translateX(0) rotate(0);opacity:0}
  10%{opacity:0.7}90%{opacity:0.6}100%{transform:translateY(105vh) translateX(80px) rotate(540deg);opacity:0}}
.orb{position:fixed;border-radius:50%;pointer-events:none;z-index:0;
  filter:blur(60px);opacity:0.55;animation:orbFloat 20s ease-in-out infinite;}
.orb-1{width:340px;height:340px;top:-10%;left:-8%;background:radial-gradient(circle,#ff6ba8,transparent 70%);animation-delay:0s}
.orb-2{width:380px;height:380px;bottom:-12%;right:-10%;background:radial-gradient(circle,#a78bfa,transparent 70%);animation-delay:-7s}
.orb-3{width:300px;height:300px;top:40%;right:20%;background:radial-gradient(circle,#ffd966,transparent 70%);animation-delay:-14s}
.orb-4{width:280px;height:280px;top:60%;left:15%;background:radial-gradient(circle,#7ee8c7,transparent 70%);animation-delay:-3s}
@keyframes orbFloat{0%,100%{transform:translate(0,0) scale(1)}
  25%{transform:translate(40px,-50px) scale(1.12)}
  50%{transform:translate(-30px,40px) scale(0.94)}
  75%{transform:translate(50px,30px) scale(1.08)}}
#app{position:absolute;inset:0;z-index:2;display:flex;flex-direction:column;overflow:hidden}
.screen{flex:1;display:flex;flex-direction:column;overflow:hidden;min-height:0}
.glass{background:var(--glass-bg);
  backdrop-filter:blur(26px) saturate(190%);
  -webkit-backdrop-filter:blur(26px) saturate(190%);
  border:1.5px solid var(--glass-border);border-radius:24px;
  box-shadow:0 12px 44px rgba(255,77,148,0.22),
    0 0 0 1px rgba(255,255,255,0.55) inset,
    0 0 42px -10px rgba(255,109,168,0.42);
  position:relative;overflow:hidden;}
.glass::before{content:'';position:absolute;top:0;left:0;right:0;height:1.5px;
  background:linear-gradient(90deg,transparent,rgba(255,255,255,0.95),transparent);opacity:0.75}
@property --angle{syntax:'<angle>';initial-value:0deg;inherits:false}
.neon::after{content:'';position:absolute;inset:-2px;border-radius:inherit;padding:2px;
  background:conic-gradient(from var(--angle),transparent 0%,var(--pink-1) 25%,var(--gold) 50%,var(--violet) 75%,transparent 100%);
  -webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);
  -webkit-mask-composite:xor;mask-composite:exclude;
  animation:spin 5s linear infinite;pointer-events:none;opacity:0.85;}
@keyframes spin{to{--angle:360deg}}
.wrap{flex:1;display:flex;align-items:center;justify-content:center;padding:20px;overflow-y:auto;position:relative;z-index:1}
.card{width:100%;max-width:400px;padding:34px 26px 30px;position:relative;
  animation:popIn 0.7s cubic-bezier(0.34,1.56,0.64,1)}
@keyframes popIn{from{opacity:0;transform:scale(0.9) translateY(40px);filter:blur(10px)}
  to{opacity:1;transform:scale(1) translateY(0);filter:blur(0)}}
.logo{width:110px;height:110px;border-radius:50%;object-fit:cover;
  border:3px solid #fff;background:#fff;
  box-shadow:0 0 0 4px rgba(255,109,168,0.3),0 8px 32px rgba(255,77,148,0.5),0 0 60px rgba(255,109,168,0.5);
  margin:0 auto 16px;display:block;animation:logoFloat 3.5s ease-in-out infinite;}
@keyframes logoFloat{0%,100%{transform:translateY(0) rotate(-2deg)}50%{transform:translateY(-10px) rotate(2deg)}}
.brand{font-size:28px;font-weight:900;letter-spacing:6px;text-align:center;
  background:linear-gradient(90deg,#ff4d94,#ff8fc3,#ffb84d,#ff4d94);
  background-size:300% 100%;
  -webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;
  margin-bottom:6px;animation:shimmerText 4s linear infinite;
  filter:drop-shadow(0 2px 8px rgba(255,77,148,0.4));}
@keyframes shimmerText{to{background-position:300% 0}}
.brand-sub{text-align:center;font-size:12px;letter-spacing:3px;color:var(--text-dim);font-weight:700;margin-bottom:26px}
.brand-sub b{color:var(--pink-2);text-shadow:0 0 8px rgba(255,77,148,0.4)}
.field{margin-bottom:16px}
.field label{display:block;font-size:11px;font-weight:800;color:var(--text-dim);
  text-transform:uppercase;letter-spacing:1.5px;margin-bottom:8px;}
.field input{width:100%;padding:15px 18px;background:rgba(255,255,255,0.85);
  border:2px solid rgba(255,109,168,0.25);border-radius:16px;
  color:var(--text);font-size:16px;outline:none;font-family:inherit;
  transition:all 0.3s;box-shadow:inset 0 1px 4px rgba(255,109,168,0.08);}
.field input:focus{border-color:var(--pink-2);background:#fff;
  box-shadow:0 0 0 4px rgba(255,77,148,0.15),0 4px 20px rgba(255,77,148,0.2);}
.field input::placeholder{color:var(--muted)}
.btn{width:100%;padding:16px;border:none;border-radius:16px;
  font-size:14px;font-weight:900;letter-spacing:2px;text-transform:uppercase;
  cursor:pointer;transition:all 0.3s;font-family:inherit;
  margin-top:10px;position:relative;overflow:hidden;
  background:linear-gradient(135deg,#ff4d94,#ff6ba8,#ff8fc3);color:#fff;
  box-shadow:0 10px 32px rgba(255,77,148,0.4),inset 0 1px 0 rgba(255,255,255,0.4);}
.btn::before{content:'';position:absolute;top:0;left:-100%;width:100%;height:100%;
  background:linear-gradient(90deg,transparent,rgba(255,255,255,0.5),transparent);
  transition:left 0.6s;}
.btn:hover:not(:disabled)::before{left:100%}
.btn:hover:not(:disabled){transform:translateY(-2px);
  box-shadow:0 14px 40px rgba(255,77,148,0.6),inset 0 1px 0 rgba(255,255,255,0.4);}
.btn:active{transform:scale(0.98)}
.btn:disabled{opacity:0.5;cursor:not-allowed}
.msg{margin-top:14px;padding:13px 16px;border-radius:14px;font-size:12px;
  font-weight:600;display:flex;align-items:center;gap:8px;animation:fadeIn 0.4s;}
@keyframes fadeIn{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:translateY(0)}}
.msg.err{background:rgba(230,57,128,0.12);border:1.5px solid rgba(230,57,128,0.4);color:var(--rose)}
.msg.warn{background:rgba(255,184,77,0.15);border:1.5px solid rgba(255,184,77,0.4);color:#b87500}
.msg.stuck{background:rgba(94,200,255,0.15);border:1.5px solid rgba(94,200,255,0.45);color:#0b6fa0}
.msg.success{background:rgba(78,204,163,0.15);border:1.5px solid rgba(78,204,163,0.45);color:#0d7a5c}
.foot{margin-top:22px;text-align:center;font-size:10px;color:var(--muted);line-height:1.8;letter-spacing:0.5px}
.foot b{color:var(--pink-2)}
.avatar{width:86px;height:86px;border-radius:50%;margin:0 auto 16px;
  background:linear-gradient(135deg,#ff6ba8,#ffb84d);
  display:flex;align-items:center;justify-content:center;
  font-size:38px;font-weight:900;color:#fff;
  box-shadow:0 0 0 4px rgba(255,255,255,0.8),0 8px 32px rgba(255,77,148,0.5),0 0 60px rgba(255,109,168,0.5);
  animation:avatarPop 0.7s cubic-bezier(0.34,1.56,0.64,1) 0.2s both;}
@keyframes avatarPop{from{transform:scale(0);opacity:0}to{transform:scale(1);opacity:1}}
.greet{font-size:15px;color:var(--pink-2);font-weight:800;text-align:center;margin-bottom:6px;letter-spacing:1px}
.name{font-size:24px;font-weight:900;color:var(--text);text-align:center;margin-bottom:6px}
.tag{font-size:10px;color:var(--text-dim);letter-spacing:2.5px;text-transform:uppercase;font-weight:700;text-align:center;margin-bottom:8px}
.stat{display:flex;justify-content:space-between;padding:15px 18px;
  background:rgba(255,255,255,0.75);border:1.5px solid rgba(255,109,168,0.2);
  border-radius:16px;margin-top:11px;transition:all 0.25s;}
.stat:hover{transform:translateY(-2px);box-shadow:0 6px 20px rgba(255,77,148,0.15)}
.stat .lbl{font-size:12px;color:var(--text-dim);font-weight:700}
.stat .val{font-size:15px;font-weight:900;color:var(--rose);font-family:monospace;text-align:right;overflow-wrap:anywhere}
.step{font-size:11px;letter-spacing:2.5px;color:var(--pink-2);font-weight:900;text-align:center;margin-bottom:10px}
.title{font-size:22px;font-weight:900;text-align:center;margin-bottom:8px;color:var(--text)}
.sub{font-size:12px;text-align:center;color:var(--text-dim);line-height:1.7;margin-bottom:22px}
.hint{font-size:11px;color:var(--text-dim);background:rgba(255,255,255,0.62);
  border:1.5px solid rgba(255,109,168,0.2);border-radius:14px;padding:14px 16px;
  margin-top:16px;line-height:1.7;text-align:left;}
.hint b{color:var(--pink-2);font-weight:800}
.close-btn{position:absolute;top:14px;right:14px;width:36px;height:36px;
  border-radius:50%;background:rgba(230,57,128,0.12);
  border:1.5px solid rgba(230,57,128,0.35);
  color:var(--rose);font-size:17px;font-weight:900;cursor:pointer;
  display:flex;align-items:center;justify-content:center;font-family:inherit;
  transition:all 0.25s;z-index:2;}
.close-btn:hover{background:rgba(230,57,128,0.25);transform:rotate(90deg)}
.back-btn{position:absolute;top:14px;left:14px;padding:7px 14px;
  border-radius:20px;background:rgba(255,109,168,0.15);
  border:1.5px solid rgba(255,109,168,0.3);
  color:var(--pink-2);font-size:11px;font-weight:800;cursor:pointer;
  font-family:inherit;letter-spacing:0.5px;transition:all 0.25s;z-index:2;}
.back-btn:hover{background:rgba(255,109,168,0.25);transform:translateY(-1px)}
.header{display:flex;align-items:center;gap:12px;padding:14px 16px;margin:12px 12px 0}
.hlogo{width:46px;height:46px;border-radius:50%;object-fit:cover;
  border:2px solid #fff;background:#fff;flex-shrink:0;
  box-shadow:0 0 0 3px rgba(255,109,168,0.3),0 4px 16px rgba(255,77,148,0.4);}
.hbrand{flex:1;min-width:0}
.hbrand h1{font-size:14px;font-weight:900;letter-spacing:2.5px;
  background:linear-gradient(90deg,#ff4d94,#ffb84d);
  -webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;}
.hbrand small{display:block;font-size:10px;color:var(--pink-2);letter-spacing:1px;margin-top:2px;
  font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.hact{display:flex;gap:8px;align-items:center}
.pulse-dot{width:8px;height:8px;border-radius:50%;background:var(--mint);
  box-shadow:0 0 10px var(--mint);animation:pulseDot 1.5s ease-in-out infinite}
.pulse-dot.off{background:var(--muted);box-shadow:0 0 10px var(--muted);animation:none}
@keyframes pulseDot{0%,100%{opacity:1;transform:scale(1)}50%{opacity:0.5;transform:scale(0.7)}}
.act{width:38px;height:38px;border-radius:50%;border:1.5px solid rgba(255,109,168,0.35);
  background:rgba(255,255,255,0.7);color:var(--text-dim);font-size:16px;cursor:pointer;
  display:flex;align-items:center;justify-content:center;font-family:inherit;
  transition:all 0.25s;backdrop-filter:blur(10px);}
.act.kill{color:var(--rose);border-color:rgba(230,57,128,0.4);background:rgba(230,57,128,0.12)}
.act.kill:hover{background:rgba(230,57,128,0.25);transform:scale(1.1)}
.act.logout{color:#b87500;border-color:rgba(255,184,77,0.4);background:rgba(255,184,77,0.15)}
.act.logout:hover{background:rgba(255,184,77,0.3);transform:scale(1.1)}
.scroll{flex:1;overflow-y:auto;padding:14px 12px 100px;position:relative;z-index:1}
.bal-card{padding:22px 22px;margin-bottom:14px;position:relative;overflow:visible}
.bal-lbl{font-size:10px;letter-spacing:2.5px;color:var(--text-dim);font-weight:900;
  text-transform:uppercase;margin-bottom:10px;display:flex;align-items:center;gap:6px}
.bal-lbl::before{content:'💎';font-size:14px}
.bal-val{font-size:36px;font-weight:900;color:var(--rose-deep);
  font-family:"SF Mono","Consolas",monospace;line-height:1;
  text-shadow:0 2px 16px rgba(255,77,148,0.4),0 0 32px rgba(255,109,168,0.3);
  transition:all 0.4s;display:inline-block;}
.bal-val.upd{color:var(--mint);transform:scale(1.06);text-shadow:0 2px 16px rgba(78,204,163,0.5)}
.bal-suf{font-size:20px;color:var(--text-dim);margin-left:8px;font-weight:700}
.res-card{padding:30px 22px;margin-bottom:14px;text-align:center;
  min-height:290px;display:flex;flex-direction:column;
  align-items:center;justify-content:center;position:relative;}
.res-sess{font-size:11px;letter-spacing:2.5px;color:var(--text-dim);font-weight:900;
  text-transform:uppercase;margin-bottom:16px}
.res-lbl{font-size:12px;color:var(--text-dim);letter-spacing:3px;font-weight:800;
  text-transform:uppercase;margin-bottom:14px}
.res-val{font-size:64px;font-weight:900;letter-spacing:5px;margin-bottom:10px;position:relative;
  transition:all 0.4s;}
.res-val.tai{background:linear-gradient(135deg,#5ec8ff,#3aa3ff,#5ec8ff);
  background-size:200% 100%;
  -webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;
  animation:shimmerText 2.5s linear infinite;
  filter:drop-shadow(0 4px 20px rgba(94,200,255,0.7)) drop-shadow(0 0 40px rgba(94,200,255,0.5));}
.res-val.xiu{background:linear-gradient(135deg,#ff4d94,#e63980,#ff4d94);
  background-size:200% 100%;
  -webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;
  animation:shimmerText 2.5s linear infinite;
  filter:drop-shadow(0 4px 20px rgba(255,77,148,0.7)) drop-shadow(0 0 40px rgba(255,77,148,0.5));}
.res-val.wait{color:var(--muted);font-size:40px;letter-spacing:4px}
.res-val.pop{animation:resPop 0.6s cubic-bezier(0.34,1.56,0.64,1)}
@keyframes resPop{0%{transform:scale(0.7);opacity:0.3}60%{transform:scale(1.08)}100%{transform:scale(1);opacity:1}}
.conf-badge{margin-top:6px;display:inline-flex;align-items:center;gap:6px;
  padding:6px 14px;border-radius:20px;
  background:linear-gradient(135deg,rgba(126,232,199,0.2),rgba(94,200,255,0.2));
  border:1.5px solid rgba(126,232,199,0.5);
  font-size:11px;font-weight:800;color:#0d7a5c;letter-spacing:1px;
  animation:fadeIn 0.5s;}
.rev-badge{position:absolute;top:14px;left:14px;
  padding:6px 12px;background:linear-gradient(135deg,rgba(167,139,250,0.2),rgba(167,139,250,0.3));
  border:1.5px solid rgba(167,139,250,0.6);
  color:#6d4fd6;border-radius:24px;font-size:10px;font-weight:900;letter-spacing:1px;
  display:flex;align-items:center;gap:4px;}
.cheat-badge{position:absolute;top:14px;right:14px;
  padding:6px 12px;background:linear-gradient(135deg,rgba(94,200,255,0.2),rgba(94,200,255,0.3));
  border:1.5px solid rgba(94,200,255,0.6);
  color:#0b6fa0;border-radius:24px;font-size:10px;font-weight:900;letter-spacing:1px;
  animation:pulseStuck 2s infinite;}
@keyframes pulseStuck{0%,100%{box-shadow:0 0 0 rgba(94,200,255,0.4)}50%{box-shadow:0 0 20px rgba(94,200,255,0.8)}}
.out{margin-top:20px;padding-top:20px;border-top:1.5px dashed rgba(255,109,168,0.3);
  width:100%;display:none}
.out.show{display:block;animation:fadeIn 0.5s}
.out .big{font-size:28px;font-weight:900;letter-spacing:2px;margin-bottom:8px}
.out .big.win{color:var(--mint);text-shadow:0 2px 20px rgba(78,204,163,0.5)}
.out .big.lose{color:var(--rose);text-shadow:0 2px 20px rgba(230,57,128,0.5)}
.out .big.jp{background:linear-gradient(90deg,#ff4d94,#ffb84d,#ff4d94);
  background-size:200% 100%;
  -webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;
  animation:shimmerText 2s linear infinite;
  filter:drop-shadow(0 4px 20px rgba(255,184,77,0.8));}
.out .det{font-size:13px;color:var(--text-dim);font-family:monospace;line-height:1.8;font-weight:600}
.out .det b{color:var(--rose);font-weight:900}
.bet-card{padding:18px 22px;margin-bottom:14px;
  display:flex;align-items:center;justify-content:space-between;gap:14px;
  background:linear-gradient(135deg,rgba(255,109,168,0.15),rgba(255,255,255,0.72));}
.bet-lbl{font-size:10px;letter-spacing:2px;color:var(--text-dim);font-weight:900;
  text-transform:uppercase;margin-bottom:6px;display:flex;align-items:center;gap:6px}
.bet-lbl::before{content:'🎰';font-size:12px}
.bet-val{font-size:24px;font-weight:900;color:var(--rose-deep);font-family:monospace;
  text-shadow:0 2px 12px rgba(255,77,148,0.4);transition:all 0.3s}
.bet-val.pulse{animation:bpulse 0.6s}
@keyframes bpulse{50%{transform:scale(1.12);color:var(--pink-2)}}
.bet-str{text-align:right}
.bet-str small{font-size:9px;color:var(--text-dim);letter-spacing:1.5px;font-weight:900;
  text-transform:uppercase;display:block}
.bet-str b{font-size:16px;font-weight:900;color:var(--pink-2);font-family:monospace;
  display:block;margin-top:2px;text-shadow:0 2px 8px rgba(255,77,148,0.3)}
.prog{padding:16px 22px;margin-bottom:14px}
.prog-lbl{display:flex;justify-content:space-between;font-size:11px;font-weight:900;
  margin-bottom:10px;color:var(--text-dim);letter-spacing:0.5px}
.prog-lbl b{color:var(--rose);font-family:monospace}
.prog-bar{height:12px;background:rgba(255,109,168,0.15);border-radius:6px;
  overflow:hidden;border:1.5px solid rgba(255,109,168,0.25);}
.prog-fill{height:100%;background:linear-gradient(90deg,#ff4d94,#ff8fc3,#ffb84d,#ffd966);
  background-size:200% 100%;border-radius:6px;transition:width 0.6s;
  box-shadow:0 0 16px rgba(255,77,148,0.7);animation:shimmerBg 2s linear infinite;}
@keyframes shimmerBg{to{background-position:200% 0}}
.nav{position:absolute;bottom:0;left:0;right:0;padding:12px 20px 16px;
  display:flex;justify-content:center;gap:10px;
  background:linear-gradient(180deg,rgba(255,228,240,0.4),rgba(255,208,230,0.98) 40%);
  backdrop-filter:blur(20px);
  border-top:1.5px solid rgba(255,109,168,0.2);z-index:10;}
.nav-btn{flex:1;max-width:180px;padding:13px 18px;background:rgba(255,255,255,0.7);
  border:1.5px solid rgba(255,109,168,0.25);color:var(--text-dim);
  font-size:12px;font-weight:900;letter-spacing:1px;border-radius:16px;
  cursor:pointer;font-family:inherit;text-transform:uppercase;
  transition:all 0.25s;backdrop-filter:blur(10px);}
.nav-btn.on{background:linear-gradient(135deg,#ff4d94,#ff6ba8);color:#fff;
  border-color:transparent;box-shadow:0 6px 24px rgba(255,77,148,0.5);}
.nav-btn:not(.on):hover{background:rgba(255,255,255,0.9);color:var(--pink-2)}
.h-head{display:flex;align-items:center;justify-content:space-between;padding:16px 20px;margin:12px 12px 0}
.h-title{font-size:15px;font-weight:900;color:var(--pink-2);letter-spacing:2px;text-transform:uppercase}
.h-count{font-size:11px;color:var(--text-dim);font-weight:800;padding:5px 12px;
  background:rgba(255,109,168,0.15);border-radius:20px;border:1.5px solid rgba(255,109,168,0.3)}
.h-scroll{flex:1;overflow-y:auto;padding:14px 12px 100px}
.h-row{padding:15px 18px;margin-bottom:10px;background:rgba(255,255,255,0.75);
  backdrop-filter:blur(10px);border:1.5px solid rgba(255,109,168,0.2);
  border-radius:16px;display:flex;align-items:center;gap:12px;
  border-left:4px solid var(--muted);transition:all 0.2s;}
.h-row:hover{transform:translateX(4px)}
.h-row.win{border-left-color:var(--mint);
  background:linear-gradient(90deg,rgba(78,204,163,0.1),rgba(255,255,255,0.85))}
.h-row.lose{border-left-color:var(--rose);
  background:linear-gradient(90deg,rgba(230,57,128,0.08),rgba(255,255,255,0.85))}
.h-row.jp{border-left-color:var(--gold);
  background:linear-gradient(90deg,rgba(255,184,77,0.15),rgba(255,255,255,0.9));
  box-shadow:0 4px 20px rgba(255,184,77,0.2)}
.h-sid{font-family:monospace;color:var(--pink-2);font-weight:900;font-size:12px;min-width:64px}
.h-mid{flex:1;min-width:0}
.h-mid .r1{font-size:13px;font-weight:900;margin-bottom:4px;white-space:nowrap;
  overflow:hidden;text-overflow:ellipsis;color:var(--text)}
.h-mid .r2{font-size:11px;color:var(--text-dim);font-family:monospace;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-weight:600}
.h-amt{font-family:monospace;font-weight:900;font-size:14px;min-width:80px;text-align:right}
.h-amt.win{color:var(--mint)}
.h-amt.lose{color:var(--rose)}
.empty{padding:60px 20px;text-align:center;color:var(--text-dim);font-size:13px}
.empty .icon{font-size:56px;margin-bottom:18px;opacity:0.6;display:block}
.empty .title{font-size:16px;font-weight:900;color:var(--text);margin-bottom:8px}
.empty .sub{font-size:12px;color:var(--muted)}
#toast{position:fixed;top:20px;right:20px;z-index:9999;display:flex;flex-direction:column;gap:10px;
  pointer-events:none;max-width:340px;}
.toast{padding:14px 20px;border-radius:16px;font-size:13px;font-weight:800;
  color:var(--text);background:rgba(255,255,255,0.98);
  border:1.5px solid var(--glass-border);
  box-shadow:0 12px 40px rgba(255,77,148,0.3);
  backdrop-filter:blur(20px);position:relative;overflow:hidden;
  animation:toastIn 0.4s cubic-bezier(0.34,1.56,0.64,1);}
.toast::after{content:'';position:absolute;bottom:0;left:0;height:3px;width:100%;
  background:linear-gradient(90deg,var(--pink-2),var(--gold));
  transform-origin:left;animation:toastBar 3s linear forwards;}
@keyframes toastBar{from{transform:scaleX(1)}to{transform:scaleX(0)}}
.toast.success{border-color:rgba(78,204,163,0.6);
  background:linear-gradient(135deg,rgba(78,204,163,0.15),#fff)}
.toast.error{border-color:rgba(230,57,128,0.6);
  background:linear-gradient(135deg,rgba(230,57,128,0.15),#fff)}
.toast.gold{border-color:rgba(255,184,77,0.6);
  background:linear-gradient(135deg,rgba(255,184,77,0.15),#fff)}
.toast.stuck{border-color:rgba(94,200,255,0.6);
  background:linear-gradient(135deg,rgba(94,200,255,0.15),#fff)}
@keyframes toastIn{from{opacity:0;transform:translateX(100px)}to{opacity:1;transform:translateX(0)}}
.sparkle{position:fixed;width:8px;height:8px;border-radius:50%;pointer-events:none;z-index:9998;
  animation:sparkleAnim 1s ease-out forwards;
  box-shadow:0 0 12px currentColor,0 0 24px currentColor;}
@keyframes sparkleAnim{0%{transform:translate(0,0) scale(1);opacity:1}
  100%{transform:translate(var(--dx),var(--dy)) scale(0);opacity:0}}
@media (max-width:360px){
  .card{padding:28px 20px}
  .logo{width:94px;height:94px}
  .brand{font-size:24px;letter-spacing:4px}
  .res-val{font-size:54px}
  .bal-val{font-size:30px}
}
@media (prefers-reduced-motion:reduce){
  .petal,.logo,.brand,.res-val,.orb,.bg-layer,.aurora,.prog-fill{animation:none!important}
}
</style>
</head>
<body>
<div class="bg-layer"></div>
<div class="aurora"></div>
<div class="orb orb-1"></div>
<div class="orb orb-2"></div>
<div class="orb orb-3"></div>
<div class="orb orb-4"></div>
<canvas id="particles"></canvas>
<div id="app"></div>
<div id="toast"></div>
<script>
const LOGO_URL = 'https://raw.githubusercontent.com/nguyenha783255-wq/LOGO-LC79/main/IMG_20260901_094944_094.jpg';
const LS_KEY = 'sakura_pro_v2';
const app = document.getElementById('app');
const toastBox = document.getElementById('toast');

const S = {
  step: 'login', tab: 'main', user: '', nickname: '', balance: 0, authToken: '', device: '',
  loading: false, error: '',
  config: {base_bet:0,profit_stop:0,auto:false,paused:false,lose_streak:0,bet_streak:0},
  history: [], stats: {wins:0,losses:0,total:0,winrate:0,profit:0},
  pendingPred: null, pendingSession: null, pendingBetAmount: null, pendingConf: null,
  workerAlive: false, lastWsError: null, reverseMode: false,
  setupBaseBet: 0, setupTarget: 0, lastBalance: 0,
};

(function() {
  const d = [navigator.userAgent, navigator.language, screen.width+'x'+screen.height].join('|');
  let h = 0; for (let i = 0; i < d.length; i++) h = ((h << 5) - h) + d.charCodeAt(i), h |= 0;
  S.device = 'ONI-' + Math.abs(h).toString(16).toUpperCase().slice(0, 8);
})();

(function initPetals() {
  const count = window.innerWidth < 600 ? 12 : 18;
  for (let i = 0; i < count; i++) {
    const p = document.createElement('div');
    p.className = 'petal';
    p.style.left = Math.random() * 100 + '%';
    const dur = 9 + Math.random() * 10;
    p.style.animationDuration = dur + 's';
    p.style.animationDelay = (Math.random() * dur) + 's';
    const sz = 10 + Math.random() * 10;
    p.style.width = sz + 'px'; p.style.height = sz + 'px';
    document.body.appendChild(p);
  }
})();

(function initParticles() {
  const canvas = document.getElementById('particles');
  const ctx = canvas.getContext('2d');
  let particles = [];
  const colors = ['#ff6ba8', '#ff8fc3', '#ffb84d', '#a78bfa', '#5ec8ff', '#4ecca3', '#7ee8c7'];
  function resize() {
    canvas.width = window.innerWidth; canvas.height = window.innerHeight;
    particles = [];
    const count = window.innerWidth < 600 ? 34 : 60;
    for (let i = 0; i < count; i++) {
      particles.push({
        x: Math.random() * canvas.width, y: Math.random() * canvas.height,
        vx: (Math.random() - 0.5) * 0.4, vy: (Math.random() - 0.5) * 0.4,
        r: Math.random() * 3 + 1, color: colors[Math.floor(Math.random() * colors.length)],
        alpha: Math.random() * 0.5 + 0.3,
      });
    }
  }
  function animate() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    for (const p of particles) {
      p.x += p.vx; p.y += p.vy;
      if (p.x < 0 || p.x > canvas.width) p.vx *= -1;
      if (p.y < 0 || p.y > canvas.height) p.vy *= -1;
      ctx.globalAlpha = p.alpha; ctx.fillStyle = p.color;
      ctx.shadowColor = p.color; ctx.shadowBlur = 10;
      ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2); ctx.fill();
    }
    ctx.shadowBlur = 0; ctx.globalAlpha = 1;
    requestAnimationFrame(animate);
  }
  resize(); window.addEventListener('resize', resize, {passive: true}); animate();
})();

const fmt = n => (n || 0).toLocaleString('vi-VN');
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

function toast(msg, type) {
  const el = document.createElement('div');
  el.className = 'toast ' + (type || 'info');
  el.textContent = msg;
  toastBox.appendChild(el);
  setTimeout(() => { el.style.opacity = '0'; el.style.transform = 'translateX(100px)'; el.style.transition = 'all 0.3s'; }, 2800);
  setTimeout(() => el.remove(), 3200);
}

function sparkleAround(el) {
  if (!el) return;
  const rect = el.getBoundingClientRect();
  const cx = rect.left + rect.width / 2, cy = rect.top + rect.height / 2;
  const colors = ['#ff4d94', '#ff8fc3', '#ffb84d', '#5ec8ff', '#4ecca3', '#a78bfa'];
  for (let i = 0; i < 16; i++) {
    const s = document.createElement('div');
    s.className = 'sparkle';
    s.style.left = cx + 'px'; s.style.top = cy + 'px';
    s.style.background = colors[i % colors.length];
    s.style.color = colors[i % colors.length];
    const angle = (Math.PI * 2 * i) / 16;
    const dist = 70 + Math.random() * 70;
    s.style.setProperty('--dx', Math.cos(angle) * dist + 'px');
    s.style.setProperty('--dy', Math.sin(angle) * dist + 'px');
    document.body.appendChild(s);
    setTimeout(() => s.remove(), 1000);
  }
}

function animateBalance(el, from, to, dur = 700) {
  if (!el) return;
  const start = performance.now();
  function tick(now) {
    const t = Math.min(1, (now - start) / dur);
    const eased = 1 - Math.pow(1 - t, 3);
    const val = Math.round(from + (to - from) * eased);
    el.textContent = fmt(val);
    if (t < 1) requestAnimationFrame(tick);
    else el.textContent = fmt(to);
  }
  requestAnimationFrame(tick);
}

function saveAuth(u, t, n) { try { localStorage.setItem(LS_KEY, JSON.stringify({u,t,n,ts:Date.now()})); } catch(e) {} }
function loadAuth() { try { const j = localStorage.getItem(LS_KEY); return j ? JSON.parse(j) : null; } catch(e) { return null; } }
function clearAuth() { try { localStorage.removeItem(LS_KEY); } catch(e) {} }

function render() {
  if (S.step === 'login') renderLogin();
  else if (S.step === 'info') renderInfo();
  else if (S.step === 'base_bet') renderBaseBet();
  else if (S.step === 'target') renderTarget();
  else if (S.step === 'main') { if (S.tab === 'history') renderHistory(); else renderMain(); }
}

function renderLogin() {
  app.innerHTML =
    '<div class="screen"><div class="wrap"><div class="card glass neon">' +
    '<img src="' + LOGO_URL + '" class="logo" onerror="this.style.display=\'none\'">' +
    '<div class="brand">SAKURA</div>' +
    '<div class="brand-sub">🌸 AI · <b>MD5</b> · PREMIUM</div>' +
    '<div class="field"><label>👤 TÀI KHOẢN</label><input id="in_u" type="text" placeholder="Nhập tài khoản..." value="' + esc(S.user) + '"></div>' +
    '<div class="field"><label>🔒 MẬT KHẨU</label><input id="in_p" type="password" placeholder="••••••••"></div>' +
    '<button class="btn" id="btn_login"' + (S.loading?' disabled':'') + '>' + (S.loading?'ĐANG XÁC THỰC':'ĐĂNG NHẬP') + '</button>' +
    (S.error ? '<div class="msg err">⚠️ ' + esc(S.error) + '</div>' : '') +
    '<div class="foot"><b>SAKURA PRO</b> · Admin <b>@SAKURA</b></div>' +
    '</div></div></div>';
  document.getElementById('btn_login').onclick = doLogin;
  document.getElementById('in_p').onkeydown = e => { if (e.key === 'Enter') doLogin(); };
  document.getElementById('in_p').focus();
}

async function doLogin() {
  const u = document.getElementById('in_u').value.trim();
  const p = document.getElementById('in_p').value.trim();
  if (!u || !p) { S.error = 'Nhập đủ TK/MK'; render(); return; }
  S.loading = true; S.error = ''; render();
  try {
    const r = await api('verify', {user:u, pass:p, device:S.device});
    if (!r.ok) { S.loading = false; S.error = r.msg || 'Login fail'; render(); return; }
    Object.assign(S, {user:r.user, nickname:r.nickname, balance:r.balance, lastBalance:r.balance,
      config:r.config, history:r.history||[], authToken:r.auth_token,
      workerAlive:!!r.worker_alive, loading:false});
    saveAuth(r.user, r.auth_token, r.nickname);
    S.step = (S.config.onboarded && S.config.base_bet > 0) ? 'main' : 'info';
    S.tab = 'main'; render(); startTick();
    toast('🌸 Chào Ông Chủ ' + r.nickname, 'gold');
  } catch (e) { S.loading = false; S.error = 'Lỗi: ' + e.message; render(); }
}

async function tryResume() {
  const saved = loadAuth();
  if (!saved || !saved.u || !saved.t) { render(); return; }
  try {
    const r = await api('resume', {user:saved.u, auth_token:saved.t});
    if (!r.ok) { clearAuth(); render(); return; }
    Object.assign(S, {user:r.user, nickname:r.nickname, balance:r.balance, lastBalance:r.balance,
      config:r.config, history:r.history||[], authToken:r.auth_token,
      workerAlive:!!r.worker_alive, pendingPred:r.pending_pred, pendingSession:r.pending_session,
      pendingBetAmount:r.pending_bet_amount, pendingConf:r.pending_conf,
      reverseMode:!!r.reverse_mode, lastWsError:r.last_ws_error});
    S.step = (S.config.onboarded && S.config.base_bet > 0) ? 'main' : 'info';
    S.tab = 'main'; saveAuth(r.user, r.auth_token, r.nickname); render(); startTick();
  } catch (e) { clearAuth(); render(); }
}

function renderInfo() {
  const init = (S.nickname || '?')[0].toUpperCase();
  app.innerHTML =
    '<div class="screen"><div class="wrap"><div class="card glass neon">' +
    '<button class="close-btn" id="btn_close">✕</button>' +
    '<div class="avatar">' + esc(init) + '</div>' +
    '<div class="greet">ようこそ、お兄ちゃん</div>' +
    '<div class="name">' + esc(S.nickname) + '</div>' +
    '<div class="tag">ACCOUNT VERIFIED</div>' +
    '<div class="stat"><span class="lbl">💰 SỐ DƯ</span><span class="val">' + fmt(S.balance) + 'đ</span></div>' +
    '<div class="stat"><span class="lbl">🔑 TÀI KHOẢN</span><span class="val">' + esc(S.user) + '</span></div>' +
    '<div class="stat"><span class="lbl">📱 DEVICE</span><span class="val" style="font-size:11px;color:var(--pink-2)">' + esc(S.device) + '</span></div>' +
    '</div></div></div>';
  document.getElementById('btn_close').onclick = () => { S.step = 'base_bet'; render(); };
}

function renderBaseBet() {
  const bal = S.balance || 0;
  let sug = 10000;
  if (bal > 0) sug = Math.max(1000, Math.min(Math.floor(bal * 0.02 / 1000) * 1000, 100000));
  const val = S.setupBaseBet || sug;
  app.innerHTML =
    '<div class="screen"><div class="wrap"><div class="card glass neon">' +
    '<button class="back-btn" id="btn_back1">← Quay lại</button>' +
    '<div class="step">BƯỚC 1 / 2</div>' +
    '<div class="title">Vốn Cược Mỗi Tay</div>' +
    '<div class="sub">Số dư: <b style="color:var(--rose)">' + fmt(bal) + 'đ</b></div>' +
    '<div class="field"><label>💰 SỐ VỐN (VNĐ)</label><input id="in_base" type="number" inputmode="numeric" value="' + val + '" min="1000" step="1000"></div>' +
    '<button class="btn" id="btn_next1">TIẾP TỤC →</button>' +
    (S.error ? '<div class="msg err">⚠️ ' + esc(S.error) + '</div>' : '') +
    '<div class="hint">💎 Gấp thếp: <b>base × 2^streak</b> · reset khi thắng</div>' +
    '</div></div></div>';
  const inp = document.getElementById('in_base');
  inp.focus(); inp.select();
  document.getElementById('btn_back1').onclick = () => { S.step = 'info'; render(); };
  document.getElementById('btn_next1').onclick = () => {
    const v = parseInt(inp.value) || 0;
    if (v < 1000) { S.error = 'Vốn tối thiểu 1.000đ'; render(); return; }
    S.error = ''; S.setupBaseBet = v; S.step = 'target'; render();
  };
  inp.onkeydown = e => { if (e.key === 'Enter') document.getElementById('btn_next1').click(); };
}

function renderTarget() {
  const bal = S.balance || 0;
  let sug = 100000;
  if (bal > 0) sug = Math.max(10000, Math.floor(bal * 0.1 / 1000) * 1000 || 100000);
  const val = S.setupTarget || sug;
  app.innerHTML =
    '<div class="screen"><div class="wrap"><div class="card glass neon">' +
    '<button class="back-btn" id="btn_back2">← Quay lại</button>' +
    '<div class="step">BƯỚC 2 / 2</div>' +
    '<div class="title">Mục Tiêu Lợi Nhuận</div>' +
    '<div class="sub">Khi đạt mục tiêu, bot tự dừng.</div>' +
    '<div class="field"><label>🎯 MỤC TIÊU (VNĐ)</label><input id="in_target" type="number" inputmode="numeric" value="' + val + '" min="10000" step="10000"></div>' +
    '<button class="btn" id="btn_start"' + (S.loading?' disabled':'') + '>' + (S.loading?'ĐANG KHỞI ĐỘNG':'🌸 BẮT ĐẦU AUTO') + '</button>' +
    (S.error ? '<div class="msg err">⚠️ ' + esc(S.error) + '</div>' : '') +
    '<div class="hint"><b>🌸 AI ĐA TẦNG</b><br>' +
    '• Phân tích cầu, xu hướng và nhịp điệu nhiều lớp<br>' +
    '• Tự phát hiện bất thường & điều chỉnh chiến lược<br>' +
    '• Tự học từ lịch sử để tăng độ chính xác<br>' +
    '• Gấp thếp: <b>base × 2^streak</b>, reset khi thắng<br>' +
    '• Đạt mục tiêu lợi nhuận → tự dừng an toàn</div>' +
    '</div></div></div>';
  const inp = document.getElementById('in_target');
  inp.focus(); inp.select();
  document.getElementById('btn_back2').onclick = () => { S.step = 'base_bet'; render(); };
  document.getElementById('btn_start').onclick = async () => {
    const v = parseInt(inp.value) || 0;
    if (v < 10000) { S.error = 'Mục tiêu tối thiểu 10.000đ'; render(); return; }
    S.error = ''; S.setupTarget = v; await startAuto();
  };
  inp.onkeydown = e => { if (e.key === 'Enter') document.getElementById('btn_start').click(); };
}

async function startAuto() {
  S.loading = true; render();
  try {
    const r = await api('setup', {user:S.user, base_bet:S.setupBaseBet, profit_stop:S.setupTarget});
    if (!r.ok) { S.loading = false; S.error = r.msg || 'Không bắt đầu được'; render(); return; }
    S.config = r.config; S.loading = false;
    S.step = 'main'; S.tab = 'main'; render(); startTick();
    toast('🌸 AUTO đã bật', 'success');
  } catch (e) { S.loading = false; S.error = 'Lỗi: ' + e.message; render(); }
}

function renderMain() {
  const p = S.pendingPred;
  let predCls = 'wait';
  if (p === 'Tài') predCls = 'tai';
  else if (p === 'Xỉu') predCls = 'xiu';
  const predTxt = p || 'ĐANG CHỜ';
  const lastH = S.history[0] || null;
  let betTxt = '—';
  if (S.pendingBetAmount) betTxt = fmt(S.pendingBetAmount) + 'đ';

  const bs = S.config.bet_streak || 0;
  const mult = Math.pow(2, Math.min(bs, 62));
  const modeText = 'x' + (mult >= 1e9 ? mult.toExponential(1) : mult);

  const confBadge = (S.pendingConf && p)
    ? '<div class="conf-badge">🎯 ĐỘ TIN CẬY ' + S.pendingConf + '%</div>' : '';

  const revBadge = S.reverseMode
    ? '<div class="rev-badge">🔄 AI</div>' : '';

  const cheatBadge = lastH && lastH.conf && lastH.conf >= 85 && lastH.win
    ? '<div class="cheat-badge">⚡</div>' : '';

  const profit = S.stats.profit || 0;
  const target = S.config.profit_stop || 0;
  let progressPct = 0;
  if (target > 0) progressPct = Math.min(100, Math.max(0, (profit/target)*100));
  let progressCard = '';
  if (target > 0) {
    progressCard = '<div class="prog glass">' +
      '<div class="prog-lbl"><span>🎯 MỤC TIÊU</span><b>' + fmt(profit) + ' / ' + fmt(target) + ' đ</b></div>' +
      '<div class="prog-bar"><div class="prog-fill" style="width:' + progressPct + '%"></div></div></div>';
  }

  let wsWarn = '';
  if (S.lastWsError) {
    wsWarn = '<div class="msg err" style="margin-top:8px;font-size:11px">⚠️ ' + esc(S.lastWsError) + '</div>';
  }

  const aliveDot = S.workerAlive
    ? '<div class="pulse-dot" title="Worker đang chạy"></div>'
    : '<div class="pulse-dot off" title="Worker tắt"></div>';

  app.innerHTML =
    '<div class="screen">' +
    '<div class="header glass">' +
    '<img src="' + LOGO_URL + '" class="hlogo" onerror="this.style.display=\'none\'">' +
    '<div class="hbrand"><h1>SAKURA</h1><small>🌸 ' + esc(S.nickname) + '</small></div>' +
    '<div class="hact">' + aliveDot +
    '<button class="act kill" id="btn_kill" title="Dừng">⏹</button>' +
    '<button class="act logout" id="btn_logout" title="Đăng xuất">⏏</button>' +
    '</div></div>' +
    '<div class="scroll">' +
    '<div class="bal-card glass"><div class="bal-lbl">SỐ DƯ HIỆN TẠI</div>' +
    '<span class="bal-val" id="bal_val">' + fmt(S.balance) + '</span><span class="bal-suf">đ</span></div>' +
    '<div class="res-card glass">' +
    revBadge + cheatBadge +
    '<div class="res-sess">PHIÊN #' + (S.pendingSession || '—') + '</div>' +
    '<div class="res-lbl">' + (p ? 'DỰ ĐOÁN' : 'ĐANG CHỜ') + '</div>' +
    '<div class="res-val ' + predCls + '" id="pred_val">' + predTxt + '</div>' +
    confBadge +
    '<div class="out ' + (lastH?'show':'') + '" id="outcome_box">' + (lastH ? renderOutcome(lastH) : '') + '</div>' +
    '</div>' +
    '<div class="bet-card glass">' +
    '<div><div class="bet-lbl">SỐ TIỀN CƯỢC</div><div class="bet-val" id="bet_val">' + betTxt + '</div></div>' +
    '<div class="bet-str"><small>GẤP THẾP</small><b id="mode_val">' + modeText + '</b></div>' +
    '</div>' + progressCard + wsWarn +
    '</div>' +
    '<div class="nav">' +
    '<button class="nav-btn on" id="nav_main">🌸 Chính</button>' +
    '<button class="nav-btn" id="nav_hist">📜 Lịch sử</button>' +
    '</div></div>';

  document.getElementById('nav_main').onclick = () => { S.tab = 'main'; render(); };
  document.getElementById('nav_hist').onclick = () => { S.tab = 'history'; render(); };
  document.getElementById('btn_kill').onclick = doKill;
  document.getElementById('btn_logout').onclick = doLogout;

  if (p && S.lastPredSeen !== p) {
    S.lastPredSeen = p;
    setTimeout(() => sparkleAround(document.getElementById('pred_val')), 100);
  }
  if (S.lastBalance !== S.balance) {
    const from = S.lastBalance, to = S.balance;
    S.lastBalance = to;
    setTimeout(() => animateBalance(document.getElementById('bal_val'), from, to), 50);
  }
}

function renderOutcome(h) {
  if (!h) return '';
  let cls = 'lose', label = '💔 THUA';
  if (h.win) { cls = 'win'; label = '🎉 THẮNG'; }
  if (h.jackpot) { cls = 'jp'; label = '🎰 NỔ HŨ!'; }
  const dice = (h.dices||[]).join('-');
  let delta = '-' + fmt(h.amount);
  if (h.win) delta = '+' + fmt(Math.floor(h.amount*0.98));
  const predTxt = h.pred === 'Tài' ? 'TÀI' : 'XỈU';
  const resTxt = h.result === 'TAI' ? 'TÀI' : 'XỈU';
  const confTxt = h.conf ? ' · ' + h.conf + '%' : '';
  return '<div class="big ' + cls + '">' + label + '</div>' +
    '<div class="det">🎲 ' + dice + ' · ' + predTxt + ' → ' + resTxt + confTxt + '<br><b>' + delta + 'đ</b></div>';
}

async function doKill() {
  if (!confirm('🛑 TẮT AUTO?')) return;
  try {
    await api('kill', {user:S.user});
    S.config.auto = false; S.config.paused = true;
    S.pendingPred = null; S.pendingSession = null; S.pendingBetAmount = null; S.pendingConf = null;
    toast('🛑 ĐÃ DỪNG', 'error'); render();
  } catch (e) { toast('Lỗi: ' + e.message, 'error'); }
}

async function doLogout() {
  if (!confirm('🚪 ĐĂNG XUẤT?')) return;
  try {
    await api('logout', {user:S.user});
    clearAuth();
    Object.assign(S, {step:'login', user:'', nickname:'', balance:0, authToken:'', history:[],
      stats:{}, pendingPred:null, pendingSession:null, config:{}});
    render(); toast('Đã đăng xuất', 'gold');
  } catch (e) { toast('Lỗi: ' + e.message, 'error'); }
}

function renderHistory() {
  const hist = S.history || [];
  let body;
  if (hist.length === 0) {
    body = '<div class="empty"><span class="icon">🌸</span><div class="title">Chưa có lịch sử</div><div class="sub">Bật AUTO để ghi nhận</div></div>';
  } else {
    body = hist.slice(0,100).map(h => {
      let cls = 'lose', delta = '-' + fmt(h.amount);
      if (h.win) { cls = 'win'; delta = '+' + fmt(Math.floor(h.amount*0.98)); }
      const jp = h.jackpot ? 'jp' : '';
      const dice = (h.dices||[]).join('-');
      const predTxt = h.pred === 'Tài' ? '🔵 TÀI' : '🔴 XỈU';
      const resTxt = h.result === 'TAI' ? '🔵 TÀI' : '🔴 XỈU';
      const jpIcon = h.jackpot ? ' 🎰' : '';
      const confTxt = h.conf ? ' · ' + h.conf + '%' : '';
      return '<div class="h-row ' + cls + ' ' + jp + '">' +
        '<div class="h-sid">#' + h.session + '</div>' +
        '<div class="h-mid"><div class="r1">' + predTxt + ' → ' + resTxt + jpIcon + '</div>' +
        '<div class="r2">🎲 ' + dice + ' · ' + h.ts + confTxt + '</div></div>' +
        '<div class="h-amt ' + cls + '">' + delta + '</div>' +
        '</div>';
    }).join('');
  }

  app.innerHTML =
    '<div class="screen">' +
    '<div class="h-head glass">' +
    '<div class="h-title">📜 Lịch sử</div>' +
    '<div class="h-count">' + hist.length + '</div>' +
    '</div>' +
    '<div class="h-scroll">' + body + '</div>' +
    '<div class="nav">' +
    '<button class="nav-btn" id="nav_main">🌸 Chính</button>' +
    '<button class="nav-btn on" id="nav_hist">📜 Lịch sử</button>' +
    '</div></div>';

  document.getElementById('nav_main').onclick = () => { S.tab = 'main'; render(); };
  document.getElementById('nav_hist').onclick = () => { S.tab = 'history'; render(); };
}

// API helper
async function api(action, data) {
  const url = '?action=' + action;
  const body = new URLSearchParams();
  if (data) for (const k in data) if (data[k] !== undefined && data[k] !== null) body.append(k, data[k]);
  if (S.authToken) body.append('auth_token', S.authToken);
  const r = await fetch(url, {method:'POST', body, headers:{'Content-Type':'application/x-www-form-urlencoded'}});
  return r.json();
}

// Tick loop — refresh status periodically
let tickTimer = null;
function startTick() {
  if (tickTimer) clearInterval(tickTimer);
  let tickCounter = 0;
  tickTimer = setInterval(async () => {
    if (S.step !== 'main') return;
    tickCounter++;
    try {
      // Full refresh every 4s
      if (tickCounter % 4 === 0) {
        const r = await fetch('?action=status&user=' + encodeURIComponent(S.user) + '&auth_token=' + encodeURIComponent(S.authToken), {cache:'no-store'});
        const j = await r.json();
        if (j.ok) {
          S.balance = j.balance ?? S.balance;
          S.config = j.config || S.config;
          S.history = j.history || S.history;
          S.stats = j.stats || S.stats;
          S.pendingPred = j.pending_pred ?? null;
          S.pendingSession = j.pending_session ?? null;
          S.pendingBetAmount = j.pending_bet_amount ?? null;
          S.pendingConf = j.pending_conf ?? null;
          S.workerAlive = !!j.worker_alive;
          S.reverseMode = !!j.reverse_mode;
          S.lastWsError = j.last_ws_error;
          if (S.step === 'main') render();
        }
      } else {
        const r = await fetch('?action=tick', {method:'POST', body:new URLSearchParams({user:S.user, auth_token:S.authToken})});
        const j = await r.json();
        if (j.ok) {
          S.workerAlive = !!j.worker_alive;
          S.pendingPred = j.pending_pred ?? null;
          S.pendingSession = j.pending_session ?? null;
          S.pendingConf = j.pending_conf ?? null;
          S.reverseMode = !!j.reverse_mode;
          S.lastWsError = j.last_ws_error;
        }
      }
    } catch (e) {}
  }, 1000);
}

// boot
tryResume();
</script>
</body>
</html>
<?php }