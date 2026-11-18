<?php
/**
 * DENIUS AUTO v9.3-MD5 — STUCK PREDICTION + GẤP THẾP CHUẨN
 * 
 * FIX:
 *  1. stuck_pred: Thua ≥3 tay → lưu prediction tay thua thứ 3, các tay sau theo đúng prediction đó
 *     → thắng mới clear stuck + quay lại tính công thức
 *  2. Gấp thếp: bet = base × 2^bet_streak, KHÔNG cap (chỉ cap kỹ thuật 62 + balance)
 *  3. Balance: KHÔNG update từ postBalance (chỉ log), chỉ tự tính settle
 *     (tránh conflict khiến balance sai)
 */

$CFG = [
    'game' => [
        'login_url'    => 'https://apifo88daigia.tele68.com/api?c=3&un={USER}&pw={PASS_MD5}&cp=R&cl=R&pf=web&at=',
        'lobby_url'    => 'https://wlb.tele68.com/v1/lobby/auth/login?cp=R&cl=R&pf=web&at=',
        'ws_host'      => 'wtxmd52.tele68.com',
        'ws_path'      => '/txmd5/',
        'sessions_api' => 'https://wtxmd52.tele68.com/v1/txmd5/sessions',
        'b_offset'     => 22,
    ],
    'security' => [
        'hmac_secret' => 'DENIUS_v93_STUCK_HMAC',
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
        'stuck_pred'  => null,   // 'Tài'|'Xỉu'|null
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

// ═══════ JACKPOT ═══════
function denius_detect_jackpot(array $found, array $dices): bool {
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

// ═══════ FORMULA DENIUS ═══════
function denius_map_result(string $raw): ?string {
    $map = ['Tài'=>'TAI','Xỉu'=>'XIU','tai'=>'TAI','xiu'=>'XIU','TAI'=>'TAI','XIU'=>'XIU','TÀI'=>'TAI','XỈU'=>'XIU'];
    return $map[$raw] ?? null;
}
function denius_count_streak(array $sessions): array {
    if (empty($sessions)) return ['side'=>null, 'len'=>0];
    $first = denius_map_result((string)($sessions[0]['resultTruyenThong'] ?? ''));
    if ($first === null) return ['side'=>null, 'len'=>0];
    $len = 1;
    for ($i = 1; $i < count($sessions); $i++) {
        $r = denius_map_result((string)($sessions[$i]['resultTruyenThong'] ?? ''));
        if ($r === $first) $len++; else break;
    }
    return ['side'=>$first, 'len'=>$len];
}
function denius_find_session(array $sessions, int $targetId): ?array {
    foreach ($sessions as $row) if ((int)$row['id'] === $targetId) return $row;
    return null;
}
function denius_compute(array $sessions, int $latestId): array {
    global $CFG;
    $bOffset = (int)($CFG['game']['b_offset'] ?? 22);
    $out = [
        'ok'=>false, 'skip'=>true, 'prediction'=>null,
        'A'=>0, 'B'=>0, 'K'=>0, 'final'=>0,
        'streak'=>0, 'streakSide'=>null, 'prevResult'=>null,
        'bExact'=>false, 'bWanted'=>$latestId - $bOffset, 'bActual'=>0,
        'reason'=>'Không đủ dữ liệu',
    ];
    $prev = denius_find_session($sessions, $latestId);
    if (!$prev) { $out['reason'] = 'Không tìm phiên #'.$latestId; return $out; }
    $prevSide = denius_map_result((string)($prev['resultTruyenThong'] ?? ''));
    if ($prevSide === null) { $out['reason'] = 'Phiên #'.$latestId.' chưa có KQ'; return $out; }

    $dices = $prev['dices'] ?? [0,0,0];
    $dice1 = (int)($dices[0] ?? 0);
    $A = $dice1 + ($latestId % 10);

    $bRow = denius_find_session($sessions, $latestId - $bOffset);
    if ($bRow) {
        $out['bExact'] = true;
        $out['bActual'] = $latestId - $bOffset;
    } else {
        $minId = PHP_INT_MAX; $furthest = null;
        foreach ($sessions as $row) {
            $id = (int)$row['id'];
            if ($id < $latestId && $id < $minId) { $minId = $id; $furthest = $row; }
        }
        if (!$furthest) { $out['A'] = $A; $out['prevResult'] = $prevSide;
            $out['reason'] = 'Không có phiên B'; return $out; }
        $bRow = $furthest;
        $out['bActual'] = $minId;
    }
    $bD = $bRow['dices'] ?? [0,0,0];
    $B = 0; foreach ($bD as $v) $B += (int)$v;

    $K = 0; $final = 0;
    if ($B > $A) { $K = $B - $A; $final = $K - 2; }
    elseif ($A > $B) { $K = $A - $B; $final = $K; }

    $streakInfo = denius_count_streak($sessions);

    $pred = null; $skip = false; $reason = '';
    if ($final === 4) { $skip = true; $reason = 'BỎ TAY (final=4)'; }
    elseif ($final === 5) { $pred = $prevSide; $reason = 'Theo prev (final=5)'; }
    elseif ($final < 0) { $pred = (abs($final) % 2 === 0) ? 'XIU' : 'TAI'; $reason = 'final âm ('.$final.')'; }
    elseif ($final >= 10) { $pred = ($final % 2 === 0) ? 'XIU' : 'TAI'; $reason = 'final≥10 ('.$final.')'; }
    else { $pred = ($prevSide === 'TAI') ? 'XIU' : 'TAI'; $reason = 'Bẻ prev (final='.$final.')'; }

    if (!$skip && $streakInfo['len'] >= 2 && $streakInfo['side'] !== null && $pred !== null) {
        if ($pred !== $streakInfo['side']) {
            $pred = ($K % 2 === 0) ? 'TAI' : 'XIU';
            $reason .= ' | BẺ BỆT: K='.$K.' → '.$pred;
        } else {
            $reason .= ' | Đang bệt '.$streakInfo['side'].' → giữ';
        }
    }

    $out['ok'] = ($pred !== null);
    $out['skip'] = $skip;
    $out['prediction'] = $pred;
    $out['A'] = $A; $out['B'] = $B; $out['K'] = $K; $out['final'] = $final;
    $out['streak'] = $streakInfo['len'];
    $out['streakSide'] = $streakInfo['side'];
    $out['prevResult'] = $prevSide;
    $out['reason'] = $reason;
    return $out;
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
        key_log($key, 'error', '[V93-WS] ❌ Connect fail: ' . $ws->error);
        return ['ok'=>false, 'reason'=>'Connect: '.$ws->error];
    }
    key_log($key, 'info', '[V93-WS] ✅ Connected MD5');

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
                    key_log($key, 'success', '[V93-WS] 💰 Bet SENT MD5: #'.$ps.' '.$side.' '.number_format($amount));
                    $actions[] = ['type'=>'bet', 'msg'=>"Bet MD5 #$ps $side $amount"];
                    key_update($key, function($dd) use ($ps, $amount) {
                        $dd['bet_session'] = $ps;
                        $dd['bet_amount'] = $amount;
                        return $dd;
                    });
                    // Chờ ack — chỉ LOG postBalance, KHÔNG update balance
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
                                key_log($key, 'success', '[V93-WS] ✅ Bet ACK');
                                if (isset($m2[1]['postBalance'])) {
                                    // CHỈ log, KHÔNG update balance (tránh conflict)
                                    key_update($key, function($dd) use ($m2) {
                                        $dd['last_post_balance'] = $m2[1]['postBalance'];
                                        return $dd;
                                    });
                                    key_log($key, 'info', '[V93-WS] 📊 postBalance server = '.number_format($m2[1]['postBalance']));
                                }
                            }
                        }
                    }
                    $ws->close();
                    return ['ok'=>true, 'reason'=>'Bet sent + ack MD5'];
                }
            }
            if ($ev === 'session-result') { $ws->close(); return ['ok'=>false, 'reason'=>'Session settled before bet']; }
        }
    }
    $ws->close();
    $reason = 'Timeout 8s — stage='.$stage;
    if ($joined && !$sawBetting) $reason .= ' (không bắt được BETTING)';
    key_log($key, 'error', '[V93-WS] ❌ ' . $reason);
    return ['ok'=>false, 'reason'=>$reason];
}

// ═══════ WORKER v9.3 ═══════
function worker_step(string $key): array {
    $actions = [];
    $s = key_load($key);
    if (!$s) return $actions;
    $cfg = $s['config'] ?? [];
    if (empty($cfg['auto']) || !empty($cfg['paused'])) return $actions;

    // Check profit target
    $pTarget = (int)($cfg['profit_stop'] ?? 0);
    if ($pTarget > 0 && (int)($s['profit_total'] ?? 0) >= $pTarget && empty($s['pending_pred'])) {
        key_update($key, function($d) { $d['config']['auto'] = false; $d['config']['paused'] = true; return $d; });
        key_log($key, 'success', '🎉 ĐẠT MỤC TIÊU');
        return $actions;
    }

    $data = fetch_sessions_api();
    if (!$data || empty($data['list'])) {
        if (($s['last_api_fail_log'] ?? 0) < time() - 60) {
            key_log($key, 'warn', '[V93] ⚠️ sessions API fail MD5');
            key_update($key, fn($d) => array_merge($d, ['last_api_fail_log' => time()]));
        }
        return $actions;
    }
    $sessions = $data['list'];

    $latestId = 0;
    foreach ($sessions as $row) {
        if (denius_map_result((string)($row['resultTruyenThong'] ?? '')) !== null) {
            $latestId = (int)$row['id']; break;
        }
    }
    if ($latestId === 0) { key_log($key, 'warn', '[V93] Không có phiên có KQ MD5'); return $actions; }

    $lastId = (int)($s['last_session_id'] ?? 0);

    // Baseline
    if ($lastId === 0) {
        key_update($key, fn($d) => array_merge($d, ['last_session_id'=>$latestId]));
        key_log($key, 'info', '[V93] 📡 Baseline MD5 #'.$latestId);
        return $actions;
    }

    // Process settled sessions
    if ($latestId > $lastId) {
        for ($sid = $lastId + 1; $sid <= $latestId; $sid++) {
            $found = denius_find_session($sessions, $sid);
            if (!$found) continue;
            $result = denius_map_result((string)($found['resultTruyenThong'] ?? ''));
            if ($result === null) continue;
            $dices = $found['dices'] ?? [0,0,0];
            $tong = 0; foreach ($dices as $v) $tong += (int)$v;
            $jackpot = denius_detect_jackpot($found, $dices);

            if ((int)($s['pending_session'] ?? 0) === $sid && !empty($s['pending_pred'])) {
                $pred = $s['pending_pred'];
                $betPlaced = ((int)($s['bet_session'] ?? 0) === $sid);

                if (!$betPlaced) {
                    key_log($key, 'error', '[V93] ⚠️ Phiên MD5 #'.$sid.' KHÔNG đặt được cược — clear pending');
                    key_update($key, function($d) {
                        $d['pending_pred']=null; $d['pending_session']=null;
                        $d['pending_bet_amount']=null; $d['bet_session']=null; $d['bet_amount']=0;
                        return $d;
                    });
                    $s = key_load($key);
                    continue;
                }

                $win = (($pred==='Tài'||$pred==='T') && $result==='TAI') || (($pred==='Xỉu'||$pred==='X') && $result==='XIU');

                // ═══ SETTLE: STUCK LOGIC + BALANCE TỰ TÍNH ═══
                key_update($key, function($d) use ($sid, $pred, $result, $dices, $win, $jackpot, $tong) {
                    $c = $d['config'];
                    $st = (int)($c['lose_streak'] ?? 0);
                    $bSt = (int)($c['bet_streak'] ?? 0);
                    $wasStuck = $c['stuck_pred'] ?? null;

                    if ($win) {
                        // THẮNG → reset hết, clear stuck
                        $st = 0;
                        $bSt = 0;
                        $c['stuck_pred'] = null;
                        $d['win_count_total'] = (int)($d['win_count_total'] ?? 0) + 1;
                        if ($wasStuck !== null) {
                            // Log riêng: thắng sau khi thoát stuck
                        }
                    } else {
                        // THUA
                        $d['loss_count_total'] = (int)($d['loss_count_total'] ?? 0) + 1;
                        $st++;
                        $bSt++;
                        // Nếu bet_streak >= 3 và chưa stuck → set stuck = prediction vừa thua (tay thứ 3)
                        if ($bSt >= 3 && empty($c['stuck_pred'])) {
                            $c['stuck_pred'] = $pred;
                        }
                    }
                    $c['lose_streak'] = $st;
                    $c['bet_streak'] = $bSt;

                    // Balance tự tính — không dùng postBalance
                    $betAmt = (int)($d['bet_amount'] ?? 0);
                    $bal = (int)($d['balance'] ?? 0);
                    $delta = $win ? intval($betAmt * 0.98) : -$betAmt;
                    $bal += $delta;
                    if ($bal < 0) $bal = 0;
                    $d['balance'] = $bal;
                    $d['profit_total'] = (int)($d['profit_total'] ?? 0) + $delta;

                    // History
                    $d['history'] = $d['history'] ?? [];
                    array_unshift($d['history'], [
                        'ts'=>date('H:i:s d/m'),'session'=>$sid,'pred'=>$pred,'result'=>$result,
                        'dices'=>$dices,'tong'=>$tong,'win'=>$win,'amount'=>$betAmt,
                        'balance_after'=>$bal,'streak'=>$st,'bet_streak'=>$bSt,
                        'stuck'=>$c['stuck_pred'] ?? null,
                        'jackpot'=>$jackpot,
                    ]);
                    $d['history'] = array_slice($d['history'], 0, 500);

                    // Clear pending
                    $d['pending_pred']=null; $d['pending_session']=null;
                    $d['pending_bet_amount']=null; $d['bet_session']=null; $d['bet_amount']=0;

                    // Pattern 10
                    $sym = ($result==='TAI')?'T':'X';
                    $p10 = ($d['pattern_10'] ?? '') . $sym;
                    if (strlen($p10)>10) $p10 = substr($p10,-10);
                    $d['pattern_10'] = $p10;

                    $d['config'] = $c;
                    $pS = (int)($c['profit_stop'] ?? 0);
                    if ($pS > 0 && (int)$d['profit_total'] >= $pS) { $c['auto']=false; $c['paused']=true; $d['config']=$c; }
                    return $d;
                });
                $icon = $win ? '✅' : '❌';
                $log = "$icon MD5 #$sid: $pred → $result (".implode('-',$dices).")".($jackpot?' 🎰':'');
                key_log($key, $win?'success':'error', $log);
                $actions[] = ['type'=>'result', 'msg'=>$log];
                $s = key_load($key);
            }
        }
        key_update($key, fn($d) => array_merge($d, ['last_session_id'=>$latestId]));
        $s = key_load($key);
    }

    // Clear stale pending
    if (!empty($s['pending_session']) && (int)$s['pending_session'] <= $latestId) {
        key_update($key, function($d) {
            $d['pending_pred']=null; $d['pending_session']=null;
            $d['pending_bet_amount']=null; $d['bet_session']=null; $d['bet_amount']=0;
            return $d;
        });
        $s = key_load($key);
    }

    // Compute prediction + bet
    $cfg = $s['config'];
    if (!empty($cfg['auto']) && empty($cfg['paused']) && empty($s['pending_pred'])) {
        $stuckPred = $cfg['stuck_pred'] ?? null;
        $lastComputeId = (int)($s['last_compute_id'] ?? 0);
        $shouldLog = ($lastComputeId !== $latestId);
        $isStuckMode = false;
        $predStr = null;
        $reason = '';
        $computeInfo = null;

        if (!empty($stuckPred) && ($stuckPred === 'Tài' || $stuckPred === 'Xỉu')) {
            // ═══ STUCK MODE: theo prediction của phiên thua tay 3 ═══
            $predStr = $stuckPred;
            $reason = 'STUCK → theo dự đoán phiên vừa rồi: ' . $stuckPred;
            $isStuckMode = true;
        } else {
            // ═══ NORMAL MODE: tính công thức ═══
            $result = denius_compute($sessions, $latestId);
            $computeInfo = $result;

            if ($result['skip']) {
                if ($shouldLog) {
                    key_log($key, 'info', '[V93] ⏭ BỎ TAY MD5 #'.($latestId+1)
                        .' | A='.$result['A'].' B='.$result['B'].' K='.$result['K'].' final='.$result['final']
                        .' | '.$result['reason']);
                    key_update($key, fn($d) => array_merge($d, ['last_compute_id'=>$latestId]));
                }
                return $actions;
            }
            if ($result['prediction'] === null) {
                if ($shouldLog) {
                    key_log($key, 'warn', '[V93] ⚠️ Không predict MD5 #'.($latestId+1).' | '.$result['reason']);
                    key_update($key, fn($d) => array_merge($d, ['last_compute_id'=>$latestId]));
                }
                return $actions;
            }
            $predStr = ($result['prediction']==='TAI') ? 'Tài' : 'Xỉu';
            $reason = $result['reason'];
        }

        // ═══ GẤP THẾP CHUẨN: base × 2^bet_streak ═══
        $betStreak = (int)($cfg['bet_streak'] ?? 0);
        $baseBet = max(1000, (int)($cfg['base_bet'] ?? 10000));
        $bal = (int)($s['balance'] ?? 0);
        $mult = (int)pow(2, min($betStreak, 62));
        $betAmt = $baseBet * $mult;
        if ($bal > 0 && $betAmt > $bal) $betAmt = $bal;
        if ($betAmt < 1000) $betAmt = 1000;

        if ($bal < 1000) {
            key_update($key, function($d) { $d['config']['auto']=false; $d['config']['paused']=true; return $d; });
            key_log($key, 'error', '[V93] 🛑 Balance < 1000đ — dừng auto');
            return $actions;
        }

        key_update($key, function($d) use ($predStr, $latestId, $betAmt) {
            $d['pending_pred'] = $predStr;
            $d['pending_session'] = $latestId + 1;
            $d['pending_bet_amount'] = $betAmt;
            $d['last_compute_id'] = $latestId;
            return $d;
        });

        if ($shouldLog) {
            $tag = $isStuckMode ? '🔄 STUCK' : '🎯';
            $log = '[V93] '.$tag.' MD5 #'.($latestId+1).': '.$predStr.' '.number_format($betAmt).'đ'
                .' (bet_streak='.$betStreak.' × '.$mult.')';
            if ($isStuckMode) {
                $log .= ' | ' . $reason;
            } else {
                $log .= ' | A='.$computeInfo['A'].' B='.$computeInfo['B']
                      . ' K='.$computeInfo['K'].' final='.$computeInfo['final']
                      . ' | '.$computeInfo['reason'];
                if (!$computeInfo['bExact']) $log .= ' | ⚠️ B fallback #'.$computeInfo['bActual'];
            }
            key_log($key, 'info', $log);
            $actions[] = ['type'=>'predict', 'msg'=>$log];
        }
        $s = key_load($key);
    }

    // WS bet
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
    if (!worker_lock($key)) { error_log("[V93] Lock exists for $key"); return; }
    $sleep = (int)($CFG['worker']['loop_sleep'] ?? 1);
    $deadline = time() + $max; $lastBeat = 0;
    $buf = (int)($CFG['worker']['respawn_buffer'] ?? 60);
    worker_heartbeat($key, 'running');
    key_log($key, 'info', '[V93] 🚀 Worker MD5 started PID='.getmypid());
    while (time() < $deadline) {
        $s = key_load($key);
        if (!$s) break;
        try { worker_step($key); }
        catch (Throwable $e) { key_log($key, 'error', '[V93] 💥 '.$e->getMessage()); }
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
    key_log($key, $spawned ? 'info' : 'error', '[V93] Spawn MD5: '.($spawned ? $method : 'FAILED'));
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
            $s['config'] = array_merge($CFG['default_config'], $s['config']??[]);
            foreach (['win_count_total','loss_count_total','profit_total','last_session_id'] as $k) if (!isset($s[$k])) $s[$k]=0;
            foreach (['pending_pred','pending_session','pending_bet_amount','bet_session'] as $k) if (!array_key_exists($k, $s)) $s[$k]=null;
            if (!isset($s['bet_amount'])) $s['bet_amount']=0;
            if (!isset($s['pattern_10'])) $s['pattern_10']='';
            if (!array_key_exists('stuck_pred', $s['config'])) $s['config']['stuck_pred']=null;
            key_save($key, $s); key_save_by_user($u, $key);
            key_log($key, 'info', '🔐 Login MD5 v9.3 — '.$dev);
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
                'pending_bet_amount'=>$s['pending_bet_amount']??null,
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
            $c['bet_streak'] = 0; $c['lose_streak'] = 0; $c['stuck_pred'] = null;
            $s['config'] = $c;
            $s['pending_pred']=null; $s['pending_session']=null; $s['pending_bet_amount']=null;
            $s['bet_session']=null; $s['bet_amount']=0; $s['last_compute_id']=0;
            $s['last_ws_error']=null; $s['last_session_id'] = 0;
            key_save($key, $s);
            $lp = KEY_DIR.'/'.hash('sha256',strtolower($key)).'.lock';
            if (is_file($lp)) {
                $pid = (int)trim(@file_get_contents($lp));
                if ($pid > 0 && function_exists('posix_kill')) { @posix_kill($pid, SIGTERM); usleep(200000); }
                @unlink($lp);
            }
            spawn_worker_async($key);
            key_log($key, 'success', '[V93] ▶ SETUP MD5: auto=true, base='.number_format($c['base_bet']).' target='.number_format($c['profit_stop']));
            echo json_encode(['ok'=>true,'config'=>$c,'worker_alive'=>worker_alive($key)]);
            exit;

        case 'kill':
            $u = trim($_POST['user'] ?? ''); $tk = trim($_POST['auth_token'] ?? '');
            if (!require_auth($u, $tk)) { echo json_encode(['ok'=>false,'msg'=>'Unauthorized']); exit; }
            $key = key_resolve($u);
            key_update($key, function($d) {
                $d['config']['auto']=false; $d['config']['paused']=true;
                $d['config']['lose_streak']=0; $d['config']['bet_streak']=0; $d['config']['stuck_pred']=null;
                $d['pending_pred']=null; $d['pending_session']=null; $d['pending_bet_amount']=null;
                $d['bet_session']=null; $d['bet_amount']=0;
                return $d;
            });
            $lp = KEY_DIR.'/'.hash('sha256',strtolower($key)).'.lock';
            if (is_file($lp)) {
                $pid = (int)trim(@file_get_contents($lp));
                if ($pid > 0 && function_exists('posix_kill')) @posix_kill($pid, SIGTERM);
                @unlink($lp);
            }
            key_log($key, 'warn', '[V93] 🛑 KILL MD5');
            echo json_encode(['ok'=>true]);
            exit;

        case 'reset_stuck':
            // Reset stuck thủ công (giữ nguyên bet_streak, chỉ clear stuck)
            $u = trim($_POST['user'] ?? ''); $tk = trim($_POST['auth_token'] ?? '');
            if (!require_auth($u, $tk)) { echo json_encode(['ok'=>false,'msg'=>'Unauthorized']); exit; }
            $key = key_resolve($u);
            key_update($key, function($d) { $d['config']['stuck_pred'] = null; return $d; });
            key_log($key, 'info', '[V93] Reset stuck → quay lại tính CT');
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
                'pending_bet_amount'=>$s['pending_bet_amount']??null,
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
            $compute = null;
            if ($data && !empty($data['list'])) {
                $sessions = $data['list'];
                $sessInfo['count'] = count($sessions);
                $latestId = 0;
                foreach ($sessions as $row) {
                    if (denius_map_result((string)($row['resultTruyenThong'] ?? '')) !== null) {
                        $latestId = (int)$row['id']; break;
                    }
                }
                $sessInfo['latestId'] = $latestId;
                $sessInfo['sessions'] = array_slice(array_map(function($r) {
                    return ['id'=>(int)$r['id'], 'result'=>$r['resultTruyenThong']??'', 'dices'=>$r['dices']??[]];
                }, $sessions), 0, 30);
                if ($latestId > 0) $compute = denius_compute($sessions, $latestId);
            }
            // Next bet simulation
            $cfg = $s['config'] ?? [];
            $betStreak = (int)($cfg['bet_streak'] ?? 0);
            $baseBet = (int)($cfg['base_bet'] ?? 0);
            $bal = (int)($s['balance'] ?? 0);
            $mult = (int)pow(2, min($betStreak, 62));
            $nextBetAmt = $baseBet * $mult;
            if ($bal > 0 && $nextBetAmt > $bal) $nextBetAmt = $bal;
            echo json_encode([
                'ok'=>true, 'table'=>'MD5', 'version'=>'v9.3',
                'ws_host'=>$CFG['game']['ws_host'],
                'config'=>$cfg,
                'state'=>[
                    'balance'=>$bal,
                    'bet_streak'=>$betStreak,
                    'lose_streak'=>(int)($cfg['lose_streak'] ?? 0),
                    'stuck_pred'=>$cfg['stuck_pred'] ?? null,
                    'last_session_id'=>$s['last_session_id']??0,
                    'last_compute_id'=>$s['last_compute_id']??0,
                    'pending_pred'=>$s['pending_pred']??null,
                    'pending_session'=>$s['pending_session']??null,
                    'pending_bet_amount'=>$s['pending_bet_amount']??null,
                    'bet_session'=>$s['bet_session']??null,
                    'last_ws_error'=>$s['last_ws_error']??null,
                    'last_post_balance'=>$s['last_post_balance']??null,
                    'worker'=>['alive'=>worker_alive($key), 'info'=>$s['worker']??null],
                ],
                'next_bet_simulation'=>[
                    'base_bet'=>$baseBet,
                    'bet_streak'=>$betStreak,
                    'multiplier'=>$mult,
                    'bet_amount'=>$nextBetAmt,
                    'balance_cap'=>$bal,
                ],
                'sessions_api_result'=>$sessInfo,
                'compute_next'=>$compute,
                'b_offset'=>$CFG['game']['b_offset'],
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
<meta name="theme-color" content="#05020f">
<title>DENIUS v9.3 · MD5</title>
<style>
:root{--bg:#05020f;--sakura:#ffb7d5;--gold:#ffd966;--mint:#7ef0b4;--ruby:#ff5c7a;--cyan:#6ee7ff;--text:#fff5eb;--dim:#a89cbd;--muted:#5e4d75;--bd:rgba(255,183,213,0.15)}
*{margin:0;padding:0;box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html{height:100dvh;overflow:hidden;font-size:16px}
body{height:100dvh;overflow:hidden;position:fixed;inset:0;background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,system-ui,sans-serif;user-select:none;touch-action:manipulation;overscroll-behavior:none}
#app{position:absolute;inset:0;display:flex;flex-direction:column;overflow:hidden}
.screen{flex:1;display:flex;flex-direction:column;overflow:hidden;min-height:0}
.glass{background:linear-gradient(135deg,rgba(28,15,56,0.75),rgba(10,6,24,0.9));backdrop-filter:blur(30px);-webkit-backdrop-filter:blur(30px);border:1px solid var(--bd);border-radius:20px}
.wrap{flex:1;display:flex;align-items:center;justify-content:center;padding:20px;overflow-y:auto}
.card{width:100%;max-width:400px;padding:32px 24px;position:relative;animation:pop 0.6s cubic-bezier(0.34,1.56,0.64,1)}
@keyframes pop{from{opacity:0;transform:scale(0.9) translateY(30px)}to{opacity:1;transform:scale(1) translateY(0)}}
.logo{width:100px;height:100px;border-radius:50%;border:2px solid var(--sakura);background:#120828;box-shadow:0 0 40px rgba(255,183,213,0.5);animation:float 3s ease-in-out infinite;margin-bottom:14px;object-fit:cover;display:block;margin-left:auto;margin-right:auto}
@keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-8px)}}
.brand{font-size:24px;font-weight:900;letter-spacing:5px;text-align:center;background:linear-gradient(90deg,#ffd6e8,#ffe89a,#6ee7ff,#ffd6e8);background-size:300% 100%;-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:4px;animation:shim 4s linear infinite}
@keyframes shim{to{background-position:300% 0}}
.brand-sub{text-align:center;font-size:11px;letter-spacing:2px;color:var(--dim);font-weight:600;margin-bottom:22px}
.brand-sub b{color:var(--cyan)}
.field{margin-bottom:14px}
.field label{display:block;font-size:10px;font-weight:800;color:var(--dim);text-transform:uppercase;letter-spacing:1.5px;margin-bottom:6px}
.field input{width:100%;padding:14px 16px;background:rgba(5,2,15,0.8);border:1px solid var(--bd);border-radius:14px;color:var(--text);font-size:16px;outline:none;font-family:inherit;transition:all 0.25s}
.field input:focus{border-color:var(--sakura);box-shadow:0 0 0 3px rgba(255,183,213,0.15)}
.btn{width:100%;padding:15px;border:none;border-radius:14px;font-size:13px;font-weight:900;letter-spacing:2px;text-transform:uppercase;cursor:pointer;transition:all 0.3s;font-family:inherit;margin-top:8px;position:relative;overflow:hidden;background:linear-gradient(135deg,#ffd6e8,#ffb7d5);color:#1a0d33;box-shadow:0 8px 28px -8px rgba(255,183,213,0.5)}
.btn:hover:not(:disabled){transform:translateY(-2px);box-shadow:0 12px 36px -8px rgba(255,183,213,0.7)}
.btn:disabled{opacity:0.5;cursor:not-allowed}
.msg{margin-top:12px;padding:12px 16px;border-radius:12px;font-size:12px}
.msg.err{background:rgba(255,92,122,0.1);border:1px solid rgba(255,92,122,0.3);color:#ffa0b3}
.msg.warn{background:rgba(255,217,102,0.1);border:1px solid rgba(255,217,102,0.3);color:var(--gold)}
.msg.stuck{background:rgba(110,231,255,0.1);border:1px solid rgba(110,231,255,0.3);color:var(--cyan)}
.foot{margin-top:20px;text-align:center;font-size:10px;color:var(--muted);line-height:1.8}
.foot b{color:var(--sakura)}
.close-btn{position:absolute;top:12px;right:12px;width:34px;height:34px;border-radius:50%;background:rgba(255,92,122,0.15);border:1px solid rgba(255,92,122,0.4);color:var(--ruby);font-size:16px;font-weight:900;cursor:pointer;display:flex;align-items:center;justify-content:center;font-family:inherit}
.back-btn{position:absolute;top:12px;left:12px;padding:6px 12px;border-radius:20px;background:rgba(255,183,213,0.1);border:1px solid var(--bd);color:var(--dim);font-size:10px;font-weight:800;cursor:pointer;font-family:inherit;letter-spacing:1px}
.avatar{width:80px;height:80px;border-radius:50%;margin:0 auto 14px;background:linear-gradient(135deg,#ffb7d5,#c4a7e7);display:flex;align-items:center;justify-content:center;font-size:36px;font-weight:900;color:#1a0d33;box-shadow:0 0 40px rgba(255,183,213,0.5)}
.greet{font-size:14px;color:var(--sakura);font-weight:700;text-align:center;margin-bottom:4px}
.name{font-size:22px;font-weight:900;color:var(--text);text-align:center;margin-bottom:4px}
.tag{font-size:10px;color:var(--dim);letter-spacing:2px;text-transform:uppercase;font-weight:600;text-align:center}
.stat{display:flex;justify-content:space-between;padding:14px;background:rgba(255,183,213,0.05);border:1px solid var(--bd);border-radius:14px;margin-top:10px}
.stat .lbl{font-size:11px;color:var(--dim);font-weight:700}
.stat .val{font-size:15px;font-weight:900;color:var(--gold);font-family:monospace;text-align:right;overflow-wrap:anywhere}
.step{font-size:10px;letter-spacing:2px;color:var(--sakura);font-weight:800;text-align:center;margin-bottom:8px}
.title{font-size:20px;font-weight:900;text-align:center;margin-bottom:6px}
.sub{font-size:11px;text-align:center;color:var(--dim);line-height:1.6;margin-bottom:20px}
.hint{font-size:10px;color:var(--dim);background:rgba(255,183,213,0.06);border:1px solid rgba(255,183,213,0.15);border-radius:10px;padding:12px 14px;margin-top:14px;line-height:1.6;text-align:left}
.hint b{color:var(--sakura)}
.header{display:flex;align-items:center;gap:12px;padding:12px 16px;margin:12px 12px 0}
.hlogo{width:44px;height:44px;border-radius:50%;border:1.5px solid var(--sakura);background:#120828;flex-shrink:0;object-fit:cover}
.hbrand{flex:1;min-width:0}
.hbrand h1{font-size:13px;font-weight:900;letter-spacing:2px;background:linear-gradient(90deg,#ffd6e8,#ffe89a);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
.hbrand small{display:block;font-size:9px;color:var(--cyan);letter-spacing:1px;margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-weight:700}
.hact{display:flex;gap:6px}
.act{width:36px;height:36px;border-radius:50%;border:1px solid var(--bd);background:rgba(28,15,56,0.6);color:var(--dim);font-size:15px;cursor:pointer;display:flex;align-items:center;justify-content:center;font-family:inherit;transition:all 0.2s}
.act.kill{color:var(--ruby);border-color:rgba(255,92,122,0.35);background:rgba(255,92,122,0.1)}
.act.logout{color:var(--gold);border-color:rgba(255,217,102,0.35);background:rgba(255,217,102,0.1)}
.scroll{flex:1;overflow-y:auto;padding:14px 12px 96px}
.bal-card{padding:20px;margin-bottom:14px}
.bal-lbl{font-size:9px;letter-spacing:2px;color:var(--dim);font-weight:800;text-transform:uppercase;margin-bottom:8px}
.bal-val{font-size:32px;font-weight:900;color:var(--gold);font-family:"SF Mono",Consolas,monospace;line-height:1;text-shadow:0 0 24px rgba(255,217,102,0.5);transition:all 0.3s;display:inline-block}
.bal-val.upd{color:var(--mint);transform:scale(1.05)}
.bal-suf{font-size:18px;color:var(--dim);margin-left:6px}
.res-card{padding:28px 20px;margin-bottom:14px;text-align:center;min-height:260px;display:flex;flex-direction:column;align-items:center;justify-content:center;position:relative}
.res-sess{font-size:10px;letter-spacing:2px;color:var(--dim);font-weight:800;text-transform:uppercase;margin-bottom:14px}
.res-lbl{font-size:11px;color:var(--dim);letter-spacing:3px;font-weight:700;text-transform:uppercase;margin-bottom:12px}
.res-val{font-size:60px;font-weight:900;letter-spacing:4px;margin-bottom:8px}
.res-val.tai{background:linear-gradient(135deg,#7ec8ff,#4a9eff,#7ec8ff);background-size:200% 100%;-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;animation:shim 3s linear infinite;filter:drop-shadow(0 0 30px rgba(78,158,255,0.7))}
.res-val.xiu{background:linear-gradient(135deg,#ff8fa0,#ff5c7a,#ff8fa0);background-size:200% 100%;-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;animation:shim 3s linear infinite;filter:drop-shadow(0 0 30px rgba(255,92,122,0.7))}
.res-val.wait{color:var(--muted);font-size:36px}
.stuck-badge{position:absolute;top:10px;right:10px;padding:5px 10px;background:rgba(110,231,255,0.15);border:1px solid rgba(110,231,255,0.5);color:var(--cyan);border-radius:20px;font-size:9px;font-weight:900;letter-spacing:0.5px;animation:pulseStuck 2s infinite}
@keyframes pulseStuck{0%,100%{box-shadow:0 0 0 rgba(110,231,255,0.4)}50%{box-shadow:0 0 16px rgba(110,231,255,0.7)}}
.out{margin-top:18px;padding-top:18px;border-top:1px dashed rgba(255,183,213,0.2);width:100%;display:none}
.out.show{display:block}
.out .big{font-size:26px;font-weight:900;letter-spacing:2px;margin-bottom:6px}
.out .big.win{color:var(--mint)}
.out .big.lose{color:var(--ruby)}
.out .big.jp{background:linear-gradient(90deg,#fff,#ffd966,#fff);background-size:200% 100%;-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;animation:shim 2s linear infinite}
.out .det{font-size:12px;color:var(--dim);font-family:monospace;line-height:1.7}
.out .det b{color:var(--gold)}
.bet-card{padding:16px 20px;margin-bottom:14px;display:flex;align-items:center;justify-content:space-between;gap:14px;background:linear-gradient(135deg,rgba(255,183,213,0.1),rgba(28,15,56,0.85))}
.bet-lbl{font-size:10px;letter-spacing:2px;color:var(--dim);font-weight:800;text-transform:uppercase;margin-bottom:6px}
.bet-val{font-size:22px;font-weight:900;color:var(--gold);font-family:monospace;text-shadow:0 0 20px rgba(255,217,102,0.5);transition:all 0.3s}
.bet-val.pulse{animation:bpulse 0.6s}
@keyframes bpulse{50%{transform:scale(1.15);color:var(--sakura)}}
.bet-str{text-align:right}
.bet-str small{font-size:9px;color:var(--dim);letter-spacing:1px;font-weight:700;text-transform:uppercase;display:block}
.bet-str b{font-size:15px;font-weight:900;color:var(--sakura);font-family:monospace;display:block;margin-top:2px}
.prog{padding:14px 20px;margin-bottom:14px}
.prog-lbl{display:flex;justify-content:space-between;font-size:10px;font-weight:800;margin-bottom:8px;color:var(--dim)}
.prog-lbl b{color:var(--gold);font-family:monospace}
.prog-bar{height:10px;background:rgba(255,183,213,0.1);border-radius:5px;overflow:hidden;border:1px solid rgba(255,183,213,0.15)}
.prog-fill{height:100%;background:linear-gradient(90deg,#ffb7d5,#ffd966,#7ef0b4);border-radius:5px;transition:width 0.6s;box-shadow:0 0 14px rgba(255,183,213,0.7)}
.nav{position:absolute;bottom:0;left:0;right:0;padding:10px 20px 14px;display:flex;justify-content:center;gap:8px;background:linear-gradient(180deg,rgba(5,2,15,0.3),rgba(5,2,15,0.98) 40%);backdrop-filter:blur(20px);border-top:1px solid var(--bd);z-index:10}
.nav-btn{flex:1;max-width:180px;padding:12px 16px;background:rgba(28,15,56,0.7);border:1px solid var(--bd);color:var(--dim);font-size:11px;font-weight:800;letter-spacing:1px;border-radius:14px;cursor:pointer;font-family:inherit;text-transform:uppercase;transition:all 0.2s}
.nav-btn.on{background:linear-gradient(135deg,#ffd6e8,#ffb7d5);color:#1a0d33;border-color:transparent;box-shadow:0 6px 20px -6px rgba(255,183,213,0.6)}
.h-head{display:flex;align-items:center;justify-content:space-between;padding:14px 18px;margin:12px 12px 0}
.h-title{font-size:14px;font-weight:900;color:var(--sakura);letter-spacing:2px;text-transform:uppercase}
.h-count{font-size:10px;color:var(--dim);font-weight:700;padding:4px 10px;background:rgba(255,183,213,0.1);border-radius:20px;border:1px solid var(--bd)}
.h-scroll{flex:1;overflow-y:auto;padding:14px 12px 96px}
.h-row{padding:14px 16px;margin-bottom:8px;background:linear-gradient(135deg,rgba(28,15,56,0.7),rgba(10,6,24,0.85));border:1px solid var(--bd);border-radius:14px;display:flex;align-items:center;gap:12px;border-left:3px solid var(--muted)}
.h-row.win{border-left-color:var(--mint)}
.h-row.lose{border-left-color:var(--ruby)}
.h-row.jp{border-left-color:var(--gold);background:linear-gradient(135deg,rgba(255,217,102,0.12),rgba(10,6,24,0.85))}
.h-row.stuck-lose{border-left-color:var(--cyan)}
.h-sid{font-family:monospace;color:var(--sakura);font-weight:800;font-size:11px;min-width:60px}
.h-mid{flex:1;min-width:0}
.h-mid .r1{font-size:12px;font-weight:800;margin-bottom:3px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.h-mid .r2{font-size:10px;color:var(--dim);font-family:monospace;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.h-amt{font-family:monospace;font-weight:900;font-size:13px;min-width:76px;text-align:right}
.h-amt.win{color:var(--mint)}
.h-amt.lose{color:var(--ruby)}
.empty{padding:60px 20px;text-align:center;color:var(--dim);font-size:12px}
.empty .icon{font-size:52px;margin-bottom:16px;opacity:0.4;display:block}
.empty .title{font-size:14px;font-weight:800;color:var(--text);margin-bottom:6px}
.empty .sub{font-size:11px;color:var(--muted)}
#toast{position:fixed;top:20px;right:20px;z-index:9999;display:flex;flex-direction:column;gap:8px;pointer-events:none;max-width:340px}
.toast{padding:12px 18px;border-radius:12px;font-size:12px;font-weight:600;color:#fff;background:rgba(28,15,56,0.98);border:1px solid var(--bd);box-shadow:0 12px 32px -8px rgba(0,0,0,0.6);backdrop-filter:blur(12px);animation:ti 0.35s}
.toast.success{border-color:rgba(126,240,180,0.4)}
.toast.error{border-color:rgba(255,92,122,0.4)}
.toast.gold{border-color:rgba(255,217,102,0.4)}
.toast.stuck{border-color:rgba(110,231,255,0.4)}
@keyframes ti{from{opacity:0;transform:translateX(100px)}to{opacity:1;transform:translateX(0)}}
</style>
</head>
<body>
<div id="app"></div>
<div id="toast"></div>
<script>
const LOGO_URL = 'https://raw.githubusercontent.com/nguyenha783255-wq/LOGO-LC79/main/IMG_20260901_094944_094.jpg';
const LS_KEY = 'denius_v93_md5';
const app = document.getElementById('app');
const toastBox = document.getElementById('toast');

const S = {
  step: 'login', tab: 'main', user: '', nickname: '', balance: 0, authToken: '', device: '',
  loading: false, error: '',
  config: {base_bet:0,profit_stop:0,auto:false,paused:false,lose_streak:0,bet_streak:0,stuck_pred:null},
  history: [], stats: {wins:0,losses:0,total:0,winrate:0,profit:0},
  pendingPred: null, pendingSession: null, pendingBetAmount: null,
  workerAlive: false, lastWsError: null,
  setupBaseBet: 0, setupTarget: 0, lastJackpotSession: null, lastStuckPred: null,
};

(function() {
  const d = [navigator.userAgent, navigator.language, screen.width+'x'+screen.height].join('|');
  let h = 0; for (let i = 0; i < d.length; i++) h = ((h << 5) - h) + d.charCodeAt(i), h |= 0;
  S.device = 'ONI-' + Math.abs(h).toString(16).toUpperCase().slice(0, 8);
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

function saveAuth(u, t, n) { try { localStorage.setItem(LS_KEY, JSON.stringify({u,t,n,ts:Date.now()})); } catch(e) {} }
function loadAuth() { try { const j = localStorage.getItem(LS_KEY); return j ? JSON.parse(j) : null; } catch(e) { return null; } }
function clearAuth() { try { localStorage.removeItem(LS_KEY); } catch(e) {} }

function render() {
  if (S.step === 'login') renderLogin();
  else if (S.step === 'info') renderInfo();
  else if (S.step === 'base_bet') renderBaseBet();
  else if (S.step === 'target') renderTarget();
  else if (S.step === 'main') {
    if (S.tab === 'history') renderHistory();
    else renderMain();
  }
}

function renderLogin() {
  app.innerHTML =
    '<div class="screen"><div class="wrap"><div class="card glass">' +
    '<img src="' + LOGO_URL + '" class="logo" onerror="this.style.display=\'none\'">' +
    '<div class="brand">DENIUS</div>' +
    '<div class="brand-sub">お兄ちゃん · <b>MD5</b> · v9.3</div>' +
    '<div class="field"><label>👤 TÀI KHOẢN</label><input id="in_u" type="text" placeholder="Nhập tài khoản..." value="' + esc(S.user) + '"></div>' +
    '<div class="field"><label>🔒 MẬT KHẨU</label><input id="in_p" type="password" placeholder="••••••••"></div>' +
    '<button class="btn" id="btn_login"' + (S.loading?' disabled':'') + '>' + (S.loading?'ĐANG XÁC THỰC':'ĐĂNG NHẬP') + '</button>' +
    (S.error ? '<div class="msg err">⚠️ ' + esc(S.error) + '</div>' : '') +
    '<div class="foot"><b>V9.3 · STUCK + GẤP THẾP</b> · Admin <b>@DENIUS09</b></div>' +
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
    Object.assign(S, {user:r.user, nickname:r.nickname, balance:r.balance, config:r.config,
      history:r.history||[], authToken:r.auth_token, workerAlive:!!r.worker_alive, loading:false});
    saveAuth(r.user, r.auth_token, r.nickname);
    S.step = (S.config.onboarded && S.config.base_bet > 0) ? 'main' : 'info';
    S.tab = 'main';
    render();
    startTick();
    toast('Chào Ông Chủ ' + r.nickname, 'gold');
  } catch (e) { S.loading = false; S.error = 'Lỗi: ' + e.message; render(); }
}

async function tryResume() {
  const saved = loadAuth();
  if (!saved || !saved.u || !saved.t) { render(); return; }
  try {
    const r = await api('resume', {user:saved.u, auth_token:saved.t});
    if (!r.ok) { clearAuth(); render(); return; }
    Object.assign(S, {user:r.user, nickname:r.nickname, balance:r.balance, config:r.config,
      history:r.history||[], authToken:r.auth_token, workerAlive:!!r.worker_alive,
      pendingPred:r.pending_pred, pendingSession:r.pending_session,
      pendingBetAmount:r.pending_bet_amount, lastWsError:r.last_ws_error});
    S.step = (S.config.onboarded && S.config.base_bet > 0) ? 'main' : 'info';
    S.tab = 'main';
    saveAuth(r.user, r.auth_token, r.nickname);
    render();
    startTick();
  } catch (e) { clearAuth(); render(); }
}

function renderInfo() {
  const init = (S.nickname || '?')[0].toUpperCase();
  app.innerHTML =
    '<div class="screen"><div class="wrap"><div class="card glass">' +
    '<button class="close-btn" id="btn_close">✕</button>' +
    '<div class="avatar">' + esc(init) + '</div>' +
    '<div class="greet">ようこそ、お兄ちゃん</div>' +
    '<div class="name">' + esc(S.nickname) + '</div>' +
    '<div class="tag">ACCOUNT VERIFIED · MD5</div>' +
    '<div class="stat"><span class="lbl">💰 SỐ DƯ</span><span class="val">' + fmt(S.balance) + 'đ</span></div>' +
    '<div class="stat"><span class="lbl">🔑 TÀI KHOẢN</span><span class="val">' + esc(S.user) + '</span></div>' +
    '<div class="stat"><span class="lbl">📱 DEVICE</span><span class="val" style="font-size:11px;color:var(--sakura)">' + esc(S.device) + '</span></div>' +
    '</div></div></div>';
  document.getElementById('btn_close').onclick = () => { S.step = 'base_bet'; render(); };
}

function renderBaseBet() {
  const bal = S.balance || 0;
  let sug = 10000;
  if (bal > 0) sug = Math.max(1000, Math.min(Math.floor(bal * 0.02 / 1000) * 1000, 100000));
  const val = S.setupBaseBet || sug;
  app.innerHTML =
    '<div class="screen"><div class="wrap"><div class="card glass">' +
    '<button class="back-btn" id="btn_back1">← Quay lại</button>' +
    '<div class="step">BƯỚC 1 / 2</div>' +
    '<div class="title">Vốn Cược Mỗi Tay</div>' +
    '<div class="sub">Số dư: <b style="color:var(--gold)">' + fmt(bal) + 'đ</b> · Bàn <b style="color:var(--cyan)">MD5</b></div>' +
    '<div class="field"><label>💰 SỐ VỐN (VNĐ)</label><input id="in_base" type="number" inputmode="numeric" value="' + val + '" min="1000" step="1000"></div>' +
    '<button class="btn" id="btn_next1">TIẾP TỤC →</button>' +
    (S.error ? '<div class="msg err">⚠️ ' + esc(S.error) + '</div>' : '') +
    '<div class="hint">💎 Gấp thếp X2 khi thua (base × 2^bet_streak) · reset khi thắng</div>' +
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
    '<div class="screen"><div class="wrap"><div class="card glass">' +
    '<button class="back-btn" id="btn_back2">← Quay lại</button>' +
    '<div class="step">BƯỚC 2 / 2</div>' +
    '<div class="title">Mục Tiêu Lợi Nhuận</div>' +
    '<div class="sub">Khi đạt mục tiêu, bot tự dừng.</div>' +
    '<div class="field"><label>🎯 MỤC TIÊU (VNĐ)</label><input id="in_target" type="number" inputmode="numeric" value="' + val + '" min="10000" step="10000"></div>' +
    '<button class="btn" id="btn_start"' + (S.loading?' disabled':'') + '>' + (S.loading?'ĐANG KHỞI ĐỘNG':'🚀 BẮT ĐẦU AUTO MD5') + '</button>' +
    (S.error ? '<div class="msg err">⚠️ ' + esc(S.error) + '</div>' : '') +
    '<div class="hint"><b>Công thức DENIUS (MD5):</b><br>A = dice1(prev) + lastDigit(id prev)<br>B = tổng dice phiên (prev − 22)<br>K = |A−B|, final = K−2 nếu B&gt;A<br>final=4 → BỎ TAY · final=5 → theo prev · final&lt;10 → bẻ<br>Bệt + pred bẻ → K parity<br><b>3 tay thua → STUCK theo pred tay 3 (không tính CT) đến khi thắng</b><br><b>Gấp thếp:</b> base × 2^bet_streak</div>' +
    '</div></div></div>';
  const inp = document.getElementById('in_target');
  inp.focus(); inp.select();
  document.getElementById('btn_back2').onclick = () => { S.step = 'base_bet'; render(); };
  document.getElementById('btn_start').onclick = async () => {
    const v = parseInt(inp.value) || 0;
    if (v < 10000) { S.error = 'Mục tiêu tối thiểu 10.000đ'; render(); return; }
    S.error = ''; S.setupTarget = v;
    await startAuto();
  };
  inp.onkeydown = e => { if (e.key === 'Enter') document.getElementById('btn_start').click(); };
}

async function startAuto() {
  S.loading = true; render();
  try {
    const r = await api('setup', {user:S.user, base_bet:S.setupBaseBet, profit_stop:S.setupTarget});
    if (!r.ok) { S.loading = false; S.error = r.msg || 'Không bắt đầu được'; render(); return; }
    S.config = r.config;
    S.loading = false;
    S.step = 'main'; S.tab = 'main';
    render();
    startTick();
    toast('🚀 AUTO MD5 đã bật', 'success');
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
  const modeColor = 'var(--sakura)';
  const stuckPred = S.config.stuck_pred;

  let stuckBadge = '';
  if (stuckPred === 'Tài' || stuckPred === 'Xỉu') {
    stuckBadge = '<div class="stuck-badge">🔄 STUCK → ' + esc(stuckPred.toUpperCase()) + '</div>';
  }

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
    wsWarn = '<div class="msg err" style="margin-top:8px;font-size:10px">⚠️ WS: ' + esc(S.lastWsError) + '</div>';
  }

  let stuckInfo = '';
  if (stuckPred === 'Tài' || stuckPred === 'Xỉu') {
    stuckInfo = '<div class="msg stuck" style="margin-top:8px;font-size:10px">🔄 STUCK MODE — Đang theo dự đoán tay thua thứ 3: <b>' + esc(stuckPred) + '</b> (không tính CT). Thắng → quay lại bình thường.</div>';
  }

  app.innerHTML =
    '<div class="screen">' +
    '<div class="header glass">' +
    '<img src="' + LOGO_URL + '" class="hlogo" onerror="this.style.display=\'none\'">' +
    '<div class="hbrand"><h1>DENIUS</h1><small>MD5 · ' + esc(S.nickname) + '</small></div>' +
    '<div class="hact">' +
    '<button class="act kill" id="btn_kill" title="Dừng">⏹</button>' +
    '<button class="act logout" id="btn_logout" title="Đăng xuất">⏏</button>' +
    '</div></div>' +
    '<div class="scroll">' +
    '<div class="bal-card glass"><div class="bal-lbl">💰 SỐ DƯ</div>' +
    '<span class="bal-val" id="bal_val">' + fmt(S.balance) + '</span><span class="bal-suf">đ</span></div>' +
    '<div class="res-card glass">' +
    stuckBadge +
    '<div class="res-sess">PHIÊN #' + (S.pendingSession || '—') + '</div>' +
    '<div class="res-lbl">' + (p ? 'DỰ ĐOÁN MD5' : 'ĐANG CHỜ') + '</div>' +
    '<div class="res-val ' + predCls + '" id="pred_val">' + predTxt + '</div>' +
    '<div class="out ' + (lastH?'show':'') + '" id="outcome_box">' + (lastH ? renderOutcome(lastH) : '') + '</div>' +
    '</div>' +
    '<div class="bet-card glass">' +
    '<div><div class="bet-lbl">SỐ TIỀN CƯỢC</div><div class="bet-val" id="bet_val">' + betTxt + '</div></div>' +
    '<div class="bet-str"><small>GẤP THẾP</small><b id="mode_val" style="color:' + modeColor + '">' + modeText + '</b></div>' +
    '</div>' +
    progressCard +
    stuckInfo +
    wsWarn +
    '</div>' +
    '<div class="nav">' +
    '<button class="nav-btn on" id="nav_main">🎯 Chính</button>' +
    '<button class="nav-btn" id="nav_hist">📜 Lịch sử</button>' +
    '</div></div>';

  document.getElementById('nav_main').onclick = () => { S.tab = 'main'; render(); };
  document.getElementById('nav_hist').onclick = () => { S.tab = 'history'; render(); };
  document.getElementById('btn_kill').onclick = doKill;
  document.getElementById('btn_logout').onclick = doLogout;
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
  return '<div class="big ' + cls + '">' + label + '</div>' +
    '<div class="det">🎲 ' + dice + ' · ' + predTxt + ' → ' + resTxt + '<br><b>' + delta + 'đ</b></div>';
}

async function doKill() {
  if (!confirm('🛑 TẮT AUTO MD5?')) return;
  try {
    await api('kill', {user:S.user});
    S.config.auto = false; S.config.paused = true;
    S.pendingPred = null; S.pendingSession = null; S.pendingBetAmount = null;
    toast('🛑 ĐÃ DỪNG', 'error');
    render();
  } catch (e) { toast('Lỗi: ' + e.message, 'error'); }
}

async function doLogout() {
  if (!confirm('🚪 ĐĂNG XUẤT?')) return;
  try {
    await api('logout', {user:S.user});
    clearAuth();
    Object.assign(S, {step:'login', user:'', nickname:'', balance:0, authToken:'', history:[], stats:{}, pendingPred:null, pendingSession:null, config:{}});
    render();
    toast('Đã đăng xuất', 'gold');
  } catch (e) { toast('Lỗi: ' + e.message, 'error'); }
}

function renderHistory() {
  const hist = S.history || [];
  let body;
  if (hist.length === 0) {
    body = '<div class="empty"><span class="icon">🌸</span><div class="title">Chưa có lịch sử MD5</div><div class="sub">Bật AUTO để ghi nhận</div></div>';
  } else {
    body = hist.slice(0,100).map(h => {
      let cls = 'lose', delta = '-' + fmt(h.amount);
      if (h.win) { cls = 'win'; delta = '+' + fmt(Math.floor(h.amount*0.98)); }
      if (!h.win && h.stuck) cls = 'stuck-lose';
      const jp = h.jackpot ? 'jp' : '';
      const dice = (h.dices||[]).join('-');
      const predTxt = h.pred === 'Tài' ? '🔵 TÀI' : '🔴 XỈU';
      const resTxt = h.result === 'TAI' ? '🔵 TÀI' : '🔴 XỈU';
      const jpIcon = h.jackpot ? ' 🎰' : '';
      const stuckIcon = h.stuck ? ' 🔄' : '';
      return '<div class="h-row ' + cls + ' ' + jp + '">' +
        '<div class="h-sid">#' + h.session + '</div>' +
        '<div class="h-mid"><div class="r1">' + predTxt + ' → ' + resTxt + jpIcon + stuckIcon + '</div>' +
        '<div class="r2">🎲 ' + dice + ' · ' + h.ts + '</div></div>' +
        '<div class="h-amt ' + cls + '">' + delta + '</div></div>';
    }).join('');
  }
  app.innerHTML =
    '<div class="screen">' +
    '<div class="h-head glass"><div class="h-title">📜 LỊCH SỬ MD5</div><div class="h-count">' + hist.length + ' phiên</div></div>' +
    '<div class="h-scroll" id="hist_list">' + body + '</div>' +
    '<div class="nav"><button class="nav-btn" id="nav_main2">🎯 Chính</button><button class="nav-btn on" id="nav_hist2">📜 Lịch sử</button></div>' +
    '</div>';
  document.getElementById('nav_main2').onclick = () => { S.tab = 'main'; render(); };
  document.getElementById('nav_hist2').onclick = () => { S.tab = 'history'; render(); };
}

async function api(action, data) {
  data = data || {};
  if (S.authToken && !data.auth_token) data.auth_token = S.authToken;
  const fd = new FormData();
  fd.append('action', action);
  for (const k in data) fd.append(k, data[k]);
  const r = await fetch(location.pathname + '?action=' + action, {method:'POST', body:fd});
  return r.json();
}
async function getStatus() {
  const url = location.pathname + '?action=status&user=' + encodeURIComponent(S.user) + '&auth_token=' + encodeURIComponent(S.authToken) + '&_=' + Date.now();
  const r = await fetch(url);
  return r.json();
}

let tickBusy = false, lastHistLen = 0;
async function tick() {
  if (!S.user || !S.authToken || tickBusy) return;
  tickBusy = true;
  try {
    await api('tick', {user:S.user}).catch(() => {});
    const j = await getStatus();
    if (!j.ok) { tickBusy = false; return; }
    const oldBal = S.balance;
    const oldStuck = S.config.stuck_pred;
    const oldHistLen = lastHistLen;
    S.balance = j.balance || 0;
    S.history = j.history || [];
    S.workerAlive = !!j.worker_alive;
    S.stats = j.stats || S.stats;
    S.pendingPred = j.pending_pred;
    S.pendingSession = j.pending_session;
    S.pendingBetAmount = j.pending_bet_amount;
    S.lastWsError = j.last_ws_error;
    if (j.config) {
      Object.assign(S.config, {
        auto:j.config.auto, paused:j.config.paused, lose_streak:j.config.lose_streak,
        bet_streak:j.config.bet_streak, base_bet:j.config.base_bet, profit_stop:j.config.profit_stop,
        stuck_pred:j.config.stuck_pred,
      });
    }
    if (S.config.stuck_pred !== oldStuck) {
      if (S.config.stuck_pred) toast('🔄 STUCK MODE: theo ' + S.config.stuck_pred, 'stuck');
      else if (oldStuck) toast('✅ Thoát STUCK — tính CT lại', 'success');
    }
    lastHistLen = S.history.length;

    if (S.step === 'main' && S.tab === 'main') {
      const bv = document.getElementById('bal_val');
      if (bv && S.balance !== oldBal) {
        bv.classList.add('upd');
        bv.textContent = fmt(S.balance);
        setTimeout(() => bv.classList.remove('upd'), 500);
      }
      const pv = document.getElementById('pred_val');
      if (pv) {
        let cls = 'wait';
        if (S.pendingPred === 'Tài') cls = 'tai';
        else if (S.pendingPred === 'Xỉu') cls = 'xiu';
        pv.className = 'res-val ' + cls;
        pv.textContent = S.pendingPred || 'ĐANG CHỜ';
      }
      const ps = document.querySelector('.res-sess');
      if (ps) ps.textContent = 'PHIÊN #' + (S.pendingSession || '—');
      const pl = document.querySelector('.res-lbl');
      if (pl) pl.textContent = S.pendingPred ? 'DỰ ĐOÁN MD5' : 'ĐANG CHỜ';
      const bv2 = document.getElementById('bet_val');
      if (bv2) {
        let t = '—';
        if (S.pendingBetAmount) t = fmt(S.pendingBetAmount) + 'đ';
        if (bv2.textContent !== t) { bv2.textContent = t; bv2.classList.add('pulse'); setTimeout(() => bv2.classList.remove('pulse'), 600); }
      }
      const mv = document.getElementById('mode_val');
      if (mv) {
        const bs = S.config.bet_streak || 0;
        const m = Math.pow(2, Math.min(bs, 62));
        mv.textContent = 'x' + (m >= 1e9 ? m.toExponential(1) : m);
      }
      const ob = document.getElementById('outcome_box');
      if (ob && S.history[0]) { ob.innerHTML = renderOutcome(S.history[0]); ob.classList.add('show'); }
      const pf = document.querySelector('.prog-fill');
      if (pf && S.config.profit_stop > 0) pf.style.width = Math.min(100, Math.max(0, ((S.stats.profit||0)/S.config.profit_stop)*100)) + '%';
      const plbl = document.querySelector('.prog-lbl b');
      if (plbl && S.config.profit_stop > 0) plbl.textContent = fmt(S.stats.profit||0) + ' / ' + fmt(S.config.profit_stop) + ' đ';
    } else if (S.step === 'main' && S.tab === 'history') {
      const hl = document.getElementById('hist_list');
      if (hl && S.history.length) {
        const keys = S.history.map(h => h.session).join(',');
        if (hl.dataset.keys !== keys) {
          hl.dataset.keys = keys;
          hl.innerHTML = S.history.slice(0,100).map(h => {
            let cls = 'lose', delta = '-' + fmt(h.amount);
            if (h.win) { cls = 'win'; delta = '+' + fmt(Math.floor(h.amount*0.98)); }
            if (!h.win && h.stuck) cls = 'stuck-lose';
            const jp = h.jackpot ? 'jp' : '';
            const dice = (h.dices||[]).join('-');
            const predTxt = h.pred === 'Tài' ? '🔵 TÀI' : '🔴 XỈU';
            const resTxt = h.result === 'TAI' ? '🔵 TÀI' : '🔴 XỈU';
            const jpIcon = h.jackpot ? ' 🎰' : '';
            const stuckIcon = h.stuck ? ' 🔄' : '';
            return '<div class="h-row ' + cls + ' ' + jp + '">' +
              '<div class="h-sid">#' + h.session + '</div>' +
              '<div class="h-mid"><div class="r1">' + predTxt + ' → ' + resTxt + jpIcon + stuckIcon + '</div>' +
              '<div class="r2">🎲 ' + dice + ' · ' + h.ts + '</div></div>' +
              '<div class="h-amt ' + cls + '">' + delta + '</div></div>';
          }).join('');
        }
      }
    }
  } catch(e) {}
  tickBusy = false;
}

let tickTimer = null;
function startTick() {
  if (tickTimer) clearInterval(tickTimer);
  tick();
  tickTimer = setInterval(tick, 3000);
}

tryResume();
</script>
</body>
</html>
<?php }
