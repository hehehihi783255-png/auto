<?php
/**
 * DENIUS AUTO v4.0 — ORIGINAL PREDICTION + SUPER UI
 * denius_predict() = port 1:1 từ get_denius_prediction (V7.1_premium.py)
 */

$CFG = [
    'game' => [
        'login_url'    => 'https://apifo88daigia.tele68.com/api?c=3&un={USER}&pw={PASS_MD5}&cp=R&cl=R&pf=web&at=',
        'lobby_url'    => 'https://wlb.tele68.com/v1/lobby/auth/login?cp=R&cl=R&pf=web&at=',
        'ws_host'      => 'wtx.tele68.com',
        'ws_path'      => '/tx/',
        'sessions_api' => 'https://wtx.tele68.com/v1/tx/sessions',
    ],
    'security' => [
        'hmac_secret' => 'DENIUS_v4_ORIGINAL_TTOAN_HMAC_KEY',
        'session_ttl' => 2592000,
    ],
    'worker' => [
        'loop_sleep'     => 1,
        'resume_timeout' => 90,
        'max_runtime'    => 3600,
        'respawn_buffer' => 60,
    ],
    'default_config' => [
        'base_bet'=>0, 'profit_stop'=>0, 'target_win'=>0,
        'mode'=>'double', 'max_lose_streak'=>4,
        'auto'=>false, 'paused'=>false, 'lose_streak'=>0,
        'onboarded'=>false,
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
function hmac_sign(string $p): string {
    global $CFG;
    return hash_hmac('sha256', $p, $CFG['security']['hmac_secret']);
}
function issue_token(string $u): string {
    $exp = time() + ($GLOBALS['CFG']['security']['session_ttl'] ?? 2592000);
    $p = $u . '|' . $exp;
    return base64_encode($p . '|' . hmac_sign($p));
}
function verify_token(string $tok, string $u): bool {
    $d = base64_decode($tok, true);
    if ($d === false) return false;
    $parts = explode('|', $d);
    if (count($parts) !== 3) return false;
    [$user, $exp, $sig] = $parts;
    if ($user !== $u) return false;
    if ((int)$exp < time()) return false;
    return hash_equals(hmac_sign($user . '|' . $exp), $sig);
}
function require_auth(string $u, string $tok): bool {
    if (!$u || !$tok) return false;
    if (!verify_token($tok, $u)) return false;
    return (bool)key_load_by_user($u);
}

// ═══════ STORAGE ═══════
function key_path(string $key): string {
    return KEY_DIR . '/' . hash('sha256', strtolower(trim($key))) . '.json';
}
function key_load(string $key): array {
    $p = key_path($key);
    if (!is_file($p)) return [];
    $j = json_decode(file_get_contents($p), true);
    return is_array($j) ? $j : [];
}
function key_save(string $key, array $d): void {
    $p = key_path($key);
    $t = $p . '.tmp';
    file_put_contents($t, json_encode($d, JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT), LOCK_EX);
    rename($t, $p);
    @chmod($p, 0600);
}
function key_update(string $key, callable $mutator): array {
    $p = key_path($key);
    $fp = @fopen($p, 'c+');
    if (!$fp) {
        $d = key_load($key);
        $mutator($d);
        return $d;
    }
    @flock($fp, LOCK_EX);
    $raw = stream_get_contents($fp);
    $d = json_decode($raw ?: '{}', true);
    if (!is_array($d)) $d = [];
    $new = $mutator($d);
    if (is_array($new)) $d = $new;
    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, json_encode($d, JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT));
    fflush($fp);
    @flock($fp, LOCK_UN);
    fclose($fp);
    @chmod($p, 0600);
    return $d;
}
function key_log(string $key, string $lvl, string $msg): void {
    key_update($key, function($d) use ($lvl, $msg) {
        if (!isset($d['logs'])) $d['logs'] = [];
        array_unshift($d['logs'], ['ts'=>date('H:i:s d/m'), 'level'=>$lvl, 'msg'=>$msg]);
        $d['logs'] = array_slice($d['logs'], 0, 300);
        return $d;
    });
}
function key_load_by_user(string $user): array {
    $idx = DATA_DIR . '/user_index.json';
    if (!is_file($idx)) return [];
    $m = json_decode(file_get_contents($idx), true);
    if (!is_array($m)) return [];
    $k = $m[strtolower($user)] ?? null;
    if (!$k) return [];
    return key_load($k);
}
function key_save_by_user(string $user, string $key): void {
    $idx = DATA_DIR . '/user_index.json';
    $m = [];
    if (is_file($idx)) {
        $j = json_decode(file_get_contents($idx), true);
        if (is_array($j)) $m = $j;
    }
    $m[strtolower($user)] = $key;
    file_put_contents($idx, json_encode($m, JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT), LOCK_EX);
}
function key_resolve(string $u): string {
    $idx = DATA_DIR . '/user_index.json';
    if (is_file($idx)) {
        $m = json_decode(file_get_contents($idx), true);
        if (is_array($m) && isset($m[strtolower($u)])) return $m[strtolower($u)];
    }
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
    if (!is_array($d) || empty($d['success'])) {
        $msg = $d['message'] ?? 'Sai TK/MK';
        return ['_error'=>'Đăng nhập thất bại: ' . $msg];
    }
    $sk = $d['sessionKey'] ?? '';
    $sk .= str_repeat('=', (4 - strlen($sk) % 4) % 4);
    $sess = json_decode(base64_decode($sk), true);
    if (!is_array($sess)) $sess = [];
    $nick = $sess['nickname'] ?? $sess['nickName'] ?? '';
    $body = json_encode(['nickName'=>$nick,'accessToken'=>$d['accessToken'] ?? '']);
    $ctx2 = stream_context_create(['http'=>['method'=>'POST','header'=>"Content-Type: application/json\r\nUser-Agent: Mozilla/5.0\r\n",'content'=>$body,'timeout'=>15,'ignore_errors'=>true]]);
    $raw2 = @file_get_contents($CFG['game']['lobby_url'], false, $ctx2);
    $lb = json_decode($raw2 ?: '', true);
    if (!is_array($lb)) $lb = [];
    if (empty($lb['token'])) return ['_error'=>'Lobby không trả JWT'];
    $money = 0;
    if (isset($lb['loginResp']['money'])) $money = $lb['loginResp']['money'];
    elseif (isset($lb['remoteLoginResp']['money'])) $money = $lb['remoteLoginResp']['money'];
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
    if (!is_array($j) || !isset($j['list'])) return null;
    return $j;
}

// ═══════════════════════════════════════════════════════════════
// 🧠 DENIUS PREDICT — 100% PORT từ get_denius_prediction (V7.1)
// ═══════════════════════════════════════════════════════════════
function denius_predict(array $R, int $loss_streak = 0): string {
    $n = count($R);
    if ($n === 0) return 'T';
    if ($n < 3) return $R[$n-1];

    $last = $R[$n-1];
    $opp = ($last === 'T') ? 'X' : 'T';

    // 🛡️ CHẾ ĐỘ SINH TỒN
    if ($loss_streak >= 2) {
        return $last;
    }

    // Phân tích 8 phiên gần nhất
    $recent_8 = ($n >= 8) ? array_slice($R, -8) : $R;
    $flips = 0;
    $rc = count($recent_8);
    for ($i = 1; $i < $rc; $i++) {
        if ($recent_8[$i] !== $recent_8[$i-1]) $flips++;
    }

    // Đếm độ dài chuỗi bệt hiện tại
    $streak = 1;
    for ($i = $n - 2; $i >= 0; $i--) {
        if ($R[$i] === $last) $streak++;
        else break;
    }

    // 1. BẢO VỆ BỆT (Streak Shield)
    if ($streak >= 3) {
        return $last;
    }

    // 2. THỢ SĂN 1-1 (Zigzag Hunter)
    if ($n >= 5 && $flips >= 4 && $streak <= 2) {
        return $opp;
    }

    // 3. TIÊN TRI ĐIỂM GÃY (Predictive)
    if ($n >= 4) {
        // Đang 1-1 tự nhiên gãy thành bệt 2
        if ($R[$n-1] === $R[$n-2] && $R[$n-2] !== $R[$n-3] && $R[$n-3] !== $R[$n-4]) {
            return $last;
        }
        // Đang bệt dài tự nhiên gãy
        if ($R[$n-1] !== $R[$n-2] && $R[$n-2] === $R[$n-3] && $R[$n-3] === $R[$n-4]) {
            return $last;
        }
    }

    // 4. CHỐNG LOẠN (Chaos Guard)
    if ($n >= 10 && $flips >= 8) {
        return $last;
    }

    // Mặc định: Bám đuôi
    return $last;
}

// ═══════ TINY WS ═══════
class TinyWS {
    public $sock;
    public $error = '';
    private $h, $p, $path, $headers;
    public function __construct($h, $p, $path, $headers = []) {
        $this->h = $h; $this->p = $p; $this->path = $path; $this->headers = $headers;
    }
    public function connect(): bool {
        $ctx = stream_context_create(['ssl'=>['verify_peer'=>false,'verify_peer_name'=>false,'allow_self_signed'=>true]]);
        $this->sock = @stream_socket_client("tls://{$this->h}:{$this->p}", $en, $es, 10, STREAM_CLIENT_CONNECT, $ctx);
        if (!$this->sock) { $this->error = "TCP fail: $en:$es"; return false; }
        stream_set_timeout($this->sock, 15);
        stream_set_blocking($this->sock, true);
        $key = base64_encode(random_bytes(16));
        $req = "GET {$this->path} HTTP/1.1\r\nHost: {$this->h}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {$key}\r\nSec-WebSocket-Version: 13\r\nOrigin: https://{$this->h}\r\nUser-Agent: Mozilla/5.0\r\n";
        foreach ($this->headers as $hd) $req .= $hd . "\r\n";
        $req .= "\r\n";
        fwrite($this->sock, $req);
        $resp = ''; $dl = microtime(true) + 10;
        while (!str_contains($resp, "\r\n\r\n") && microtime(true) < $dl) {
            $c = fread($this->sock, 2048);
            if ($c === false || $c === '') { $this->error = 'Handshake fail'; return false; }
            $resp .= $c;
        }
        if (stripos($resp, ' 101') === false) { $this->error = 'Handshake: ' . substr($resp, 0, 160); return false; }
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
        $op = $b1 & 0x0f;
        $masked = ($b2 & 0x80) !== 0;
        $len = $b2 & 0x7f;
        if ($len === 126) {
            $ext = @fread($this->sock, 2);
            if (strlen($ext) < 2) return null;
            $len = unpack('n', $ext)[1];
        } elseif ($len === 127) {
            $ext = @fread($this->sock, 8);
            if (strlen($ext) < 8) return null;
            $len = unpack('J', $ext)[1];
        }
        $mask = null;
        if ($masked) {
            $mask = @fread($this->sock, 4);
            if (strlen($mask) < 4) return null;
        }
        $data = '';
        while (strlen($data) < $len) {
            $c = @fread($this->sock, $len - strlen($data));
            if ($c === false || $c === '') return null;
            $data .= $c;
        }
        if ($mask) {
            $u = '';
            for ($i = 0; $i < $len; $i++) $u .= $data[$i] ^ $mask[$i % 4];
            $data = $u;
        }
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
    public function close(): void {
        if ($this->sock) @fclose($this->sock);
        $this->sock = null;
    }
}

// ═══════ WS BET ═══════
function do_ws_bet(string $key, array $s, array &$actions): bool {
    global $CFG;
    if (empty($s['token'])) return false;
    $pred = $s['pending_pred'] ?? null;
    if (!$pred) return false;
    $side = 'XIU';
    if ($pred === 'Tài' || $pred === 'T' || $pred === 'TAI') $side = 'TAI';
    $ps = (int)($s['pending_session'] ?? 0);
    $amount = (int)($s['pending_bet_amount'] ?? 10000);
    if ($amount < 1000) $amount = 1000;
    $wsPath = rtrim($CFG['game']['ws_path'], '/') . '/?EIO=4&transport=websocket';
    $ws = new TinyWS($CFG['game']['ws_host'], 443, $wsPath, ['Authorization: Bearer ' . $s['token']]);
    if (!$ws->connect()) { key_log($key, 'error', '❌ WS fail: ' . $ws->error); return false; }
    $auth = json_encode(['token'=>$s['token']], JSON_UNESCAPED_UNICODE);
    $joined = false; $done = false;
    $deadline = microtime(true) + 20;
    while (microtime(true) < $deadline) {
        $frames = $ws->readOneFrame(1);
        if ($frames === null) { key_log($key, 'warn', '⚠️ WS đóng'); break; }
        if ($frames === []) continue;
        foreach ($frames as $pkt) {
            if ($pkt === '' || $pkt === null) continue;
            if (str_starts_with($pkt, '0{')) { $ws->sendRaw('40/tx,' . $auth); continue; }
            if ($pkt === '2') { $ws->sendRaw('3'); continue; }
            if ($pkt === '3' || $pkt === '6') continue;
            if ($pkt === '1') { $ws->close(); return false; }
            if (!str_starts_with($pkt, '4')) continue;
            $sio = substr($pkt, 1);
            if (str_starts_with($sio, '0/tx,')) { $joined = true; continue; }
            if (str_starts_with($sio, '1') || str_starts_with($sio, '4')) { $ws->close(); return false; }
            if (!str_starts_with($sio, '2')) continue;
            $body = substr($sio, 1);
            if (str_starts_with($body, '/tx,')) $body = substr($body, strlen('/tx,'));
            $msg = json_decode($body, true);
            if (!is_array($msg) || count($msg) < 1) continue;
            $ev = $msg[0] ?? '';
            $d = $msg[1] ?? [];
            if ($ev === 'tick-update') {
                $state = $d['state'] ?? null;
                $tickSid = isset($d['id']) ? (int)$d['id'] : null;
                if ($state === 'BETTING' && $joined && !$done) {
                    if ($tickSid !== null && $tickSid < $ps) continue;
                    $ws->sendRaw('42/tx,' . json_encode(['bet', ['type'=>$side, 'amount'=>$amount]], JSON_UNESCAPED_UNICODE));
                    $done = true;
                    key_log($key, 'success', "💰 ĐẶT #$ps [$side] × " . number_format($amount) . " — KHỚP $pred");
                    $actions[] = ['type'=>'bet', 'msg'=>"Bet #$ps $side $amount"];
                    key_update($key, function($dd) use ($ps, $amount) {
                        $dd['bet_session'] = $ps;
                        $dd['bet_amount'] = $amount;
                        return $dd;
                    });
                    $wait = microtime(true) + 2.5;
                    while (microtime(true) < $wait) {
                        $more = $ws->readOneFrame(1);
                        if ($more === null) break;
                        if ($more === []) continue;
                        foreach ($more as $p2) {
                            if ($p2 === '2') { $ws->sendRaw('3'); continue; }
                            if (!str_starts_with($p2, '4')) continue;
                            $s2 = substr($p2, 1);
                            if (!str_starts_with($s2, '2')) continue;
                            $b2 = substr($s2, 1);
                            if (str_starts_with($b2, '/tx,')) $b2 = substr($b2, strlen('/tx,'));
                            $m2 = json_decode($b2, true);
                            if (!is_array($m2)) continue;
                            if (($m2[0] ?? '') === 'bet-result') {
                                if (isset($m2[1]['postBalance'])) {
                                    key_update($key, function($dd) use ($m2) {
                                        $dd['balance'] = $m2[1]['postBalance'];
                                        return $dd;
                                    });
                                }
                            }
                        }
                    }
                    $ws->close();
                    return true;
                }
            }
            if ($ev === 'session-result') { $ws->close(); return false; }
        }
    }
    $ws->close();
    return $done;
}

// ═══════ WORKER ═══════
function worker_step(string $key): array {
    $actions = [];
    $s = key_load($key);
    if (!$s) return $actions;
    $cfg = $s['config'] ?? [];
    if (empty($cfg['auto']) || !empty($cfg['paused'])) return $actions;

    // Check profit target
    $pTarget = (int)($cfg['profit_stop'] ?? 0);
    $pTotal = (int)($s['profit_total'] ?? 0);
    if ($pTarget > 0 && $pTotal >= $pTarget && empty($s['pending_pred'])) {
        key_update($key, function($d) {
            $d['config']['auto'] = false;
            $d['config']['paused'] = true;
            return $d;
        });
        key_log($key, 'success', '🎉 ĐẠT MỤC TIÊU LÃI');
        return $actions;
    }

    $data = fetch_sessions_api();
    if (!$data || empty($data['list'])) return $actions;
    $latest = $data['list'][0];
    $latestId = (int)$latest['id'];
    $lastId = (int)($s['last_session_id'] ?? 0);

    if ($lastId === 0) {
        key_update($key, fn($d) => array_merge($d, ['last_session_id'=>$latestId]));
        key_log($key, 'info', "📡 Baseline #$latestId");
        return $actions;
    }

    if ($latestId > $lastId) {
        for ($sid = $lastId + 1; $sid <= $latestId; $sid++) {
            $found = null;
            foreach ($data['list'] as $row) {
                if ((int)$row['id'] === $sid) { $found = $row; break; }
            }
            if (!$found) continue;
            $raw = $found['resultTruyenThong'] ?? 'N/A';
            $map = ['Tài'=>'TAI','Xỉu'=>'XIU','tai'=>'TAI','xiu'=>'XIU','TAI'=>'TAI','XIU'=>'XIU'];
            $result = $map[$raw] ?? 'N/A';
            if ($result !== 'TAI' && $result !== 'XIU') continue;
            $dices = $found['dices'] ?? [0,0,0];
            $tong = array_sum($dices);
            $jackpot = (count(array_unique($dices)) === 1 && $dices[0] != 0);

            if (($s['pending_session'] ?? null) == $sid && !empty($s['pending_pred'])) {
                $pred = $s['pending_pred'];
                $win = false;
                if (($pred === 'Tài' || $pred === 'T') && $result === 'TAI') $win = true;
                elseif (($pred === 'Xỉu' || $pred === 'X') && $result === 'XIU') $win = true;

                key_update($key, function($d) use ($sid, $pred, $result, $dices, $win, $jackpot, $tong) {
                    $c = $d['config'];
                    $st = (int)($c['lose_streak'] ?? 0);
                    if ($win) {
                        $st = 0;
                        $d['win_count_total'] = (int)($d['win_count_total'] ?? 0) + 1;
                    } else {
                        $d['loss_count_total'] = (int)($d['loss_count_total'] ?? 0) + 1;
                        $st++;
                        if ($st >= 4) $st = 0;
                    }
                    $c['lose_streak'] = $st;
                    $betAmt = (int)($d['bet_amount'] ?? 0);
                    $bal = (int)($d['balance'] ?? 0);
                    $profitDelta = 0;
                    if ($win) {
                        $profitDelta = intval($betAmt * 0.98);
                        $bal += $profitDelta;
                    } else {
                        $profitDelta = -$betAmt;
                        $bal -= $betAmt;
                    }
                    $d['balance'] = $bal;
                    $d['profit_total'] = (int)($d['profit_total'] ?? 0) + $profitDelta;
                    $d['history'] = $d['history'] ?? [];
                    array_unshift($d['history'], [
                        'ts'=>date('H:i:s d/m'),'session'=>$sid,'pred'=>$pred,'result'=>$result,
                        'dices'=>$dices,'tong'=>$tong,'win'=>$win,'amount'=>$betAmt,
                        'balance_after'=>$bal,'streak'=>$st,'jackpot'=>$jackpot,
                    ]);
                    $d['history'] = array_slice($d['history'], 0, 500);
                    $d['pending_pred'] = null;
                    $d['pending_session'] = null;
                    $d['pending_bet_amount'] = null;
                    $d['bet_session'] = null;
                    $d['bet_amount'] = 0;
                    $sym = ($result === 'TAI') ? 'T' : 'X';
                    $p10 = ($d['pattern_10'] ?? '') . $sym;
                    if (strlen($p10) > 10) $p10 = substr($p10, -10);
                    $d['pattern_10'] = $p10;
                    $d['config'] = $c;
                    $pS = (int)($c['profit_stop'] ?? 0);
                    if ($pS > 0 && (int)$d['profit_total'] >= $pS) {
                        $c['auto'] = false;
                        $c['paused'] = true;
                        $d['config'] = $c;
                    }
                    return $d;
                });
                $icon = $win ? '✅' : '❌';
                $log = "$icon Phiên #$sid: $pred → $result (" . implode('-', $dices) . ")";
                if ($jackpot) $log .= ' 🎉';
                key_log($key, $win ? 'success' : 'error', $log);
                $actions[] = ['type'=>'result', 'msg'=>$log];
                $s = key_load($key);
            }
        }
        key_update($key, fn($d) => array_merge($d, ['last_session_id'=>$latestId]));
    }

    if (!empty($s['pending_session']) && (int)$s['pending_session'] <= $latestId) {
        key_update($key, function($d) {
            $d['pending_pred']=null;
            $d['pending_session']=null;
            $d['pending_bet_amount']=null;
            $d['bet_session']=null;
            $d['bet_amount']=0;
            return $d;
        });
        $s = key_load($key);
    }

    $cfg = $s['config'];
    if (!empty($cfg['auto']) && empty($cfg['paused']) && empty($s['pending_pred'])) {
        // Build R (chronological: oldest → newest)
        $R = [];
        foreach (array_reverse($s['history'] ?? []) as $h) {
            $r = $h['result'] ?? '';
            if ($r === 'TAI') $R[] = 'T';
            elseif ($r === 'XIU') $R[] = 'X';
        }
        if (empty($R) && !empty($data['list'])) {
            foreach (array_reverse(array_slice($data['list'], 0, 50)) as $row) {
                $rr = $row['resultTruyenThong'] ?? '';
                $mm = ['Tài'=>'T','Xỉu'=>'X','tai'=>'T','xiu'=>'X','TAI'=>'T','XIU'=>'X'];
                if (isset($mm[$rr])) $R[] = $mm[$rr];
            }
        }

        $lossStreak = (int)($cfg['lose_streak'] ?? 0);
        $pred = denius_predict($R, $lossStreak);
        $predStr = ($pred === 'T') ? 'Tài' : 'Xỉu';

        $baseBet = max(1000, (int)($cfg['base_bet'] ?? 10000));
        $betAmt = $baseBet;
        if ($lossStreak > 0) {
            $betAmt = $baseBet * (1 << min($lossStreak, 4));
        }
        $bal = (int)($s['balance'] ?? 0);
        if ($betAmt > $bal && $bal > 0) $betAmt = max(1000, $bal);

        key_update($key, function($d) use ($predStr, $latestId, $betAmt) {
            $d['pending_pred'] = $predStr;
            $d['pending_session'] = $latestId + 1;
            $d['pending_bet_amount'] = $betAmt;
            return $d;
        });
        $log = "🎯 #" . ($latestId + 1) . ": $predStr — " . number_format($betAmt) . 'đ';
        key_log($key, 'info', $log);
        $actions[] = ['type'=>'predict', 'msg'=>$log];
        $s = key_load($key);
    }

    $cfg = $s['config'];
    if (!empty($s['pending_pred']) && !empty($cfg['auto']) && empty($cfg['paused'])) {
        if (($s['bet_session'] ?? null) != $s['pending_session']) {
            do_ws_bet($key, $s, $actions);
        }
    }
    return $actions;
}

function worker_heartbeat(string $key, string $status = 'running'): void {
    key_update($key, function($d) use ($status) {
        $startedAt = time();
        if (isset($d['worker']['started_at'])) $startedAt = $d['worker']['started_at'];
        $d['worker'] = ['last_beat'=>time(),'pid'=>getmypid(),'status'=>$status,'started_at'=>$startedAt];
        return $d;
    });
}
function worker_alive(string $key): bool {
    global $CFG;
    $s = key_load($key);
    $w = $s['worker'] ?? [];
    if (empty($w['last_beat'])) return false;
    $to = $CFG['worker']['resume_timeout'] ?? 90;
    return (time() - (int)$w['last_beat']) < $to;
}
function worker_lock(string $key): bool {
    $lp = KEY_DIR . '/' . hash('sha256', strtolower($key)) . '.lock';
    if (is_file($lp)) {
        $pid = (int)trim(@file_get_contents($lp));
        if ($pid > 0) {
            $alive = false;
            if (function_exists('posix_kill')) $alive = @posix_kill($pid, 0);
            else $alive = (time() - filemtime($lp)) < 60;
            if ($alive) return false;
        }
        @unlink($lp);
    }
    $fp = @fopen($lp, 'c+');
    if (!$fp) return false;
    if (!flock($fp, LOCK_EX | LOCK_NB)) { fclose($fp); return false; }
    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, (string)getmypid());
    fflush($fp);
    register_shutdown_function(function() use ($fp, $lp) {
        @flock($fp, LOCK_UN);
        @fclose($fp);
        @unlink($lp);
    });
    return true;
}
function run_worker_daemon(string $key, int $max): void {
    global $CFG;
    if (function_exists('fastcgi_finish_request')) @fastcgi_finish_request();
    else {
        @ob_end_clean();
        header('Connection: close');
        header('Content-Length: 0');
        @flush();
        @ob_end_flush();
    }
    @ignore_user_abort(true);
    @set_time_limit(0);
    @ini_set('memory_limit', '256M');
    if (!worker_lock($key)) return;
    $sleep = (int)($CFG['worker']['loop_sleep'] ?? 1);
    $deadline = time() + $max;
    $lastBeat = 0;
    $buf = (int)($CFG['worker']['respawn_buffer'] ?? 60);
    worker_heartbeat($key, 'running');
    while (time() < $deadline) {
        $s = key_load($key);
        if (!$s) break;
        try { worker_step($key); }
        catch (Throwable $e) { key_log($key, 'error', '💥 ' . $e->getMessage()); }
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
        if ($pid > 0 && function_exists('posix_kill') && @posix_kill($pid, 0)) return;
    }
    $scheme = 'http';
    if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') $scheme = 'https';
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $path = $_SERVER['SCRIPT_NAME'] ?? '/index.php';
    $url = "$scheme://$host$path?action=worker&key=" . urlencode($key) . "&max=3600";
    if (function_exists('exec') && !in_array('exec', array_map('trim', explode(',', (string)ini_get('disable_functions'))))) {
        $php = PHP_BINARY ?: 'php';
        $code = 'ignore_user_abort(true);set_time_limit(0);@file_get_contents(' . var_export($url, true) . ');';
        @exec(sprintf('%s -r %s > /dev/null 2>&1 &', escapeshellarg($php), escapeshellarg($code)));
        return;
    }
    if (function_exists('shell_exec') && !in_array('shell_exec', array_map('trim', explode(',', (string)ini_get('disable_functions'))))) {
        @shell_exec("curl -s --max-time 2 " . escapeshellarg($url) . " > /dev/null 2>&1 &");
        return;
    }
    if (function_exists('fsockopen')) {
        $parsed = parse_url($url);
        $h = $parsed['host'] ?? $host;
        $port = 80;
        if (($parsed['scheme'] ?? 'http') === 'https') $port = 443;
        $fp = @fsockopen($h, $port, $en, $es, 0.5);
        if ($fp) {
            stream_set_timeout($fp, 1);
            $p = ($parsed['path'] ?? '/') . '?' . ($parsed['query'] ?? '');
            @fwrite($fp, "GET {$p} HTTP/1.1\r\nHost: {$h}\r\nConnection: Close\r\n\r\n");
            @fclose($fp);
            return;
        }
    }
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
if ($action === 'keepalive') {
    header('Content-Type: application/json');
    echo json_encode(['ok'=>true,'ts'=>time()]);
    exit;
}

header('Content-Type: application/json; charset=utf-8');
try {
    switch ($action) {
        case 'verify':
            $u = trim($_POST['user'] ?? '');
            $p = trim($_POST['pass'] ?? '');
            $dev = trim($_POST['device'] ?? 'WEB');
            if (!$u || !$p) { echo json_encode(['ok'=>false,'msg'=>'Thiếu tài khoản/mật khẩu']); exit; }
            $key = $u;
            $existing = key_load($key);
            $canResume = !empty($existing['user']) && !empty($existing['token']);
            $gl = game_login($u, $p);
            if (isset($gl['_error'])) {
                if ($canResume) {
                    $gl = ['nickname'=>$existing['nickname']??$u,'token'=>$existing['token'],'money'=>$existing['balance']??0];
                    key_log($key, 'info', '♻️ Resume');
                } else { echo json_encode(['ok'=>false,'msg'=>$gl['_error']]); exit; }
            }
            $s = $existing ?: [];
            $s['user'] = $u;
            $s['key'] = $key;
            $s['device'] = $dev;
            $s['nickname'] = $gl['nickname'] ?? $u;
            $s['token'] = $gl['token'] ?? '';
            $s['balance'] = $gl['money'] ?? ($s['balance'] ?? 0);
            if (!isset($s['history'])) $s['history'] = [];
            if (!isset($s['logs'])) $s['logs'] = [];
            $s['config'] = array_merge($CFG['default_config'], $s['config'] ?? []);
            if (!isset($s['win_count_total'])) $s['win_count_total'] = 0;
            if (!isset($s['loss_count_total'])) $s['loss_count_total'] = 0;
            if (!isset($s['profit_total'])) $s['profit_total'] = 0;
            if (!isset($s['last_session_id'])) $s['last_session_id'] = 0;
            if (!array_key_exists('pending_pred', $s)) $s['pending_pred'] = null;
            if (!array_key_exists('pending_session', $s)) $s['pending_session'] = null;
            if (!array_key_exists('pending_bet_amount', $s)) $s['pending_bet_amount'] = null;
            if (!array_key_exists('bet_session', $s)) $s['bet_session'] = null;
            if (!array_key_exists('bet_amount', $s)) $s['bet_amount'] = 0;
            if (!isset($s['pattern_10'])) $s['pattern_10'] = '';
            key_save($key, $s);
            key_save_by_user($u, $key);
            key_log($key, 'info', '🔐 Login — ' . $dev);
            if (!worker_alive($key)) spawn_worker_async($key);
            echo json_encode([
                'ok'=>true,'user'=>$u,'nickname'=>$s['nickname'],'balance'=>$s['balance'],
                'config'=>$s['config'],'history'=>$s['history'],
                'auth_token'=>issue_token($u),'worker_alive'=>worker_alive($key),'resumed'=>$canResume,
            ]);
            exit;

        case 'resume':
            $u = trim($_POST['user'] ?? '');
            $tk = trim($_POST['auth_token'] ?? '');
            if (!verify_token($tk, $u)) { echo json_encode(['ok'=>false,'msg'=>'Token expired']); exit; }
            $key = key_resolve($u);
            $s = key_load($key);
            if (!$s || empty($s['token'])) { echo json_encode(['ok'=>false,'msg'=>'Session lost']); exit; }
            if (!empty($s['config']['auto']) && empty($s['config']['paused']) && !worker_alive($key)) {
                @unlink(KEY_DIR . '/' . hash('sha256', strtolower($key)) . '.lock');
                spawn_worker_async($key);
            }
            $wins = (int)($s['win_count_total'] ?? 0);
            $losses = (int)($s['loss_count_total'] ?? 0);
            $tot = $wins + $losses;
            $wr = 0;
            if ($tot > 0) $wr = round($wins / $tot * 100, 1);
            $profit = (int)($s['profit_total'] ?? 0);
            echo json_encode([
                'ok'=>true,'user'=>$u,'nickname'=>$s['nickname']??'','balance'=>$s['balance']??0,
                'config'=>$s['config']??[],'history'=>array_slice($s['history']??[], 0, 100),
                'auth_token'=>issue_token($u),'worker_alive'=>worker_alive($key),
                'pending_pred'=>$s['pending_pred']??null,'pending_session'=>$s['pending_session']??null,
                'pending_bet_amount'=>$s['pending_bet_amount']??null,
                'last_session_id'=>$s['last_session_id']??0,'pattern_10'=>$s['pattern_10']??'',
                'win_count_total'=>$wins,'loss_count_total'=>$losses,'profit_total'=>$profit,
                'stats'=>['wins'=>$wins,'losses'=>$losses,'total'=>$tot,'winrate'=>$wr,'profit'=>$profit],
                'ts'=>time(),
            ]);
            exit;

        case 'setup':
            $u = trim($_POST['user'] ?? '');
            $tk = trim($_POST['auth_token'] ?? '');
            if (!require_auth($u, $tk)) { echo json_encode(['ok'=>false,'msg'=>'Unauthorized']); exit; }
            $key = key_resolve($u);
            $s = key_load($key);
            $c = $s['config'];
            $baseBet = (int)($_POST['base_bet'] ?? 10000);
            if ($baseBet < 1000) $baseBet = 1000;
            $profitStop = (int)($_POST['profit_stop'] ?? 0);
            if ($profitStop < 0) $profitStop = 0;
            $c['base_bet'] = $baseBet;
            $c['profit_stop'] = $profitStop;
            $c['mode'] = 'double';
            $c['max_lose_streak'] = 4;
            $c['onboarded'] = true;
            $c['auto'] = true;
            $c['paused'] = false;
            $s['config'] = $c;
            key_save($key, $s);
            if (!worker_alive($key)) {
                @unlink(KEY_DIR . '/' . hash('sha256', strtolower($key)) . '.lock');
                spawn_worker_async($key);
            }
            key_log($key, 'success', '▶ AUTO · vốn ' . number_format($baseBet) . ' · target ' . number_format($profitStop));
            echo json_encode(['ok'=>true,'config'=>$c,'worker_alive'=>worker_alive($key)]);
            exit;

        case 'kill':
            $u = trim($_POST['user'] ?? '');
            $tk = trim($_POST['auth_token'] ?? '');
            if (!require_auth($u, $tk)) { echo json_encode(['ok'=>false,'msg'=>'Unauthorized']); exit; }
            $key = key_resolve($u);
            key_update($key, function($d) {
                $d['config']['auto'] = false;
                $d['config']['paused'] = true;
                $d['config']['lose_streak'] = 0;
                $d['pending_pred'] = null;
                $d['pending_session'] = null;
                $d['pending_bet_amount'] = null;
                $d['bet_session'] = null;
                $d['bet_amount'] = 0;
                return $d;
            });
            $lp = KEY_DIR . '/' . hash('sha256', strtolower($key)) . '.lock';
            if (is_file($lp)) {
                $pid = (int)trim(@file_get_contents($lp));
                if ($pid > 0 && function_exists('posix_kill')) @posix_kill($pid, SIGTERM);
                @unlink($lp);
            }
            key_log($key, 'warn', '🛑 KILL — Dừng toàn bộ');
            echo json_encode(['ok'=>true]);
            exit;

        case 'status':
            $u = trim($_GET['user'] ?? '');
            $tk = trim($_GET['auth_token'] ?? '');
            if (!verify_token($tk, $u)) { echo json_encode(['ok'=>false,'msg'=>'Unauthorized']); exit; }
            $key = key_resolve($u);
            $s = key_load($key);
            if (!empty($s['config']['auto']) && empty($s['config']['paused']) && !worker_alive($key)) {
                @unlink(KEY_DIR . '/' . hash('sha256', strtolower($key)) . '.lock');
                spawn_worker_async($key);
            }
            $wins = (int)($s['win_count_total'] ?? 0);
            $losses = (int)($s['loss_count_total'] ?? 0);
            $tot = $wins + $losses;
            $wr = 0;
            if ($tot > 0) $wr = round($wins / $tot * 100, 1);
            $profit = (int)($s['profit_total'] ?? 0);
            echo json_encode([
                'ok'=>true,'nickname'=>$s['nickname']??'','balance'=>$s['balance']??0,
                'config'=>$s['config']??[],'history'=>array_slice($s['history']??[], 0, 100),
                'pending_pred'=>$s['pending_pred']??null,'pending_session'=>$s['pending_session']??null,
                'pending_bet_amount'=>$s['pending_bet_amount']??null,
                'last_session_id'=>$s['last_session_id']??0,'pattern_10'=>$s['pattern_10']??'',
                'win_count_total'=>$wins,'loss_count_total'=>$losses,'profit_total'=>$profit,
                'stats'=>['wins'=>$wins,'losses'=>$losses,'total'=>$tot,'winrate'=>$wr,'profit'=>$profit],
                'worker_alive'=>worker_alive($key),
                'ts'=>time(),
            ]);
            exit;

        case 'tick':
            $u = trim($_POST['user'] ?? '');
            $tk = trim($_POST['auth_token'] ?? '');
            if (!verify_token($tk, $u)) { echo json_encode(['ok'=>false,'msg'=>'Unauthorized']); exit; }
            $key = key_resolve($u);
            $s = key_load($key);
            if (!empty($s['config']['auto']) && empty($s['config']['paused']) && !worker_alive($key)) {
                @unlink(KEY_DIR . '/' . hash('sha256', strtolower($key)) . '.lock');
                spawn_worker_async($key);
            }
            $s2 = key_load($key);
            echo json_encode([
                'ok'=>true,'worker_alive'=>worker_alive($key),
                'pending_pred'=>$s2['pending_pred']??null,'pending_session'=>$s2['pending_session']??null,
            ]);
            exit;

        case 'logout':
            $u = trim($_POST['user'] ?? '');
            $tk = trim($_POST['auth_token'] ?? '');
            if (!verify_token($tk, $u)) { echo json_encode(['ok'=>false,'msg'=>'Unauthorized']); exit; }
            $key = key_resolve($u);
            @unlink(key_path($key));
            $lp = KEY_DIR . '/' . hash('sha256', strtolower($key)) . '.lock';
            if (is_file($lp)) {
                $pid = (int)trim(@file_get_contents($lp));
                if ($pid > 0 && function_exists('posix_kill')) @posix_kill($pid, SIGTERM);
                @unlink($lp);
            }
            echo json_encode(['ok'=>true]);
            exit;
    }
    echo json_encode(['ok'=>false,'msg'=>'Action lạ']);
} catch (Throwable $e) {
    echo json_encode(['ok'=>false,'msg'=>'Lỗi: ' . $e->getMessage()]);
}
exit;

// ═══════════════════════════════════════════════════════════════
// UI — SUPER EFFECTS FIXED LAYOUT
// ═══════════════════════════════════════════════════════════════
function render_ui(): void { ?>
<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, minimum-scale=1, user-scalable=no, viewport-fit=cover">
<meta name="theme-color" content="#05020f">
<title>DENIUS · お兄ちゃん</title>
<style>
:root{
  --bg-0:#05020f;
  --bg-1:#0a0618;
  --bg-2:#120828;
  --bg-3:#1a0e35;
  --sakura:#ffb7d5;
  --sakura-bright:#ffd6e8;
  --lavender:#c4a7e7;
  --violet:#8b6fc4;
  --gold:#ffd966;
  --gold-bright:#ffe89a;
  --mint:#7ef0b4;
  --ruby:#ff5c7a;
  --cyan:#6ee7ff;
  --text:#fff5eb;
  --text-dim:#a89cbd;
  --muted:#5e4d75;
  --border:rgba(255,183,213,0.10);
  --border-strong:rgba(255,183,213,0.26);
}
*{margin:0;padding:0;box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html{
  height:100%;
  height:100dvh;
  overflow:hidden;
  -webkit-text-size-adjust:100%;
  text-size-adjust:100%;
}
body{
  height:100%;
  height:100dvh;
  overflow:hidden;
  position:fixed;
  inset:0;
  background:var(--bg-0);
  color:var(--text);
  font-family:-apple-system,BlinkMacSystemFont,"Hiragino Sans","Yu Gothic","Noto Sans JP","Inter","Segoe UI",system-ui,sans-serif;
  -webkit-font-smoothing:antialiased;
  user-select:none;
  touch-action:manipulation;
  overscroll-behavior:none;
}
#particles{
  position:fixed;
  inset:0;
  z-index:0;
  pointer-events:none;
  opacity:0.85;
}
.orb{
  position:fixed;
  border-radius:50%;
  filter:blur(80px);
  opacity:0.5;
  pointer-events:none;
  z-index:0;
  animation:orbFloat 18s ease-in-out infinite;
}
.orb-1{width:340px;height:340px;top:-10%;left:-10%;background:radial-gradient(circle,#ffb7d5,transparent 70%);animation-delay:0s}
.orb-2{width:380px;height:380px;bottom:-15%;right:-15%;background:radial-gradient(circle,#c4a7e7,transparent 70%);animation-delay:-6s}
.orb-3{width:280px;height:280px;top:40%;left:60%;background:radial-gradient(circle,#6ee7ff,transparent 70%);animation-delay:-12s}
@keyframes orbFloat{
  0%,100%{transform:translate(0,0) scale(1)}
  25%{transform:translate(30px,-40px) scale(1.1)}
  50%{transform:translate(-20px,30px) scale(0.95)}
  75%{transform:translate(40px,20px) scale(1.05)}
}
#app{
  position:absolute;
  inset:0;
  z-index:1;
  display:flex;
  flex-direction:column;
  overflow:hidden;
}
.screen{
  flex:1;
  display:flex;
  flex-direction:column;
  overflow:hidden;
  min-height:0;
}
.scrollable{
  flex:1;
  overflow-y:auto;
  overflow-x:hidden;
  -webkit-overflow-scrolling:touch;
  scrollbar-width:thin;
  scrollbar-color:rgba(255,183,213,0.3) transparent;
}
.scrollable::-webkit-scrollbar{width:4px}
.scrollable::-webkit-scrollbar-thumb{background:rgba(255,183,213,0.3);border-radius:2px}

/* ═══ GLASS CARD ═══ */
.glass{
  background:linear-gradient(135deg,rgba(28,15,56,0.75),rgba(10,6,24,0.9));
  backdrop-filter:blur(30px) saturate(180%);
  -webkit-backdrop-filter:blur(30px) saturate(180%);
  border:1px solid var(--border);
  border-radius:20px;
  box-shadow:
    0 25px 60px -20px rgba(0,0,0,0.7),
    0 0 60px -25px rgba(255,183,213,0.25),
    inset 0 1px 0 rgba(255,255,255,0.06);
}

/* ═══ NEON BORDER ═══ */
@property --angle{
  syntax:'<angle>';
  initial-value:0deg;
  inherits:false;
}
.neon::before{
  content:'';
  position:absolute;
  inset:-1px;
  border-radius:inherit;
  padding:1px;
  background:conic-gradient(from var(--angle),transparent 0%,var(--sakura) 25%,var(--gold) 50%,var(--lavender) 75%,transparent 100%);
  -webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);
  -webkit-mask-composite:xor;
  mask-composite:exclude;
  animation:spin 6s linear infinite;
  pointer-events:none;
}
@keyframes spin{to{--angle:360deg}}

/* ═══ LOGIN ═══ */
.login-wrap{
  flex:1;
  display:flex;
  align-items:center;
  justify-content:center;
  padding:20px;
  overflow-y:auto;
}
.login-card{
  width:100%;
  max-width:400px;
  position:relative;
  padding:36px 26px 30px;
  animation:popIn 0.7s cubic-bezier(0.34,1.56,0.64,1);
}
@keyframes popIn{
  from{opacity:0;transform:scale(0.9) translateY(40px);filter:blur(10px)}
  to{opacity:1;transform:scale(1) translateY(0);filter:blur(0)}
}
.logo-wrap{text-align:center;margin-bottom:16px}
.logo-img{
  width:110px;
  height:110px;
  object-fit:cover;
  border-radius:50%;
  border:2px solid var(--sakura);
  background:var(--bg-2);
  box-shadow:
    0 0 40px rgba(255,183,213,0.45),
    0 0 80px rgba(255,183,213,0.2),
    inset 0 0 20px rgba(255,183,213,0.15);
  animation:logoFloat 3.5s ease-in-out infinite;
}
@keyframes logoFloat{0%,100%{transform:translateY(0)}50%{transform:translateY(-8px)}}
.brand-title{
  font-size:24px;
  font-weight:900;
  letter-spacing:5px;
  text-align:center;
  background:linear-gradient(90deg,var(--sakura-bright),var(--gold-bright),var(--cyan),var(--sakura-bright));
  background-size:300% 100%;
  -webkit-background-clip:text;
  background-clip:text;
  -webkit-text-fill-color:transparent;
  margin-bottom:4px;
  animation:shimmer 4s linear infinite;
}
@keyframes shimmer{to{background-position:300% 0}}
.brand-sub{
  text-align:center;
  font-size:11px;
  letter-spacing:2px;
  color:var(--text-dim);
  font-weight:600;
  margin-bottom:24px;
}
.jp{color:var(--sakura);font-weight:700}
.field{margin-bottom:14px}
.field label{
  display:flex;
  align-items:center;
  gap:6px;
  font-size:10px;
  font-weight:800;
  color:var(--text-dim);
  text-transform:uppercase;
  letter-spacing:1.5px;
  margin-bottom:7px;
}
.field input{
  width:100%;
  padding:14px 16px;
  background:rgba(5,2,15,0.7);
  border:1px solid rgba(255,183,213,0.15);
  border-radius:14px;
  color:var(--text);
  font-size:16px;
  outline:none;
  transition:all 0.3s;
  font-family:inherit;
}
.field input:focus{
  border-color:var(--sakura);
  background:rgba(255,183,213,0.03);
  box-shadow:0 0 0 3px rgba(255,183,213,0.15),0 0 20px rgba(255,183,213,0.15);
}
.field input::placeholder{color:var(--muted);font-size:14px}
.btn{
  width:100%;
  padding:15px;
  border:none;
  border-radius:14px;
  font-size:13px;
  font-weight:900;
  letter-spacing:2px;
  text-transform:uppercase;
  cursor:pointer;
  transition:all 0.3s;
  font-family:inherit;
  position:relative;
  overflow:hidden;
  margin-top:10px;
  display:flex;
  align-items:center;
  justify-content:center;
  gap:8px;
}
.btn-sakura{
  background:linear-gradient(135deg,var(--sakura-bright),var(--sakura));
  color:#1a0d33;
  box-shadow:0 8px 28px -8px rgba(255,183,213,0.5);
}
.btn-sakura::before{
  content:'';
  position:absolute;
  top:0;
  left:-100%;
  width:100%;
  height:100%;
  background:linear-gradient(90deg,transparent,rgba(255,255,255,0.4),transparent);
  transition:left 0.6s;
}
.btn-sakura:hover:not(:disabled)::before{left:100%}
.btn-sakura:hover:not(:disabled){transform:translateY(-2px);box-shadow:0 12px 36px -8px rgba(255,183,213,0.7)}
.btn-sakura:active{transform:scale(0.98)}
.btn-sakura:disabled{opacity:0.5;cursor:not-allowed}
.btn .ripple{
  position:absolute;
  border-radius:50%;
  background:rgba(255,255,255,0.5);
  transform:scale(0);
  animation:ripple 0.6s ease-out;
  pointer-events:none;
}
@keyframes ripple{to{transform:scale(4);opacity:0}}
.msg{
  margin-top:14px;
  padding:12px 16px;
  border-radius:12px;
  font-size:12px;
  display:flex;
  align-items:center;
  gap:8px;
  animation:fadeDown 0.3s;
}
.msg.err{background:rgba(255,92,122,0.1);border:1px solid rgba(255,92,122,0.3);color:#ffa0b3}
@keyframes fadeDown{from{opacity:0;transform:translateY(-8px)}to{opacity:1;transform:translateY(0)}}
.login-foot{margin-top:20px;text-align:center;font-size:10px;color:var(--muted);line-height:1.8}
.login-foot b{color:var(--sakura)}

/* ═══ INFO ═══ */
.info-wrap{flex:1;display:flex;align-items:center;justify-content:center;padding:20px;overflow-y:auto}
.info-card{
  width:100%;
  max-width:380px;
  position:relative;
  padding:34px 24px 26px;
  animation:popIn 0.7s cubic-bezier(0.34,1.56,0.64,1);
}
.info-close{
  position:absolute;
  top:12px;
  right:12px;
  width:34px;
  height:34px;
  border-radius:50%;
  background:rgba(255,92,122,0.15);
  border:1px solid rgba(255,92,122,0.4);
  color:var(--ruby);
  font-size:16px;
  font-weight:900;
  cursor:pointer;
  display:flex;
  align-items:center;
  justify-content:center;
  transition:all 0.3s;
  font-family:inherit;
}
.info-close:hover{background:rgba(255,92,122,0.3);transform:rotate(90deg)}
.info-avatar{
  width:80px;
  height:80px;
  border-radius:50%;
  margin:0 auto 14px;
  background:linear-gradient(135deg,var(--sakura),var(--lavender));
  display:flex;
  align-items:center;
  justify-content:center;
  font-size:36px;
  font-weight:900;
  color:#1a0d33;
  box-shadow:0 0 40px rgba(255,183,213,0.5),0 0 80px rgba(255,183,213,0.25);
  animation:avatarPop 0.7s cubic-bezier(0.34,1.56,0.64,1) 0.2s both;
}
@keyframes avatarPop{from{transform:scale(0);opacity:0}to{transform:scale(1);opacity:1}}
.info-greet{font-size:14px;color:var(--sakura);font-weight:700;letter-spacing:1px;margin-bottom:4px;text-align:center}
.info-name{font-size:22px;font-weight:900;color:var(--text);margin-bottom:4px;text-align:center}
.info-tag{font-size:10px;color:var(--text-dim);letter-spacing:2px;text-transform:uppercase;font-weight:600;text-align:center}
.info-stats{display:flex;flex-direction:column;gap:10px;margin-top:20px}
.info-stat{
  padding:14px;
  background:rgba(255,183,213,0.05);
  border:1px solid var(--border);
  border-radius:14px;
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:12px;
}
.info-stat .lbl{font-size:11px;color:var(--text-dim);font-weight:700;letter-spacing:0.5px}
.info-stat .val{font-size:15px;font-weight:900;color:var(--gold-bright);font-family:monospace;overflow-wrap:anywhere;text-align:right}
.info-stat .val.small{font-size:11px;color:var(--sakura);letter-spacing:1px}

/* ═══ SETUP ═══ */
.setup-wrap{flex:1;display:flex;align-items:center;justify-content:center;padding:20px;overflow-y:auto}
.setup-card{
  width:100%;
  max-width:380px;
  position:relative;
  padding:32px 24px 26px;
  animation:popIn 0.7s cubic-bezier(0.34,1.56,0.64,1);
}
.setup-back{
  position:absolute;
  top:12px;
  left:12px;
  padding:6px 12px;
  border-radius:20px;
  background:rgba(255,183,213,0.1);
  border:1px solid var(--border);
  color:var(--text-dim);
  font-size:10px;
  font-weight:800;
  cursor:pointer;
  font-family:inherit;
  letter-spacing:1px;
  transition:all 0.2s;
}
.setup-back:hover{background:rgba(255,183,213,0.2);color:var(--sakura);border-color:var(--border-strong)}
.setup-step{font-size:10px;letter-spacing:2px;color:var(--sakura);font-weight:800;text-align:center;margin-bottom:8px;text-transform:uppercase}
.setup-title{font-size:20px;font-weight:900;text-align:center;margin-bottom:6px;color:var(--text)}
.setup-sub{font-size:11px;text-align:center;color:var(--text-dim);line-height:1.6;margin-bottom:22px}
.setup-hint{
  font-size:10px;
  color:var(--text-dim);
  background:rgba(255,183,213,0.06);
  border:1px solid rgba(255,183,213,0.15);
  border-radius:10px;
  padding:12px 14px;
  margin-top:16px;
  line-height:1.7;
  text-align:center;
}
.setup-hint b{color:var(--sakura)}

/* ═══ MAIN ═══ */
.main-header{
  flex-shrink:0;
  display:flex;
  align-items:center;
  gap:12px;
  padding:12px 16px;
  margin:12px 12px 0;
  position:relative;
}
.main-logo{
  width:44px;
  height:44px;
  border-radius:50%;
  object-fit:cover;
  border:1.5px solid var(--sakura);
  box-shadow:0 0 20px rgba(255,183,213,0.35);
  flex-shrink:0;
  background:var(--bg-2);
}
.main-brand{flex:1;min-width:0}
.main-brand h1{
  font-size:13px;
  font-weight:900;
  letter-spacing:2px;
  background:linear-gradient(90deg,var(--sakura-bright),var(--gold-bright));
  -webkit-background-clip:text;
  background-clip:text;
  -webkit-text-fill-color:transparent;
}
.main-brand small{
  display:block;
  font-size:9px;
  color:var(--text-dim);
  letter-spacing:1px;
  margin-top:2px;
  overflow:hidden;
  text-overflow:ellipsis;
  white-space:nowrap;
}
.main-actions{display:flex;gap:6px;flex-shrink:0}
.action-btn{
  width:36px;
  height:36px;
  border-radius:50%;
  border:1px solid var(--border);
  background:rgba(28,15,56,0.6);
  color:var(--text-dim);
  font-size:15px;
  cursor:pointer;
  display:flex;
  align-items:center;
  justify-content:center;
  transition:all 0.25s;
  font-family:inherit;
}
.action-btn.kill{color:var(--ruby);border-color:rgba(255,92,122,0.35);background:rgba(255,92,122,0.1)}
.action-btn.kill:hover{background:rgba(255,92,122,0.25);transform:scale(1.1)}
.action-btn.logout{color:var(--gold);border-color:rgba(255,217,102,0.35);background:rgba(255,217,102,0.1)}
.action-btn.logout:hover{background:rgba(255,217,102,0.25);transform:scale(1.1)}

.main-scroll{
  flex:1;
  overflow-y:auto;
  overflow-x:hidden;
  padding:14px 12px 96px;
  scrollbar-width:thin;
  scrollbar-color:rgba(255,183,213,0.3) transparent;
}
.main-scroll::-webkit-scrollbar{width:4px}
.main-scroll::-webkit-scrollbar-thumb{background:rgba(255,183,213,0.3);border-radius:2px}

.balance-card{
  padding:22px;
  margin-bottom:14px;
  position:relative;
  animation:slideIn 0.5s cubic-bezier(0.34,1.56,0.64,1) 0.05s both;
}
@keyframes slideIn{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}
.balance-label{
  font-size:9px;
  letter-spacing:2px;
  color:var(--text-dim);
  font-weight:800;
  text-transform:uppercase;
  margin-bottom:8px;
  display:flex;
  align-items:center;
  gap:6px;
}
.balance-label::before{content:'💰'}
.balance-value{
  font-size:34px;
  font-weight:900;
  color:var(--gold-bright);
  font-family:"SF Mono","Consolas",monospace;
  letter-spacing:1px;
  line-height:1;
  text-shadow:0 0 24px rgba(255,217,102,0.5);
  transition:all 0.3s;
  display:inline-block;
}
.balance-value.updating{transform:scale(1.06);color:var(--mint);text-shadow:0 0 30px rgba(126,240,180,0.7)}
.balance-suffix{font-size:18px;color:var(--text-dim);margin-left:6px;text-shadow:none}

.result-card{
  padding:32px 20px 26px;
  margin-bottom:14px;
  position:relative;
  text-align:center;
  animation:slideIn 0.5s cubic-bezier(0.34,1.56,0.64,1) 0.15s both;
  min-height:280px;
  display:flex;
  flex-direction:column;
  align-items:center;
  justify-content:center;
}
.result-session{
  font-size:10px;
  letter-spacing:2px;
  color:var(--text-dim);
  font-weight:800;
  text-transform:uppercase;
  margin-bottom:16px;
}
.result-label{
  font-size:11px;
  color:var(--text-dim);
  letter-spacing:3px;
  font-weight:700;
  text-transform:uppercase;
  margin-bottom:10px;
}
.result-prediction{
  font-size:68px;
  font-weight:900;
  line-height:1;
  margin-bottom:8px;
  letter-spacing:4px;
  transition:all 0.4s;
}
.result-prediction.tai{
  background:linear-gradient(135deg,#7ec8ff,#4a9eff,#7ec8ff);
  background-size:200% 100%;
  -webkit-background-clip:text;
  background-clip:text;
  -webkit-text-fill-color:transparent;
  filter:drop-shadow(0 0 30px rgba(78,158,255,0.7));
  animation:shimmer 3s linear infinite;
}
.result-prediction.xiu{
  background:linear-gradient(135deg,#ff8fa0,#ff5c7a,#ff8fa0);
  background-size:200% 100%;
  -webkit-background-clip:text;
  background-clip:text;
  -webkit-text-fill-color:transparent;
  filter:drop-shadow(0 0 30px rgba(255,92,122,0.7));
  animation:shimmer 3s linear infinite;
}
.result-prediction.wait{color:var(--muted);font-size:38px;letter-spacing:4px}
.result-outcome{
  margin-top:20px;
  padding-top:20px;
  border-top:1px dashed rgba(255,183,213,0.2);
  width:100%;
  display:none;
}
.result-outcome.show{display:block;animation:popIn 0.5s cubic-bezier(0.34,1.56,0.64,1)}
.result-outcome .big{font-size:28px;font-weight:900;letter-spacing:2px;margin-bottom:8px}
.result-outcome .big.win{color:var(--mint);text-shadow:0 0 30px rgba(126,240,180,0.6)}
.result-outcome .big.lose{color:var(--ruby);text-shadow:0 0 30px rgba(255,92,122,0.6)}
.result-outcome .detail{
  font-size:12px;
  color:var(--text-dim);
  font-family:"SF Mono",monospace;
  letter-spacing:0.5px;
  line-height:1.7;
}
.result-outcome .detail b{color:var(--gold-bright)}

.bet-card{
  padding:18px 20px;
  margin-bottom:14px;
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:14px;
  position:relative;
  animation:slideIn 0.5s cubic-bezier(0.34,1.56,0.64,1) 0.25s both;
  background:linear-gradient(135deg,rgba(255,183,213,0.1),rgba(28,15,56,0.85));
}
.bet-label{
  font-size:10px;
  letter-spacing:2px;
  color:var(--text-dim);
  font-weight:800;
  text-transform:uppercase;
  margin-bottom:6px;
  display:flex;
  align-items:center;
  gap:6px;
}
.bet-label::before{content:'💎'}
.bet-value{
  font-size:24px;
  font-weight:900;
  color:var(--gold-bright);
  font-family:"SF Mono",monospace;
  letter-spacing:1px;
  text-shadow:0 0 20px rgba(255,217,102,0.5);
  transition:all 0.3s;
}
.bet-value.pulse{animation:betPulse 0.6s ease-out}
@keyframes betPulse{0%{transform:scale(1)}50%{transform:scale(1.15);color:var(--sakura)}100%{transform:scale(1)}}
.bet-streak{text-align:right}
.bet-streak small{
  font-size:9px;
  color:var(--text-dim);
  letter-spacing:1px;
  font-weight:700;
  text-transform:uppercase;
  display:block;
}
.bet-streak b{
  font-size:15px;
  font-weight:900;
  color:var(--sakura);
  font-family:"SF Mono",monospace;
  display:block;
  margin-top:2px;
}

.bottom-nav{
  position:absolute;
  bottom:0;
  left:0;
  right:0;
  padding:10px 20px 14px;
  display:flex;
  justify-content:center;
  gap:8px;
  background:linear-gradient(180deg,rgba(5,2,15,0.3),rgba(5,2,15,0.98) 40%);
  backdrop-filter:blur(20px);
  -webkit-backdrop-filter:blur(20px);
  border-top:1px solid var(--border);
  z-index:10;
}
.nav-btn{
  flex:1;
  max-width:180px;
  padding:12px 16px;
  background:rgba(28,15,56,0.7);
  border:1px solid var(--border);
  color:var(--text-dim);
  font-size:11px;
  font-weight:800;
  letter-spacing:1px;
  border-radius:14px;
  cursor:pointer;
  transition:all 0.25s;
  display:flex;
  align-items:center;
  justify-content:center;
  gap:6px;
  font-family:inherit;
  text-transform:uppercase;
}
.nav-btn.on{
  background:linear-gradient(135deg,var(--sakura-bright),var(--sakura));
  color:#1a0d33;
  border-color:transparent;
  box-shadow:0 6px 20px -6px rgba(255,183,213,0.6);
}

/* ═══ HISTORY ═══ */
.history-header{
  flex-shrink:0;
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:12px;
  padding:14px 18px;
  margin:12px 12px 0;
}
.history-title{font-size:14px;font-weight:900;color:var(--sakura);letter-spacing:2px;text-transform:uppercase}
.history-count{
  font-size:10px;
  color:var(--text-dim);
  font-weight:700;
  padding:4px 10px;
  background:rgba(255,183,213,0.1);
  border-radius:20px;
  border:1px solid var(--border);
}
.hist-scroll{
  flex:1;
  overflow-y:auto;
  padding:14px 12px 96px;
  scrollbar-width:thin;
  scrollbar-color:rgba(255,183,213,0.3) transparent;
}
.hist-scroll::-webkit-scrollbar{width:4px}
.hist-scroll::-webkit-scrollbar-thumb{background:rgba(255,183,213,0.3);border-radius:2px}
.hist-row{
  padding:14px 16px;
  margin-bottom:8px;
  background:linear-gradient(135deg,rgba(28,15,56,0.7),rgba(10,6,24,0.85));
  border:1px solid var(--border);
  border-radius:14px;
  display:flex;
  align-items:center;
  gap:12px;
  border-left:3px solid var(--muted);
  animation:slideIn 0.4s cubic-bezier(0.34,1.56,0.64,1) both;
}
.hist-row.win{border-left-color:var(--mint)}
.hist-row.lose{border-left-color:var(--ruby)}
.hist-row.jackpot{border-left-color:var(--gold)}
.hist-sid{font-family:"SF Mono",monospace;color:var(--sakura);font-weight:800;font-size:11px;min-width:60px}
.hist-mid{flex:1;min-width:0}
.hist-mid .row1{font-size:12px;font-weight:800;margin-bottom:3px;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.hist-mid .row2{font-size:10px;color:var(--text-dim);font-family:"SF Mono",monospace;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.hist-amount{font-family:"SF Mono",monospace;font-weight:900;font-size:13px;min-width:76px;text-align:right}
.hist-amount.win{color:var(--mint)}
.hist-amount.lose{color:var(--ruby)}

.empty-state{padding:60px 20px;text-align:center;color:var(--text-dim);font-size:12px}
.empty-state .icon{font-size:52px;margin-bottom:16px;opacity:0.4;display:block}
.empty-state .title{font-size:14px;font-weight:800;color:var(--text);margin-bottom:6px}
.empty-state .sub{font-size:11px;color:var(--muted)}

#toast{
  position:fixed;
  top:20px;
  right:20px;
  z-index:9999;
  display:flex;
  flex-direction:column;
  gap:8px;
  pointer-events:none;
  max-width:340px;
}
.toast{
  padding:12px 18px;
  border-radius:12px;
  font-size:12px;
  font-weight:600;
  color:#fff;
  background:rgba(28,15,56,0.98);
  border:1px solid var(--border-strong);
  box-shadow:0 12px 32px -8px rgba(0,0,0,0.6);
  backdrop-filter:blur(12px);
  animation:toastIn 0.35s cubic-bezier(0.34,1.56,0.64,1);
}
.toast.success{border-color:rgba(126,240,180,0.4)}
.toast.error{border-color:rgba(255,92,122,0.4)}
.toast.gold{border-color:rgba(255,217,102,0.4)}
@keyframes toastIn{from{opacity:0;transform:translateX(100px)}to{opacity:1;transform:translateX(0)}}

@media (max-width:360px){
  .login-card,.info-card,.setup-card{padding:26px 18px}
  .logo-img{width:90px;height:90px}
  .brand-title{font-size:20px;letter-spacing:3px}
  .result-prediction{font-size:54px}
  .balance-value{font-size:28px}
}
@media (prefers-reduced-motion:reduce){
  .orb,.logo-img,.brand-title,.result-prediction,.hist-row{animation:none!important}
}
</style>
</head>
<body>
<canvas id="particles"></canvas>
<div class="orb orb-1"></div>
<div class="orb orb-2"></div>
<div class="orb orb-3"></div>
<div id="app"></div>
<div id="toast"></div>
<script>
const LOGO_URL = 'https://raw.githubusercontent.com/nguyenha783255-wq/LOGO-LC79/main/IMG_20260901_094944_094.jpg';
const LS_KEY = 'denius_v4';
const app = document.getElementById('app');
const toastBox = document.getElementById('toast');

const S = {
  step: 'login', tab: 'main',
  user: '', nickname: '', balance: 0, authToken: '', device: '',
  loading: false, error: '',
  config: {base_bet:0,profit_stop:0,auto:false,paused:false,lose_streak:0},
  history: [], stats: {wins:0,losses:0,total:0,winrate:0,profit:0},
  pendingPred: null, pendingSession: null, pendingBetAmount: null,
  workerAlive: false,
  setupBaseBet: 0, setupTarget: 0,
};

(function() {
  const d = [navigator.userAgent, navigator.language, screen.width+'x'+screen.height].join('|');
  let h = 0;
  for (let i = 0; i < d.length; i++) h = ((h << 5) - h) + d.charCodeAt(i), h |= 0;
  S.device = 'ONI-' + Math.abs(h).toString(16).toUpperCase().slice(0, 8);
})();

// ═══ PARTICLES ═══
(function initParticles() {
  const canvas = document.getElementById('particles');
  const ctx = canvas.getContext('2d');
  let particles = [];
  const colors = ['#ffb7d5', '#c4a7e7', '#ffd966', '#6ee7ff', '#7ef0b4'];
  function resize() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    particles = [];
    const count = window.innerWidth < 600 ? 40 : 70;
    for (let i = 0; i < count; i++) {
      particles.push({
        x: Math.random() * canvas.width,
        y: Math.random() * canvas.height,
        vx: (Math.random() - 0.5) * 0.35,
        vy: (Math.random() - 0.5) * 0.35,
        r: Math.random() * 2.5 + 0.5,
        color: colors[Math.floor(Math.random() * colors.length)],
        alpha: Math.random() * 0.5 + 0.2,
      });
    }
  }
  function animate() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    for (let i = 0; i < particles.length; i++) {
      const p = particles[i];
      p.x += p.vx;
      p.y += p.vy;
      if (p.x < 0 || p.x > canvas.width) p.vx *= -1;
      if (p.y < 0 || p.y > canvas.height) p.vy *= -1;
      ctx.globalAlpha = p.alpha;
      ctx.fillStyle = p.color;
      ctx.shadowColor = p.color;
      ctx.shadowBlur = 8;
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fill();
    }
    ctx.shadowBlur = 0;
    ctx.globalAlpha = 1;
    requestAnimationFrame(animate);
  }
  resize();
  window.addEventListener('resize', resize, {passive: true});
  animate();
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

function addRipple(btn, e) {
  const rect = btn.getBoundingClientRect();
  const size = Math.max(rect.width, rect.height);
  const r = document.createElement('span');
  r.className = 'ripple';
  r.style.width = r.style.height = size + 'px';
  r.style.left = (e.clientX - rect.left - size/2) + 'px';
  r.style.top = (e.clientY - rect.top - size/2) + 'px';
  btn.appendChild(r);
  setTimeout(() => r.remove(), 600);
}

function saveAuth(u, t, n) {
  try { localStorage.setItem(LS_KEY, JSON.stringify({u, t, n, ts: Date.now()})); } catch(e) {}
}
function loadAuth() {
  try { const j = localStorage.getItem(LS_KEY); return j ? JSON.parse(j) : null; } catch(e) { return null; }
}
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
    '<div class="screen"><div class="login-wrap"><div class="login-card glass neon" style="position:relative">' +
      '<div class="logo-wrap"><img src="' + LOGO_URL + '" class="logo-img" onerror="this.style.display=\'none\'"></div>' +
      '<div class="brand-title">DENIUS</div>' +
      '<div class="brand-sub"><span class="jp">お兄ちゃん</span> · AUTO BOT</div>' +
      '<div class="field"><label>👤 TÀI KHOẢN</label><input id="in_u" type="text" placeholder="Nhập tài khoản..." value="' + esc(S.user) + '"></div>' +
      '<div class="field"><label>🔒 MẬT KHẨU</label><input id="in_p" type="password" placeholder="••••••••"></div>' +
      '<button class="btn btn-sakura" id="btn_login"' + (S.loading ? ' disabled' : '') + '>' + (S.loading ? 'ĐANG XÁC THỰC' : 'ĐĂNG NHẬP') + '</button>' +
      (S.error ? '<div class="msg err">⚠️ ' + esc(S.error) + '</div>' : '') +
      '<div class="login-foot"><b>V4.0 ORIGINAL</b> · Admin <b>@DENIUS09</b></div>' +
    '</div></div></div>';
  const btn = document.getElementById('btn_login');
  btn.onclick = doLogin;
  btn.addEventListener('click', e => addRipple(btn, e));
  document.getElementById('in_p').onkeydown = e => { if (e.key === 'Enter') doLogin(); };
  document.getElementById('in_p').focus();
}

async function doLogin() {
  const u = document.getElementById('in_u').value.trim();
  const p = document.getElementById('in_p').value.trim();
  if (!u || !p) { S.error = 'Vui lòng nhập đầy đủ'; render(); return; }
  S.loading = true; S.error = ''; render();
  try {
    const r = await api('verify', {user:u, pass:p, device:S.device});
    if (!r.ok) { S.loading = false; S.error = r.msg || 'Đăng nhập thất bại'; render(); return; }
    Object.assign(S, {
      user:r.user, nickname:r.nickname, balance:r.balance, config:r.config,
      history:r.history || [], authToken:r.auth_token, workerAlive:!!r.worker_alive, loading:false,
    });
    saveAuth(r.user, r.auth_token, r.nickname);
    if (S.config.onboarded && S.config.base_bet > 0) S.step = 'main';
    else S.step = 'info';
    S.tab = 'main';
    render();
    startTick();
    toast('Chào Ông Chủ ' + r.nickname, 'gold');
  } catch (e) {
    S.loading = false; S.error = 'Lỗi: ' + e.message; render();
  }
}

async function tryResume() {
  const saved = loadAuth();
  if (!saved || !saved.u || !saved.t) { render(); return; }
  try {
    const r = await api('resume', {user:saved.u, auth_token:saved.t});
    if (!r.ok) { clearAuth(); render(); return; }
    Object.assign(S, {
      user:r.user, nickname:r.nickname, balance:r.balance, config:r.config,
      history:r.history || [], authToken:r.auth_token, workerAlive:!!r.worker_alive,
      pendingPred:r.pending_pred, pendingSession:r.pending_session,
      pendingBetAmount:r.pending_bet_amount,
    });
    if (S.config.onboarded && S.config.base_bet > 0) S.step = 'main';
    else S.step = 'info';
    S.tab = 'main';
    saveAuth(r.user, r.auth_token, r.nickname);
    render();
    startTick();
  } catch (e) { clearAuth(); render(); }
}

function renderInfo() {
  const init = (S.nickname || '?')[0].toUpperCase();
  app.innerHTML =
    '<div class="screen"><div class="info-wrap"><div class="info-card glass neon" style="position:relative">' +
      '<button class="info-close" id="btn_close">✕</button>' +
      '<div class="info-avatar">' + esc(init) + '</div>' +
      '<div class="info-greet">ようこそ、お兄ちゃん</div>' +
      '<div class="info-name">' + esc(S.nickname) + '</div>' +
      '<div class="info-tag">ACCOUNT VERIFIED</div>' +
      '<div class="info-stats">' +
        '<div class="info-stat"><span class="lbl">💰 SỐ DƯ</span><span class="val">' + fmt(S.balance) + 'đ</span></div>' +
        '<div class="info-stat"><span class="lbl">🔑 TÀI KHOẢN</span><span class="val">' + esc(S.user) + '</span></div>' +
        '<div class="info-stat"><span class="lbl">📱 DEVICE</span><span class="val small">' + esc(S.device) + '</span></div>' +
      '</div>' +
    '</div></div></div>';
  document.getElementById('btn_close').onclick = () => { S.step = 'base_bet'; render(); };
}

function renderBaseBet() {
  const bal = S.balance || 0;
  let sug = 10000;
  if (bal > 0) sug = Math.max(1000, Math.min(Math.floor(bal * 0.02 / 1000) * 1000, 100000));
  const val = S.setupBaseBet || sug;
  app.innerHTML =
    '<div class="screen"><div class="setup-wrap"><div class="setup-card glass neon" style="position:relative">' +
      '<button class="setup-back" id="btn_back1">← Quay lại</button>' +
      '<div class="setup-step">BƯỚC 1 / 2</div>' +
      '<div class="setup-title">Vốn Cược Mỗi Tay</div>' +
      '<div class="setup-sub">Số dư: <b style="color:var(--gold-bright)">' + fmt(bal) + 'đ</b></div>' +
      '<div class="field"><label>💰 SỐ VỐN (VNĐ)</label><input id="in_base" type="number" inputmode="numeric" value="' + val + '" min="1000" step="1000"></div>' +
      '<button class="btn btn-sakura" id="btn_next1">TIẾP TỤC →</button>' +
      (S.error ? '<div class="msg err">⚠️ ' + esc(S.error) + '</div>' : '') +
      '<div class="setup-hint">💎 Gấp thếp X2 tự động · max <b>4 tay sai</b></div>' +
    '</div></div></div>';
  const inp = document.getElementById('in_base');
  inp.focus(); inp.select();
  document.getElementById('btn_back1').onclick = () => { S.step = 'info'; render(); };
  const nb = document.getElementById('btn_next1');
  nb.onclick = () => {
    const v = parseInt(inp.value) || 0;
    if (v < 1000) { S.error = 'Vốn tối thiểu 1.000đ'; render(); return; }
    S.error = ''; S.setupBaseBet = v; S.step = 'target'; render();
  };
  nb.addEventListener('click', e => addRipple(nb, e));
  inp.onkeydown = e => { if (e.key === 'Enter') nb.click(); };
}

function renderTarget() {
  const bal = S.balance || 0;
  let sug = 100000;
  if (bal > 0) sug = Math.max(10000, Math.floor(bal * 0.1 / 1000) * 1000 || 100000);
  const val = S.setupTarget || sug;
  app.innerHTML =
    '<div class="screen"><div class="setup-wrap"><div class="setup-card glass neon" style="position:relative">' +
      '<button class="setup-back" id="btn_back2">← Quay lại</button>' +
      '<div class="setup-step">BƯỚC 2 / 2</div>' +
      '<div class="setup-title">Mục Tiêu Lợi Nhuận</div>' +
      '<div class="setup-sub">Khi đạt mục tiêu, bot tự dừng.</div>' +
      '<div class="field"><label>🎯 MỤC TIÊU (VNĐ)</label><input id="in_target" type="number" inputmode="numeric" value="' + val + '" min="10000" step="10000"></div>' +
      '<button class="btn btn-sakura" id="btn_start"' + (S.loading ? ' disabled' : '') + '>' + (S.loading ? 'ĐANG KHỞI ĐỘNG' : '🚀 BẮT ĐẦU AUTO') + '</button>' +
      (S.error ? '<div class="msg err">⚠️ ' + esc(S.error) + '</div>' : '') +
      '<div class="setup-hint">⚙️ X2 khi thua · max <b>4 tay</b><br>💰 Vốn mỗi tay: <b>' + fmt(S.setupBaseBet) + 'đ</b></div>' +
    '</div></div></div>';
  const inp = document.getElementById('in_target');
  inp.focus(); inp.select();
  document.getElementById('btn_back2').onclick = () => { S.step = 'base_bet'; render(); };
  const sb = document.getElementById('btn_start');
  sb.onclick = async () => {
    const v = parseInt(inp.value) || 0;
    if (v < 10000) { S.error = 'Mục tiêu tối thiểu 10.000đ'; render(); return; }
    S.error = ''; S.setupTarget = v;
    await startAuto();
  };
  sb.addEventListener('click', e => addRipple(sb, e));
  inp.onkeydown = e => { if (e.key === 'Enter') sb.click(); };
}

async function startAuto() {
  S.loading = true; render();
  try {
    const r = await api('setup', {
      user:S.user, base_bet:S.setupBaseBet,
      profit_stop:S.setupTarget,
    });
    if (!r.ok) { S.loading = false; S.error = r.msg || 'Không thể bắt đầu'; render(); return; }
    S.config = r.config;
    S.loading = false;
    S.step = 'main'; S.tab = 'main';
    render();
    startTick();
    toast('🚀 AUTO đã bật', 'success');
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

  app.innerHTML =
    '<div class="screen">' +
      '<div class="main-header glass">' +
        '<img src="' + LOGO_URL + '" class="main-logo" onerror="this.style.display=\'none\'">' +
        '<div class="main-brand"><h1>DENIUS</h1><small>お兄ちゃん · ' + esc(S.nickname) + '</small></div>' +
        '<div class="main-actions">' +
          '<button class="action-btn kill" id="btn_kill" title="Dừng">⏹</button>' +
          '<button class="action-btn logout" id="btn_logout" title="Đăng xuất">⏏</button>' +
        '</div>' +
      '</div>' +
      '<div class="main-scroll">' +
        '<div class="balance-card glass neon" style="position:relative">' +
          '<div class="balance-label">SỐ DƯ HIỆN TẠI</div>' +
          '<span class="balance-value" id="bal_val">' + fmt(S.balance) + '</span><span class="balance-suffix">đ</span>' +
        '</div>' +
        '<div class="result-card glass">' +
          '<div class="result-session">PHIÊN #' + (S.pendingSession || '—') + '</div>' +
          '<div class="result-label">' + (p ? 'DỰ ĐOÁN' : 'ĐANG PHÂN TÍCH') + '</div>' +
          '<div class="result-prediction ' + predCls + '" id="pred_val">' + predTxt + '</div>' +
          '<div class="result-outcome ' + (lastH ? 'show' : '') + '" id="outcome_box">' + (lastH ? renderOutcome(lastH) : '') + '</div>' +
        '</div>' +
        '<div class="bet-card glass">' +
          '<div><div class="bet-label">SỐ TIỀN CƯỢC</div><div class="bet-value" id="bet_val">' + betTxt + '</div></div>' +
          '<div class="bet-streak"><small>CHUỖI THUA</small><b id="streak_val">' + (S.config.lose_streak || 0) + '/4</b></div>' +
        '</div>' +
      '</div>' +
      '<div class="bottom-nav">' +
        '<button class="nav-btn on" id="nav_main">🎯 Chính</button>' +
        '<button class="nav-btn" id="nav_hist">📜 Lịch sử</button>' +
      '</div>' +
    '</div>';

  document.getElementById('nav_main').onclick = () => { S.tab = 'main'; render(); };
  document.getElementById('nav_hist').onclick = () => { S.tab = 'history'; render(); };
  document.getElementById('btn_kill').onclick = doKill;
  document.getElementById('btn_logout').onclick = doLogout;
}

function renderOutcome(h) {
  if (!h) return '';
  let cls = 'lose', label = '💔 THUA';
  if (h.win) { cls = 'win'; label = '🎉 THẮNG'; }
  const dice = (h.dices || []).join('-');
  let delta = '-' + fmt(h.amount);
  if (h.win) delta = '+' + fmt(Math.floor(h.amount * 0.98));
  let jpStr = '';
  if (h.jackpot) jpStr = '<br>✨ JACKPOT ✨';
  const predTxt = h.pred === 'Tài' ? 'TÀI' : 'XỈU';
  const resTxt = h.result === 'TAI' ? 'TÀI' : 'XỈU';
  return '<div class="big ' + cls + '">' + label + '</div>' +
    '<div class="detail">🎲 ' + dice + ' · ' + predTxt + ' → ' + resTxt + '<br><b>' + delta + 'đ</b>' + jpStr + '</div>';
}

async function doKill() {
  if (!confirm('🛑 TẮT AUTO? Toàn bộ lệnh cược sẽ dừng ngay.')) return;
  try {
    await api('kill', {user:S.user});
    S.config.auto = false; S.config.paused = true;
    S.pendingPred = null; S.pendingSession = null; S.pendingBetAmount = null;
    toast('🛑 ĐÃ DỪNG TOÀN BỘ', 'error');
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
    body = '<div class="empty-state"><span class="icon">🌸</span><div class="title">Chưa có lịch sử</div><div class="sub">Bắt đầu AUTO để ghi nhận</div></div>';
  } else {
    body = hist.slice(0, 100).map((h, idx) => {
      let cls = 'lose';
      let delta = '-' + fmt(h.amount);
      if (h.win) { cls = 'win'; delta = '+' + fmt(Math.floor(h.amount * 0.98)); }
      const jp = h.jackpot ? 'jackpot' : '';
      const dice = (h.dices || []).join('-');
      const predTxt = h.pred === 'Tài' ? '🔵 TÀI' : '🔴 XỈU';
      const resTxt = h.result === 'TAI' ? '🔵 TÀI' : '🔴 XỈU';
      const jpIcon = h.jackpot ? ' 🎉' : '';
      const delay = Math.min(idx * 0.02, 0.5);
      return '<div class="hist-row ' + cls + ' ' + jp + '" style="animation-delay:' + delay + 's">' +
        '<div class="hist-sid">#' + h.session + '</div>' +
        '<div class="hist-mid">' +
          '<div class="row1">' + predTxt + ' → ' + resTxt + jpIcon + '</div>' +
          '<div class="row2">🎲 ' + dice + ' · ' + h.ts + '</div>' +
        '</div>' +
        '<div class="hist-amount ' + cls + '">' + delta + '</div>' +
      '</div>';
    }).join('');
  }
  app.innerHTML =
    '<div class="screen">' +
      '<div class="history-header glass">' +
        '<div class="history-title">📜 LỊCH SỬ</div>' +
        '<div class="history-count">' + hist.length + ' phiên</div>' +
      '</div>' +
      '<div class="hist-scroll" id="hist_list">' + body + '</div>' +
      '<div class="bottom-nav">' +
        '<button class="nav-btn" id="nav_main2">🎯 Chính</button>' +
        '<button class="nav-btn on" id="nav_hist2">📜 Lịch sử</button>' +
      '</div>' +
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

function animateNumber(el, from, to) {
  const start = performance.now();
  const dur = 500;
  function frame(now) {
    const p = Math.min(1, (now - start) / dur);
    const ease = 1 - Math.pow(1 - p, 3);
    const val = Math.round(from + (to - from) * ease);
    el.textContent = fmt(val);
    if (p < 1) requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);
}

let tickBusy = false;
async function tick() {
  if (!S.user || !S.authToken || tickBusy) return;
  tickBusy = true;
  try {
    await api('tick', {user:S.user}).catch(() => {});
    const j = await getStatus();
    if (!j.ok) { tickBusy = false; return; }
    const oldBal = S.balance;
    S.balance = j.balance || 0;
    S.history = j.history || [];
    S.workerAlive = !!j.worker_alive;
    S.stats = j.stats || S.stats;
    S.pendingPred = j.pending_pred;
    S.pendingSession = j.pending_session;
    S.pendingBetAmount = j.pending_bet_amount;
    if (j.config) {
      S.config.auto = j.config.auto;
      S.config.paused = j.config.paused;
      S.config.lose_streak = j.config.lose_streak;
      S.config.base_bet = j.config.base_bet;
      S.config.profit_stop = j.config.profit_stop;
    }
    if (S.step === 'main' && S.tab === 'main') {
      const bv = document.getElementById('bal_val');
      if (bv && S.balance !== oldBal) {
        bv.classList.add('updating');
        animateNumber(bv, oldBal, S.balance);
        setTimeout(() => bv.classList.remove('updating'), 600);
      }
      const pv = document.getElementById('pred_val');
      if (pv) {
        let cls = 'wait';
        if (S.pendingPred === 'Tài') cls = 'tai';
        else if (S.pendingPred === 'Xỉu') cls = 'xiu';
        pv.className = 'result-prediction ' + cls;
        pv.textContent = S.pendingPred || 'ĐANG CHỜ';
      }
      const ps = document.querySelector('.result-session');
      if (ps) ps.textContent = 'PHIÊN #' + (S.pendingSession || '—');
      const pl = document.querySelector('.result-label');
      if (pl) pl.textContent = S.pendingPred ? 'DỰ ĐOÁN' : 'ĐANG PHÂN TÍCH';
      const bv2 = document.getElementById('bet_val');
      if (bv2) {
        let newTxt = '—';
        if (S.pendingBetAmount) newTxt = fmt(S.pendingBetAmount) + 'đ';
        if (bv2.textContent !== newTxt) {
          bv2.textContent = newTxt;
          bv2.classList.add('pulse');
          setTimeout(() => bv2.classList.remove('pulse'), 600);
        }
      }
      const ob = document.getElementById('outcome_box');
      if (ob && S.history[0]) {
        ob.innerHTML = renderOutcome(S.history[0]);
        ob.classList.add('show');
      }
      const sv = document.getElementById('streak_val');
      if (sv) sv.textContent = (S.config.lose_streak || 0) + '/4';
    } else if (S.step === 'main' && S.tab === 'history') {
      const hl = document.getElementById('hist_list');
      if (hl && S.history.length) {
        const keys = S.history.map(h => h.session).join(',');
        if (hl.dataset.keys !== keys) {
          hl.dataset.keys = keys;
          hl.innerHTML = S.history.slice(0, 100).map((h, idx) => {
            let cls = 'lose';
            let delta = '-' + fmt(h.amount);
            if (h.win) { cls = 'win'; delta = '+' + fmt(Math.floor(h.amount * 0.98)); }
            const jp = h.jackpot ? 'jackpot' : '';
            const dice = (h.dices || []).join('-');
            const predTxt = h.pred === 'Tài' ? '🔵 TÀI' : '🔴 XỈU';
            const resTxt = h.result === 'TAI' ? '🔵 TÀI' : '🔴 XỈU';
            const jpIcon = h.jackpot ? ' 🎉' : '';
            const delay = Math.min(idx * 0.02, 0.5);
            return '<div class="hist-row ' + cls + ' ' + jp + '" style="animation-delay:' + delay + 's">' +
              '<div class="hist-sid">#' + h.session + '</div>' +
              '<div class="hist-mid">' +
                '<div class="row1">' + predTxt + ' → ' + resTxt + jpIcon + '</div>' +
                '<div class="row2">🎲 ' + dice + ' · ' + h.ts + '</div>' +
              '</div>' +
              '<div class="hist-amount ' + cls + '">' + delta + '</div>' +
            '</div>';
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
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible' && S.user && S.authToken) tick();
  });
}

tryResume();
</script>
</body>
</html>
<?php }