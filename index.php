<?php
/**
 * DENIUS AUTO — ONIICHAN SUPREME v3.0
 * ttoan 100% verbatim | Detective Layer | Anti-Reset | Remember Login
 */
$CFG = [
    'version' => '3.0.0-supreme',
    'game' => [
        'login_url'    => 'https://apifo88daigia.tele68.com/api?c=3&un={USER}&pw={PASS_MD5}&cp=R&cl=R&pf=web&at=',
        'lobby_url'    => 'https://wlb.tele68.com/v1/lobby/auth/login?cp=R&cl=R&pf=web&at=',
        'ws_host'      => 'wtx.tele68.com',
        'ws_path'      => '/tx/',
        'sessions_api' => 'https://wtx.tele68.com/v1/tx/sessions',
    ],
    'security' => [
        'hmac_secret' => 'DENIUS_SUPREME_2024_HMAC_FIXED_KEY',
        'session_ttl' => 2592000, // 30 ngày - nhớ tài khoản
    ],
    'worker' => [
        'loop_sleep'     => 1,
        'resume_timeout' => 90,
        'max_runtime'    => 3600,
        'respawn_buffer' => 60,
    ],
    // JSONBin optional - nếu điền key sẽ backup state lên cloud (chống Render reset)
    'jsonbin' => [
        'enabled' => false,
        'key' => '',       // Điền key JSONBin.io nếu muốn persistent storage
        'bin_id' => '',    // Bin ID chứa state chung
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
header('Referrer-Policy: no-referrer');
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
    $d = base64_decode($tok, true); if ($d === false) return false;
    $parts = explode('|', $d); if (count($parts) !== 3) return false;
    [$user, $exp, $sig] = $parts;
    if ($user !== $u || (int)$exp < time()) return false;
    return hash_equals(hmac_sign($user . '|' . $exp), $sig);
}
function require_auth(string $u, string $tok): bool {
    return $u && $tok && verify_token($tok, $u) && (bool)key_load_by_user($u);
}

// ═══════ STORAGE ═══════
function key_path(string $key): string { return KEY_DIR . '/' . hash('sha256', strtolower(trim($key))) . '.json'; }
function key_load(string $key): array {
    $p = key_path($key); if (!is_file($p)) return [];
    $j = json_decode(file_get_contents($p), true);
    return is_array($j) ? $j : [];
}
function key_save(string $key, array $d): void {
    $p = key_path($key); $t = $p . '.tmp';
    file_put_contents($t, json_encode($d, JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT), LOCK_EX);
    rename($t, $p); @chmod($p, 0600);
    denius_cloud_backup($key, $d);
}
function key_update(string $key, callable $mutator): array {
    $p = key_path($key);
    $fp = @fopen($p, 'c+');
    if (!$fp) { $d = key_load($key); $mutator($d); return $d; }
    @flock($fp, LOCK_EX);
    $raw = stream_get_contents($fp);
    $d = json_decode($raw ?: '{}', true);
    if (!is_array($d)) $d = [];
    $new = $mutator($d);
    if (is_array($new)) $d = $new;
    ftruncate($fp, 0); rewind($fp);
    fwrite($fp, json_encode($d, JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT));
    fflush($fp); @flock($fp, LOCK_UN); fclose($fp); @chmod($p, 0600);
    return $d;
}
function key_log(string $key, string $lvl, string $msg): void {
    key_update($key, function($d) use ($lvl, $msg) {
        $d['logs'] = $d['logs'] ?? [];
        array_unshift($d['logs'], ['ts'=>date('H:i:s d/m'), 'level'=>$lvl, 'msg'=>$msg]);
        $d['logs'] = array_slice($d['logs'], 0, 300);
        return $d;
    });
}
function key_load_by_user(string $user): array {
    $idx = DATA_DIR . '/user_index.json';
    if (!is_file($idx)) return [];
    $m = json_decode(file_get_contents($idx), true) ?: [];
    $k = $m[strtolower($user)] ?? null;
    return $k ? key_load($k) : [];
}
function key_save_by_user(string $user, string $key): void {
    $idx = DATA_DIR . '/user_index.json';
    $m = is_file($idx) ? (json_decode(file_get_contents($idx), true) ?: []) : [];
    $m[strtolower($user)] = $key;
    file_put_contents($idx, json_encode($m, JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT), LOCK_EX);
}
function key_resolve(string $u): string {
    $idx = DATA_DIR . '/user_index.json';
    if (is_file($idx)) {
        $m = json_decode(file_get_contents($idx), true) ?: [];
        if (isset($m[strtolower($u)])) return $m[strtolower($u)];
    }
    return $u;
}

// ═══════ CLOUD BACKUP (chống Render reset) ═══════
function denius_cloud_backup(string $key, array $data): void {
    global $CFG;
    if (empty($CFG['jsonbin']['enabled']) || empty($CFG['jsonbin']['key']) || empty($CFG['jsonbin']['bin_id'])) return;
    try {
        $url = 'https://api.jsonbin.io/v3/b/' . $CFG['jsonbin']['bin_id'];
        $body = json_encode(['key'=>$key, 'data'=>$data, 'ts'=>time()], JSON_UNESCAPED_UNICODE);
        $ctx = stream_context_create(['http'=>[
            'method'=>'PUT',
            'header'=>"Content-Type: application/json\r\nX-Master-Key: {$CFG['jsonbin']['key']}\r\nX-Bin-Versioning: false\r\n",
            'content'=>$body,
            'timeout'=>3,
            'ignore_errors'=>true,
        ]]);
        @file_get_contents($url, false, $ctx);
    } catch (Throwable $e) {}
}
function denius_cloud_restore(string $key): ?array {
    global $CFG;
    if (empty($CFG['jsonbin']['enabled']) || empty($CFG['jsonbin']['key']) || empty($CFG['jsonbin']['bin_id'])) return null;
    try {
        $url = 'https://api.jsonbin.io/v3/b/' . $CFG['jsonbin']['bin_id'] . '/latest';
        $ctx = stream_context_create(['http'=>[
            'header'=>"X-Master-Key: {$CFG['jsonbin']['key']}\r\n",
            'timeout'=>3,
            'ignore_errors'=>true,
        ]]);
        $raw = @file_get_contents($url, false, $ctx);
        if (!$raw) return null;
        $j = json_decode($raw, true);
        if (!isset($j['record']['key']) || $j['record']['key'] !== $key) return null;
        return $j['record']['data'] ?? null;
    } catch (Throwable $e) { return null; }
}

// ═══════ GAME LOGIN ═══════
function game_login(string $u, string $p): array {
    global $CFG;
    $url = str_replace(['{USER}','{PASS_MD5}'], [urlencode($u), md5($p)], $CFG['game']['login_url']);
    $ctx = stream_context_create(['http'=>['timeout'=>15,'ignore_errors'=>true,'header'=>"User-Agent: Mozilla/5.0\r\n"]]);
    $raw = @file_get_contents($url, false, $ctx);
    if (!$raw) return ['_error'=>'Không kết nối server game'];
    $d = json_decode($raw, true);
    if (!is_array($d) || empty($d['success'])) return ['_error'=>'Đăng nhập thất bại: '.($d['message']??'Sai TK/MK')];
    $sk = $d['sessionKey'] ?? ''; $sk .= str_repeat('=', (4 - strlen($sk)%4)%4);
    $sess = json_decode(base64_decode($sk), true) ?: [];
    $nick = $sess['nickname'] ?? $sess['nickName'] ?? '';
    $body = json_encode(['nickName'=>$nick,'accessToken'=>$d['accessToken']??'']);
    $ctx2 = stream_context_create(['http'=>['method'=>'POST','header'=>"Content-Type: application/json\r\nUser-Agent: Mozilla/5.0\r\n",'content'=>$body,'timeout'=>15,'ignore_errors'=>true]]);
    $raw2 = @file_get_contents($CFG['game']['lobby_url'], false, $ctx2);
    $lb = json_decode($raw2 ?: '', true) ?: [];
    if (empty($lb['token'])) return ['_error'=>'Lobby không trả JWT'];
    return ['token'=>$lb['token'],'nickname'=>$nick,'money'=>$lb['loginResp']['money'] ?? $lb['remoteLoginResp']['money'] ?? 0];
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
    return is_array($j) && isset($j['list']) ? $j : null;
}

// ═══════ TTOAN — 100% VERBATIM ═══════
const TTOAN_TONG_DIEM_MEO = [
    3=>['ket_qua'=>'Xỉu','xac_suat'=>0.70],4=>['ket_qua'=>'Tài','xac_suat'=>0.60],
    5=>['ket_qua'=>'Tài','xac_suat'=>0.70],6=>['ket_qua'=>'Xỉu','xac_suat'=>0.60],
    7=>['ket_qua'=>'Tài','xac_suat'=>0.80],8=>['ket_qua'=>'Xỉu','xac_suat'=>0.80],
    9=>['ket_qua'=>'Xỉu','xac_suat'=>0.70],10=>['ket_qua'=>'Tài','xac_suat'=>0.80],
    11=>['ket_qua'=>'Xỉu','xac_suat'=>0.60],12=>['ket_qua'=>'Tài','xac_suat'=>0.80],
    13=>['ket_qua'=>'Tài','xac_suat'=>0.80],14=>['ket_qua'=>'Xỉu','xac_suat'=>0.60],
    15=>['ket_qua'=>'Xỉu','xac_suat'=>0.70],16=>['ket_qua'=>'Tài','xac_suat'=>0.60],
    17=>['ket_qua'=>'Xỉu','xac_suat'=>0.60],18=>['ket_qua'=>'Xỉu','xac_suat'=>0.80],
];
const TTOAN_CAU_PATTERNS = [
    '1-1'=>['desc'=>'Cầu 1-1','weight'=>0.85],'1-2'=>['desc'=>'Cầu 1-2','weight'=>0.80],
    '2-1'=>['desc'=>'Cầu 2-1','weight'=>0.80],'2-2'=>['desc'=>'Cầu 2-2','weight'=>0.85],
    '2-3'=>['desc'=>'Cầu 2-3','weight'=>0.75],'3-2'=>['desc'=>'Cầu 3-2','weight'=>0.75],
    '3-3'=>['desc'=>'Cầu 3-3','weight'=>0.70],'3-4'=>['desc'=>'Cầu 3-4','weight'=>0.65],
    '4-3'=>['desc'=>'Cầu 4-3','weight'=>0.65],'4-4'=>['desc'=>'Cầu 4-4','weight'=>0.60],
    '1-3'=>['desc'=>'Cầu 1-3','weight'=>0.70],'3-1'=>['desc'=>'Cầu 3-1','weight'=>0.70],
    '1-4'=>['desc'=>'Cầu 1-4','weight'=>0.65],'4-1'=>['desc'=>'Cầu 4-1','weight'=>0.65],
    'bệt'=>['desc'=>'Cầu bệt','weight'=>0.50],'đảo'=>['desc'=>'Cầu đảo','weight'=>0.75],
    'cầu nghiêng'=>['desc'=>'Cầu nghiêng','weight'=>0.70],'cầu lặp'=>['desc'=>'Cầu lặp','weight'=>0.85],
    'cầu đan'=>['desc'=>'Cầu đan','weight'=>0.75],
];
function ttoan_random(): float { return (float)mt_rand() / (float)(mt_getrandmax() + 1); }

function ttoan_detect_streak_and_break(array $h): array {
    $h = array_values($h);
    if (count($h) === 0) return ['streak'=>0,'currentResult'=>null,'breakProb'=>0.0];
    $streak = 1; $cur = $h[count($h)-1]['ket_qua'];
    for ($i = count($h)-2; $i >= 0; $i--) if ($h[$i]['ket_qua'] === $cur) $streak++; else break;
    $l15 = array_map(fn($it)=>$it['ket_qua'], array_slice($h, -15));
    if (count($l15) === 0) return ['streak'=>$streak,'currentResult'=>$cur,'breakProb'=>0.0];
    $sw = 0; for ($i = 1; $i < count($l15); $i++) if ($l15[$i] !== $l15[$i-1]) $sw++;
    $tc = count(array_filter($l15, fn($r) => $r === 'Tài')); $xc = count($l15) - $tc;
    $imb = abs($tc - $xc) / count($l15); $bp = 0.0;
    if ($streak >= 8) $bp = min(0.6 + $sw/15 + $imb*0.15, 0.9);
    elseif ($streak >= 5) $bp = min(0.35 + $sw/10 + $imb*0.25, 0.85);
    elseif ($streak >= 3 && $sw >= 7) $bp = 0.3;
    return ['streak'=>$streak,'currentResult'=>$cur,'breakProb'=>$bp];
}
function ttoan_evaluate_model_performance(array $h, string $name, array $mp, int $lb = 10): float {
    $h = array_values($h);
    if (!isset($mp[$name]) || count($h) < 2) return 1.0;
    $lb = min($lb, count($h) - 1); $c = 0;
    for ($i = 0; $i < $lb; $i++) {
        $sid = $h[count($h) - ($i + 2)]['phien'];
        $p = $mp[$name][$sid] ?? 0; $a = $h[count($h) - ($i + 1)]['ket_qua'];
        if (($p === 1 && $a === 'Tài') || ($p === 2 && $a === 'Xỉu')) $c++;
    }
    $ratio = ($lb > 0) ? 1 + ($c - $lb / 2) / ($lb / 2) : 1.0;
    return max(0.5, min(1.5, $ratio));
}
function ttoan_smart_bridge_break(array $h): array {
    $h = array_values($h);
    if (count($h) < 3) return ['prediction'=>0,'breakProb'=>0.0,'reason'=>'Không đủ dữ liệu'];
    $sb = ttoan_detect_streak_and_break($h);
    $streak = $sb['streak']; $cur = $sb['currentResult']; $bp = $sb['breakProb'];
    $l20r = array_map(fn($it)=>$it['ket_qua'], array_slice($h, -20));
    $l20s = array_map(fn($it)=>$it['tong'] ?? 0, array_slice($h, -20));
    $fbp = $bp; $reason = '';
    $avg = array_sum($l20s) / (count($l20s) ?: 1); $ds = 0.0;
    foreach ($l20s as $s) $ds += abs($s - $avg);
    $sd = $ds / (count($l20s) ?: 1);
    $l5 = array_slice($l20r, -5); $pc = [];
    for ($i = 0; $i <= count($l20r) - 3; $i++) {
        $p = implode(',', array_slice($l20r, $i, 3)); $pc[$p] = ($pc[$p] ?? 0) + 1;
    }
    $mcp = null;
    if (count($pc) > 0) { arsort($pc); $mcp = [key($pc), current($pc)]; }
    $hr = ($mcp !== null && $mcp[1] >= 3);
    $l5s = count($l5) > 0; foreach ($l5 as $r) if ($r !== $cur) { $l5s = false; break; }
    if ($streak >= 6) { $fbp = min($fbp + 0.15, 0.9); $reason = "[Bẻ Cầu] Chuỗi $streak $cur dài"; }
    elseif ($streak >= 4 && $sd > 3) { $fbp = min($fbp + 0.10, 0.85); $reason = sprintf("[Bẻ Cầu] Biến động %.1f", $sd); }
    elseif ($hr && $l5s) { $fbp = min($fbp + 0.05, 0.8); $reason = "[Bẻ Cầu] Mẫu lặp {$mcp[0]}"; }
    else { $fbp = max($fbp - 0.15, 0.15); $reason = '[Bẻ Cầu] Không mẫu mạnh'; }
    $pred = ($fbp > 0.65) ? ($cur === 'Tài' ? 2 : 1) : ($cur === 'Tài' ? 1 : 2);
    return ['prediction'=>$pred,'breakProb'=>$fbp,'reason'=>$reason];
}
function ttoan_trend_and_prob(array $h): int {
    $h = array_values($h); if (count($h) < 3) return 0;
    $sb = ttoan_detect_streak_and_break($h);
    if ($sb['streak'] >= 5) {
        if ($sb['breakProb'] > 0.75) return $sb['currentResult'] === 'Tài' ? 2 : 1;
        return $sb['currentResult'] === 'Tài' ? 1 : 2;
    }
    $l15 = array_map(fn($it)=>$it['ket_qua'], array_slice($h, -15));
    if (count($l15) === 0) return 0;
    $tw = 0.0; $xw = 0.0;
    foreach ($l15 as $i => $r) { $w = pow(1.2, $i); if ($r === 'Tài') $tw += $w; else $xw += $w; }
    $tot = $tw + $xw; $l10 = array_slice($l15, -10); $pats = [];
    if (count($l10) >= 4) for ($i = 0; $i <= count($l10) - 4; $i++) $pats[] = implode(',', array_slice($l10, $i, 4));
    $pc = []; foreach ($pats as $p) $pc[$p] = ($pc[$p] ?? 0) + 1;
    $mc = null; if (count($pc) > 0) { arsort($pc); $mc = [key($pc), current($pc)]; }
    if ($mc !== null && $mc[1] >= 3) {
        $pp = explode(',', $mc[0]); return ($pp[count($pp) - 1] !== $l10[count($l10) - 1]) ? 1 : 2;
    }
    if ($tot > 0 && abs($tw - $xw) / $tot >= 0.25) return $tw > $xw ? 2 : 1;
    return $l15[count($l15) - 1] === 'Xỉu' ? 1 : 2;
}
function ttoan_short_pattern(array $h): int {
    $h = array_values($h); if (count($h) < 3) return 0;
    $sb = ttoan_detect_streak_and_break($h);
    if ($sb['streak'] >= 4) {
        if ($sb['breakProb'] > 0.75) return $sb['currentResult'] === 'Tài' ? 2 : 1;
        return $sb['currentResult'] === 'Tài' ? 1 : 2;
    }
    $l8 = array_map(fn($it)=>$it['ket_qua'], array_slice($h, -8));
    if (count($l8) === 0) return 0;
    $pats = []; if (count($l8) >= 3) for ($i = 0; $i <= count($l8) - 3; $i++) $pats[] = implode(',', array_slice($l8, $i, 3));
    $pc = []; foreach ($pats as $p) $pc[$p] = ($pc[$p] ?? 0) + 1;
    $mc = null; if (count($pc) > 0) { arsort($pc); $mc = [key($pc), current($pc)]; }
    if ($mc !== null && $mc[1] >= 2) {
        $pp = explode(',', $mc[0]); return ($pp[count($pp) - 1] !== $l8[count($l8) - 1]) ? 1 : 2;
    }
    return $l8[count($l8) - 1] === 'Xỉu' ? 1 : 2;
}
function ttoan_mean_deviation(array $h): int {
    $h = array_values($h); if (count($h) < 3) return 0;
    $sb = ttoan_detect_streak_and_break($h);
    if ($sb['streak'] >= 4) {
        if ($sb['breakProb'] > 0.75) return $sb['currentResult'] === 'Tài' ? 2 : 1;
        return $sb['currentResult'] === 'Tài' ? 1 : 2;
    }
    $l12 = array_map(fn($it)=>$it['ket_qua'], array_slice($h, -12));
    if (count($l12) === 0) return 0;
    $tc = count(array_filter($l12, fn($r) => $r === 'Tài')); $xc = count($l12) - $tc;
    if (abs($tc - $xc) / count($l12) < 0.35) return $l12[count($l12) - 1] === 'Xỉu' ? 1 : 2;
    return $xc > $tc ? 1 : 2;
}
function ttoan_recent_switch(array $h): int {
    $h = array_values($h); if (count($h) < 3) return 0;
    $sb = ttoan_detect_streak_and_break($h);
    if ($sb['streak'] >= 4) {
        if ($sb['breakProb'] > 0.75) return $sb['currentResult'] === 'Tài' ? 2 : 1;
        return $sb['currentResult'] === 'Tài' ? 1 : 2;
    }
    $l10 = array_map(fn($it)=>$it['ket_qua'], array_slice($h, -10));
    if (count($l10) === 0) return 0;
    $last = $l10[count($l10) - 1];
    return $last === 'Xỉu' ? 1 : 2;
}
function ttoan_is_bad_pattern(array $h): bool {
    $h = array_values($h); if (count($h) < 3) return false;
    $l15 = array_map(fn($it)=>$it['ket_qua'], array_slice($h, -15));
    if (count($l15) === 0) return false;
    $sw = 0; for ($i = 1; $i < count($l15); $i++) if ($l15[$i] !== $l15[$i-1]) $sw++;
    $sb = ttoan_detect_streak_and_break($h);
    return ($sw >= 9 || $sb['streak'] >= 10);
}
function ttoan_ai_htdd_logic(array $h): array {
    $h = array_values($h);
    if (count($h) < 3) { $p = ttoan_random() < 0.5 ? 'Tài' : 'Xỉu'; return ['prediction'=>$p,'reason'=>'Không đủ lịch sử','source'=>'AI HTDD']; }
    $l5 = array_map(fn($it)=>$it['ket_qua'], array_slice($h, -5));
    $l5s = array_map(fn($it)=>$it['tong'] ?? 0, array_slice($h, -5));
    $tc = count(array_filter($l5, fn($r) => $r === 'Tài')); $xc = count($l5) - $tc;
    $l3 = array_map(fn($it)=>$it['ket_qua'], array_slice($h, -3));
    if (implode(',', $l3) === 'Tài,Xỉu,Tài') return ['prediction'=>'Xỉu','reason'=>'Mẫu 1T1X','source'=>'AI HTDD'];
    if (implode(',', $l3) === 'Xỉu,Tài,Xỉu') return ['prediction'=>'Tài','reason'=>'Mẫu 1X1T','source'=>'AI HTDD'];
    if (count($h) >= 4) {
        $l4 = array_map(fn($it)=>$it['ket_qua'], array_slice($h, -4));
        if (implode(',', $l4) === 'Tài,Tài,Xỉu,Xỉu') return ['prediction'=>'Tài','reason'=>'Mẫu 2T2X','source'=>'AI HTDD'];
        if (implode(',', $l4) === 'Xỉu,Xỉu,Tài,Tài') return ['prediction'=>'Xỉu','reason'=>'Mẫu 2X2T','source'=>'AI HTDD'];
    }
    if (count($h) >= 9) {
        $l6 = array_slice($h, -6); $aT = true; $aX = true;
        foreach ($l6 as $it) { if ($it['ket_qua'] !== 'Tài') $aT = false; if ($it['ket_qua'] !== 'Xỉu') $aX = false; }
        if ($aT) return ['prediction'=>'Xỉu','reason'=>'Chuỗi Tài 6','source'=>'AI HTDD'];
        if ($aX) return ['prediction'=>'Tài','reason'=>'Chuỗi Xỉu 6','source'=>'AI HTDD'];
    }
    $avg = array_sum($l5s) / (count($l5s) ?: 1);
    if ($avg > 10) return ['prediction'=>'Tài','reason'=>sprintf('TB cao (%.1f)', $avg),'source'=>'AI HTDD'];
    if ($avg < 8) return ['prediction'=>'Xỉu','reason'=>sprintf('TB thấp (%.1f)', $avg),'source'=>'AI HTDD'];
    if ($tc > $xc + 1) return ['prediction'=>'Xỉu','reason'=>"Tài đa số $tc/".count($l5),'source'=>'AI HTDD'];
    if ($xc > $tc + 1) return ['prediction'=>'Tài','reason'=>"Xỉu đa số $xc/".count($l5),'source'=>'AI HTDD'];
    $tt = count(array_filter($h, fn($it) => $it['ket_qua'] === 'Tài')); $tx = count($h) - $tt;
    if ($tt > $tx + 2) return ['prediction'=>'Xỉu','reason'=>'Tổng Tài nhiều','source'=>'AI HTDD'];
    if ($tx > $tt + 2) return ['prediction'=>'Tài','reason'=>'Tổng Xỉu nhiều','source'=>'AI HTDD'];
    return ['prediction'=>ttoan_random() < 0.5 ? 'Tài' : 'Xỉu','reason'=>'Cân bằng','source'=>'AI HTDD'];
}
function ttoan_phan_tich_cau(array $h): array {
    $h = array_values($h);
    if (count($h) < 3) return ['cau'=>'Khong xac dinh','weight'=>0.0,'streaks'=>[]];
    $rs = array_map(fn($it)=>$it['ket_qua'], array_slice($h, -30));
    $streaks = []; $cs = 1; $ct = $rs[0];
    for ($i = 1; $i < count($rs); $i++) {
        if ($rs[$i] === $ct) $cs++;
        else { $streaks[] = ['type'=>$ct,'count'=>$cs]; $ct = $rs[$i]; $cs = 1; }
    }
    $streaks[] = ['type'=>$ct,'count'=>$cs];
    $cau = 'Khong xac dinh'; $w = 0.5;
    $mx = 0; foreach ($streaks as $s) if ($s['count'] > $mx) $mx = $s['count'];
    if ($mx >= 6) { $cau = 'bệt'; $w = 0.5; }
    $c11 = 0; for ($i = 0; $i < count($streaks) - 1; $i++) if ($streaks[$i]['count'] === 1 && $streaks[$i+1]['count'] === 1) $c11++;
    if ($c11 >= 3) { $cau = '1-1'; $w = 0.85; }
    $c22 = 0; for ($i = 0; $i < count($streaks) - 1; $i++) if ($streaks[$i]['count'] === 2 && $streaks[$i+1]['count'] === 2) $c22++;
    if ($c22 >= 2) { $cau = '2-2'; $w = 0.85; }
    $c12 = 0; for ($i = 0; $i < count($streaks) - 1; $i++) if ($streaks[$i]['count'] === 1 && $streaks[$i+1]['count'] === 2) $c12++;
    if ($c12 >= 2) { $cau = '1-2'; $w = 0.80; }
    $c21 = 0; for ($i = 0; $i < count($streaks) - 1; $i++) if ($streaks[$i]['count'] === 2 && $streaks[$i+1]['count'] === 1) $c21++;
    if ($c21 >= 2) { $cau = '2-1'; $w = 0.80; }
    $c32 = 0; for ($i = 0; $i < count($streaks) - 1; $i++) if ($streaks[$i]['count'] === 3 && $streaks[$i+1]['count'] === 2) $c32++;
    if ($c32 >= 2) { $cau = '3-2'; $w = 0.75; }
    $c23 = 0; for ($i = 0; $i < count($streaks) - 1; $i++) if ($streaks[$i]['count'] === 2 && $streaks[$i+1]['count'] === 3) $c23++;
    if ($c23 >= 2) { $cau = '2-3'; $w = 0.75; }
    $c33 = 0; for ($i = 0; $i < count($streaks) - 1; $i++) if ($streaks[$i]['count'] === 3 && $streaks[$i+1]['count'] === 3) $c33++;
    if ($c33 >= 2) { $cau = '3-3'; $w = 0.70; }
    $cd = 0; for ($i = 0; $i < count($streaks) - 2; $i++) if ($streaks[$i]['count'] === $streaks[$i+2]['count'] && $streaks[$i]['type'] !== $streaks[$i+2]['type']) $cd++;
    if ($cd >= 2) { $cau = 'đảo'; $w = 0.75; }
    $l10 = array_slice($rs, -10);
    $t10 = count(array_filter($l10, fn($r) => $r === 'Tài')); $x10 = count($l10) - $t10;
    if (abs($t10 - $x10) >= 6) { $cau = 'cầu nghiêng'; $w = 0.70; }
    $p3 = []; for ($i = 0; $i <= count($rs) - 3; $i++) $p3[] = implode(',', array_slice($rs, $i, 3));
    $pc3 = []; foreach ($p3 as $p) $pc3[$p] = ($pc3[$p] ?? 0) + 1;
    $mp3 = null; if (count($pc3) > 0) { arsort($pc3); $mp3 = [key($pc3), current($pc3)]; }
    if ($mp3 !== null && $mp3[1] >= 4) { $cau = 'cầu lặp'; $w = 0.85; }
    $cdan = 0;
    for ($i = 0; $i < count($rs) - 4; $i++) {
        $sl = array_slice($rs, $i, 5);
        if ($sl[0] !== $sl[1] && $sl[1] === $sl[3] && $sl[0] === $sl[2] && $sl[2] !== $sl[4]) $cdan++;
    }
    if ($cdan >= 2) { $cau = 'cầu đan'; $w = 0.75; }
    return ['cau'=>$cau,'weight'=>$w,'streaks'=>$streaks];
}
function ttoan_generate_prediction(array $h, ?array &$mpExt = null): array {
    $h = array_values($h);
    $hasExt = ($mpExt !== null);
    if ($hasExt) $mp = $mpExt; else { static $st = []; $mp = $st; }
    if (!is_array($mp)) $mp = [];
    if (!isset($mp['trend'])) $mp = ['trend'=>[],'short'=>[],'mean'=>[],'switch'=>[],'bridge'=>[]];
    if (count($h) === 0) {
        if ($hasExt) $mpExt = $mp;
        $r = ttoan_random() < 0.5 ? 'Tài' : 'Xỉu';
        return ['prediction'=>$r,'doTinCay'=>50,'giaiThich'=>'Không đủ lịch sử'];
    }
    $cs = $h[count($h)-1]['phien']; $ct = $h[count($h)-1]['tong']; $lr = $h[count($h)-1]['ket_qua'];
    $fb = ($lr === 'Tài') ? 2 : 1;
    $trendP = count($h) < 5 ? $fb : ttoan_trend_and_prob($h);
    $shortP = count($h) < 5 ? $fb : ttoan_short_pattern($h);
    $meanP = count($h) < 5 ? $fb : ttoan_mean_deviation($h);
    $swP = count($h) < 5 ? $fb : ttoan_recent_switch($h);
    $brP = count($h) < 5 ? ['prediction'=>$fb,'breakProb'=>0.0,'reason'=>'LS ngắn'] : ttoan_smart_bridge_break($h);
    $aiP = ttoan_ai_htdd_logic($h);
    $cau = ttoan_phan_tich_cau($h);
    $meo = TTOAN_TONG_DIEM_MEO[$ct] ?? ['ket_qua'=>'Kxđ','xac_suat'=>0.5];
    $mp['trend'][$cs] = $trendP; $mp['short'][$cs] = $shortP;
    $mp['mean'][$cs] = $meanP; $mp['switch'][$cs] = $swP; $mp['bridge'][$cs] = $brP['prediction'];
    $perf = [
        'trend'=>ttoan_evaluate_model_performance($h, 'trend', $mp),
        'short'=>ttoan_evaluate_model_performance($h, 'short', $mp),
        'mean'=>ttoan_evaluate_model_performance($h, 'mean', $mp),
        'switch'=>ttoan_evaluate_model_performance($h, 'switch', $mp),
        'bridge'=>ttoan_evaluate_model_performance($h, 'bridge', $mp),
    ];
    $w = [
        'trend'=>0.15*$perf['trend'],'short'=>0.15*$perf['short'],'mean'=>0.15*$perf['mean'],
        'switch'=>0.15*$perf['switch'],'bridge'=>0.15*$perf['bridge'],
        'aihtdd'=>0.15,'cau'=>0.10,'tongDiem'=>0.10,
    ];
    $ts = 0.0; $xs = 0.0;
    if ($trendP === 1) $ts += $w['trend']; elseif ($trendP === 2) $xs += $w['trend'];
    if ($shortP === 1) $ts += $w['short']; elseif ($shortP === 2) $xs += $w['short'];
    if ($meanP === 1) $ts += $w['mean']; elseif ($meanP === 2) $xs += $w['mean'];
    if ($swP === 1) $ts += $w['switch']; elseif ($swP === 2) $xs += $w['switch'];
    if ($brP['prediction'] === 1) $ts += $w['bridge']; elseif ($brP['prediction'] === 2) $xs += $w['bridge'];
    if ($aiP['prediction'] === 'Tài') $ts += $w['aihtdd']; else $xs += $w['aihtdd'];
    $cauInfo = TTOAN_CAU_PATTERNS[$cau['cau']] ?? ['desc'=>'Kxđ','weight'=>0.5];
    $cauPred = null;
    if ($cau['cau'] === '1-1') $cauPred = ($lr === 'Tài') ? 'Xỉu' : 'Tài';
    elseif ($cau['cau'] === '2-2') $cauPred = ($lr === 'Xỉu') ? 'Tài' : 'Xỉu';
    elseif ($cau['cau'] === '1-2') $cauPred = 'Tài';
    elseif ($cau['cau'] === '2-1') $cauPred = 'Xỉu';
    elseif ($cau['cau'] === 'bệt') $cauPred = $lr;
    elseif ($cau['cau'] === 'đảo') $cauPred = ($lr === 'Tài') ? 'Xỉu' : 'Tài';
    elseif ($cau['cau'] === 'cầu nghiêng') {
        $l10c = array_map(fn($it)=>$it['ket_qua'], array_slice($h, -10));
        $t10c = count(array_filter($l10c, fn($r) => $r === 'Tài'));
        $cauPred = ($t10c > 5) ? 'Xỉu' : 'Tài';
    } else $cauPred = $lr;
    if ($cauPred === 'Tài') $ts += $w['cau'] * $cau['weight']; else $xs += $w['cau'] * $cau['weight'];
    if ($meo['ket_qua'] === 'Tài') $ts += $w['tongDiem'] * $meo['xac_suat'];
    elseif ($meo['ket_qua'] === 'Xỉu') $xs += $w['tongDiem'] * $meo['xac_suat'];
    if (ttoan_is_bad_pattern($h)) { $ts *= 0.8; $xs *= 0.8; }
    $l10 = array_map(fn($it)=>$it['ket_qua'], array_slice($h, -10));
    $l10t = count(array_filter($l10, fn($r) => $r === 'Tài'));
    if ($l10t >= 7) $xs += 0.15; elseif ($l10t <= 3) $ts += 0.15;
    if ($brP['breakProb'] > 0.65) { if ($brP['prediction'] === 1) $ts += 0.2; else $xs += 0.2; }
    $tot = $ts + $xs;
    $tp = $tot > 0 ? ($ts / $tot) * 100 : 50.0;
    $xp = $tot > 0 ? ($xs / $tot) * 100 : 50.0;
    $final = ($ts > $xs) ? 'Tài' : 'Xỉu';
    $conf = (int)round(max($tp, $xp));
    $ex = sprintf('[%s] [Tổng %s: %s %d%%] %s | %s | T:%.1f%% X:%.1f%%',
        $cauInfo['desc'], $ct, $meo['ket_qua'], (int)round($meo['xac_suat']*100),
        $aiP['reason'], $brP['reason'], $tp, $xp);
    if ($hasExt) $mpExt = $mp;
    return ['prediction'=>$final,'doTinCay'=>$conf,'giaiThich'=>$ex];
}

// ═══════ DETECTIVE LAYER — 10 THÁM TỬ ═══════
function denius_detectives(array $h, string $ttoanPred): array {
    $n = count($h);
    if ($n < 10) return ['verdict'=>'SKIP','agree_rate'=>0,'votes'=>[],'note'=>'Ít dữ liệu','regime'=>'unknown','boost'=>-15];

    $seq = array_map(fn($it) => $it['ket_qua'] === 'Tài' ? 'T' : 'X', $h);
    $tSym = ($ttoanPred === 'Tài') ? 'T' : 'X';
    $o = ($tSym === 'T') ? 'X' : 'T';
    $last = $seq[$n-1];
    $votes = [];

    // D1: STREAK
    $streak = 1;
    for ($i = $n-2; $i >= 0 && $seq[$i] === $last; $i--) $streak++;
    if ($streak <= 3) $v = 'FOLLOW';
    elseif ($streak >= 7) $v = ($tSym !== $last) ? 'FOLLOW' : 'SKIP';
    else $v = ($tSym === $last) ? 'FOLLOW' : 'CONFLICT';
    $votes['streak'] = ['v'=>$v, 'note'=>"Bệt $streak$last"];

    // D2: PATTERN
    $runs = []; $curS = $seq[0]; $curL = 1;
    for ($i = 1; $i < $n; $i++) {
        if ($seq[$i] === $curS) $curL++;
        else { $runs[] = [$curS, $curL]; $curS = $seq[$i]; $curL = 1; }
    }
    $runs[] = [$curS, $curL];
    $recentRuns = array_slice($runs, -6);
    $pat = null;
    if (count($recentRuns) >= 4) {
        $lens = array_map(fn($r) => $r[1], $recentRuns);
        if ($lens[0]==1 && $lens[1]==1 && $lens[2]==1 && $lens[3]==1) $pat = '1-1';
        elseif ($lens[0]==2 && $lens[1]==2 && $lens[2]==2) $pat = '2-2';
        elseif ($lens[0]==3 && $lens[1]==3) $pat = '3-3';
        elseif ($lens[0]==1 && $lens[1]==2 && $lens[2]==1) $pat = '1-2';
    }
    if ($pat === '1-1' || $pat === '2-2') $v = ($tSym === $o) ? 'FOLLOW' : 'CONFLICT';
    elseif ($pat === '3-3') $v = ($tSym === $last) ? 'FOLLOW' : 'CONFLICT';
    else $v = 'FOLLOW';
    $votes['pattern'] = ['v'=>$v, 'note'=>$pat ?? 'Không mẫu'];

    // D3: VOLATILITY
    $recent = array_slice($seq, -20);
    $sw = 0; for ($i = 1; $i < count($recent); $i++) if ($recent[$i] !== $recent[$i-1]) $sw++;
    $vol = $sw / max(1, count($recent) - 1);
    if ($vol < 0.4) $v = 'FOLLOW'; elseif ($vol > 0.75) $v = 'SKIP'; else $v = 'CONFLICT';
    $votes['volatility'] = ['v'=>$v, 'note'=>'Biến động '.round($vol*100).'%'];

    // D4: BIAS
    $l20 = array_slice($seq, -20);
    $tc = count(array_filter($l20, fn($c) => $c === 'T'));
    $bias = $tc / count($l20);
    if ($bias >= 0.65) $v = ($tSym === 'X') ? 'FOLLOW' : 'SKIP';
    elseif ($bias <= 0.35) $v = ($tSym === 'T') ? 'FOLLOW' : 'SKIP';
    else $v = 'FOLLOW';
    $votes['bias'] = ['v'=>$v, 'note'=>'Tỉ lệ T '.round($bias*100).'%'];

    // D5: MOMENTUM (3/5/10)
    $mom = []; foreach ([3,5,10] as $k) { $sl = array_slice($seq, -$k); $mom[$k] = count(array_filter($sl, fn($c) => $c === 'T')) / count($sl); }
    $trend = ($mom[3] > 0.5 && $mom[5] > 0.5 && $mom[10] > 0.5) ? 'T'
           : ($mom[3] < 0.5 && $mom[5] < 0.5 && $mom[10] < 0.5) ? 'X' : null;
    if ($trend === null) $v = 'CONFLICT'; elseif ($trend === $tSym) $v = 'FOLLOW'; else $v = 'SKIP';
    $votes['momentum'] = ['v'=>$v, 'note'=>'Xu hướng '.($trend ?? 'hỗn hợp')];

    // D6: ENTROPY
    $p = $tc / 20;
    $ent = ($p > 0 ? -$p*log($p, 2) : 0) + ($p < 1 ? -(1-$p)*log(1-$p, 2) : 0);
    if ($ent < 0.7) $v = 'FOLLOW'; elseif ($ent > 0.95) $v = 'SKIP'; else $v = 'CONFLICT';
    $votes['entropy'] = ['v'=>$v, 'note'=>'Entropy '.round($ent, 2)];

    // D7: MARKOV bậc 2
    $ctx = $seq[$n-2] . $seq[$n-1]; $tNext = 0; $xNext = 0;
    for ($i = 2; $i < $n; $i++) if ($seq[$i-2] . $seq[$i-1] === $ctx) { if ($seq[$i] === 'T') $tNext++; else $xNext++; }
    $tot = $tNext + $xNext;
    if ($tot >= 3) {
        $pm = ($tNext > $xNext) ? 'T' : 'X';
        $v = ($pm === $tSym) ? 'FOLLOW' : 'SKIP';
        $votes['markov'] = ['v'=>$v, 'note'=>"Markov $tNext/$tot"];
    } else $votes['markov'] = ['v'=>'CONFLICT', 'note'=>'Markov ít mẫu'];

    // D8: CLUSTER
    $clusters = [];
    for ($i = 0; $i + 5 <= $n; $i += 5) {
        $ch = array_slice($seq, $i, 5);
        $clusters[] = count(array_filter($ch, fn($c) => $c === 'T')) >= 3 ? 'T' : 'X';
    }
    $lastCl = end($clusters);
    if (count($clusters) >= 2 && end($clusters) !== $clusters[count($clusters)-2]) {
        $v = ($lastCl === $tSym) ? 'FOLLOW' : 'CONFLICT';
        $votes['cluster'] = ['v'=>$v, 'note'=>"Cluster $lastCl"];
    } else $votes['cluster'] = ['v'=>'CONFLICT', 'note'=>'Cluster ổn định'];

    // D9: REVERSAL
    $prevRuns = array_slice($runs, 0, -1); $avgRun = 0;
    if (count($prevRuns) > 0) $avgRun = array_sum(array_map(fn($r) => $r[1], $prevRuns)) / count($prevRuns);
    if ($streak >= 4 && $avgRun > 0 && $streak / $avgRun > 2) {
        $v = ($tSym === $o) ? 'FOLLOW' : 'CONFLICT';
        $votes['reversal'] = ['v'=>$v, 'note'=>'Đảo chiều tiềm năng'];
    } else $votes['reversal'] = ['v'=>'CONFLICT', 'note'=>'Không đảo rõ'];

    // D10: REGIME
    if ($vol < 0.3 && $ent < 0.7) $regime = 'stable';
    elseif ($vol > 0.7 || $ent > 0.9) $regime = 'chaos';
    else $regime = 'volatile';
    if ($regime === 'stable') $v = ($trend !== null && $trend === $tSym) ? 'FOLLOW' : 'CONFLICT';
    elseif ($regime === 'chaos') $v = 'SKIP';
    else $v = 'CONFLICT';
    $votes['regime'] = ['v'=>$v, 'note'=>"Chế độ $regime"];

    // Tổng hợp
    $f = 0; $s = 0; $c = 0;
    foreach ($votes as $rv) {
        if ($rv['v'] === 'FOLLOW') $f++;
        elseif ($rv['v'] === 'SKIP') $s++;
        else $c++;
    }
    $total = $f + $s + $c; $agree = $total ? $f / $total : 0.5;
    if ($agree >= 0.65) $verdict = 'FOLLOW';
    elseif ($agree <= 0.35) $verdict = 'SKIP';
    else $verdict = 'CONFLICT';
    $boost = $verdict === 'FOLLOW' ? 8 : ($verdict === 'SKIP' ? -25 : -5);
    return [
        'verdict'=>$verdict,'agree_rate'=>$agree,'votes'=>$votes,
        'follow'=>$f,'skip'=>$s,'conflict'=>$c,
        'boost'=>$boost,'regime'=>$regime,
    ];
}

// ═══════ WEBSOCKET CLIENT ═══════
class TinyWS {
    public $sock; public $error = '';
    private $h, $p, $path, $headers;
    public function __construct($h, $p, $path, $headers = []) {
        $this->h = $h; $this->p = $p; $this->path = $path; $this->headers = $headers;
    }
    public function connect(): bool {
        $ctx = stream_context_create(['ssl'=>['verify_peer'=>false,'verify_peer_name'=>false,'allow_self_signed'=>true]]);
        $this->sock = @stream_socket_client("tls://{$this->h}:{$this->p}", $en, $es, 10, STREAM_CLIENT_CONNECT, $ctx);
        if (!$this->sock) { $this->error = "TCP fail: $en:$es"; return false; }
        stream_set_timeout($this->sock, 15); stream_set_blocking($this->sock, true);
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
        if ($n === false) return null; if ($n === 0) return [];
        $hdr = @fread($this->sock, 2);
        if ($hdr === false || strlen($hdr) < 2) return null;
        $b1 = ord($hdr[0]); $b2 = ord($hdr[1]);
        $op = $b1 & 0x0f; $masked = ($b2 & 0x80) !== 0; $len = $b2 & 0x7f;
        if ($len === 126) { $ext = @fread($this->sock, 2); if (strlen($ext) < 2) return null; $len = unpack('n', $ext)[1]; }
        elseif ($len === 127) { $ext = @fread($this->sock, 8); if (strlen($ext) < 8) return null; $len = unpack('J', $ext)[1]; }
        $mask = null; if ($masked) { $mask = @fread($this->sock, 4); if (strlen($mask) < 4) return null; }
        $data = ''; while (strlen($data) < $len) { $c = @fread($this->sock, $len - strlen($data)); if ($c === false || $c === '') return null; $data .= $c; }
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
function do_ws_bet(string $key, array $s, array &$actions): bool {
    global $CFG;
    if (empty($s['token'])) return false;
    if (!empty($s['pending_skip'])) { key_log($key, 'warn', '🔍 SKIP — thám tử báo bỏ phiên'); return false; }
    $pred = $s['pending_pred'] ?? null;
    if (!$pred) return false;
    $side = ($pred === 'Tài' || $pred === 'T' || $pred === 'TAI') ? 'TAI' : 'XIU';
    $ps = (int)$s['pending_session'];
    $amount = (int)($s['pending_bet_amount'] ?? 10000);
    if ($amount < 1000) $amount = 1000;
    $wsPath = rtrim($CFG['game']['ws_path'], '/') . '/?EIO=4&transport=websocket';
    $ws = new TinyWS($CFG['game']['ws_host'], 443, $wsPath, ['Authorization: Bearer ' . $s['token']]);
    if (!$ws->connect()) { key_log($key, 'error', '❌ WS fail: ' . $ws->error); return false; }
    $auth = json_encode(['token'=>$s['token']], JSON_UNESCAPED_UNICODE);
    $joined = false; $done = false; $ack = false;
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
            $ev = $msg[0] ?? ''; $d = $msg[1] ?? [];
            if ($ev === 'tick-update') {
                $state = $d['state'] ?? null; $tickSid = isset($d['id']) ? (int)$d['id'] : null;
                if ($state === 'BETTING' && $joined && !$done) {
                    if ($tickSid !== null && $tickSid < $ps) continue;
                    $ws->sendRaw('42/tx,' . json_encode(['bet', ['type'=>$side, 'amount'=>$amount]], JSON_UNESCAPED_UNICODE));
                    $done = true;
                    key_log($key, 'success', "💰 ĐẶT #$ps [$side] × " . number_format($amount) . " — KHỚP $pred");
                    $actions[] = ['type'=>'bet', 'msg'=>"Bet #$ps $side $amount"];
                    key_update($key, function($dd) use ($ps, $amount) { $dd['bet_session'] = $ps; $dd['bet_amount'] = $amount; return $dd; });
                    $wait = microtime(true) + 2.5;
                    while (microtime(true) < $wait) {
                        $more = $ws->readOneFrame(1);
                        if ($more === null) break; if ($more === []) continue;
                        foreach ($more as $p2) {
                            if ($p2 === '2') { $ws->sendRaw('3'); continue; }
                            if (!str_starts_with($p2, '4')) continue;
                            $s2 = substr($p2, 1); if (!str_starts_with($s2, '2')) continue;
                            $b2 = substr($s2, 1);
                            if (str_starts_with($b2, '/tx,')) $b2 = substr($b2, strlen('/tx,'));
                            $m2 = json_decode($b2, true); if (!is_array($m2)) continue;
                            if (($m2[0] ?? '') === 'bet-result') {
                                $ack = true;
                                if (isset($m2[1]['postBalance'])) {
                                    key_update($key, function($dd) use ($m2) { $dd['balance'] = $m2[1]['postBalance']; return $dd; });
                                }
                            }
                        }
                    }
                    $ws->close();
                    if (!$ack) key_log($key, 'warn', '⚠️ Chưa nhận bet-result');
                    return true;
                }
            }
            if ($ev === 'session-result') { $ws->close(); return false; }
        }
    }
    $ws->close();
    return $done;
}

// ═══════ WORKER CORE ═══════
function worker_step(string $key): array {
    $actions = [];
    $s = key_load($key);
    if (!$s) return $actions;
    $cfg = $s['config'] ?? [];
    if (empty($cfg['auto']) || !empty($cfg['paused'])) return $actions;

    $data = fetch_sessions_api();
    if (!$data || empty($data['list'])) return $actions;
    $latest = $data['list'][0]; $latestId = (int)$latest['id'];
    $lastId = (int)($s['last_session_id'] ?? 0);

    if ($lastId === 0) {
        key_update($key, fn($d) => array_merge($d, ['last_session_id'=>$latestId]));
        key_log($key, 'info', "📡 Baseline #$latestId");
        return $actions;
    }

    if ($latestId > $lastId) {
        for ($sid = $lastId + 1; $sid <= $latestId; $sid++) {
            $found = null;
            foreach ($data['list'] as $row) if ((int)$row['id'] === $sid) { $found = $row; break; }
            if (!$found) continue;
            $raw = $found['resultTruyenThong'] ?? 'N/A';
            $map = ['Tài'=>'TAI','Xỉu'=>'XIU','tai'=>'TAI','xiu'=>'XIU','TAI'=>'TAI','XIU'=>'XIU'];
            $result = $map[$raw] ?? 'N/A';
            if ($result !== 'TAI' && $result !== 'XIU') continue;
            $dices = $found['dices'] ?? [0,0,0]; $tong = array_sum($dices);
            $jackpot = (count(array_unique($dices)) === 1 && $dices[0] != 0);

            if (($s['pending_session'] ?? null) == $sid && !empty($s['pending_pred'])) {
                $pred = $s['pending_pred'];
                $skipped = !empty($s['pending_skip']);
                $win = !$skipped && ((($pred==='Tài'||$pred==='T') && $result==='TAI') || (($pred==='Xỉu'||$pred==='X') && $result==='XIU'));

                key_update($key, function($d) use ($sid, $pred, $result, $dices, $win, $jackpot, $tong, $skipped) {
                    $c = $d['config'];
                    $st = (int)($c['lose_streak'] ?? 0);
                    if ($skipped) { /* skip: không thay đổi streak, không tính win/loss */ }
                    elseif ($win) { $st = 0; $d['win_count_total'] = (int)($d['win_count_total'] ?? 0) + 1; }
                    else { $d['loss_count_total'] = (int)($d['loss_count_total'] ?? 0) + 1; $st++; if ($st >= 4) $st = 0; }
                    $c['lose_streak'] = $st;
                    $betAmt = (int)($d['bet_amount'] ?? 0);
                    $bal = (int)($d['balance'] ?? 0);
                    if (!$skipped) {
                        if ($win) $bal += intval($betAmt * 0.98);
                        else $bal -= $betAmt;
                        $d['balance'] = $bal;
                        $d['profit_total'] = (int)($d['profit_total'] ?? 0) + ($win ? intval($betAmt * 0.98) : -$betAmt);
                    }
                    $d['history'] = $d['history'] ?? [];
                    array_unshift($d['history'], [
                        'ts'=>date('H:i:s d/m'),'session'=>$sid,'pred'=>$pred,'result'=>$result,
                        'dices'=>$dices,'tong'=>$tong,'win'=>$win,'amount'=>$betAmt,
                        'balance_after'=>$bal,'streak'=>$st,'jackpot'=>$jackpot,'skipped'=>$skipped,
                    ]);
                    $d['history'] = array_slice($d['history'], 0, 500);
                    $d['pending_pred'] = null; $d['pending_session'] = null;
                    $d['pending_conf'] = null; $d['pending_bet_amount'] = null;
                    $d['pending_skip'] = null; $d['bet_session'] = null; $d['bet_amount'] = 0;
                    $sym = ($result === 'TAI') ? 'T' : 'X';
                    $p10 = ($d['pattern_10'] ?? '') . $sym;
                    if (strlen($p10) > 10) $p10 = substr($p10, -10);
                    $d['pattern_10'] = $p10;
                    $d['config'] = $c;
                    if ((int)($c['target_win'] ?? 0) > 0 && (int)$d['win_count_total'] >= (int)$c['target_win']) { $c['auto'] = false; $c['paused'] = true; $d['config'] = $c; }
                    if ((int)($c['profit_stop'] ?? 0) > 0 && (int)$d['profit_total'] >= (int)$c['profit_stop']) { $c['auto'] = false; $c['paused'] = true; $d['config'] = $c; }
                    return $d;
                });
                $icon = $skipped ? '⏭' : ($win ? '✅' : '❌');
                $log = "$icon Phiên #$sid: $pred → $result (" . implode('-', $dices) . ")" . ($jackpot ? ' 🎉' : '') . ($skipped ? ' [SKIP]' : '');
                key_log($key, $skipped ? 'warn' : ($win ? 'success' : 'error'), $log);
                $actions[] = ['type'=>'result', 'msg'=>$log];
                $s = key_load($key);
            }
        }
        key_update($key, fn($d) => array_merge($d, ['last_session_id'=>$latestId]));
    }

    if (!empty($s['pending_session']) && (int)$s['pending_session'] <= $latestId) {
        key_update($key, function($d) {
            $d['pending_pred']=null;$d['pending_session']=null;$d['pending_conf']=null;
            $d['pending_bet_amount']=null;$d['pending_skip']=null;$d['bet_session']=null;$d['bet_amount']=0;
            return $d;
        });
        $s = key_load($key);
    }

    $cfg = $s['config'];
    if (!empty($cfg['auto']) && empty($cfg['paused']) && empty($s['pending_pred'])) {
        $hseq = [];
        foreach (array_reverse($s['history'] ?? []) as $h) {
            $r = $h['result'] ?? '';
            if ($r === 'TAI') $hseq[] = ['phien'=>$h['session'],'ket_qua'=>'Tài','tong'=>$h['tong']??0,'xuc_xac'=>$h['dices']??[]];
            elseif ($r === 'XIU') $hseq[] = ['phien'=>$h['session'],'ket_qua'=>'Xỉu','tong'=>$h['tong']??0,'xuc_xac'=>$h['dices']??[]];
        }
        if (empty($hseq) && !empty($data['list'])) {
            foreach (array_reverse(array_slice($data['list'], 0, 50)) as $row) {
                $rr = $row['resultTruyenThong'] ?? '';
                $mm = ['Tài'=>'Tài','Xỉu'=>'Xỉu','tai'=>'Tài','xiu'=>'Xỉu','TAI'=>'Tài','XIU'=>'Xỉu'];
                if (isset($mm[$rr])) $hseq[] = ['phien'=>(int)$row['id'],'ket_qua'=>$mm[$rr],'tong'=>array_sum($row['dices']??[0,0,0]),'xuc_xac'=>$row['dices']??[]];
            }
        }

        // 🎯 TTOAN → PREDICTION
        $mpState = $s['model_predictions'] ?? [];
        $ai = ttoan_generate_prediction($hseq, $mpState);
        $predStr = $ai['prediction'];
        $conf = $ai['doTinCay'];

        // 🕵️ DETECTIVE — đánh giá, KHÔNG đổi prediction
        $detective = denius_detectives($hseq, $predStr);
        $finalConf = max(0, min(100, $conf + $detective['boost']));
        $skip = ($detective['verdict'] === 'SKIP');

        // Bet amount
        $baseBet = max(1000, (int)($cfg['base_bet'] ?? 10000));
        $betAmt = $baseBet;
        $st = (int)($cfg['lose_streak'] ?? 0);
        if ($st > 0) $betAmt = $baseBet * (1 << min($st, 4));
        $bal = (int)($s['balance'] ?? 0);
        if ($betAmt > $bal && $bal > 0) $betAmt = max(1000, $bal);

        key_update($key, function($d) use ($predStr, $latestId, $finalConf, $betAmt, $mpState, $skip, $detective) {
            $d['pending_pred'] = $predStr;
            $d['pending_session'] = $latestId + 1;
            $d['pending_conf'] = $finalConf;
            $d['pending_bet_amount'] = $betAmt;
            $d['pending_skip'] = $skip;
            $d['pending_detective'] = [
                'verdict'=>$detective['verdict'],
                'agree_rate'=>$detective['agree_rate'],
                'follow'=>$detective['follow'],
                'skip'=>$detective['skip'],
                'conflict'=>$detective['conflict'],
                'regime'=>$detective['regime'],
                'votes'=>$detective['votes'],
            ];
            $d['model_predictions'] = $mpState;
            return $d;
        });
        $log = "🎯 #" . ($latestId + 1) . ": $predStr (conf " . round($finalConf,1) . "%, thám tử: " . $detective['verdict'] . ") — " . ($skip ? 'SKIP' : number_format($betAmt) . 'đ');
        key_log($key, 'info', $log);
        $actions[] = ['type'=>'predict', 'msg'=>$log];
        $s = key_load($key);
    }

    $cfg = $s['config'];
    if (!empty($s['pending_pred']) && empty($cfg['paused']) && !empty($cfg['auto']) && empty($s['pending_skip'])) {
        if (($s['bet_session'] ?? null) != $s['pending_session']) {
            do_ws_bet($key, $s, $actions);
        }
    }
    return $actions;
}

function worker_heartbeat(string $key, string $status = 'running'): void {
    key_update($key, function($d) use ($status) {
        $d['worker'] = ['last_beat'=>time(),'pid'=>getmypid(),'status'=>$status,
            'started_at'=>$d['worker']['started_at'] ?? time()];
        return $d;
    });
}
function worker_alive(string $key): bool {
    global $CFG;
    $s = key_load($key); $w = $s['worker'] ?? [];
    if (empty($w['last_beat'])) return false;
    return (time() - (int)$w['last_beat']) < ($CFG['worker']['resume_timeout'] ?? 90);
}
function worker_lock(string $key): bool {
    $lp = KEY_DIR . '/' . hash('sha256', strtolower($key)) . '.lock';
    if (is_file($lp)) {
        $pid = (int)trim(@file_get_contents($lp));
        if ($pid > 0) {
            $alive = function_exists('posix_kill') ? @posix_kill($pid, 0) : (time() - filemtime($lp)) < 60;
            if ($alive) return false;
        }
        @unlink($lp);
    }
    $fp = @fopen($lp, 'c+');
    if (!$fp) return false;
    if (!flock($fp, LOCK_EX | LOCK_NB)) { fclose($fp); return false; }
    ftruncate($fp, 0); rewind($fp); fwrite($fp, (string)getmypid()); fflush($fp);
    register_shutdown_function(function() use ($fp, $lp) { @flock($fp, LOCK_UN); @fclose($fp); @unlink($lp); });
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
    while (time() < $deadline) {
        $s = key_load($key); if (!$s) break;
        try { worker_step($key); } catch (Throwable $e) { key_log($key, 'error', '💥 ' . $e->getMessage()); }
        if (time() - $lastBeat >= 10) { worker_heartbeat($key, 'running'); $lastBeat = time(); }
        if ((time() + $buf) >= $deadline) {
            $s2 = key_load($key);
            if (!empty($s2['config']['auto']) && empty($s2['config']['paused'])) {
                $lp = KEY_DIR . '/' . hash('sha256', strtolower($key)) . '.lock';
                @unlink($lp);
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
    $scheme = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
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
        $parsed = parse_url($url); $h = $parsed['host'] ?? $host;
        $port = ($parsed['scheme'] ?? 'http') === 'https' ? 443 : 80;
        $fp = @fsockopen($h, $port, $en, $es, 0.5);
        if ($fp) {
            stream_set_timeout($fp, 1);
            $p = ($parsed['path'] ?? '/') . '?' . ($parsed['query'] ?? '');
            @fwrite($fp, "GET {$p} HTTP/1.1\r\nHost: {$h}\r\nConnection: Close\r\n\r\n");
            @fclose($fp); return;
        }
    }
    try { $ctx = stream_context_create(['http'=>['timeout'=>0.5]]); @file_get_contents($url, false, $ctx); } catch (Throwable $e) {}
}

// ═══════ ROUTER ═══════
$action = $_GET['action'] ?? $_POST['action'] ?? '';
if ($action === '') { render_ui(); exit; }

if ($action === 'cron') {
    header('Content-Type: application/json; charset=utf-8');
    $idx = DATA_DIR . '/user_index.json'; $out = ['ok'=>true,'checked'=>0,'spawned'=>[]];
    if (is_file($idx)) {
        foreach (json_decode(file_get_contents($idx), true) ?: [] as $u => $k) {
            $out['checked']++; $s = key_load($k); if (!$s) continue;
            if (empty($s['config']['auto']) || !empty($s['config']['paused'])) continue;
            if (worker_alive($k)) continue;
            @unlink(KEY_DIR . '/' . hash('sha256', strtolower($k)) . '.lock');
            spawn_worker_async($k); $out['spawned'][] = $u;
        }
    }
    echo json_encode($out); exit;
}

if ($action === 'worker') {
    $key = trim($_GET['key'] ?? '');
    if (!$key) { http_response_code(400); echo 'missing'; exit; }
    run_worker_daemon($key, (int)($_GET['max'] ?? 3600)); exit;
}

if ($action === 'keepalive') {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['ok'=>true,'ts'=>time()]); exit;
}

header('Content-Type: application/json; charset=utf-8');
try {
    switch ($action) {
        case 'verify':
            $u = trim($_POST['user'] ?? ''); $p = trim($_POST['pass'] ?? '');
            $dev = trim($_POST['device'] ?? 'WEB-SUPREME');
            if (!$u || !$p) { echo json_encode(['ok'=>false,'msg'=>'Thiếu tài khoản/mật khẩu']); exit; }
            $key = $u;
            $existing = key_load($key);
            if (!$existing) $existing = denius_cloud_restore($key) ?? [];
            $canResume = !empty($existing['user']) && !empty($existing['token']);
            $gl = game_login($u, $p);
            if (isset($gl['_error'])) {
                if ($canResume) {
                    $gl = ['nickname'=>$existing['nickname']??$u,'token'=>$existing['token'],'money'=>$existing['balance']??0];
                    key_log($key, 'info', '♻️ Resume');
                } else { echo json_encode(['ok'=>false,'msg'=>$gl['_error']]); exit; }
            }
            $s = $existing ?: [];
            $s['user'] = $u; $s['key'] = $key; $s['device'] = $dev;
            $s['nickname'] = $gl['nickname'] ?? $u;
            $s['token'] = $gl['token'] ?? '';
            $s['balance'] = $gl['money'] ?? ($s['balance'] ?? 0);
            $s['history'] = $s['history'] ?? [];
            $s['logs'] = $s['logs'] ?? [];
            $s['config'] = array_merge($CFG['default_config'], $s['config'] ?? []);
            $s['win_count_total'] = $s['win_count_total'] ?? 0;
            $s['loss_count_total'] = $s['loss_count_total'] ?? 0;
            $s['profit_total'] = $s['profit_total'] ?? 0;
            $s['last_session_id'] = $s['last_session_id'] ?? 0;
            $s['pending_pred'] = $s['pending_pred'] ?? null;
            $s['pending_session'] = $s['pending_session'] ?? null;
            $s['pending_conf'] = $s['pending_conf'] ?? null;
            $s['pending_bet_amount'] = $s['pending_bet_amount'] ?? null;
            $s['pending_skip'] = $s['pending_skip'] ?? null;
            $s['pending_detective'] = $s['pending_detective'] ?? null;
            $s['bet_session'] = $s['bet_session'] ?? null;
            $s['bet_amount'] = $s['bet_amount'] ?? 0;
            $s['model_predictions'] = $s['model_predictions'] ?? [];
            $s['pattern_10'] = $s['pattern_10'] ?? '';
            key_save($key, $s); key_save_by_user($u, $key);
            key_log($key, 'info', '🔐 Login — ' . $dev);
            if (!worker_alive($key)) spawn_worker_async($key);
            echo json_encode([
                'ok'=>true,'user'=>$u,'nickname'=>$s['nickname'],'balance'=>$s['balance'],
                'config'=>$s['config'],'history'=>$s['history'],
                'auth_token'=>issue_token($u),'worker_alive'=>worker_alive($key),'resumed'=>$canResume,
            ]); exit;

        case 'resume':
            $u = trim($_POST['user'] ?? ''); $tk = trim($_POST['auth_token'] ?? '');
            if (!verify_token($tk, $u)) { echo json_encode(['ok'=>false,'msg'=>'Token expired']); exit; }
            $key = key_resolve($u); $s = key_load($key);
            if (!$s) $s = denius_cloud_restore($key) ?? [];
            if (!$s || empty($s['token'])) { echo json_encode(['ok'=>false,'msg'=>'Session lost']); exit; }
            if (!empty($s['config']['auto']) && empty($s['config']['paused']) && !worker_alive($key)) {
                @unlink(KEY_DIR . '/' . hash('sha256', strtolower($key)) . '.lock');
                spawn_worker_async($key);
            }
            $wins = (int)($s['win_count_total'] ?? 0);
            $losses = (int)($s['loss_count_total'] ?? 0);
            $tot = $wins + $losses;
            echo json_encode([
                'ok'=>true,'user'=>$u,'nickname'=>$s['nickname']??'','balance'=>$s['balance']??0,
                'config'=>$s['config']??[],'history'=>array_slice($s['history']??[], 0, 100),
                'auth_token'=>issue_token($u),'worker_alive'=>worker_alive($key),
                'pending_pred'=>$s['pending_pred']??null,'pending_session'=>$s['pending_session']??null,
                'pending_conf'=>$s['pending_conf']??null,'pending_bet_amount'=>$s['pending_bet_amount']??null,
                'pending_skip'=>$s['pending_skip']??null,'pending_detective'=>$s['pending_detective']??null,
                'last_session_id'=>$s['last_session_id']??0,'pattern_10'=>$s['pattern_10']??'',
                'win_count_total'=>$wins,'loss_count_total'=>$losses,'profit_total'=>(int)($s['profit_total']??0),
                'stats'=>['wins'=>$wins,'losses'=>$losses,'total'=>$tot,
                    'winrate'=>$tot>0?round($wins/$tot*100,1):0,'profit'=>(int)($s['profit_total']??0)],
                'ts'=>time(),
            ]); exit;

        case 'setup':
            $u = trim($_POST['user'] ?? ''); $tk = trim($_POST['auth_token'] ?? '');
            if (!require_auth($u, $tk)) { echo json_encode(['ok'=>false,'msg'=>'Unauthorized']); exit; }
            $key = key_resolve($u); $s = key_load($key); $c = $s['config'];
            $c['base_bet'] = max(1000, (int)($_POST['base_bet'] ?? 10000));
            $c['profit_stop'] = max(0, (int)($_POST['profit_stop'] ?? 0));
            $c['target_win'] = max(0, (int)($_POST['target_win'] ?? 0));
            $c['mode'] = 'double'; $c['max_lose_streak'] = 4;
            $c['onboarded'] = true; $c['auto'] = true; $c['paused'] = false;
            $s['config'] = $c; key_save($key, $s);
            if (!worker_alive($key)) {
                @unlink(KEY_DIR . '/' . hash('sha256', strtolower($key)) . '.lock');
                spawn_worker_async($key);
            }
            key_log($key, 'success', '▶ AUTO BẬT · vốn ' . number_format($c['base_bet']) . ' · target ' . number_format($c['target_win']));
            echo json_encode(['ok'=>true,'config'=>$c,'worker_alive'=>worker_alive($key)]);
            exit;

        case 'kill':
            $u = trim($_POST['user'] ?? ''); $tk = trim($_POST['auth_token'] ?? '');
            if (!require_auth($u, $tk)) { echo json_encode(['ok'=>false,'msg'=>'Unauthorized']); exit; }
            $key = key_resolve($u);
            key_update($key, function($d) {
                $d['config']['auto'] = false; $d['config']['paused'] = true; $d['config']['lose_streak'] = 0;
                $d['pending_pred']=null; $d['pending_session']=null; $d['pending_conf']=null;
                $d['pending_bet_amount']=null; $d['pending_skip']=null; $d['pending_detective']=null;
                $d['bet_session']=null; $d['bet_amount']=0; $d['kill_ts']=time();
                return $d;
            });
            $lp = KEY_DIR . '/' . hash('sha256', strtolower($key)) . '.lock';
            if (is_file($lp)) {
                $pid = (int)trim(@file_get_contents($lp));
                if ($pid > 0 && function_exists('posix_kill')) @posix_kill($pid, SIGTERM);
                @unlink($lp);
            }
            key_log($key, 'warn', '🛑 KILL — Toàn bộ cược đã dừng');
            echo json_encode(['ok'=>true,'msg'=>'Đã dừng toàn bộ']);
            exit;

        case 'status':
            $u = trim($_GET['user'] ?? ''); $tk = trim($_GET['auth_token'] ?? '');
            if (!verify_token($tk, $u)) { echo json_encode(['ok'=>false,'msg'=>'Unauthorized']); exit; }
            $key = key_resolve($u); $s = key_load($key);
            if (!$s) $s = denius_cloud_restore($key) ?? [];
            if (!empty($s['config']['auto']) && empty($s['config']['paused']) && !worker_alive($key)) {
                @unlink(KEY_DIR . '/' . hash('sha256', strtolower($key)) . '.lock');
                spawn_worker_async($key);
            }
            $wins = (int)($s['win_count_total'] ?? 0); $losses = (int)($s['loss_count_total'] ?? 0);
            $tot = $wins + $losses;
            echo json_encode([
                'ok'=>true,'nickname'=>$s['nickname']??'','balance'=>$s['balance']??0,
                'config'=>$s['config']??[],'history'=>array_slice($s['history']??[], 0, 100),
                'pending_pred'=>$s['pending_pred']??null,'pending_session'=>$s['pending_session']??null,
                'pending_conf'=>$s['pending_conf']??null,'pending_bet_amount'=>$s['pending_bet_amount']??null,
                'pending_skip'=>$s['pending_skip']??null,'pending_detective'=>$s['pending_detective']??null,
                'last_session_id'=>$s['last_session_id']??0,'pattern_10'=>$s['pattern_10']??'',
                'win_count_total'=>$wins,'loss_count_total'=>$losses,'profit_total'=>(int)($s['profit_total']??0),
                'stats'=>['wins'=>$wins,'losses'=>$losses,'total'=>$tot,
                    'winrate'=>$tot>0?round($wins/$tot*100,1):0,'profit'=>(int)($s['profit_total']??0)],
                'worker_alive'=>worker_alive($key),'ts'=>time(),
            ]); exit;

        case 'tick':
            $u = trim($_POST['user'] ?? ''); $tk = trim($_POST['auth_token'] ?? '');
            if (!verify_token($tk, $u)) { echo json_encode(['ok'=>false,'msg'=>'Unauthorized']); exit; }
            $key = key_resolve($u); $s = key_load($key);
            if (!empty($s['config']['auto']) && empty($s['config']['paused']) && !worker_alive($key)) {
                @unlink(KEY_DIR . '/' . hash('sha256', strtolower($key)) . '.lock');
                spawn_worker_async($key);
            }
            $s2 = key_load($key);
            echo json_encode([
                'ok'=>true,'worker_alive'=>worker_alive($key),
                'pending_pred'=>$s2['pending_pred']??null,'pending_session'=>$s2['pending_session']??null,
            ]); exit;

        case 'logout':
            $u = trim($_POST['user'] ?? ''); $tk = trim($_POST['auth_token'] ?? '');
            if (!verify_token($tk, $u)) { echo json_encode(['ok'=>false,'msg'=>'Unauthorized']); exit; }
            $key = key_resolve($u);
            @unlink(key_path($key));
            $lp = KEY_DIR . '/' . hash('sha256', strtolower($key)) . '.lock';
            if (is_file($lp)) {
                $pid = (int)trim(@file_get_contents($lp));
                if ($pid > 0 && function_exists('posix_kill')) @posix_kill($pid, SIGTERM);
                @unlink($lp);
            }
            echo json_encode(['ok'=>true]); exit;
    }
    echo json_encode(['ok'=>false,'msg'=>'Action lạ']);
} catch (Throwable $e) { echo json_encode(['ok'=>false,'msg'=>'Lỗi: ' . $e->getMessage()]); }
exit;

// ═══════ UI ═══════
function render_ui(): void { ?>
<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<meta name="theme-color" content="#0a0618">
<title>DENIUS · お兄ちゃん SUPREME</title>
<style>
:root{
  --bg:#0a0618;--bg-2:#120828;--bg-3:#1c0f38;
  --card:rgba(28,15,56,0.72);--card-solid:#1a0d33;
  --border:rgba(255,183,213,0.10);--border-strong:rgba(255,183,213,0.26);
  --sakura:#ffb7d5;--sakura-bright:#ffd6e8;--sakura-dim:rgba(255,183,213,0.14);
  --lavender:#c4a7e7;--violet:#8b6fc4;
  --gold:#ffd966;--gold-bright:#ffe89a;
  --mint:#7ef0b4;--ruby:#ff5c7a;
  --text:#fff5eb;--text-dim:#a89cbd;--muted:#5e4d75;
  --radius:20px;--radius-lg:26px;
}
*{margin:0;padding:0;box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html,body{min-height:100%;background:var(--bg);color:var(--text);overflow-x:hidden;
  font-family:-apple-system,BlinkMacSystemFont,"Hiragino Sans","Yu Gothic","Noto Sans JP","Inter","Segoe UI",system-ui,sans-serif;
  -webkit-font-smoothing:antialiased;user-select:none}
/* Animated mesh background */
.mesh-bg{position:fixed;inset:-50%;z-index:0;pointer-events:none;opacity:0.85;
  background:
    radial-gradient(circle at 20% 30%,rgba(255,183,213,0.18),transparent 40%),
    radial-gradient(circle at 80% 20%,rgba(139,111,196,0.14),transparent 42%),
    radial-gradient(circle at 60% 80%,rgba(255,217,102,0.06),transparent 45%),
    radial-gradient(circle at 30% 90%,rgba(196,167,231,0.12),transparent 42%);
  animation:meshRotate 30s linear infinite}
@keyframes meshRotate{to{transform:rotate(360deg)}}
/* Noise texture */
body::before{content:'';position:fixed;inset:0;z-index:0;pointer-events:none;opacity:0.35;
  background-image:url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='120' height='120'><filter id='n'><feTurbulence baseFrequency='0.9' numOctaves='3' stitchTiles='stitch'/><feColorMatrix values='0 0 0 0 1  0 0 0 0 1  0 0 0 0 1  0 0 0 0.04 0'/></filter><rect width='120' height='120' filter='url(%23n)'/></svg>")}
/* Sakura petals */
.sakura-layer{position:fixed;inset:0;pointer-events:none;z-index:1;overflow:hidden}
.petal{position:absolute;width:12px;height:12px;
  background:radial-gradient(ellipse at 30% 30%,var(--sakura-bright),var(--sakura) 55%,transparent 80%);
  border-radius:50% 0 50% 50%;opacity:0.55;animation:fall linear infinite;
  filter:drop-shadow(0 0 4px rgba(255,183,213,0.4))}
@keyframes fall{0%{transform:translateY(-20px) translateX(0) rotate(0);opacity:0}10%{opacity:0.7}90%{opacity:0.7}100%{transform:translateY(105vh) translateX(60px) rotate(360deg);opacity:0}}
#app{position:relative;z-index:2;min-height:100vh;display:flex;flex-direction:column}
/* Login */
.login-screen{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.login-card{width:100%;max-width:420px;position:relative;
  background:linear-gradient(160deg,rgba(28,15,56,0.88),rgba(10,6,24,0.95));
  border:1px solid var(--border-strong);border-radius:var(--radius-lg);padding:38px 28px 32px;
  box-shadow:0 30px 80px -20px rgba(0,0,0,0.85),0 0 80px -30px rgba(255,183,213,0.3);
  backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);
  animation:cardEnter 0.7s cubic-bezier(0.34,1.56,0.64,1)}
.login-card::before{content:'';position:absolute;inset:0;border-radius:var(--radius-lg);padding:1px;
  background:conic-gradient(from 0deg,transparent 0%,var(--sakura) 25%,var(--gold) 50%,var(--lavender) 75%,transparent 100%);
  -webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);
  -webkit-mask-composite:xor;mask-composite:exclude;animation:borderSpin 8s linear infinite;opacity:0.7}
@keyframes borderSpin{to{transform:rotate(360deg)}}
@keyframes cardEnter{from{opacity:0;transform:translateY(40px) scale(0.94)}to{opacity:1;transform:translateY(0) scale(1)}}
.logo-wrap{text-align:center;margin-bottom:18px}
.logo-img{width:120px;height:120px;object-fit:cover;border-radius:50%;
  border:2px solid var(--sakura);background:var(--bg-2);
  box-shadow:0 0 40px rgba(255,183,213,0.45),0 0 80px rgba(255,183,213,0.2),inset 0 0 20px rgba(255,183,213,0.15);
  animation:logoFloat 3.5s ease-in-out infinite,pulseGlow 3s ease-in-out infinite}
@keyframes logoFloat{0%,100%{transform:translateY(0)}50%{transform:translateY(-8px)}}
@keyframes pulseGlow{0%,100%{box-shadow:0 0 40px rgba(255,183,213,0.45),0 0 80px rgba(255,183,213,0.2),inset 0 0 20px rgba(255,183,213,0.15)}50%{box-shadow:0 0 55px rgba(255,183,213,0.65),0 0 100px rgba(255,183,213,0.3),inset 0 0 25px rgba(255,183,213,0.2)}}
.brand-title{font-size:24px;font-weight:900;letter-spacing:4px;text-align:center;
  background:linear-gradient(90deg,var(--sakura-bright),var(--gold-bright),var(--sakura-bright));
  background-size:200% 100%;
  -webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;
  text-shadow:0 0 30px rgba(255,183,213,0.3);margin-bottom:6px;animation:shimmer 4s linear infinite}
@keyframes shimmer{to{background-position:200% 0}}
.brand-sub{text-align:center;font-size:11px;letter-spacing:2px;color:var(--text-dim);
  font-weight:600;margin-bottom:26px;display:flex;align-items:center;justify-content:center;gap:6px}
.jp{color:var(--sakura);font-weight:700}
.field{margin-bottom:14px}
.field label{display:flex;align-items:center;gap:6px;font-size:10px;font-weight:800;
  color:var(--text-dim);text-transform:uppercase;letter-spacing:1.5px;margin-bottom:7px}
.field input{width:100%;padding:14px 16px;
  background:rgba(10,6,24,0.85);border:1px solid rgba(255,183,213,0.1);border-radius:14px;
  color:var(--text);font-size:14px;outline:none;transition:all 0.3s;font-family:inherit}
.field input:focus{border-color:var(--sakura);background:rgba(255,183,213,0.03);
  box-shadow:0 0 0 3px rgba(255,183,213,0.12),0 0 20px rgba(255,183,213,0.1)}
.field input::placeholder{color:var(--muted)}
.btn{width:100%;padding:15px;border:none;border-radius:14px;font-size:13px;font-weight:900;
  letter-spacing:2px;text-transform:uppercase;cursor:pointer;transition:all 0.3s;
  font-family:inherit;position:relative;overflow:hidden;margin-top:10px;
  display:flex;align-items:center;justify-content:center;gap:8px}
.btn-sakura{background:linear-gradient(135deg,var(--sakura-bright),var(--sakura));
  color:#1a0d33;box-shadow:0 8px 28px -8px rgba(255,183,213,0.5),0 0 40px -15px rgba(255,183,213,0.3)}
.btn-sakura::before{content:'';position:absolute;top:0;left:-100%;width:100%;height:100%;
  background:linear-gradient(90deg,transparent,rgba(255,255,255,0.3),transparent);transition:left 0.5s}
.btn-sakura:hover:not(:disabled)::before{left:100%}
.btn-sakura:hover:not(:disabled){transform:translateY(-2px);
  box-shadow:0 12px 36px -8px rgba(255,183,213,0.7),0 0 50px -15px rgba(255,183,213,0.5)}
.btn-sakura:active{transform:scale(0.98)}
.btn-sakura:disabled{opacity:0.5;cursor:not-allowed}
.btn-sakura:disabled::after{content:'';position:absolute;width:16px;height:16px;top:50%;right:22px;margin-top:-8px;
  border-radius:50%;border:2px solid rgba(26,13,51,0.3);border-top-color:#1a0d33;animation:spin 0.7s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.btn-ghost{background:rgba(255,183,213,0.06);color:var(--sakura);border:1px solid var(--border);
  box-shadow:none;padding:12px;font-size:12px;margin-top:8px}
.btn-ghost:hover{background:rgba(255,183,213,0.12);border-color:var(--border-strong)}
.msg{margin-top:14px;padding:12px 16px;border-radius:12px;font-size:12px;
  display:flex;align-items:center;gap:8px;animation:slideDown 0.3s}
.msg.err{background:rgba(255,92,122,0.1);border:1px solid rgba(255,92,122,0.3);color:#ffa0b3}
@keyframes slideDown{from{opacity:0;transform:translateY(-8px)}to{opacity:1;transform:translateY(0)}}
.login-foot{margin-top:22px;text-align:center;font-size:10px;color:var(--muted);line-height:1.8;letter-spacing:0.5px}
.login-foot b{color:var(--sakura)}
/* Info */
.info-screen{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.info-card{width:100%;max-width:400px;position:relative;
  background:linear-gradient(160deg,rgba(28,15,56,0.92),rgba(10,6,24,0.96));
  border:1px solid var(--border-strong);border-radius:var(--radius-lg);padding:34px 26px 26px;
  backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);
  box-shadow:0 30px 80px -20px rgba(0,0,0,0.85),0 0 80px -30px rgba(255,183,213,0.3);
  animation:infoEnter 0.8s cubic-bezier(0.34,1.56,0.64,1)}
@keyframes infoEnter{from{opacity:0;transform:scale(0.9) translateY(-30px);filter:blur(15px)}to{opacity:1;transform:scale(1) translateY(0);filter:blur(0)}}
.info-close{position:absolute;top:14px;right:14px;width:34px;height:34px;border-radius:50%;
  background:rgba(255,92,122,0.12);border:1px solid rgba(255,92,122,0.35);color:var(--ruby);
  font-size:16px;font-weight:900;cursor:pointer;display:flex;align-items:center;justify-content:center;
  transition:all 0.25s;font-family:inherit;line-height:1}
.info-close:hover{background:rgba(255,92,122,0.25);transform:rotate(90deg)}
.info-head{text-align:center;margin-bottom:22px}
.info-avatar{width:80px;height:80px;border-radius:50%;margin:0 auto 14px;
  background:linear-gradient(135deg,var(--sakura),var(--lavender));
  display:flex;align-items:center;justify-content:center;
  font-size:36px;font-weight:900;color:#1a0d33;
  box-shadow:0 0 40px rgba(255,183,213,0.5),0 0 80px rgba(255,183,213,0.25);
  animation:avatarPop 0.7s cubic-bezier(0.34,1.56,0.64,1) 0.2s both}
@keyframes avatarPop{from{transform:scale(0);opacity:0}to{transform:scale(1);opacity:1}}
.info-greet{font-size:14px;color:var(--sakura);font-weight:700;letter-spacing:1px;margin-bottom:4px;animation:fadeIn 0.6s 0.3s both}
.info-name{font-size:22px;font-weight:900;color:var(--text);margin-bottom:6px;animation:fadeIn 0.6s 0.4s both}
.info-tag{font-size:10px;color:var(--text-dim);letter-spacing:2px;text-transform:uppercase;font-weight:600;animation:fadeIn 0.6s 0.5s both}
@keyframes fadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
.info-stats{display:grid;grid-template-columns:1fr;gap:10px;margin-top:20px;animation:fadeIn 0.6s 0.6s both}
.info-stat{padding:14px;background:rgba(255,183,213,0.05);border:1px solid var(--border);border-radius:14px;
  display:flex;align-items:center;justify-content:space-between;gap:12px}
.info-stat .lbl{font-size:11px;color:var(--text-dim);font-weight:700;letter-spacing:0.5px;display:flex;align-items:center;gap:6px}
.info-stat .val{font-size:15px;font-weight:900;color:var(--gold-bright);font-family:"SF Mono",monospace}
.info-stat .val.small{font-size:11px;color:var(--sakura);letter-spacing:1px}
/* Setup */
.setup-screen{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.setup-card{width:100%;max-width:400px;position:relative;
  background:linear-gradient(160deg,rgba(28,15,56,0.92),rgba(10,6,24,0.96));
  border:1px solid var(--border-strong);border-radius:var(--radius-lg);padding:32px 26px 26px;
  backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);
  box-shadow:0 30px 80px -20px rgba(0,0,0,0.85),0 0 80px -30px rgba(255,183,213,0.3);
  animation:infoEnter 0.7s cubic-bezier(0.34,1.56,0.64,1)}
.setup-back{position:absolute;top:14px;left:14px;padding:6px 12px;border-radius:20px;
  background:rgba(255,183,213,0.08);border:1px solid var(--border);color:var(--text-dim);
  font-size:10px;font-weight:800;cursor:pointer;font-family:inherit;letter-spacing:1px;
  display:flex;align-items:center;gap:5px;transition:all 0.2s}
.setup-back:hover{background:rgba(255,183,213,0.15);color:var(--sakura);border-color:var(--border-strong)}
.setup-step{font-size:10px;letter-spacing:2px;color:var(--sakura);font-weight:800;text-align:center;
  margin-bottom:8px;text-transform:uppercase}
.setup-title{font-size:20px;font-weight:900;text-align:center;margin-bottom:6px;color:var(--text);letter-spacing:0.5px}
.setup-sub{font-size:11px;text-align:center;color:var(--text-dim);line-height:1.6;margin-bottom:22px}
.setup-hint{font-size:10px;color:var(--text-dim);background:rgba(255,183,213,0.06);
  border:1px solid rgba(255,183,213,0.15);border-radius:10px;padding:12px 14px;margin-top:16px;
  line-height:1.7;text-align:center}
.setup-hint b{color:var(--sakura)}
/* Main */
.main-screen{min-height:100vh;display:flex;flex-direction:column;padding:16px 16px 100px}
.main-header{display:flex;align-items:center;gap:12px;padding:14px 16px;margin-bottom:14px;
  background:linear-gradient(135deg,rgba(28,15,56,0.88),rgba(10,6,24,0.92));
  border:1px solid var(--border-strong);border-radius:18px;
  backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);
  box-shadow:0 8px 28px -12px rgba(0,0,0,0.5)}
.main-logo{width:44px;height:44px;border-radius:50%;object-fit:cover;
  border:1.5px solid var(--sakura);box-shadow:0 0 20px rgba(255,183,213,0.35);
  flex-shrink:0;background:var(--bg-2)}
.main-brand{flex:1;min-width:0}
.main-brand h1{font-size:13px;font-weight:900;letter-spacing:2px;
  background:linear-gradient(90deg,var(--sakura-bright),var(--gold-bright));
  -webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
.main-brand small{display:block;font-size:9px;color:var(--text-dim);letter-spacing:1px;margin-top:2px;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.main-actions{display:flex;gap:6px;flex-shrink:0}
.action-btn{width:36px;height:36px;border-radius:50%;border:1px solid var(--border);
  background:rgba(28,15,56,0.6);color:var(--text-dim);font-size:15px;cursor:pointer;
  display:flex;align-items:center;justify-content:center;transition:all 0.25s;font-family:inherit}
.action-btn.kill{color:var(--ruby);border-color:rgba(255,92,122,0.3);background:rgba(255,92,122,0.08)}
.action-btn.kill:hover{background:rgba(255,92,122,0.2);transform:scale(1.1)}
.action-btn.logout{color:var(--gold);border-color:rgba(255,217,102,0.3);background:rgba(255,217,102,0.08)}
.action-btn.logout:hover{background:rgba(255,217,102,0.2);transform:scale(1.1)}
.balance-card{padding:20px 22px;margin-bottom:14px;
  background:linear-gradient(135deg,rgba(28,15,56,0.92),rgba(10,6,24,0.94));
  border:1px solid var(--border-strong);border-radius:20px;
  backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);
  position:relative;overflow:hidden}
.balance-card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;
  background:linear-gradient(90deg,transparent,var(--sakura),var(--gold),var(--sakura),transparent);
  opacity:0.7;animation:shimmer 3s linear infinite}
.balance-label{font-size:9px;letter-spacing:2px;color:var(--text-dim);font-weight:800;
  text-transform:uppercase;margin-bottom:6px;display:flex;align-items:center;gap:6px}
.balance-value{font-size:32px;font-weight:900;color:var(--gold-bright);
  font-family:"SF Mono","Consolas",monospace;letter-spacing:1px;
  text-shadow:0 0 24px rgba(255,217,102,0.5);transition:all 0.3s;line-height:1}
.balance-value.updating{transform:scale(1.05);color:var(--mint);text-shadow:0 0 30px rgba(126,240,180,0.6)}
.balance-value.suffix{font-size:18px;color:var(--text-dim);margin-left:6px;text-shadow:none}
.result-card{padding:32px 22px;margin-bottom:14px;text-align:center;
  background:linear-gradient(160deg,rgba(28,15,56,0.94),rgba(10,6,24,0.96));
  border:1px solid var(--border-strong);border-radius:var(--radius-lg);
  backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);
  box-shadow:0 10px 40px -12px rgba(0,0,0,0.6),0 0 60px -30px rgba(255,183,213,0.25);
  position:relative;overflow:hidden;min-height:240px;
  display:flex;flex-direction:column;align-items:center;justify-content:center}
.result-card::before{content:'';position:absolute;top:0;left:15%;right:15%;height:1px;
  background:linear-gradient(90deg,transparent,var(--sakura),var(--gold),var(--sakura),transparent);
  opacity:0.7}
.result-session{font-size:10px;letter-spacing:2px;color:var(--text-dim);font-weight:800;
  text-transform:uppercase;margin-bottom:18px}
.result-prediction{font-size:64px;font-weight:900;line-height:1;margin-bottom:12px;
  transition:all 0.4s;letter-spacing:3px}
.result-prediction.tai{background:linear-gradient(135deg,#7ec8ff,#4a9eff,#7ec8ff);
  background-size:200% 100%;-webkit-background-clip:text;background-clip:text;
  -webkit-text-fill-color:transparent;filter:drop-shadow(0 0 30px rgba(78,158,255,0.6));
  animation:shimmer 3s linear infinite}
.result-prediction.xiu{background:linear-gradient(135deg,#ff8fa0,#ff5c7a,#ff8fa0);
  background-size:200% 100%;-webkit-background-clip:text;background-clip:text;
  -webkit-text-fill-color:transparent;filter:drop-shadow(0 0 30px rgba(255,92,122,0.6));
  animation:shimmer 3s linear infinite}
.result-prediction.wait{color:var(--muted);font-size:38px;letter-spacing:4px}
.result-label{font-size:11px;color:var(--text-dim);letter-spacing:3px;font-weight:700;
  text-transform:uppercase;margin-bottom:10px}
.result-conf{margin-top:12px;padding-top:16px;border-top:1px dashed rgba(255,183,213,0.15);width:100%}
.conf-bar{height:6px;border-radius:3px;background:rgba(255,255,255,0.05);overflow:hidden;margin-top:8px}
.conf-bar>i{display:block;height:100%;background:linear-gradient(90deg,var(--ruby),var(--gold),var(--mint));
  border-radius:3px;transition:width 0.4s;box-shadow:0 0 12px rgba(255,217,102,0.5)}
.conf-label{font-size:10px;color:var(--text-dim);font-weight:700;letter-spacing:0.5px;
  display:flex;justify-content:space-between}
.conf-label b{color:var(--gold-bright)}
.result-outcome{margin-top:18px;padding-top:18px;border-top:1px dashed rgba(255,183,213,0.15);
  width:100%;display:none}
.result-outcome.show{display:block;animation:outcomeIn 0.5s cubic-bezier(0.34,1.56,0.64,1)}
@keyframes outcomeIn{from{opacity:0;transform:scale(0.9)}to{opacity:1;transform:scale(1)}}
.result-outcome .big{font-size:26px;font-weight:900;letter-spacing:2px;margin-bottom:6px}
.result-outcome .big.win{color:var(--mint);text-shadow:0 0 30px rgba(126,240,180,0.5)}
.result-outcome .big.lose{color:var(--ruby);text-shadow:0 0 30px rgba(255,92,122,0.5)}
.result-outcome .big.skip{color:var(--gold);text-shadow:0 0 30px rgba(255,217,102,0.5)}
.result-outcome .detail{font-size:12px;color:var(--text-dim);font-family:monospace;letter-spacing:0.5px}
.result-outcome .detail b{color:var(--gold-bright)}
.bet-card{padding:16px 20px;margin-bottom:14px;
  background:linear-gradient(135deg,rgba(255,183,213,0.08),rgba(28,15,56,0.92));
  border:1px solid rgba(255,183,213,0.22);border-radius:18px;
  backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);
  display:flex;align-items:center;justify-content:space-between;gap:14px;
  box-shadow:0 8px 24px -12px rgba(0,0,0,0.4)}
.bet-label{font-size:10px;letter-spacing:2px;color:var(--text-dim);font-weight:800;
  text-transform:uppercase;margin-bottom:4px;display:flex;align-items:center;gap:6px}
.bet-label::before{content:'💎';font-size:12px}
.bet-value{font-size:22px;font-weight:900;color:var(--gold-bright);
  font-family:"SF Mono",monospace;letter-spacing:1px;
  text-shadow:0 0 20px rgba(255,217,102,0.4);transition:all 0.3s}
.bet-value.pulse{animation:betPulse 0.6s ease-out}
@keyframes betPulse{0%{transform:scale(1)}50%{transform:scale(1.15);color:var(--sakura)}100%{transform:scale(1)}}
.bet-streak{text-align:right}
.bet-streak small{font-size:9px;color:var(--text-dim);letter-spacing:1px;font-weight:700;
  text-transform:uppercase;display:block}
.bet-streak b{font-size:15px;font-weight:900;color:var(--sakura);font-family:"SF Mono",monospace;
  display:block;margin-top:2px}
/* Detective panel */
.detective-panel{padding:14px 16px;margin-bottom:14px;
  background:linear-gradient(135deg,rgba(139,111,196,0.08),rgba(28,15,56,0.92));
  border:1px solid rgba(196,167,231,0.22);border-radius:18px;
  backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px)}
.det-head{display:flex;align-items:center;justify-content:space-between;gap:10px;cursor:pointer}
.det-title{font-size:11px;font-weight:900;color:var(--lavender);letter-spacing:1.5px;
  text-transform:uppercase;display:flex;align-items:center;gap:8px}
.det-verdict{font-size:10px;font-weight:900;padding:4px 10px;border-radius:20px;letter-spacing:1px}
.det-verdict.follow{background:rgba(126,240,180,0.15);color:var(--mint);border:1px solid rgba(126,240,180,0.3)}
.det-verdict.skip{background:rgba(255,92,122,0.15);color:var(--ruby);border:1px solid rgba(255,92,122,0.3)}
.det-verdict.conflict{background:rgba(255,217,102,0.15);color:var(--gold);border:1px solid rgba(255,217,102,0.3)}
.det-toggle{color:var(--text-dim);font-size:11px;transition:transform 0.3s}
.det-toggle.open{transform:rotate(180deg)}
.det-votes{margin-top:12px;display:none;grid-template-columns:1fr 1fr;gap:6px}
.det-votes.open{display:grid}
.det-vote{padding:8px 10px;background:rgba(255,255,255,0.03);border:1px solid var(--border);
  border-radius:8px;font-size:10px;display:flex;flex-direction:column;gap:2px}
.det-vote .vn{font-weight:800;color:var(--text-dim);text-transform:uppercase;font-size:9px;letter-spacing:0.5px}
.det-vote .vv{font-weight:900;font-size:11px;letter-spacing:0.5px}
.det-vote .vv.follow{color:var(--mint)}
.det-vote .vv.skip{color:var(--ruby)}
.det-vote .vv.conflict{color:var(--gold)}
.det-vote .vt{font-size:9px;color:var(--muted);font-family:monospace}
/* Bottom nav */
.bottom-nav{position:fixed;bottom:0;left:0;right:0;z-index:20;padding:10px 20px 14px;
  background:linear-gradient(180deg,rgba(10,6,24,0.4),rgba(10,6,24,0.98) 40%);
  backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);
  border-top:1px solid var(--border);display:flex;justify-content:center;gap:8px}
.nav-btn{flex:1;max-width:180px;padding:12px 16px;background:rgba(28,15,56,0.6);
  border:1px solid var(--border);color:var(--text-dim);font-size:11px;font-weight:800;
  letter-spacing:1px;border-radius:14px;cursor:pointer;transition:all 0.25s;
  display:flex;align-items:center;justify-content:center;gap:6px;font-family:inherit;
  text-transform:uppercase}
.nav-btn.on{background:linear-gradient(135deg,var(--sakura-bright),var(--sakura));
  color:#1a0d33;border-color:transparent;box-shadow:0 6px 20px -6px rgba(255,183,213,0.5)}
.nav-btn:not(.on):hover{color:var(--text);background:rgba(255,183,213,0.05);border-color:var(--border-strong)}
/* History */
.history-screen{padding:16px 16px 100px;min-height:100vh}
.history-header{display:flex;align-items:center;justify-content:space-between;gap:12px;
  padding:14px 18px;margin-bottom:14px;
  background:linear-gradient(135deg,rgba(28,15,56,0.88),rgba(10,6,24,0.92));
  border:1px solid var(--border-strong);border-radius:18px;
  backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px)}
.history-title{font-size:14px;font-weight:900;color:var(--sakura);letter-spacing:2px;text-transform:uppercase}
.history-count{font-size:10px;color:var(--text-dim);font-weight:700;padding:4px 10px;
  background:rgba(255,183,213,0.08);border-radius:20px;border:1px solid var(--border)}
.hist-list{display:flex;flex-direction:column;gap:8px}
.hist-row{padding:14px 16px;
  background:linear-gradient(135deg,rgba(28,15,56,0.72),rgba(10,6,24,0.82));
  border:1px solid var(--border);border-radius:14px;display:flex;align-items:center;gap:12px;
  transition:all 0.2s;backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);
  border-left:3px solid var(--muted)}
.hist-row.win{border-left-color:var(--mint);background:linear-gradient(90deg,rgba(126,240,180,0.06),rgba(10,6,24,0.82))}
.hist-row.lose{border-left-color:var(--ruby);background:linear-gradient(90deg,rgba(255,92,122,0.06),rgba(10,6,24,0.82))}
.hist-row.skip{border-left-color:var(--gold);background:linear-gradient(90deg,rgba(255,217,102,0.06),rgba(10,6,24,0.82))}
.hist-row.jackpot{border-left-color:var(--gold);animation:jackpotPulse 2s ease-in-out infinite}
@keyframes jackpotPulse{0%,100%{box-shadow:0 0 0 rgba(255,217,102,0)}50%{box-shadow:0 0 20px rgba(255,217,102,0.3)}}
.hist-sid{font-family:"SF Mono",monospace;color:var(--sakura);font-weight:800;
  font-size:11px;min-width:60px}
.hist-mid{flex:1;min-width:0}
.hist-mid .row1{font-size:12px;font-weight:800;margin-bottom:3px;
  display:flex;align-items:center;gap:6px;flex-wrap:wrap;color:var(--text)}
.hist-mid .row2{font-size:10px;color:var(--text-dim);font-family:"SF Mono",monospace;letter-spacing:0.3px}
.hist-amount{font-family:"SF Mono",monospace;font-weight:900;font-size:13px;
  min-width:76px;text-align:right;letter-spacing:0.3px}
.hist-amount.win{color:var(--mint)}
.hist-amount.lose{color:var(--ruby)}
.hist-amount.skip{color:var(--gold)}
.empty-state{padding:60px 20px;text-align:center;color:var(--text-dim);font-size:12px}
.empty-state .icon{font-size:52px;margin-bottom:16px;opacity:0.4;display:block}
.empty-state .title{font-size:14px;font-weight:800;color:var(--text);margin-bottom:6px}
.empty-state .sub{font-size:11px;color:var(--muted);letter-spacing:0.5px}
/* Toast */
#toast{position:fixed;top:20px;right:20px;z-index:9999;display:flex;flex-direction:column;gap:8px;pointer-events:none;max-width:340px}
.toast{padding:12px 18px;border-radius:12px;font-size:12px;font-weight:600;color:#fff;
  background:rgba(28,15,56,0.98);border:1px solid var(--border-strong);
  box-shadow:0 12px 32px -8px rgba(0,0,0,0.6);backdrop-filter:blur(12px);
  animation:toastIn 0.35s cubic-bezier(0.34,1.56,0.64,1);display:flex;align-items:center;gap:10px}
.toast.success{border-color:rgba(126,240,180,0.4);background:linear-gradient(135deg,rgba(126,240,180,0.15),rgba(28,15,56,0.98))}
.toast.error{border-color:rgba(255,92,122,0.4);background:linear-gradient(135deg,rgba(255,92,122,0.15),rgba(28,15,56,0.98))}
.toast.gold{border-color:rgba(255,217,102,0.4);background:linear-gradient(135deg,rgba(255,217,102,0.15),rgba(28,15,56,0.98))}
@keyframes toastIn{from{opacity:0;transform:translateX(100px)}to{opacity:1;transform:translateX(0)}}
/* Reconnect banner */
.reconnect-banner{position:fixed;top:0;left:0;right:0;z-index:1000;padding:10px;
  background:linear-gradient(90deg,rgba(255,92,122,0.9),rgba(255,143,160,0.9));
  color:#fff;font-size:11px;font-weight:800;text-align:center;letter-spacing:1px;
  display:none;animation:slideDown 0.3s}
.reconnect-banner.show{display:block}
.hide{display:none!important}
@media(max-width:360px){
  .login-card,.info-card,.setup-card{padding:26px 20px}
  .logo-img{width:96px;height:96px}
  .brand-title{font-size:20px;letter-spacing:3px}
  .result-prediction{font-size:52px}
  .balance-value{font-size:26px}
}
@media (prefers-reduced-motion:reduce){.petal,.logo-img,.brand-title,.mesh-bg,.result-prediction,.hist-row.jackpot{animation:none!important}}
</style>
</head>
<body>
<div class="mesh-bg"></div>
<div class="sakura-layer" id="sakura"></div>
<div class="reconnect-banner" id="reconnect">⚡ MẤT KẾT NỐI · ĐANG THỬ LẠI...</div>
<div id="app"></div>
<div id="toast"></div>
<script>
// ══════════════════════════════════════════════════════
// STATE
// ══════════════════════════════════════════════════════
const LOGO_URL = 'https://raw.githubusercontent.com/nguyenha783255-wq/LOGO-LC79/main/IMG_20260901_094944_094.jpg';
const LS_KEY = 'denius_supreme_v3';
const app = document.getElementById('app');
const toastBox = document.getElementById('toast');
const reconnectBanner = document.getElementById('reconnect');

const S = {
  step: 'login', tab: 'main',
  user: '', nickname: '', balance: 0, authToken: '', device: '',
  loading: false, error: '',
  config: {base_bet:0,profit_stop:0,target_win:0,auto:false,paused:false,lose_streak:0,mode:'double',max_lose_streak:4,onboarded:false},
  history: [], stats: {wins:0,losses:0,total:0,winrate:0,profit:0},
  pendingPred: null, pendingSession: null, pendingConf: null, pendingBetAmount: null,
  pendingSkip: null, pendingDetective: null,
  workerAlive: false,
  setupBaseBet: 0, setupTarget: 0,
  detOpen: false,
};

(function() {
  const d = [navigator.userAgent, navigator.language, screen.width+'x'+screen.height, new Date().getTimezoneOffset()].join('|');
  let h = 0; for (let i = 0; i < d.length; i++) h = ((h << 5) - h) + d.charCodeAt(i), h |= 0;
  S.device = 'ONI-' + Math.abs(h).toString(16).toUpperCase().slice(0, 8);
})();

// Sakura
function spawnSakura() {
  const layer = document.getElementById('sakura');
  if (!layer) return;
  const count = window.innerWidth < 600 ? 10 : 16;
  for (let i = 0; i < count; i++) {
    const p = document.createElement('div');
    p.className = 'petal';
    p.style.left = Math.random() * 100 + '%';
    const dur = 8 + Math.random() * 8;
    p.style.animationDuration = dur + 's';
    p.style.animationDelay = (Math.random() * dur) + 's';
    const sz = 8 + Math.random() * 8;
    p.style.width = sz + 'px';
    p.style.height = sz + 'px';
    layer.appendChild(p);
  }
}

const fmt = n => (n || 0).toLocaleString('vi-VN');
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

function toast(msg, type = 'info') {
  const el = document.createElement('div');
  el.className = 'toast ' + type;
  el.textContent = msg;
  toastBox.appendChild(el);
  setTimeout(() => { el.style.opacity = '0'; el.style.transform = 'translateX(100px)'; }, 2800);
  setTimeout(() => el.remove(), 3200);
}

// ══════════════════════════════════════════════════════
// REMEMBER ME
// ══════════════════════════════════════════════════════
function saveAuth(user, token, nickname) {
  try { localStorage.setItem(LS_KEY, JSON.stringify({u:user, t:token, n:nickname, ts:Date.now()})); } catch(e) {}
}
function loadAuth() {
  try { const j = localStorage.getItem(LS_KEY); return j ? JSON.parse(j) : null; } catch(e) { return null; }
}
function clearAuth() { try { localStorage.removeItem(LS_KEY); } catch(e) {} }

// ══════════════════════════════════════════════════════
// RENDER
// ══════════════════════════════════════════════════════
function render() {
  if (S.step === 'login') renderLogin();
  else if (S.step === 'info') renderInfo();
  else if (S.step === 'base_bet') renderBaseBet();
  else if (S.step === 'target') renderTarget();
  else if (S.step === 'main') S.tab === 'history' ? renderHistory() : renderMain();
}

function renderLogin() {
  app.innerHTML = `
    <div class="login-screen">
      <div class="login-card">
        <div class="logo-wrap"><img src="${LOGO_URL}" alt="DENIUS" class="logo-img" onerror="this.style.display='none'"></div>
        <div class="brand-title">DENIUS</div>
        <div class="brand-sub"><span class="jp">お兄ちゃん</span> · AUTO BOT</div>
        <div class="field">
          <label>👤 TÀI KHOẢN</label>
          <input id="in_u" type="text" placeholder="Nhập tài khoản..." value="${esc(S.user)}">
        </div>
        <div class="field">
          <label>🔒 MẬT KHẨU</label>
          <input id="in_p" type="password" placeholder="••••••••">
        </div>
        <button class="btn btn-sakura" id="btn_login" ${S.loading ? 'disabled' : ''}>
          ${S.loading ? 'ĐANG XÁC THỰC' : 'ĐĂNG NHẬP'}
        </button>
        ${S.error ? `<div class="msg err">⚠️ ${esc(S.error)}</div>` : ''}
        <div class="login-foot"><b>V3.0 SUPREME</b> · Admin <b>@DENIUS09</b></div>
      </div>
    </div>
  `;
  document.getElementById('btn_login').onclick = doLogin;
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
    S.step = (S.config.onboarded && S.config.base_bet > 0) ? 'main' : 'info';
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
      pendingConf:r.pending_conf, pendingBetAmount:r.pending_bet_amount,
      pendingSkip:r.pending_skip, pendingDetective:r.pending_detective,
      stats:r.stats,
    });
    S.step = (S.config.onboarded && S.config.base_bet > 0) ? 'main' : 'info';
    S.tab = 'main';
    saveAuth(r.user, r.auth_token, r.nickname);
    render();
    startTick();
  } catch (e) { clearAuth(); render(); }
}

function renderInfo() {
  const init = (S.nickname || '?')[0].toUpperCase();
  app.innerHTML = `
    <div class="info-screen">
      <div class="info-card">
        <button class="info-close" id="btn_info_close" title="Đóng">✕</button>
        <div class="info-head">
          <div class="info-avatar">${esc(init)}</div>
          <div class="info-greet">ようこそ、お兄ちゃん</div>
          <div class="info-name">${esc(S.nickname)}</div>
          <div class="info-tag">ACCOUNT VERIFIED</div>
        </div>
        <div class="info-stats">
          <div class="info-stat"><span class="lbl">💰 SỐ DƯ</span><span class="val">${fmt(S.balance)}đ</span></div>
          <div class="info-stat"><span class="lbl">🔑 TÀI KHOẢN</span><span class="val">${esc(S.user)}</span></div>
          <div class="info-stat"><span class="lbl">📱 DEVICE</span><span class="val small">${esc(S.device)}</span></div>
        </div>
      </div>
    </div>
  `;
  document.getElementById('btn_info_close').onclick = () => { S.step = 'base_bet'; render(); };
}

function renderBaseBet() {
  const bal = S.balance || 0;
  const sug = Math.max(1000, Math.min(bal > 0 ? Math.floor(bal * 0.02 / 1000) * 1000 : 10000, 100000));
  app.innerHTML = `
    <div class="setup-screen">
      <div class="setup-card">
        <button class="setup-back" id="btn_back_1">← Quay lại</button>
        <div class="setup-step">BƯỚC 1 / 2</div>
        <div class="setup-title">Vốn Cược Mỗi Tay</div>
        <div class="setup-sub">Số dư hiện tại: <b style="color:var(--gold-bright)">${fmt(bal)}đ</b></div>
        <div class="field">
          <label>💰 SỐ VỐN (VNĐ)</label>
          <input id="in_base" type="number" inputmode="numeric" placeholder="VD: 10000" value="${S.setupBaseBet || sug}" min="1000" step="1000">
        </div>
        <button class="btn btn-sakura" id="btn_next_1">TIẾP TỤC →</button>
        ${S.error ? `<div class="msg err">⚠️ ${esc(S.error)}</div>` : ''}
        <div class="setup-hint">
          💎 Hệ thống <b>gấp thếp X2</b> tự động<br>
          Tối đa <b>4 tay sai</b> — sau đó tự reset
        </div>
      </div>
    </div>
  `;
  const inp = document.getElementById('in_base');
  inp.focus(); inp.select();
  document.getElementById('btn_back_1').onclick = () => { S.step = 'info'; render(); };
  document.getElementById('btn_next_1').onclick = () => {
    const v = parseInt(inp.value) || 0;
    if (v < 1000) { S.error = 'Vốn tối thiểu 1.000đ'; render(); return; }
    S.error = ''; S.setupBaseBet = v; S.step = 'target'; render();
  };
  inp.onkeydown = e => { if (e.key === 'Enter') document.getElementById('btn_next_1').click(); };
}

function renderTarget() {
  const bal = S.balance || 0;
  const sug = Math.max(10000, Math.floor(bal * 0.1 / 1000) * 1000 || 100000);
  app.innerHTML = `
    <div class="setup-screen">
      <div class="setup-card">
        <button class="setup-back" id="btn_back_2">← Quay lại</button>
        <div class="setup-step">BƯỚC 2 / 2</div>
        <div class="setup-title">Mục Tiêu Lợi Nhuận</div>
        <div class="setup-sub">Khi đạt mục tiêu, bot tự động dừng.</div>
        <div class="field">
          <label>🎯 MỤC TIÊU (VNĐ)</label>
          <input id="in_target" type="number" inputmode="numeric" placeholder="VD: 500000" value="${S.setupTarget || sug}" min="10000" step="10000">
        </div>
        <button class="btn btn-sakura" id="btn_start" ${S.loading ? 'disabled' : ''}>
          ${S.loading ? 'ĐANG KHỞI ĐỘNG' : '🚀 BẮT ĐẦU AUTO'}
        </button>
        ${S.error ? `<div class="msg err">⚠️ ${esc(S.error)}</div>` : ''}
        <div class="setup-hint">
          ⚙️ <b>Tự động:</b> X2 khi thua · max <b>4 tay</b><br>
          💰 Vốn mỗi tay: <b>${fmt(S.setupBaseBet)}đ</b>
        </div>
      </div>
    </div>
  `;
  const inp = document.getElementById('in_target');
  inp.focus(); inp.select();
  document.getElementById('btn_back_2').onclick = () => { S.step = 'base_bet'; render(); };
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
    const r = await api('setup', {
      user:S.user, base_bet:S.setupBaseBet,
      target_win:S.setupTarget, profit_stop:S.setupTarget,
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
  const predCls = p === 'Tài' ? 'tai' : (p === 'Xỉu' ? 'xiu' : 'wait');
  const predTxt = p || 'ĐANG CHỜ';
  const lastH = S.history[0] || null;
  const conf = S.pendingConf || 0;
  const det = S.pendingDetective;
  const detVerdict = det ? det.verdict : 'CONFLICT';
  const detCls = detVerdict === 'FOLLOW' ? 'follow' : (detVerdict === 'SKIP' ? 'skip' : 'conflict');
  const detLabel = detVerdict === 'FOLLOW' ? '✓ ĐỒNG THUẬN' : (detVerdict === 'SKIP' ? '✕ BỎ PHIÊN' : '⚠ PHÂN VÂN');
  const detAgree = det ? Math.round(det.agree_rate * 100) : 0;

  app.innerHTML = `
    <div class="main-screen">
      <div class="main-header">
        <img src="${LOGO_URL}" alt="DENIUS" class="main-logo" onerror="this.style.display='none'">
        <div class="main-brand">
          <h1>DENIUS</h1>
          <small>お兄ちゃん · ${esc(S.nickname)}</small>
        </div>
        <div class="main-actions">
          <button class="action-btn kill" id="btn_kill" title="Dừng toàn bộ">⏹</button>
          <button class="action-btn logout" id="btn_logout" title="Đăng xuất">⏏</button>
        </div>
      </div>
      <div class="balance-card">
        <div class="balance-label">💰 SỐ DƯ HIỆN TẠI</div>
        <div><span class="balance-value" id="bal_val">${fmt(S.balance)}</span><span class="balance-value suffix">đ</span></div>
      </div>
      <div class="result-card">
        <div class="result-session">PHIÊN #${S.pendingSession || '—'}</div>
        <div class="result-label">${p ? 'DỰ ĐOÁN' : 'ĐANG PHÂN TÍCH'}</div>
        <div class="result-prediction ${predCls}" id="pred_val">${predTxt}</div>
        ${p ? `<div class="result-conf">
          <div class="conf-label"><span>ĐỘ TIN CẬY</span><b>${conf.toFixed(1)}%</b></div>
          <div class="conf-bar"><i style="width:${Math.min(100, conf)}%"></i></div>
        </div>` : ''}
        <div class="result-outcome ${lastH ? 'show' : ''}" id="outcome_box">
          ${lastH ? renderOutcome(lastH) : ''}
        </div>
      </div>
      <div class="bet-card">
        <div>
          <div class="bet-label">SỐ TIỀN CƯỢC</div>
          <div class="bet-value" id="bet_val">${S.pendingBetAmount ? fmt(S.pendingBetAmount) + 'đ' : '—'}</div>
        </div>
        <div class="bet-streak">
          <small>CHUỖI THUA</small>
          <b>${S.config.lose_streak || 0}/4</b>
        </div>
      </div>
      ${det ? `
      <div class="detective-panel">
        <div class="det-head" id="det_head">
          <div class="det-title">🕵️ THÁM TỬ · ${det.follow}/${det.follow + det.skip + det.conflict}</div>
          <div class="det-verdict ${detCls}">${detLabel} · ${detAgree}%</div>
          <div class="det-toggle ${S.detOpen ? 'open' : ''}">▾</div>
        </div>
        <div class="det-votes ${S.detOpen ? 'open' : ''}" id="det_votes">
          ${Object.entries(det.votes || {}).map(([k, v]) => `
            <div class="det-vote">
              <div class="vn">${esc(k)}</div>
              <div class="vv ${v.v.toLowerCase()}">${v.v}</div>
              <div class="vt">${esc(v.note)}</div>
            </div>
          `).join('')}
        </div>
      </div>` : ''}
    </div>
    <div class="bottom-nav">
      <button class="nav-btn on" id="nav_main">🎯 Chính</button>
      <button class="nav-btn" id="nav_hist">📜 Lịch sử</button>
    </div>
  `;

  document.getElementById('nav_main').onclick = () => { S.tab = 'main'; render(); };
  document.getElementById('nav_hist').onclick = () => { S.tab = 'history'; render(); };
  document.getElementById('btn_kill').onclick = doKill;
  document.getElementById('btn_logout').onclick = doLogout;
  const dh = document.getElementById('det_head');
  if (dh) dh.onclick = () => {
    S.detOpen = !S.detOpen;
    document.getElementById('det_votes').classList.toggle('open', S.detOpen);
    dh.querySelector('.det-toggle').classList.toggle('open', S.detOpen);
  };
}

function renderOutcome(h) {
  if (!h) return '';
  const skipped = h.skipped;
  const win = h.win;
  const cls = skipped ? 'skip' : (win ? 'win' : 'lose');
  const label = skipped ? '⏭ BỎ QUA' : (win ? '🎉 THẮNG' : '💔 THUA');
  const dice = (h.dices || []).join('-');
  const delta = skipped ? '—' : (win ? '+' + fmt(Math.floor(h.amount * 0.98)) : '-' + fmt(h.amount));
  return `
    <div class="big ${cls}">${label}</div>
    <div class="detail">
      🎲 ${dice} · ${h.pred === 'Tài' ? 'TÀI' : 'XỈU'} → ${h.result === 'TAI' ? 'TÀI' : 'XỈU'}
      <br><b>${delta}đ</b>${h.jackpot ? '<br>✨ JACKPOT ✨' : ''}
    </div>
  `;
}

async function doKill() {
  if (!confirm('🛑 TẮT AUTO? Toàn bộ lệnh cược sẽ dừng ngay lập tức.')) return;
  try {
    await api('kill', {user:S.user});
    S.config.auto = false; S.config.paused = true;
    S.pendingPred = null; S.pendingSession = null; S.pendingConf = null;
    S.pendingBetAmount = null; S.pendingSkip = null; S.pendingDetective = null;
    toast('🛑 ĐÃ DỪNG TOÀN BỘ', 'error');
    render();
  } catch (e) { toast('Lỗi: ' + e.message, 'error'); }
}

async function doLogout() {
  if (!confirm('🚪 ĐĂNG XUẤT? Bạn sẽ cần đăng nhập lại.')) return;
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
  app.innerHTML = `
    <div class="history-screen">
      <div class="history-header">
        <div class="history-title">📜 LỊCH SỬ</div>
        <div class="history-count">${hist.length} phiên</div>
      </div>
      <div class="hist-list" id="hist_list">
        ${hist.length === 0 ? `<div class="empty-state"><span class="icon">🌸</span><div class="title">Chưa có lịch sử</div><div class="sub">Bắt đầu AUTO để ghi nhận</div></div>` : hist.slice(0, 100).map(h => {
          const skipped = h.skipped;
          const win = h.win;
          const cls = skipped ? 'skip' : (win ? 'win' : 'lose');
          const jp = h.jackpot ? 'jackpot' : '';
          const dice = (h.dices || []).join('-');
          const delta = skipped ? 'SKIP' : (win ? '+' + fmt(Math.floor(h.amount * 0.98)) : '-' + fmt(h.amount));
          return `
            <div class="hist-row ${cls} ${jp}">
              <div class="hist-sid">#${h.session}</div>
              <div class="hist-mid">
                <div class="row1">
                  ${h.pred === 'Tài' ? '🔵' : '🔴'} ${h.pred === 'Tài' ? 'TÀI' : 'XỈU'} → ${h.result === 'TAI' ? '🔵 TÀI' : '🔴 XỈU'}${h.jackpot ? ' 🎉' : ''}${skipped ? ' ⏭' : ''}
                </div>
                <div class="row2">🎲 ${dice} · ${h.ts}</div>
              </div>
              <div class="hist-amount ${cls}">${delta}</div>
            </div>
          `;
        }).join('')}
      </div>
    </div>
    <div class="bottom-nav">
      <button class="nav-btn" id="nav_main2">🎯 Chính</button>
      <button class="nav-btn on" id="nav_hist2">📜 Lịch sử</button>
    </div>
  `;
  document.getElementById('nav_main2').onclick = () => { S.tab = 'main'; render(); };
  document.getElementById('nav_hist2').onclick = () => { S.tab = 'history'; render(); };
}

// ══════════════════════════════════════════════════════
// API + TICK + KEEPALIVE
// ══════════════════════════════════════════════════════
let failCount = 0;
async function api(action, data = {}) {
  if (S.authToken && !data.auth_token) data.auth_token = S.authToken;
  const fd = new FormData(); fd.append('action', action);
  for (const k in data) fd.append(k, data[k]);
  try {
    const r = await fetch(location.pathname + '?action=' + action, {method:'POST', body:fd});
    failCount = 0;
    reconnectBanner.classList.remove('show');
    return await r.json();
  } catch (e) {
    failCount++;
    if (failCount >= 3) reconnectBanner.classList.add('show');
    throw e;
  }
}
async function getStatus() {
  try {
    const r = await fetch(location.pathname + '?action=status&user=' + encodeURIComponent(S.user) + '&auth_token=' + encodeURIComponent(S.authToken) + '&_=' + Date.now());
    failCount = 0; reconnectBanner.classList.remove('show');
    return await r.json();
  } catch (e) {
    failCount++;
    if (failCount >= 3) reconnectBanner.classList.add('show');
    throw e;
  }
}

let tickBusy = false;
async function tick() {
  if (!S.user || !S.authToken || tickBusy) return;
  tickBusy = true;
  try {
    const j = await getStatus();
    if (!j.ok) { tickBusy = false; return; }
    const oldBal = S.balance;
    S.balance = j.balance || 0;
    S.history = j.history || [];
    S.workerAlive = !!j.worker_alive;
    S.stats = j.stats || S.stats;
    S.pendingPred = j.pending_pred;
    S.pendingSession = j.pending_session;
    S.pendingConf = j.pending_conf;
    S.pendingBetAmount = j.pending_bet_amount;
    S.pendingSkip = j.pending_skip;
    S.pendingDetective = j.pending_detective;
    if (j.config) Object.assign(S.config, {
      auto:j.config.auto, paused:j.config.paused, lose_streak:j.config.lose_streak,
      base_bet:j.config.base_bet, profit_stop:j.config.profit_stop, target_win:j.config.target_win,
    });
    if (S.step === 'main' && S.tab === 'main') {
      updateMainUI(oldBal);
    } else if (S.step === 'main' && S.tab === 'history') {
      updateHistoryUI();
    }
  } catch(e) {} finally { tickBusy = false; }
}

function updateMainUI(oldBal) {
  const bv = document.getElementById('bal_val');
  if (bv) {
    bv.textContent = fmt(S.balance);
    if (S.balance !== oldBal) { bv.classList.add('updating'); setTimeout(() => bv.classList.remove('updating'), 400); }
  }
  const pv = document.getElementById('pred_val');
  if (pv) {
    const p = S.pendingPred;
    const cls = p === 'Tài' ? 'tai' : (p === 'Xỉu' ? 'xiu' : 'wait');
    pv.className = 'result-prediction ' + cls;
    pv.textContent = p || 'ĐANG CHỜ';
  }
  const ps = document.querySelector('.result-session');
  if (ps) ps.textContent = 'PHIÊN #' + (S.pendingSession || '—');
  const pl = document.querySelector('.result-label');
  if (pl) pl.textContent = S.pendingPred ? 'DỰ ĐOÁN' : 'ĐANG PHÂN TÍCH';
  const bv2 = document.getElementById('bet_val');
  if (bv2) {
    const newTxt = S.pendingBetAmount ? fmt(S.pendingBetAmount) + 'đ' : '—';
    if (bv2.textContent !== newTxt) { bv2.textContent = newTxt; bv2.classList.add('pulse'); setTimeout(() => bv2.classList.remove('pulse'), 600); }
  }
  const ob = document.getElementById('outcome_box');
  if (ob && S.history[0]) { ob.innerHTML = renderOutcome(S.history[0]); ob.classList.add('show'); }
  const bs = document.querySelector('.bet-streak b');
  if (bs) bs.textContent = (S.config.lose_streak || 0) + '/4';
}

function updateHistoryUI() {
  const hl = document.getElementById('hist_list');
  if (!hl || !S.history.length) return;
  const keys = S.history.map(h => h.session).join(',');
  if (hl.dataset.keys === keys) return;
  hl.dataset.keys = keys;
  hl.innerHTML = S.history.slice(0, 100).map(h => {
    const skipped = h.skipped; const win = h.win;
    const cls = skipped ? 'skip' : (win ? 'win' : 'lose');
    const jp = h.jackpot ? 'jackpot' : '';
    const dice = (h.dices || []).join('-');
    const delta = skipped ? 'SKIP' : (win ? '+' + fmt(Math.floor(h.amount * 0.98)) : '-' + fmt(h.amount));
    return `<div class="hist-row ${cls} ${jp}">
      <div class="hist-sid">#${h.session}</div>
      <div class="hist-mid">
        <div class="row1">${h.pred === 'Tài' ? '🔵' : '🔴'} ${h.pred === 'Tài' ? 'TÀI' : 'XỈU'} → ${h.result === 'TAI' ? '🔵 TÀI' : '🔴 XỈU'}${h.jackpot ? ' 🎉' : ''}${skipped ? ' ⏭' : ''}</div>
        <div class="row2">🎲 ${dice} · ${h.ts}</div>
      </div>
      <div class="hist-amount ${cls}">${delta}</div>
    </div>`;
  }).join('');
}

let tickTimer = null;
function startTick() {
  if (tickTimer) clearInterval(tickTimer);
  tick();
  tickTimer = setInterval(tick, 2500);
  // Keepalive 30s chống Render sleep
  setInterval(() => {
    if (S.user) fetch(location.pathname + '?action=keepalive&_=' + Date.now(), {mode:'no-cors'}).catch(() => {});
  }, 30000);
  // Resume on visibility
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible' && S.user && S.authToken) tick();
  });
  // Worker keepalive: nếu 30s không thấy worker_alive thì ping tick
  setInterval(() => {
    if (S.user && S.authToken && !S.workerAlive && S.config.auto) {
      api('tick', {user:S.user}).catch(() => {});
    }
  }, 15000);
}

// ══════════════════════════════════════════════════════
// BOOT
// ══════════════════════════════════════════════════════
spawnSakura();
tryResume();
</script>
</body>
</html>
<?php }
