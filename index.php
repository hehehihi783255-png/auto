<?php
/**
 * ═══════════════════════════════════════════════════════════
 *  👑 DENIUS AUTO — ONIICHAN EDITION v2.0
 *  Boss: DENIUS | Admin: @DENIUS09
 *  -----------------------------------------------------------
 *  • ttoan 100% nguyên gốc — prediction = bet (1 nguồn)
 *  • Auto Martingale cố định 4 tay sai
 *  • Anti-Render-Reset: worker self-respawn + keepalive
 *  • UI: Nhật Bản otaku onichan (sakura, indigo, gold)
 * ═══════════════════════════════════════════════════════════
 */

// ═══════════════ [0] CONFIG ═══════════════
$CFG = [
    'version' => '2.0.0-oniichan',
    'game' => [
        'login_url'    => 'https://apifo88daigia.tele68.com/api?c=3&un={USER}&pw={PASS_MD5}&cp=R&cl=R&pf=web&at=',
        'lobby_url'    => 'https://wlb.tele68.com/v1/lobby/auth/login?cp=R&cl=R&pf=web&at=',
        'ws_host'      => 'wtx.tele68.com',
        'ws_path'      => '/tx/',
        'sessions_api' => 'https://wtx.tele68.com/v1/tx/sessions',
    ],
    'security' => [
        'hmac_secret' => 'DENIUS_ONIICHAN_2024_SECRET_KEY_FIXED',
        'session_ttl' => 86400,
    ],
    'worker' => [
        'loop_sleep'     => 1,
        'resume_timeout' => 90,       // giảm để worker respawn nhanh hơn
        'max_runtime'    => 3600,      // 1h, sau đó tự respawn
        'respawn_buffer' => 60,        // tự respawn trước 60s
    ],
    'default_config' => [
        'base_bet'        => 0,        // 0 = chưa setup
        'profit_stop'     => 0,
        'mode'            => 'double', // Luôn double
        'max_lose_streak' => 4,        // Cố định 4 tay sai
        'auto'            => false,
        'paused'          => false,
        'lose_streak'     => 0,
        'onboarded'       => false,
    ],
    'max_history' => 500,
];

const DATA_DIR = __DIR__ . '/.data';
const KEY_DIR  = DATA_DIR . '/by_key';

// ═══════════════ [1] BOOTSTRAP ═══════════════
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');

if (!is_dir(DATA_DIR)) @mkdir(DATA_DIR, 0700, true);
if (!is_dir(KEY_DIR))  @mkdir(KEY_DIR, 0700, true);
@file_put_contents(DATA_DIR . '/.htaccess', "Require all denied\nDeny from all\n");
@file_put_contents(DATA_DIR . '/index.html', '');
@file_put_contents(KEY_DIR  . '/.htaccess', "Require all denied\nDeny from all\n");
@file_put_contents(KEY_DIR  . '/index.html', '');

// ═══════════════ [2] AUTH ═══════════════
function hmac_sign(string $p): string {
    global $CFG;
    return hash_hmac('sha256', $p, $CFG['security']['hmac_secret']);
}
function issue_token(string $u): string {
    $exp = time() + ($GLOBALS['CFG']['security']['session_ttl'] ?? 86400);
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

// ═══════════════ [3] STORAGE ═══════════════
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

// ═══════════════ [4] GAME LOGIN + SESSIONS ═══════════════
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
    return ['token'=>$lb['token'],'nickname'=>$nick,'money'=>$lb['remoteLoginResp']['money']??0];
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

// ═══════════════ [5] TTOAN — VERBATIM FROM FILE 2 ═══════════════
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
    '1-1'=>['desc'=>'Cầu 1-1 (T-X-T-X)','weight'=>0.85],
    '1-2'=>['desc'=>'Cầu 1-2 (T-X-X-T)','weight'=>0.80],
    '2-1'=>['desc'=>'Cầu 2-1 (T-T-X-T)','weight'=>0.80],
    '2-2'=>['desc'=>'Cầu 2-2 (T-T-X-X)','weight'=>0.85],
    '2-3'=>['desc'=>'Cầu 2-3','weight'=>0.75],
    '3-2'=>['desc'=>'Cầu 3-2','weight'=>0.75],
    '3-3'=>['desc'=>'Cầu 3-3','weight'=>0.70],
    '3-4'=>['desc'=>'Cầu 3-4','weight'=>0.65],
    '4-3'=>['desc'=>'Cầu 4-3','weight'=>0.65],
    '4-4'=>['desc'=>'Cầu 4-4','weight'=>0.60],
    '1-3'=>['desc'=>'Cầu 1-3','weight'=>0.70],
    '3-1'=>['desc'=>'Cầu 3-1','weight'=>0.70],
    '1-4'=>['desc'=>'Cầu 1-4','weight'=>0.65],
    '4-1'=>['desc'=>'Cầu 4-1','weight'=>0.65],
    '2-4'=>['desc'=>'Cầu 2-4','weight'=>0.60],
    '4-2'=>['desc'=>'Cầu 4-2','weight'=>0.60],
    '5-5'=>['desc'=>'Cầu 5-5','weight'=>0.55],
    '5-1'=>['desc'=>'Cầu 5-1','weight'=>0.60],
    '1-5'=>['desc'=>'Cầu 1-5','weight'=>0.60],
    '6-6'=>['desc'=>'Cầu 6-6','weight'=>0.50],
    '7-7'=>['desc'=>'Cầu 7-7','weight'=>0.45],
    '8-8'=>['desc'=>'Cầu 8-8','weight'=>0.40],
    '10-10'=>['desc'=>'Cầu 10-10','weight'=>0.35],
    'bệt'=>['desc'=>'Cầu bệt (chuỗi dài)','weight'=>0.50],
    'đảo'=>['desc'=>'Cầu đảo (đảo ngược)','weight'=>0.75],
    'cầu nghiêng'=>['desc'=>'Cầu nghiêng (lệch về 1 bên)','weight'=>0.70],
    'cầu đối xứng'=>['desc'=>'Cầu đối xứng (T-X-X-T)','weight'=>0.80],
    'cầu lặp'=>['desc'=>'Cầu lặp (lặp lại mẫu)','weight'=>0.85],
    'cầu đan'=>['desc'=>'Cầu đan xen (T-X-T-T-X)','weight'=>0.75],
    'cầu bẻ'=>['desc'=>'Cầu bẻ (đột ngột đổi)','weight'=>0.90],
];

function ttoan_random(): float { return (float)mt_rand() / (float)(mt_getrandmax() + 1); }

function ttoan_detect_streak_and_break(array $history): array {
    $h = array_values($history);
    if (count($h) === 0) return ['streak'=>0,'currentResult'=>null,'breakProb'=>0.0];
    $streak = 1;
    $currentResult = $h[count($h)-1]['ket_qua'];
    for ($i = count($h)-2; $i >= 0; $i--) {
        if ($h[$i]['ket_qua'] === $currentResult) $streak++; else break;
    }
    $last15 = array_map(fn($it) => $it['ket_qua'], array_slice($h, -15));
    if (count($last15) === 0) return ['streak'=>$streak,'currentResult'=>$currentResult,'breakProb'=>0.0];
    $switches = 0;
    for ($i = 1; $i < count($last15); $i++) if ($last15[$i] !== $last15[$i-1]) $switches++;
    $taiCount = count(array_filter($last15, fn($r) => $r === 'Tài'));
    $xiuCount = count($last15) - $taiCount;
    $imbalance = abs($taiCount - $xiuCount) / count($last15);
    $breakProb = 0.0;
    if ($streak >= 8) $breakProb = min(0.6 + $switches/15 + $imbalance*0.15, 0.9);
    elseif ($streak >= 5) $breakProb = min(0.35 + $switches/10 + $imbalance*0.25, 0.85);
    elseif ($streak >= 3 && $switches >= 7) $breakProb = 0.3;
    return ['streak'=>$streak,'currentResult'=>$currentResult,'breakProb'=>$breakProb];
}

function ttoan_evaluate_model_performance(array $history, string $modelName, array $modelPredictions, int $lookback = 10): float {
    $h = array_values($history);
    if (!isset($modelPredictions[$modelName]) || count($h) < 2) return 1.0;
    $lookback = min($lookback, count($h) - 1);
    $correct = 0;
    for ($i = 0; $i < $lookback; $i++) {
        $sessionId = $h[count($h) - ($i + 2)]['phien'];
        $prediction = $modelPredictions[$modelName][$sessionId] ?? 0;
        $actual = $h[count($h) - ($i + 1)]['ket_qua'];
        if (($prediction === 1 && $actual === 'Tài') || ($prediction === 2 && $actual === 'Xỉu')) $correct++;
    }
    $ratio = ($lookback > 0) ? 1 + ($correct - $lookback / 2) / ($lookback / 2) : 1.0;
    return max(0.5, min(1.5, $ratio));
}

function ttoan_smart_bridge_break(array $history): array {
    $h = array_values($history);
    if (count($h) < 3) return ['prediction'=>0,'breakProb'=>0.0,'reason'=>'Không đủ dữ liệu để bẻ cầu'];
    $sb = ttoan_detect_streak_and_break($h);
    $streak = $sb['streak']; $currentResult = $sb['currentResult']; $breakProb = $sb['breakProb'];
    $last20Results = array_map(fn($it) => $it['ket_qua'], array_slice($h, -20));
    $last20Scores = array_map(fn($it) => $it['tong'] ?? 0, array_slice($h, -20));
    $finalBreakProb = $breakProb; $reason = '';
    $avgScore = array_sum($last20Scores) / (count($last20Scores) ?: 1);
    $devSum = 0.0; foreach ($last20Scores as $s) $devSum += abs($s - $avgScore);
    $scoreDeviation = $devSum / (count($last20Scores) ?: 1);
    $last5Results = array_slice($last20Results, -5);
    $patternCounts = [];
    for ($i = 0; $i <= count($last20Results) - 3; $i++) {
        $pattern = implode(',', array_slice($last20Results, $i, 3));
        $patternCounts[$pattern] = ($patternCounts[$pattern] ?? 0) + 1;
    }
    $mostCommonPattern = null;
    if (count($patternCounts) > 0) { arsort($patternCounts); $mostCommonPattern = [key($patternCounts), current($patternCounts)]; }
    $hasRepeatingPattern = ($mostCommonPattern !== null && $mostCommonPattern[1] >= 3);
    $last5AllSame = (count($last5Results) > 0);
    foreach ($last5Results as $r) { if ($r !== $currentResult) { $last5AllSame = false; break; } }
    if ($streak >= 6) { $finalBreakProb = min($finalBreakProb + 0.15, 0.9); $reason = "[Bẻ Cầu] Chuỗi {$streak} {$currentResult} dài, khả năng bẻ cầu cao"; }
    elseif ($streak >= 4 && $scoreDeviation > 3) { $finalBreakProb = min($finalBreakProb + 0.10, 0.85); $reason = sprintf("[Bẻ Cầu] Biến động điểm số lớn (%.1f)", $scoreDeviation); }
    elseif ($hasRepeatingPattern && $last5AllSame) { $finalBreakProb = min($finalBreakProb + 0.05, 0.8); $reason = "[Bẻ Cầu] Phát hiện mẫu lặp {$mostCommonPattern[0]}"; }
    else { $finalBreakProb = max($finalBreakProb - 0.15, 0.15); $reason = '[Bẻ Cầu] Không phát hiện mẫu bẻ cầu mạnh'; }
    if ($finalBreakProb > 0.65) $prediction = ($currentResult === 'Tài') ? 2 : 1;
    else $prediction = ($currentResult === 'Tài') ? 1 : 2;
    return ['prediction'=>$prediction,'breakProb'=>$finalBreakProb,'reason'=>$reason];
}

function ttoan_trend_and_prob(array $history): int {
    $h = array_values($history);
    if (count($h) < 3) return 0;
    $sb = ttoan_detect_streak_and_break($h);
    $streak = $sb['streak']; $currentResult = $sb['currentResult']; $breakProb = $sb['breakProb'];
    if ($streak >= 5) {
        if ($breakProb > 0.75) return ($currentResult === 'Tài') ? 2 : 1;
        return ($currentResult === 'Tài') ? 1 : 2;
    }
    $last15 = array_map(fn($it) => $it['ket_qua'], array_slice($h, -15));
    if (count($last15) === 0) return 0;
    $taiWeight = 0.0; $xiuWeight = 0.0;
    foreach ($last15 as $i => $r) { $w = pow(1.2, $i); if ($r === 'Tài') $taiWeight += $w; else $xiuWeight += $w; }
    $totalWeight = $taiWeight + $xiuWeight;
    $last10 = array_slice($last15, -10);
    $patterns = [];
    if (count($last10) >= 4) for ($i = 0; $i <= count($last10) - 4; $i++) $patterns[] = implode(',', array_slice($last10, $i, 4));
    $patternCounts = [];
    foreach ($patterns as $p) $patternCounts[$p] = ($patternCounts[$p] ?? 0) + 1;
    $mostCommon = null;
    if (count($patternCounts) > 0) { arsort($patternCounts); $mostCommon = [key($patternCounts), current($patternCounts)]; }
    if ($mostCommon !== null && $mostCommon[1] >= 3) {
        $parts = explode(',', $mostCommon[0]);
        return ($parts[count($parts) - 1] !== $last10[count($last10) - 1]) ? 1 : 2;
    }
    if ($totalWeight > 0 && abs($taiWeight - $xiuWeight) / $totalWeight >= 0.25) return ($taiWeight > $xiuWeight) ? 2 : 1;
    return ($last15[count($last15) - 1] === 'Xỉu') ? 1 : 2;
}

function ttoan_short_pattern(array $history): int {
    $h = array_values($history);
    if (count($h) < 3) return 0;
    $sb = ttoan_detect_streak_and_break($h);
    $streak = $sb['streak']; $currentResult = $sb['currentResult']; $breakProb = $sb['breakProb'];
    if ($streak >= 4) {
        if ($breakProb > 0.75) return ($currentResult === 'Tài') ? 2 : 1;
        return ($currentResult === 'Tài') ? 1 : 2;
    }
    $last8 = array_map(fn($it) => $it['ket_qua'], array_slice($h, -8));
    if (count($last8) === 0) return 0;
    $patterns = [];
    if (count($last8) >= 3) for ($i = 0; $i <= count($last8) - 3; $i++) $patterns[] = implode(',', array_slice($last8, $i, 3));
    $patternCounts = [];
    foreach ($patterns as $p) $patternCounts[$p] = ($patternCounts[$p] ?? 0) + 1;
    $mostCommon = null;
    if (count($patternCounts) > 0) { arsort($patternCounts); $mostCommon = [key($patternCounts), current($patternCounts)]; }
    if ($mostCommon !== null && $mostCommon[1] >= 2) {
        $parts = explode(',', $mostCommon[0]);
        return ($parts[count($parts) - 1] !== $last8[count($last8) - 1]) ? 1 : 2;
    }
    return ($last8[count($last8) - 1] === 'Xỉu') ? 1 : 2;
}

function ttoan_mean_deviation(array $history): int {
    $h = array_values($history);
    if (count($h) < 3) return 0;
    $sb = ttoan_detect_streak_and_break($h);
    $streak = $sb['streak']; $currentResult = $sb['currentResult']; $breakProb = $sb['breakProb'];
    if ($streak >= 4) {
        if ($breakProb > 0.75) return ($currentResult === 'Tài') ? 2 : 1;
        return ($currentResult === 'Tài') ? 1 : 2;
    }
    $last12 = array_map(fn($it) => $it['ket_qua'], array_slice($h, -12));
    if (count($last12) === 0) return 0;
    $taiCount = count(array_filter($last12, fn($r) => $r === 'Tài'));
    $xiuCount = count($last12) - $taiCount;
    $imbalance = abs($taiCount - $xiuCount) / count($last12);
    if ($imbalance < 0.35) return ($last12[count($last12) - 1] === 'Xỉu') ? 1 : 2;
    return ($xiuCount > $taiCount) ? 1 : 2;
}

function ttoan_recent_switch(array $history): int {
    $h = array_values($history);
    if (count($h) < 3) return 0;
    $sb = ttoan_detect_streak_and_break($h);
    $streak = $sb['streak']; $currentResult = $sb['currentResult']; $breakProb = $sb['breakProb'];
    if ($streak >= 4) {
        if ($breakProb > 0.75) return ($currentResult === 'Tài') ? 2 : 1;
        return ($currentResult === 'Tài') ? 1 : 2;
    }
    $last10 = array_map(fn($it) => $it['ket_qua'], array_slice($h, -10));
    if (count($last10) === 0) return 0;
    $switches = 0;
    for ($i = 1; $i < count($last10); $i++) if ($last10[$i] !== $last10[$i-1]) $switches++;
    $lastVal = $last10[count($last10) - 1];
    return ($lastVal === 'Xỉu') ? 1 : 2;
}

function ttoan_is_bad_pattern(array $history): bool {
    $h = array_values($history);
    if (count($h) < 3) return false;
    $last15 = array_map(fn($it) => $it['ket_qua'], array_slice($h, -15));
    if (count($last15) === 0) return false;
    $switches = 0;
    for ($i = 1; $i < count($last15); $i++) if ($last15[$i] !== $last15[$i-1]) $switches++;
    $sb = ttoan_detect_streak_and_break($h);
    return ($switches >= 9 || $sb['streak'] >= 10);
}

function ttoan_ai_htdd_logic(array $history): array {
    $h = array_values($history);
    if (count($h) < 3) {
        $randomPred = (ttoan_random() < 0.5) ? 'Tài' : 'Xỉu';
        return ['prediction'=>$randomPred,'reason'=>'Không đủ lịch sử','source'=>'AI HTDD'];
    }
    $last5Results = array_map(fn($it) => $it['ket_qua'], array_slice($h, -5));
    $last5Scores = array_map(fn($it) => $it['tong'] ?? 0, array_slice($h, -5));
    $taiCount = count(array_filter($last5Results, fn($r) => $r === 'Tài'));
    $xiuCount = count($last5Results) - $taiCount;
    $last3 = array_map(fn($it) => $it['ket_qua'], array_slice($h, -3));
    if (implode(',', $last3) === 'Tài,Xỉu,Tài') return ['prediction'=>'Xỉu','reason'=>'Mẫu 1T1X','source'=>'AI HTDD'];
    if (implode(',', $last3) === 'Xỉu,Tài,Xỉu') return ['prediction'=>'Tài','reason'=>'Mẫu 1X1T','source'=>'AI HTDD'];
    if (count($h) >= 4) {
        $last4 = array_map(fn($it) => $it['ket_qua'], array_slice($h, -4));
        if (implode(',', $last4) === 'Tài,Tài,Xỉu,Xỉu') return ['prediction'=>'Tài','reason'=>'Mẫu 2T2X','source'=>'AI HTDD'];
        if (implode(',', $last4) === 'Xỉu,Xỉu,Tài,Tài') return ['prediction'=>'Xỉu','reason'=>'Mẫu 2X2T','source'=>'AI HTDD'];
    }
    if (count($h) >= 9) {
        $last6 = array_slice($h, -6);
        $allTai = true; $allXiu = true;
        foreach ($last6 as $it) { if ($it['ket_qua'] !== 'Tài') $allTai = false; if ($it['ket_qua'] !== 'Xỉu') $allXiu = false; }
        if ($allTai) return ['prediction'=>'Xỉu','reason'=>'Chuỗi Tài 6 lần','source'=>'AI HTDD'];
        if ($allXiu) return ['prediction'=>'Tài','reason'=>'Chuỗi Xỉu 6 lần','source'=>'AI HTDD'];
    }
    $avgScore = array_sum($last5Scores) / (count($last5Scores) ?: 1);
    if ($avgScore > 10) return ['prediction'=>'Tài','reason'=>sprintf('Điểm TB cao (%.1f)',$avgScore),'source'=>'AI HTDD'];
    if ($avgScore < 8) return ['prediction'=>'Xỉu','reason'=>sprintf('Điểm TB thấp (%.1f)',$avgScore),'source'=>'AI HTDD'];
    if ($taiCount > $xiuCount + 1) return ['prediction'=>'Xỉu','reason'=>sprintf('Tài đa số (%d/%d)',$taiCount,count($last5Results)),'source'=>'AI HTDD'];
    if ($xiuCount > $taiCount + 1) return ['prediction'=>'Tài','reason'=>sprintf('Xỉu đa số (%d/%d)',$xiuCount,count($last5Results)),'source'=>'AI HTDD'];
    $totalTai = count(array_filter($h, fn($it) => $it['ket_qua'] === 'Tài'));
    $totalXiu = count($h) - $totalTai;
    if ($totalTai > $totalXiu + 2) return ['prediction'=>'Xỉu','reason'=>'Tổng Tài nhiều','source'=>'AI HTDD'];
    if ($totalXiu > $totalTai + 2) return ['prediction'=>'Tài','reason'=>'Tổng Xỉu nhiều','source'=>'AI HTDD'];
    return ['prediction'=>ttoan_random()<0.5?'Tài':'Xỉu','reason'=>'Cân bằng','source'=>'AI HTDD'];
}

function ttoan_phan_tich_cau(array $history): array {
    $h = array_values($history);
    if (count($h) < 3) return ['cau'=>'Khong xac dinh','weight'=>0.0,'streaks'=>[]];
    $results = array_map(fn($it) => $it['ket_qua'], array_slice($h, -30));
    $streaks = []; $currentStreak = 1; $currentType = $results[0];
    for ($i = 1; $i < count($results); $i++) {
        if ($results[$i] === $currentType) $currentStreak++;
        else { $streaks[] = ['type'=>$currentType,'count'=>$currentStreak]; $currentType = $results[$i]; $currentStreak = 1; }
    }
    $streaks[] = ['type'=>$currentType,'count'=>$currentStreak];
    $detectedCau = 'Khong xac dinh'; $cauWeight = 0.5;
    $maxStreak = 0; foreach ($streaks as $s) if ($s['count'] > $maxStreak) $maxStreak = $s['count'];
    if ($maxStreak >= 6) { $detectedCau = 'bệt'; $cauWeight = 0.5; }
    $oneOne = 0; for ($i = 0; $i < count($streaks) - 1; $i++) if ($streaks[$i]['count'] === 1 && $streaks[$i+1]['count'] === 1) $oneOne++;
    if ($oneOne >= 3) { $detectedCau = '1-1'; $cauWeight = 0.85; }
    $twoTwo = 0; for ($i = 0; $i < count($streaks) - 1; $i++) if ($streaks[$i]['count'] === 2 && $streaks[$i+1]['count'] === 2) $twoTwo++;
    if ($twoTwo >= 2) { $detectedCau = '2-2'; $cauWeight = 0.85; }
    $oneTwo = 0; for ($i = 0; $i < count($streaks) - 1; $i++) if ($streaks[$i]['count'] === 1 && $streaks[$i+1]['count'] === 2) $oneTwo++;
    if ($oneTwo >= 2) { $detectedCau = '1-2'; $cauWeight = 0.80; }
    $twoOne = 0; for ($i = 0; $i < count($streaks) - 1; $i++) if ($streaks[$i]['count'] === 2 && $streaks[$i+1]['count'] === 1) $twoOne++;
    if ($twoOne >= 2) { $detectedCau = '2-1'; $cauWeight = 0.80; }
    $threeTwo = 0; for ($i = 0; $i < count($streaks) - 1; $i++) if ($streaks[$i]['count'] === 3 && $streaks[$i+1]['count'] === 2) $threeTwo++;
    if ($threeTwo >= 2) { $detectedCau = '3-2'; $cauWeight = 0.75; }
    $twoThree = 0; for ($i = 0; $i < count($streaks) - 1; $i++) if ($streaks[$i]['count'] === 2 && $streaks[$i+1]['count'] === 3) $twoThree++;
    if ($twoThree >= 2) { $detectedCau = '2-3'; $cauWeight = 0.75; }
    $threeThree = 0; for ($i = 0; $i < count($streaks) - 1; $i++) if ($streaks[$i]['count'] === 3 && $streaks[$i+1]['count'] === 3) $threeThree++;
    if ($threeThree >= 2) { $detectedCau = '3-3'; $cauWeight = 0.70; }
    $daoCount = 0; for ($i = 0; $i < count($streaks) - 2; $i++) if ($streaks[$i]['count'] === $streaks[$i+2]['count'] && $streaks[$i]['type'] !== $streaks[$i+2]['type']) $daoCount++;
    if ($daoCount >= 2) { $detectedCau = 'đảo'; $cauWeight = 0.75; }
    $last10r = array_slice($results, -10);
    $tai10 = count(array_filter($last10r, fn($r) => $r === 'Tài'));
    $xiu10 = count($last10r) - $tai10;
    if (abs($tai10 - $xiu10) >= 6) { $detectedCau = 'cầu nghiêng'; $cauWeight = 0.70; }
    $pattern3 = []; for ($i = 0; $i <= count($results) - 3; $i++) $pattern3[] = implode(',', array_slice($results, $i, 3));
    $pc3 = []; foreach ($pattern3 as $p) $pc3[$p] = ($pc3[$p] ?? 0) + 1;
    $maxP3 = null; if (count($pc3) > 0) { arsort($pc3); $maxP3 = [key($pc3), current($pc3)]; }
    if ($maxP3 !== null && $maxP3[1] >= 4) { $detectedCau = 'cầu lặp'; $cauWeight = 0.85; }
    $danCount = 0;
    for ($i = 0; $i < count($results) - 4; $i++) {
        $sl = array_slice($results, $i, 5);
        if ($sl[0] !== $sl[1] && $sl[1] === $sl[3] && $sl[0] === $sl[2] && $sl[2] !== $sl[4]) $danCount++;
    }
    if ($danCount >= 2) { $detectedCau = 'cầu đan'; $cauWeight = 0.75; }
    return ['cau'=>$detectedCau,'weight'=>$cauWeight,'streaks'=>$streaks];
}

function ttoan_generate_prediction(array $history, ?array &$modelPredictions = null): array {
    $h = array_values($history);
    $hasExt = ($modelPredictions !== null);
    if ($hasExt) $mp = $modelPredictions;
    else { static $st = []; $mp = $st; }
    if (!is_array($mp)) $mp = [];
    if (!isset($mp['trend'])) $mp = ['trend'=>[],'short'=>[],'mean'=>[],'switch'=>[],'bridge'=>[]];
    if (count($h) === 0) {
        if ($hasExt) $modelPredictions = $mp;
        $r = (ttoan_random() < 0.5) ? 'Tài' : 'Xỉu';
        return ['prediction'=>$r,'doTinCay'=>50,'giaiThich'=>'Không đủ lịch sử'];
    }
    $currentSession = $h[count($h)-1]['phien'];
    $currentTong = $h[count($h)-1]['tong'];
    $lastResult = $h[count($h)-1]['ket_qua'];
    $fallbackPred = ($lastResult === 'Tài') ? 2 : 1;
    $trendPred  = (count($h) < 5) ? $fallbackPred : ttoan_trend_and_prob($h);
    $shortPred  = (count($h) < 5) ? $fallbackPred : ttoan_short_pattern($h);
    $meanPred   = (count($h) < 5) ? $fallbackPred : ttoan_mean_deviation($h);
    $switchPred = (count($h) < 5) ? $fallbackPred : ttoan_recent_switch($h);
    $bridgePred = (count($h) < 5) ? ['prediction'=>$fallbackPred,'breakProb'=>0.0,'reason'=>'Lịch sử ngắn'] : ttoan_smart_bridge_break($h);
    $aiPred = ttoan_ai_htdd_logic($h);
    $cauAnalysis = ttoan_phan_tich_cau($h);
    $tongMeo = TTOAN_TONG_DIEM_MEO[$currentTong] ?? ['ket_qua'=>'Khong xac dinh','xac_suat'=>0.5];
    $mp['trend'][$currentSession]  = $trendPred;
    $mp['short'][$currentSession]  = $shortPred;
    $mp['mean'][$currentSession]   = $meanPred;
    $mp['switch'][$currentSession] = $switchPred;
    $mp['bridge'][$currentSession] = $bridgePred['prediction'];
    $perf = [
        'trend'  => ttoan_evaluate_model_performance($h, 'trend', $mp),
        'short'  => ttoan_evaluate_model_performance($h, 'short', $mp),
        'mean'   => ttoan_evaluate_model_performance($h, 'mean', $mp),
        'switch' => ttoan_evaluate_model_performance($h, 'switch', $mp),
        'bridge' => ttoan_evaluate_model_performance($h, 'bridge', $mp),
    ];
    $weights = [
        'trend'=>0.15*$perf['trend'],'short'=>0.15*$perf['short'],'mean'=>0.15*$perf['mean'],
        'switch'=>0.15*$perf['switch'],'bridge'=>0.15*$perf['bridge'],
        'aihtdd'=>0.15,'cau'=>0.10,'tongDiem'=>0.10,
    ];
    $taiScore = 0.0; $xiuScore = 0.0;
    if ($trendPred === 1) $taiScore += $weights['trend']; elseif ($trendPred === 2) $xiuScore += $weights['trend'];
    if ($shortPred === 1) $taiScore += $weights['short']; elseif ($shortPred === 2) $xiuScore += $weights['short'];
    if ($meanPred === 1) $taiScore += $weights['mean']; elseif ($meanPred === 2) $xiuScore += $weights['mean'];
    if ($switchPred === 1) $taiScore += $weights['switch']; elseif ($switchPred === 2) $xiuScore += $weights['switch'];
    if ($bridgePred['prediction'] === 1) $taiScore += $weights['bridge']; elseif ($bridgePred['prediction'] === 2) $xiuScore += $weights['bridge'];
    if ($aiPred['prediction'] === 'Tài') $taiScore += $weights['aihtdd']; else $xiuScore += $weights['aihtdd'];
    $cauInfo = TTOAN_CAU_PATTERNS[$cauAnalysis['cau']] ?? ['desc'=>'Khong xac dinh','weight'=>0.5];
    $cauPred = null;
    if ($cauAnalysis['cau'] === '1-1') $cauPred = ($lastResult === 'Tài') ? 'Xỉu' : 'Tài';
    elseif ($cauAnalysis['cau'] === '2-2') $cauPred = ($lastResult === 'Xỉu') ? 'Tài' : 'Xỉu';
    elseif ($cauAnalysis['cau'] === '1-2') $cauPred = 'Tài';
    elseif ($cauAnalysis['cau'] === '2-1') $cauPred = 'Xỉu';
    elseif ($cauAnalysis['cau'] === 'bệt') $cauPred = $lastResult;
    elseif ($cauAnalysis['cau'] === 'đảo') $cauPred = ($lastResult === 'Tài') ? 'Xỉu' : 'Tài';
    elseif ($cauAnalysis['cau'] === 'cầu nghiêng') {
        $last10c = array_map(fn($it) => $it['ket_qua'], array_slice($h, -10));
        $tai10c = count(array_filter($last10c, fn($r) => $r === 'Tài'));
        $cauPred = ($tai10c > 5) ? 'Xỉu' : 'Tài';
    } else $cauPred = $lastResult;
    if ($cauPred === 'Tài') $taiScore += $weights['cau'] * $cauAnalysis['weight'];
    else $xiuScore += $weights['cau'] * $cauAnalysis['weight'];
    if ($tongMeo['ket_qua'] === 'Tài') $taiScore += $weights['tongDiem'] * $tongMeo['xac_suat'];
    elseif ($tongMeo['ket_qua'] === 'Xỉu') $xiuScore += $weights['tongDiem'] * $tongMeo['xac_suat'];
    if (ttoan_is_bad_pattern($h)) { $taiScore *= 0.8; $xiuScore *= 0.8; }
    $last10Results = array_map(fn($it) => $it['ket_qua'], array_slice($h, -10));
    $last10TaiCount = count(array_filter($last10Results, fn($r) => $r === 'Tài'));
    if ($last10TaiCount >= 7) $xiuScore += 0.15;
    elseif ($last10TaiCount <= 3) $taiScore += 0.15;
    if ($bridgePred['breakProb'] > 0.65) {
        if ($bridgePred['prediction'] === 1) $taiScore += 0.2; else $xiuScore += 0.2;
    }
    $totalScore = $taiScore + $xiuScore;
    $taiProb = ($totalScore > 0) ? ($taiScore / $totalScore) * 100 : 50.0;
    $xiuProb = ($totalScore > 0) ? ($xiuScore / $totalScore) * 100 : 50.0;
    $finalPrediction = ($taiScore > $xiuScore) ? 'Tài' : 'Xỉu';
    $doTinCay = (int)round(max($taiProb, $xiuProb));
    $giaiThich = sprintf('[Cau: %s] | [Tong %s: %s %d%%] | %s | %s | Tai: %s%% - Xiu: %s%%',
        $cauInfo['desc'], $currentTong, $tongMeo['ket_qua'], (int)round($tongMeo['xac_suat']*100),
        $aiPred['reason'], $bridgePred['reason'],
        number_format($taiProb,1,'.',''), number_format($xiuProb,1,'.',''));
    if ($hasExt) $modelPredictions = $mp;
    return ['prediction'=>$finalPrediction,'doTinCay'=>$doTinCay,'giaiThich'=>$giaiThich];
}

// ═══════════════ [6] WEBSOCKET CLIENT ═══════════════
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
        stream_set_timeout($this->sock, 15);
        stream_set_blocking($this->sock, true);
        $key = base64_encode(random_bytes(16));
        $req = "GET {$this->path} HTTP/1.1\r\nHost: {$this->h}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {$key}\r\nSec-WebSocket-Version: 13\r\nOrigin: https://{$this->h}\r\nUser-Agent: Mozilla/5.0\r\n";
        foreach ($this->headers as $hd) $req .= $hd . "\r\n";
        $req .= "\r\n";
        fwrite($this->sock, $req);
        $resp = ''; $dl = microtime(true)+10;
        while (!str_contains($resp,"\r\n\r\n") && microtime(true)<$dl) {
            $c = fread($this->sock, 2048);
            if ($c===false || $c==='') { $this->error='Handshake fail'; return false; }
            $resp .= $c;
        }
        if (stripos($resp,' 101')===false) { $this->error='Handshake: '.substr($resp,0,160); return false; }
        return true;
    }
    public function sendRaw(string $p): void {
        if (!$this->sock) return;
        $len = strlen($p); $f = chr(0x81);
        if ($len<126) $f .= chr(0x80|$len);
        elseif ($len<65536) $f .= chr(0x80|126).pack('n',$len);
        else $f .= chr(0x80|127).pack('J',$len);
        $m = random_bytes(4); $f .= $m;
        for ($i=0;$i<$len;$i++) $f .= $p[$i] ^ $m[$i%4];
        @fwrite($this->sock, $f);
    }
    public function readOneFrame(int $to=1): ?array {
        if (!$this->sock) return null;
        $r=[$this->sock]; $w=null; $e=null;
        $n = @stream_select($r,$w,$e,$to,0);
        if ($n===false) return null;
        if ($n===0) return [];
        $hdr = @fread($this->sock,2);
        if ($hdr===false || strlen($hdr)<2) return null;
        $b1=ord($hdr[0]); $b2=ord($hdr[1]);
        $op = $b1&0x0f; $masked = ($b2&0x80)!==0; $len = $b2&0x7f;
        if ($len===126) { $ext=@fread($this->sock,2); if (strlen($ext)<2) return null; $len=unpack('n',$ext)[1]; }
        elseif ($len===127) { $ext=@fread($this->sock,8); if (strlen($ext)<8) return null; $len=unpack('J',$ext)[1]; }
        $mask=null; if ($masked) { $mask=@fread($this->sock,4); if (strlen($mask)<4) return null; }
        $data=''; while (strlen($data)<$len) {
            $c = @fread($this->sock, $len-strlen($data));
            if ($c===false || $c==='') return null;
            $data .= $c;
        }
        if ($mask) { $u=''; for ($i=0;$i<$len;$i++) $u .= $data[$i]^$mask[$i%4]; $data=$u; }
        if ($op===0x8) return null;
        if ($op===0x9) { $this->sendPong($data); return []; }
        if ($op===0xA) return [];
        if ($op===0x0 || $op===0x1) return [$data];
        return [];
    }
    private function sendPong(string $pl): void {
        if (!$this->sock) return;
        $len=strlen($pl); $f=chr(0x8A);
        if ($len<126) $f.=chr(0x80|$len);
        elseif ($len<65536) $f.=chr(0x80|126).pack('n',$len);
        else $f.=chr(0x80|127).pack('J',$len);
        $m=random_bytes(4); $f.=$m;
        for ($i=0;$i<$len;$i++) $f .= $pl[$i]^$m[$i%4];
        @fwrite($this->sock,$f);
    }
    public function close(): void { if ($this->sock) @fclose($this->sock); $this->sock=null; }
}

// ═══════════════ [7] WS BET — FIX: ĐỌC pending_pred, KHÔNG TỰ PHÂN TÍCH ═══════════════
function do_ws_bet(string $key, array $s, array &$actions): bool {
    global $CFG;
    if (empty($s['token'])) return false;
    $pred = $s['pending_pred'] ?? null;
    if (!$pred) return false;
    $side = ($pred === 'Tài' || $pred === 'T' || $pred === 'TAI') ? 'TAI' : 'XIU';
    $pendingSession = (int)$s['pending_session'];
    $amount = (int)($s['pending_bet_amount'] ?? 10000);
    if ($amount < 1000) $amount = 1000;

    $wsPath = rtrim($CFG['game']['ws_path'],'/') . '/?EIO=4&transport=websocket';
    $ws = new TinyWS($CFG['game']['ws_host'], 443, $wsPath, ['Authorization: Bearer '.$s['token']]);
    if (!$ws->connect()) { key_log($key,'error','❌ WS fail: '.$ws->error); return false; }
    $auth = json_encode(['token'=>$s['token']], JSON_UNESCAPED_UNICODE);
    $opened = false; $joined = false; $betDone = false; $betAck = false;
    $deadline = microtime(true) + 20;

    while (microtime(true) < $deadline) {
        $frames = $ws->readOneFrame(1);
        if ($frames===null) { key_log($key,'warn','⚠️ WS đóng'); break; }
        if ($frames===[]) continue;
        foreach ($frames as $pkt) {
            if ($pkt==='' || $pkt===null) continue;
            if (str_starts_with($pkt,'0{')) { $opened = true; $ws->sendRaw('40/tx,'.$auth); continue; }
            if ($pkt==='2') { $ws->sendRaw('3'); continue; }
            if ($pkt==='3' || $pkt==='6') continue;
            if ($pkt==='1') { $ws->close(); return false; }
            if (!str_starts_with($pkt,'4')) continue;
            $sio = substr($pkt,1);
            if (str_starts_with($sio,'0/tx,')) { $joined = true; continue; }
            if (str_starts_with($sio,'1')) { $ws->close(); return false; }
            if (str_starts_with($sio,'4')) { $ws->close(); return false; }
            if (!str_starts_with($sio,'2')) continue;
            $body = substr($sio,1);
            if (str_starts_with($body,'/tx,')) $body = substr($body,strlen('/tx,'));
            $msg = json_decode($body, true);
            if (!is_array($msg) || count($msg)<1) continue;
            $ev = $msg[0] ?? ''; $d = $msg[1] ?? [];

            if ($ev==='tick-update') {
                $state = $d['state'] ?? null;
                $tickSid = isset($d['id']) ? (int)$d['id'] : null;
                if ($state==='BETTING' && $joined && !$betDone) {
                    if ($tickSid!==null && $tickSid < $pendingSession) continue;
                    $event = ['bet', ['type'=>$side, 'amount'=>$amount]];
                    $ws->sendRaw('42/tx,'.json_encode($event, JSON_UNESCAPED_UNICODE));
                    $betDone = true;
                    $logMsg = "💰 ĐẶT #$pendingSession [$side] × ".number_format($amount)." — KHỚP dự đoán ($pred)";
                    key_log($key,'success',$logMsg);
                    $actions[] = ['type'=>'bet','msg'=>$logMsg];
                    key_update($key, function($dd) use ($pendingSession,$amount) {
                        $dd['bet_session'] = $pendingSession;
                        $dd['bet_amount'] = $amount;
                        return $dd;
                    });
                    $wait = microtime(true) + 2.5;
                    while (microtime(true) < $wait) {
                        $more = $ws->readOneFrame(1);
                        if ($more===null) break;
                        if ($more===[]) continue;
                        foreach ($more as $p2) {
                            if ($p2==='2') { $ws->sendRaw('3'); continue; }
                            if (!str_starts_with($p2,'4')) continue;
                            $s2 = substr($p2,1);
                            if (!str_starts_with($s2,'2')) continue;
                            $b2 = substr($s2,1);
                            if (str_starts_with($b2,'/tx,')) $b2 = substr($b2,strlen('/tx,'));
                            $m2 = json_decode($b2,true);
                            if (!is_array($m2)) continue;
                            if (($m2[0]??'')==='bet-result') {
                                $betAck = true;
                                if (isset($m2[1]['postBalance'])) {
                                    key_update($key, function($dd) use ($m2) { $dd['balance'] = $m2[1]['postBalance']; return $dd; });
                                }
                            }
                        }
                    }
                    $ws->close();
                    if (!$betAck) key_log($key,'warn','⚠️ Chưa nhận bet-result');
                    return true;
                }
            }
            if ($ev==='session-result') { $ws->close(); return false; }
        }
    }
    $ws->close();
    if (!$betDone) key_log($key,'warn','⚠️ Không bet được trong 20s');
    return $betDone;
}

// ═══════════════ [8] WORKER CORE ═══════════════
function worker_step(string $key): array {
    $actions = [];
    $s = key_load($key);
    if (!$s) return $actions;
    $cfg = $s['config'] ?? [];

    if (empty($cfg['auto']) || !empty($cfg['paused'])) return $actions;

    $data = fetch_sessions_api();
    if (!$data || empty($data['list'])) return $actions;
    $latest = $data['list'][0];
    $latestId = (int)$latest['id'];
    $lastId = (int)($s['last_session_id'] ?? 0);

    if ($lastId === 0) {
        key_update($key, fn($d) => array_merge($d, ['last_session_id'=>$latestId]));
        key_log($key,'info',"📡 Baseline phiên #$latestId");
        return $actions;
    }

    if ($latestId > $lastId) {
        for ($sid = $lastId+1; $sid <= $latestId; $sid++) {
            $found = null;
            foreach ($data['list'] as $row) if ((int)$row['id']===$sid) { $found=$row; break; }
            if (!$found) continue;
            $raw = $found['resultTruyenThong'] ?? 'N/A';
            $map = ['Tài'=>'TAI','Xỉu'=>'XIU','tai'=>'TAI','xiu'=>'XIU','TAI'=>'TAI','XIU'=>'XIU'];
            $result = $map[$raw] ?? 'N/A';
            if ($result!=='TAI' && $result!=='XIU') continue;
            $dices = $found['dices'] ?? [0,0,0];
            $tong = array_sum($dices);
            $isJackpot = (count(array_unique($dices))===1 && $dices[0]!=0);

            if (($s['pending_session'] ?? null) == $sid && !empty($s['pending_pred'])) {
                $pred = $s['pending_pred'];
                $win = (($pred==='Tài'||$pred==='T') && $result==='TAI') || (($pred==='Xỉu'||$pred==='X') && $result==='XIU');

                key_update($key, function($d) use ($sid,$pred,$result,$dices,$win,$isJackpot,$tong) {
                    $c = $d['config'];
                    $st = (int)($c['lose_streak'] ?? 0);
                    $mx = 4;
                    if ($win) {
                        $st = 0;
                        $d['win_count_total'] = (int)($d['win_count_total'] ?? 0) + 1;
                    } else {
                        $d['loss_count_total'] = (int)($d['loss_count_total'] ?? 0) + 1;
                        $st++;
                        if ($st >= $mx) $st = 0;
                    }
                    $c['lose_streak'] = $st;
                    $betAmt = (int)($d['bet_amount'] ?? $c['base_bet'] ?? 10000);
                    $bal = (int)($d['balance'] ?? 0);
                    if ($win) $bal += intval($betAmt * 0.98);
                    else $bal -= $betAmt;
                    $d['balance'] = $bal;
                    $d['profit_total'] = (int)($d['profit_total'] ?? 0) + ($win ? intval($betAmt*0.98) : -$betAmt);
                    $d['history'] = $d['history'] ?? [];
                    array_unshift($d['history'], [
                        'ts'=>date('H:i:s d/m'),'session'=>$sid,'pred'=>$pred,'result'=>$result,
                        'dices'=>$dices,'tong'=>$tong,'win'=>$win,'amount'=>$betAmt,
                        'balance_after'=>$bal,'streak'=>$st,'jackpot'=>$isJackpot,
                    ]);
                    $d['history'] = array_slice($d['history'], 0, 500);
                    $d['pending_pred'] = null; $d['pending_session'] = null;
                    $d['pending_conf'] = null; $d['pending_bet_amount'] = null;
                    $d['bet_session'] = null; $d['bet_amount'] = 0;
                    $sym = ($result==='TAI')?'T':'X';
                    $p10 = ($d['pattern_10'] ?? '') . $sym;
                    if (strlen($p10)>10) $p10 = substr($p10,-10);
                    $d['pattern_10'] = $p10;
                    $d['config'] = $c;
                    // Kiểm tra target/profit stop
                    $wT = (int)($c['target_win'] ?? 0);
                    if ($wT > 0 && (int)$d['win_count_total'] >= $wT) {
                        $c['auto'] = false; $c['paused'] = true; $d['config'] = $c;
                    }
                    $pS = (int)($c['profit_stop'] ?? 0);
                    if ($pS > 0 && (int)$d['profit_total'] >= $pS) {
                        $c['auto'] = false; $c['paused'] = true; $d['config'] = $c;
                    }
                    return $d;
                });

                $icon = $win ? '✅' : '❌';
                $diceStr = implode('-', $dices);
                $logMsg = "$icon Phiên #$sid: $pred → $result ($diceStr)".($isJackpot?' 🎉 JACKPOT!':'');
                key_log($key, $win?'success':'error', $logMsg);
                $actions[] = ['type'=>'result','msg'=>$logMsg];
                $s = key_load($key);
            }
        }
        key_update($key, fn($d) => array_merge($d, ['last_session_id'=>$latestId]));
    }

    if (!empty($s['pending_session']) && (int)$s['pending_session'] <= $latestId) {
        key_update($key, function($d) {
            $d['pending_pred']=null;$d['pending_session']=null;$d['pending_conf']=null;
            $d['pending_bet_amount']=null;$d['bet_session']=null;$d['bet_amount']=0;
            return $d;
        });
        $s = key_load($key);
    }

    $cfg = $s['config'];
    if (!empty($cfg['auto']) && empty($cfg['paused']) && empty($s['pending_pred'])) {
        // Build history chronological
        $hseq = [];
        $hist = array_reverse($s['history'] ?? []);
        foreach ($hist as $h) {
            $r = $h['result'] ?? '';
            if ($r==='TAI') $hseq[] = ['phien'=>$h['session'],'ket_qua'=>'Tài','tong'=>$h['tong']??0,'xuc_xac'=>$h['dices']??[]];
            elseif ($r==='XIU') $hseq[] = ['phien'=>$h['session'],'ket_qua'=>'Xỉu','tong'=>$h['tong']??0,'xuc_xac'=>$h['dices']??[]];
        }
        if (empty($hseq) && !empty($data['list'])) {
            $seed = array_reverse(array_slice($data['list'], 0, 50));
            foreach ($seed as $row) {
                $rr = $row['resultTruyenThong'] ?? '';
                $mm = ['Tài'=>'Tài','Xỉu'=>'Xỉu','tai'=>'Tài','xiu'=>'Xỉu','TAI'=>'Tài','XIU'=>'Xỉu'];
                if (isset($mm[$rr])) {
                    $hseq[] = ['phien'=>(int)$row['id'],'ket_qua'=>$mm[$rr],'tong'=>array_sum($row['dices']??[0,0,0]),'xuc_xac'=>$row['dices']??[]];
                }
            }
        }

        // 🎯 TÍNH PREDICTION BẰNG TTOAN — LƯU VÀO STATE
        $mpState = $s['model_predictions'] ?? [];
        $ai = ttoan_generate_prediction($hseq, $mpState);
        $predStr = $ai['prediction']; // 'Tài' | 'Xỉu'
        $conf = $ai['doTinCay'];

        // Bet amount: martingale cố định
        $baseBet = max(1000, (int)($cfg['base_bet'] ?? 10000));
        $betAmt = $baseBet;
        $st = (int)($cfg['lose_streak'] ?? 0);
        if ($st > 0) {
            $mult = 1 << min($st, 4);
            $betAmt = $baseBet * $mult;
        }
        $bal = (int)($s['balance'] ?? 0);
        if ($betAmt > $bal && $bal > 0) $betAmt = max(1000, $bal);

        // 💾 SAVE PENDING — ĐÂY LÀ NGUỒN DUY NHẤT CHO CẢ HIỂN THỊ VÀ CƯỢC
        key_update($key, function($d) use ($predStr,$latestId,$conf,$betAmt,$mpState) {
            $d['pending_pred'] = $predStr;
            $d['pending_session'] = $latestId + 1;
            $d['pending_conf'] = $conf;
            $d['pending_bet_amount'] = $betAmt;
            $d['model_predictions'] = $mpState;
            return $d;
        });
        $logMsg = "🎯 Phiên #".($latestId+1).": $predStr (conf ".number_format($conf,1)."%) — cược ".number_format($betAmt)."đ";
        key_log($key,'info',$logMsg);
        $actions[] = ['type'=>'predict','msg'=>$logMsg];
        $s = key_load($key);
    }

    $cfg = $s['config'];
    if (!empty($s['pending_pred']) && !empty($cfg['auto']) && empty($cfg['paused'])) {
        if (($s['bet_session'] ?? null) != $s['pending_session']) {
            key_log($key,'info',"🔓 Đặt cược #{$s['pending_session']} ({$s['pending_pred']})...");
            do_ws_bet($key, $s, $actions);
        }
    }
    return $actions;
}

function worker_heartbeat(string $key, string $status='running'): void {
    key_update($key, function($d) use ($status) {
        $d['worker'] = [
            'last_beat'=>time(),'pid'=>getmypid(),'status'=>$status,
            'started_at'=>$d['worker']['started_at'] ?? time(),
        ];
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
        if ($pid > 0) {
            $alive = function_exists('posix_kill') ? @posix_kill($pid, 0) : (time() - filemtime($lp)) < 60;
            if ($alive) return false;
        }
        @unlink($lp);
    }
    $fp = @fopen($lp, 'c+');
    if (!$fp) return false;
    if (!flock($fp, LOCK_EX|LOCK_NB)) { fclose($fp); return false; }
    ftruncate($fp,0); rewind($fp); fwrite($fp,(string)getmypid()); fflush($fp);
    register_shutdown_function(function() use ($fp,$lp) {
        @flock($fp,LOCK_UN); @fclose($fp); @unlink($lp);
    });
    return true;
}
function run_worker_daemon(string $key, int $max): void {
    global $CFG;
    if (function_exists('fastcgi_finish_request')) @fastcgi_finish_request();
    else { @ob_end_clean(); header('Connection: close'); header('Content-Length: 0'); @flush(); @ob_end_flush(); }
    @ignore_user_abort(true);
    @set_time_limit(0);
    @ini_set('memory_limit','256M');
    if (!worker_lock($key)) return;
    $sleep = (int)($CFG['worker']['loop_sleep'] ?? 1);
    $deadline = time() + $max;
    $lastBeat = 0;
    $selfRespawn = !empty($CFG['worker']['self_respawn']);
    $buf = (int)($CFG['worker']['respawn_buffer'] ?? 60);
    worker_heartbeat($key,'running');
    key_log($key,'info','🚀 Worker PID='.getmypid()." max={$max}s");
    while (time() < $deadline) {
        $s = key_load($key);
        if (!$s) break;
        try { worker_step($key); }
        catch (Throwable $e) { key_log($key,'error','💥 '.$e->getMessage()); }
        if (time() - $lastBeat >= 10) { worker_heartbeat($key,'running'); $lastBeat = time(); }
        if ($selfRespawn && (time() + $buf) >= $deadline) {
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
    worker_heartbeat($key,'stopped');
}
function spawn_worker_async(string $key): void {
    // Double-check lock
    $lp = KEY_DIR . '/' . hash('sha256', strtolower($key)) . '.lock';
    if (is_file($lp)) {
        $pid = (int)trim(@file_get_contents($lp));
        if ($pid > 0 && function_exists('posix_kill') && @posix_kill($pid, 0)) return;
    }
    $scheme = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS']!=='off') ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $path = $_SERVER['SCRIPT_NAME'] ?? '/index.php';
    $url = "$scheme://$host$path?action=worker&key=".urlencode($key)."&max=3600";

    if (function_exists('exec') && !in_array('exec', array_map('trim', explode(',',(string)ini_get('disable_functions'))))) {
        $php = PHP_BINARY ?: 'php';
        $code = 'ignore_user_abort(true);set_time_limit(0);@file_get_contents('.var_export($url,true).');';
        @exec(sprintf('%s -r %s > /dev/null 2>&1 &', escapeshellarg($php), escapeshellarg($code)));
        return;
    }
    if (function_exists('shell_exec') && !in_array('shell_exec', array_map('trim', explode(',',(string)ini_get('disable_functions'))))) {
        @shell_exec("curl -s --max-time 2 ".escapeshellarg($url)." > /dev/null 2>&1 &");
        return;
    }
    if (function_exists('fsockopen')) {
        $parsed = parse_url($url);
        $h = $parsed['host'] ?? $host;
        $port = ($parsed['scheme']??'http')==='https'?443:80;
        $fp = @fsockopen($h,$port,$en,$es,0.5);
        if ($fp) {
            stream_set_timeout($fp,1);
            $p = ($parsed['path']??'/').'?'.($parsed['query']??'');
            @fwrite($fp, "GET {$p} HTTP/1.1\r\nHost: {$h}\r\nConnection: Close\r\n\r\n");
            @fclose($fp);
            return;
        }
    }
    try {
        $ctx = stream_context_create(['http'=>['timeout'=>0.5]]);
        @file_get_contents($url,false,$ctx);
    } catch (Throwable $e) {}
}

// ═══════════════ [9] ROUTER ═══════════════
$action = $_GET['action'] ?? $_POST['action'] ?? '';
if ($action === '') { render_ui(); exit; }

if ($action === 'cron') {
    header('Content-Type: application/json; charset=utf-8');
    $idx = DATA_DIR.'/user_index.json';
    $out = ['ok'=>true,'checked'=>0,'spawned'=>[]];
    if (is_file($idx)) {
        $users = json_decode(file_get_contents($idx),true) ?: [];
        foreach ($users as $u => $k) {
            $out['checked']++;
            $s = key_load($k);
            if (!$s) continue;
            if (empty($s['config']['auto']) || !empty($s['config']['paused'])) continue;
            if (worker_alive($k)) continue;
            $lp = KEY_DIR.'/'.hash('sha256',strtolower($k)).'.lock';
            @unlink($lp);
            spawn_worker_async($k);
            $out['spawned'][] = $u;
        }
    }
    echo json_encode($out); exit;
}

if ($action === 'worker') {
    $key = trim($_GET['key'] ?? '');
    if (!$key) { http_response_code(400); echo 'missing key'; exit; }
    $max = (int)($_GET['max'] ?? 3600);
    run_worker_daemon($key, $max);
    exit;
}

if ($action === 'keepalive') {
    // Chỉ để giữ server sống, không làm gì khác
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['ok'=>true,'ts'=>time()]); exit;
}

header('Content-Type: application/json; charset=utf-8');
try {
    switch ($action) {
        case 'verify':
            $u = trim($_POST['user'] ?? ''); $p = trim($_POST['pass'] ?? '');
            $dev = trim($_POST['device'] ?? 'WEB-ONIICHAN');
            if (!$u || !$p) { echo json_encode(['ok'=>false,'msg'=>'Vui lòng nhập đủ tài khoản/mật khẩu']); exit; }
            $key = $u;
            $existing = key_load($key);
            $canResume = !empty($existing['user']) && !empty($existing['token']);
            $gl = game_login($u, $p);
            if (isset($gl['_error'])) {
                if ($canResume) {
                    $gl = ['nickname'=>$existing['nickname']??$u,'token'=>$existing['token'],'money'=>$existing['balance']??0];
                    key_log($key,'info','♻️ Resume session cũ');
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
            $s['bet_session'] = $s['bet_session'] ?? null;
            $s['bet_amount'] = $s['bet_amount'] ?? 0;
            $s['model_predictions'] = $s['model_predictions'] ?? [];
            $s['pattern_10'] = $s['pattern_10'] ?? '';
            key_save($key, $s);
            key_save_by_user($u, $key);
            key_log($key,'info','🔐 Đăng nhập — '.$dev);
            if (!worker_alive($key)) spawn_worker_async($key);
            echo json_encode([
                'ok'=>true,'user'=>$u,'nickname'=>$s['nickname'],'balance'=>$s['balance'],
                'config'=>$s['config'],'history'=>$s['history'],
                'auth_token'=>issue_token($u),'worker_alive'=>worker_alive($key),
                'resumed'=>$canResume,
            ]); exit;

        case 'setup':
            // Nhận base_bet + target, bật auto, lưu onboarded
            $u = trim($_POST['user'] ?? ''); $tk = trim($_POST['auth_token'] ?? '');
            if (!require_auth($u,$tk)) { echo json_encode(['ok'=>false,'msg'=>'Unauthorized']); exit; }
            $key = key_resolve($u);
            $s = key_load($key);
            $c = $s['config'];
            $c['base_bet'] = max(1000, (int)($_POST['base_bet'] ?? 10000));
            $c['profit_stop'] = max(0, (int)($_POST['profit_stop'] ?? 0));
            $c['target_win'] = max(0, (int)($_POST['target_win'] ?? 0));
            $c['mode'] = 'double';        // Cố định
            $c['max_lose_streak'] = 4;     // Cố định
            $c['onboarded'] = true;
            $c['auto'] = true;
            $c['paused'] = false;
            $s['config'] = $c;
            key_save($key, $s);
            if (!worker_alive($key)) {
                $lp = KEY_DIR.'/'.hash('sha256',strtolower($key)).'.lock';
                @unlink($lp);
                spawn_worker_async($key);
            }
            key_log($key,'success','▶ BẮT ĐẦU AUTO · vốn '.number_format($c['base_bet']).' · target '.number_format($c['target_win']));
            echo json_encode(['ok'=>true,'config'=>$c,'worker_alive'=>worker_alive($key)]);
            exit;

        case 'status':
            $u = trim($_GET['user'] ?? ''); $tk = trim($_GET['auth_token'] ?? '');
            if (!require_auth($u,$tk)) { echo json_encode(['ok'=>false,'msg'=>'Unauthorized']); exit; }
            $key = key_resolve($u);
            $s = key_load($key);
            // Anti-reset: nếu auto bật và worker chết → respawn
            if (!empty($s['config']['auto']) && empty($s['config']['paused']) && !worker_alive($key)) {
                $lp = KEY_DIR.'/'.hash('sha256',strtolower($key)).'.lock';
                @unlink($lp);
                spawn_worker_async($key);
            }
            $wins = (int)($s['win_count_total'] ?? 0);
            $losses = (int)($s['loss_count_total'] ?? 0);
            $tot = $wins + $losses;
            $profit = (int)($s['profit_total'] ?? 0);
            echo json_encode([
                'ok'=>true,'nickname'=>$s['nickname'] ?? '','balance'=>$s['balance'] ?? 0,
                'config'=>$s['config'] ?? [],
                'history'=>array_slice($s['history'] ?? [], 0, 100),
                'pending_pred'=>$s['pending_pred'] ?? null,
                'pending_session'=>$s['pending_session'] ?? null,
                'pending_conf'=>$s['pending_conf'] ?? null,
                'pending_bet_amount'=>$s['pending_bet_amount'] ?? null,
                'last_session_id'=>$s['last_session_id'] ?? 0,
                'win_count_total'=>$wins,'loss_count_total'=>$losses,'profit_total'=>$profit,
                'stats'=>['wins'=>$wins,'losses'=>$losses,'total'=>$tot,
                    'winrate'=>$tot>0?round($wins/$tot*100,1):0,'profit'=>$profit],
                'worker_alive'=>worker_alive($key),
                'pattern_10'=>$s['pattern_10'] ?? '',
                'ts'=>time(),
            ]); exit;

        case 'tick':
            $u = trim($_POST['user'] ?? ''); $tk = trim($_POST['auth_token'] ?? '');
            if (!require_auth($u,$tk)) { echo json_encode(['ok'=>false,'msg'=>'Unauthorized']); exit; }
            $key = key_resolve($u);
            $s = key_load($key);
            if (!empty($s['config']['auto']) && empty($s['config']['paused']) && !worker_alive($key)) {
                $lp = KEY_DIR.'/'.hash('sha256',strtolower($key)).'.lock';
                @unlink($lp);
                spawn_worker_async($key);
            }
            $s2 = key_load($key);
            echo json_encode([
                'ok'=>true,'worker_alive'=>worker_alive($key),
                'pending_pred'=>$s2['pending_pred'] ?? null,
                'pending_session'=>$s2['pending_session'] ?? null,
            ]); exit;

        case 'logout':
            $u = trim($_POST['user'] ?? ''); $tk = trim($_POST['auth_token'] ?? '');
            if (!require_auth($u,$tk)) { echo json_encode(['ok'=>false,'msg'=>'Unauthorized']); exit; }
            $key = key_resolve($u);
            @unlink(key_path($key));
            @unlink(KEY_DIR.'/'.hash('sha256',strtolower($key)).'.lock');
            echo json_encode(['ok'=>true]); exit;
    }
    echo json_encode(['ok'=>false,'msg'=>'Action lạ']);
} catch (Throwable $e) {
    echo json_encode(['ok'=>false,'msg'=>'Lỗi: '.$e->getMessage()]);
}
exit;

// ═══════════════ [10] UI — JAPANESE OTAKU ONIICHAN ═══════════════
function render_ui(): void { ?>
<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<meta name="theme-color" content="#0d0719">
<title>DENIUS AUTO · お兄ちゃん Edition</title>
<style>
:root{
  --bg:#0d0719;
  --bg-2:#150a26;
  --bg-3:#1e1035;
  --card:rgba(30,16,53,0.72);
  --card-solid:#1a0e2e;
  --border:rgba(255,183,213,0.12);
  --border-strong:rgba(255,183,213,0.28);
  --sakura:#ffb7d5;
  --sakura-bright:#ffd6e8;
  --sakura-dim:rgba(255,183,213,0.15);
  --lavender:#c4a7e7;
  --gold:#ffd966;
  --gold-bright:#ffe89a;
  --mint:#7ef0b4;
  --coral:#ff8fa0;
  --ruby:#ff5c7a;
  --text:#fff5eb;
  --text-dim:#b8a8c8;
  --muted:#6b5a80;
  --radius:18px;
  --radius-lg:24px;
}
*{margin:0;padding:0;box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html,body{min-height:100%;background:var(--bg);color:var(--text);overflow-x:hidden;
  font-family:-apple-system,BlinkMacSystemFont,"Hiragino Sans","Yu Gothic","Noto Sans JP","Inter","Segoe UI",system-ui,sans-serif;
  -webkit-font-smoothing:antialiased;user-select:none}
body{
  background-image:
    radial-gradient(ellipse 80% 60% at 50% -10%,rgba(255,183,213,0.12),transparent 60%),
    radial-gradient(ellipse 60% 40% at 90% 100%,rgba(196,167,231,0.10),transparent 55%),
    radial-gradient(ellipse 50% 40% at 10% 80%,rgba(255,217,102,0.05),transparent 55%);
  background-attachment:fixed;min-height:100vh;
}
/* Sakura petals */
.sakura-layer{position:fixed;inset:0;pointer-events:none;z-index:0;overflow:hidden}
.petal{position:absolute;width:12px;height:12px;background:radial-gradient(ellipse at 30% 30%,var(--sakura-bright),var(--sakura) 55%,transparent 80%);border-radius:50% 0 50% 50%;opacity:0.55;animation:fall linear infinite;filter:drop-shadow(0 0 4px rgba(255,183,213,0.4))}
@keyframes fall{
  0%{transform:translateY(-20px) translateX(0) rotate(0deg);opacity:0}
  10%{opacity:0.7}
  90%{opacity:0.7}
  100%{transform:translateY(105vh) translateX(60px) rotate(360deg);opacity:0}
}
/* Main container */
#app{position:relative;z-index:1;min-height:100vh;display:flex;flex-direction:column}
/* ═══ LOGIN ═══ */
.login-screen{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.login-card{
  width:100%;max-width:420px;
  background:linear-gradient(160deg,rgba(30,16,53,0.85),rgba(13,7,25,0.92));
  border:1px solid var(--border-strong);border-radius:var(--radius-lg);
  padding:40px 30px 34px;position:relative;overflow:hidden;
  box-shadow:0 30px 80px -20px rgba(0,0,0,0.85),0 0 80px -30px rgba(255,183,213,0.25);
  backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);
  animation:cardEnter 0.7s cubic-bezier(0.34,1.56,0.64,1);
}
@keyframes cardEnter{from{opacity:0;transform:translateY(40px) scale(0.94)}to{opacity:1;transform:translateY(0) scale(1)}}
.login-card::before{
  content:'';position:absolute;top:0;left:0;right:0;height:2px;
  background:linear-gradient(90deg,transparent,var(--sakura),var(--gold),var(--sakura),transparent);
  opacity:0.7;
}
.login-card::after{
  content:'🌸';position:absolute;top:-10px;right:20px;font-size:14px;opacity:0.4;
  animation:floatFlower 4s ease-in-out infinite;
}
@keyframes floatFlower{0%,100%{transform:translateY(0) rotate(0deg)}50%{transform:translateY(10px) rotate(15deg)}}
.logo-wrap{text-align:center;margin-bottom:20px;position:relative}
.logo-img{
  width:120px;height:120px;object-fit:cover;border-radius:50%;
  border:2px solid var(--sakura);
  box-shadow:0 0 40px rgba(255,183,213,0.45),0 0 80px rgba(255,183,213,0.2),inset 0 0 20px rgba(255,183,213,0.15);
  animation:logoFloat 3.5s ease-in-out infinite,pulseGlow 3s ease-in-out infinite;
  background:var(--bg-2);
}
@keyframes logoFloat{0%,100%{transform:translateY(0)}50%{transform:translateY(-8px)}}
@keyframes pulseGlow{0%,100%{box-shadow:0 0 40px rgba(255,183,213,0.45),0 0 80px rgba(255,183,213,0.2),inset 0 0 20px rgba(255,183,213,0.15)}50%{box-shadow:0 0 55px rgba(255,183,213,0.65),0 0 100px rgba(255,183,213,0.3),inset 0 0 25px rgba(255,183,213,0.2)}}
.brand-title{
  font-size:24px;font-weight:900;letter-spacing:4px;text-align:center;
  background:linear-gradient(90deg,var(--sakura-bright),var(--gold-bright),var(--sakura-bright));
  -webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;
  text-shadow:0 0 30px rgba(255,183,213,0.3);margin-bottom:6px;
}
.brand-sub{
  text-align:center;font-size:11px;letter-spacing:2px;color:var(--text-dim);
  font-weight:600;margin-bottom:26px;display:flex;align-items:center;justify-content:center;gap:6px;
}
.jp-accent{color:var(--sakura);font-weight:700}
/* Inputs */
.field{margin-bottom:14px}
.field label{display:flex;align-items:center;gap:6px;font-size:10px;font-weight:800;color:var(--text-dim);text-transform:uppercase;letter-spacing:1.5px;margin-bottom:7px}
.field input{
  width:100%;padding:14px 16px;
  background:rgba(13,7,25,0.85);border:1px solid rgba(255,183,213,0.1);
  border-radius:14px;color:var(--text);font-size:14px;outline:none;transition:all 0.3s;
  font-family:inherit;
}
.field input:focus{
  border-color:var(--sakura);background:rgba(255,183,213,0.03);
  box-shadow:0 0 0 3px rgba(255,183,213,0.12),0 0 20px rgba(255,183,213,0.1);
}
.field input::placeholder{color:var(--muted)}
.btn-main{
  width:100%;padding:15px;border:none;border-radius:14px;
  font-size:13px;font-weight:900;letter-spacing:2px;text-transform:uppercase;cursor:pointer;
  transition:all 0.3s;font-family:inherit;position:relative;overflow:hidden;margin-top:10px;
}
.btn-sakura{
  background:linear-gradient(135deg,var(--sakura-bright),var(--sakura));
  color:#1a0e2e;box-shadow:0 8px 28px -8px rgba(255,183,213,0.5),0 0 40px -15px rgba(255,183,213,0.3);
}
.btn-sakura:hover:not(:disabled){transform:translateY(-2px);box-shadow:0 12px 36px -8px rgba(255,183,213,0.7),0 0 50px -15px rgba(255,183,213,0.5)}
.btn-sakura:disabled{opacity:0.5;cursor:not-allowed}
.btn-sakura:disabled::after{content:'';position:absolute;width:16px;height:16px;top:50%;right:22px;margin-top:-8px;border-radius:50%;border:2px solid rgba(26,14,46,0.3);border-top-color:#1a0e2e;animation:spin 0.7s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.msg{margin-top:14px;padding:12px 16px;border-radius:12px;font-size:12px;display:flex;align-items:center;gap:8px;animation:slideDown 0.3s}
.msg.err{background:rgba(255,92,122,0.1);border:1px solid rgba(255,92,122,0.3);color:#ffa0b3}
.msg.ok{background:rgba(126,240,180,0.1);border:1px solid rgba(126,240,180,0.3);color:var(--mint)}
@keyframes slideDown{from{opacity:0;transform:translateY(-8px)}to{opacity:1;transform:translateY(0)}}
.login-foot{margin-top:22px;text-align:center;font-size:10px;color:var(--muted);line-height:1.8;letter-spacing:0.5px}
.login-foot b{color:var(--sakura)}
/* ═══ INFO PANEL (after login) ═══ */
.info-screen{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.info-card{
  width:100%;max-width:400px;position:relative;
  background:linear-gradient(160deg,rgba(30,16,53,0.9),rgba(13,7,25,0.94));
  border:1px solid var(--border-strong);border-radius:var(--radius-lg);
  padding:32px 26px 26px;backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);
  box-shadow:0 30px 80px -20px rgba(0,0,0,0.85),0 0 80px -30px rgba(255,183,213,0.3);
  animation:infoEnter 0.8s cubic-bezier(0.34,1.56,0.64,1);
}
@keyframes infoEnter{
  from{opacity:0;transform:scale(0.9) translateY(-30px);filter:blur(15px)}
  to{opacity:1;transform:scale(1) translateY(0);filter:blur(0)}
}
.info-close{
  position:absolute;top:14px;right:14px;width:32px;height:32px;border-radius:50%;
  background:rgba(255,92,122,0.12);border:1px solid rgba(255,92,122,0.35);
  color:var(--ruby);font-size:18px;font-weight:900;cursor:pointer;display:flex;align-items:center;justify-content:center;
  transition:all 0.25s;font-family:inherit;line-height:1;
}
.info-close:hover{background:rgba(255,92,122,0.25);transform:rotate(90deg)}
.info-head{text-align:center;margin-bottom:22px}
.info-avatar{
  width:76px;height:76px;border-radius:50%;margin:0 auto 14px;
  background:linear-gradient(135deg,var(--sakura),var(--lavender));
  display:flex;align-items:center;justify-content:center;
  font-size:34px;font-weight:900;color:#1a0e2e;
  box-shadow:0 0 40px rgba(255,183,213,0.5),0 0 80px rgba(255,183,213,0.25);
  animation:avatarPop 0.7s cubic-bezier(0.34,1.56,0.64,1) 0.2s both;
}
@keyframes avatarPop{from{transform:scale(0);opacity:0}to{transform:scale(1);opacity:1}}
.info-greet{font-size:14px;color:var(--sakura);font-weight:700;letter-spacing:1px;margin-bottom:4px;animation:fadeIn 0.6s 0.3s both}
.info-name{font-size:22px;font-weight:900;color:var(--text);margin-bottom:6px;animation:fadeIn 0.6s 0.4s both}
.info-tag{font-size:10px;color:var(--text-dim);letter-spacing:2px;text-transform:uppercase;font-weight:600;animation:fadeIn 0.6s 0.5s both}
@keyframes fadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
.info-stats{
  display:grid;grid-template-columns:1fr;gap:10px;margin-top:20px;
  animation:fadeIn 0.6s 0.6s both;
}
.info-stat{
  padding:16px;background:rgba(255,183,213,0.05);border:1px solid var(--border);border-radius:14px;
  display:flex;align-items:center;justify-content:space-between;gap:12px;
}
.info-stat .lbl{font-size:11px;color:var(--text-dim);font-weight:700;letter-spacing:0.5px;display:flex;align-items:center;gap:6px}
.info-stat .val{font-size:16px;font-weight:900;color:var(--gold-bright);font-family:"SF Mono",monospace}
.info-stat .val.small{font-size:11px;color:var(--sakura);letter-spacing:1px}
/* ═══ SETUP SCREENS ═══ */
.setup-screen{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.setup-card{
  width:100%;max-width:400px;
  background:linear-gradient(160deg,rgba(30,16,53,0.9),rgba(13,7,25,0.94));
  border:1px solid var(--border-strong);border-radius:var(--radius-lg);
  padding:34px 26px 28px;backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);
  box-shadow:0 30px 80px -20px rgba(0,0,0,0.85),0 0 80px -30px rgba(255,183,213,0.3);
  animation:infoEnter 0.7s cubic-bezier(0.34,1.56,0.64,1);
  position:relative;
}
.setup-card::before{content:'';position:absolute;top:0;left:20%;right:20%;height:1px;background:linear-gradient(90deg,transparent,var(--sakura),transparent)}
.setup-step{font-size:10px;letter-spacing:2px;color:var(--sakura);font-weight:800;text-align:center;margin-bottom:8px;text-transform:uppercase}
.setup-title{font-size:20px;font-weight:900;text-align:center;margin-bottom:6px;color:var(--text);letter-spacing:0.5px}
.setup-sub{font-size:11px;text-align:center;color:var(--text-dim);line-height:1.6;margin-bottom:24px}
.setup-hint{font-size:10px;color:var(--sakura-dim);background:rgba(255,183,213,0.06);border:1px solid rgba(255,183,213,0.15);border-radius:10px;padding:10px 12px;margin-top:14px;line-height:1.6;text-align:center}
.setup-hint b{color:var(--sakura)}
/* ═══ MAIN SCREEN ═══ */
.main-screen{min-height:100vh;display:flex;flex-direction:column;padding:16px 16px 80px}
.main-header{
  display:flex;align-items:center;justify-content:space-between;gap:12px;
  padding:14px 18px;margin-bottom:14px;
  background:linear-gradient(135deg,rgba(30,16,53,0.85),rgba(13,7,25,0.9));
  border:1px solid var(--border-strong);border-radius:18px;
  backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);
  box-shadow:0 8px 28px -12px rgba(0,0,0,0.5);
}
.main-logo{width:42px;height:42px;border-radius:50%;object-fit:cover;border:1.5px solid var(--sakura);box-shadow:0 0 20px rgba(255,183,213,0.35);flex-shrink:0;background:var(--bg-2)}
.main-brand{flex:1;min-width:0}
.main-brand h1{font-size:13px;font-weight:900;letter-spacing:2px;background:linear-gradient(90deg,var(--sakura-bright),var(--gold-bright));-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
.main-brand small{display:block;font-size:9px;color:var(--text-dim);letter-spacing:1px;margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.main-balance{text-align:right;flex-shrink:0}
.main-balance small{font-size:8px;color:var(--text-dim);letter-spacing:1.5px;font-weight:800;display:block}
.main-balance b{display:block;font-size:20px;font-weight:900;color:var(--gold-bright);font-family:"SF Mono",monospace;text-shadow:0 0 20px rgba(255,217,102,0.5);transition:all 0.3s}
.main-balance b.updating{transform:scale(1.08);color:var(--mint)}
/* Result card */
.result-card{
  padding:28px 20px;margin-bottom:14px;text-align:center;
  background:linear-gradient(160deg,rgba(30,16,53,0.9),rgba(13,7,25,0.94));
  border:1px solid var(--border-strong);border-radius:var(--radius-lg);
  backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);
  box-shadow:0 10px 40px -12px rgba(0,0,0,0.6),0 0 60px -30px rgba(255,183,213,0.2);
  position:relative;overflow:hidden;min-height:220px;
  display:flex;flex-direction:column;align-items:center;justify-content:center;
}
.result-card::before{content:'';position:absolute;top:0;left:15%;right:15%;height:1px;background:linear-gradient(90deg,transparent,var(--sakura),var(--gold),var(--sakura),transparent);opacity:0.6}
.result-session{font-size:10px;letter-spacing:2px;color:var(--text-dim);font-weight:800;text-transform:uppercase;margin-bottom:16px}
.result-prediction{font-size:60px;font-weight:900;line-height:1;margin-bottom:10px;transition:all 0.4s;letter-spacing:2px}
.result-prediction.tai{background:linear-gradient(135deg,#7ec8ff,#4a9eff,#7ec8ff);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;filter:drop-shadow(0 0 30px rgba(78,158,255,0.5))}
.result-prediction.xiu{background:linear-gradient(135deg,#ff8fa0,#ff5c7a,#ff8fa0);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;filter:drop-shadow(0 0 30px rgba(255,92,122,0.5))}
.result-prediction.wait{color:var(--muted);font-size:36px;letter-spacing:4px}
.result-label{font-size:11px;color:var(--text-dim);letter-spacing:3px;font-weight:700;text-transform:uppercase;margin-bottom:8px}
.result-outcome{margin-top:20px;padding-top:20px;border-top:1px dashed rgba(255,183,213,0.15);width:100%;display:none}
.result-outcome.show{display:block;animation:outcomeIn 0.5s cubic-bezier(0.34,1.56,0.64,1)}
@keyframes outcomeIn{from{opacity:0;transform:scale(0.9)}to{opacity:1;transform:scale(1)}}
.result-outcome .big{font-size:28px;font-weight:900;letter-spacing:2px;margin-bottom:6px}
.result-outcome .big.win{color:var(--mint);text-shadow:0 0 30px rgba(126,240,180,0.5)}
.result-outcome .big.lose{color:var(--ruby);text-shadow:0 0 30px rgba(255,92,122,0.5)}
.result-outcome .detail{font-size:12px;color:var(--text-dim);font-family:monospace;letter-spacing:0.5px}
.result-outcome .detail b{color:var(--gold-bright)}
/* Small bet box */
.bet-box{
  padding:18px 20px;margin-bottom:14px;
  background:linear-gradient(135deg,rgba(255,183,213,0.06),rgba(30,16,53,0.9));
  border:1px solid rgba(255,183,213,0.2);border-radius:18px;
  backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);
  display:flex;align-items:center;justify-content:space-between;gap:14px;
  box-shadow:0 8px 24px -12px rgba(0,0,0,0.4);
}
.bet-box-label{font-size:10px;letter-spacing:2px;color:var(--text-dim);font-weight:800;text-transform:uppercase;margin-bottom:4px;display:flex;align-items:center;gap:6px}
.bet-box-label::before{content:'💎';font-size:12px}
.bet-box-value{font-size:22px;font-weight:900;color:var(--gold-bright);font-family:"SF Mono",monospace;letter-spacing:1px;text-shadow:0 0 20px rgba(255,217,102,0.4);transition:all 0.3s}
.bet-box-value.pulse{animation:betPulse 0.6s ease-out}
@keyframes betPulse{0%{transform:scale(1)}50%{transform:scale(1.15);color:var(--sakura)}100%{transform:scale(1)}}
.bet-box-streak{text-align:right}
.bet-box-streak small{font-size:9px;color:var(--text-dim);letter-spacing:1px;font-weight:700;text-transform:uppercase;display:block}
.bet-box-streak b{font-size:15px;font-weight:900;color:var(--sakura);font-family:"SF Mono",monospace;display:block;margin-top:2px}
/* Bottom nav */
.bottom-nav{
  position:fixed;bottom:0;left:0;right:0;z-index:20;
  padding:10px 20px 14px;
  background:linear-gradient(180deg,rgba(13,7,25,0.4),rgba(13,7,25,0.98) 40%);
  backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);
  border-top:1px solid var(--border);
  display:flex;justify-content:center;gap:8px;
}
.nav-btn{
  flex:1;max-width:180px;padding:12px 16px;
  background:rgba(30,16,53,0.6);border:1px solid var(--border);
  color:var(--text-dim);font-size:11px;font-weight:800;letter-spacing:1px;
  border-radius:14px;cursor:pointer;transition:all 0.25s;
  display:flex;align-items:center;justify-content:center;gap:6px;
  font-family:inherit;text-transform:uppercase;
}
.nav-btn.on{background:linear-gradient(135deg,var(--sakura-bright),var(--sakura));color:#1a0e2e;border-color:transparent;box-shadow:0 6px 20px -6px rgba(255,183,213,0.5)}
.nav-btn:not(.on):hover{color:var(--text);background:rgba(255,183,213,0.05);border-color:var(--border-strong)}
/* History screen */
.history-screen{padding:16px 16px 80px;min-height:100vh}
.history-header{
  display:flex;align-items:center;justify-content:space-between;gap:12px;
  padding:14px 18px;margin-bottom:14px;
  background:linear-gradient(135deg,rgba(30,16,53,0.85),rgba(13,7,25,0.9));
  border:1px solid var(--border-strong);border-radius:18px;
  backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);
}
.history-title{font-size:14px;font-weight:900;color:var(--sakura);letter-spacing:2px;text-transform:uppercase}
.history-count{font-size:10px;color:var(--text-dim);font-weight:700;padding:4px 10px;background:rgba(255,183,213,0.08);border-radius:20px;border:1px solid var(--border)}
.hist-list{display:flex;flex-direction:column;gap:8px}
.hist-row{
  padding:14px 16px;
  background:linear-gradient(135deg,rgba(30,16,53,0.7),rgba(13,7,25,0.8));
  border:1px solid var(--border);border-radius:14px;
  display:flex;align-items:center;gap:12px;
  transition:all 0.2s;backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);
  border-left:3px solid var(--muted);
}
.hist-row.win{border-left-color:var(--mint);background:linear-gradient(90deg,rgba(126,240,180,0.06),rgba(13,7,25,0.8))}
.hist-row.lose{border-left-color:var(--ruby);background:linear-gradient(90deg,rgba(255,92,122,0.06),rgba(13,7,25,0.8))}
.hist-row.jackpot{border-left-color:var(--gold);animation:jackpotPulse 2s ease-in-out infinite}
@keyframes jackpotPulse{0%,100%{box-shadow:0 0 0 rgba(255,217,102,0)}50%{box-shadow:0 0 20px rgba(255,217,102,0.3)}}
.hist-sid{font-family:"SF Mono",monospace;color:var(--sakura);font-weight:800;font-size:11px;min-width:60px}
.hist-mid{flex:1;min-width:0}
.hist-mid .row1{font-size:12px;font-weight:800;margin-bottom:3px;display:flex;align-items:center;gap:6px;flex-wrap:wrap;color:var(--text)}
.hist-mid .row2{font-size:10px;color:var(--text-dim);font-family:"SF Mono",monospace;letter-spacing:0.3px}
.hist-amount{font-family:"SF Mono",monospace;font-weight:900;font-size:13px;min-width:76px;text-align:right;letter-spacing:0.3px}
.hist-amount.win{color:var(--mint)}
.hist-amount.lose{color:var(--ruby)}
.empty-state{padding:60px 20px;text-align:center;color:var(--text-dim);font-size:12px}
.empty-state .icon{font-size:52px;margin-bottom:16px;opacity:0.4;display:block}
.empty-state .title{font-size:14px;font-weight:800;color:var(--text);margin-bottom:6px}
.empty-state .sub{font-size:11px;color:var(--muted);letter-spacing:0.5px}
/* Utils */
.hide{display:none!important}
@media (max-width:360px){
  .login-card,.info-card,.setup-card{padding:26px 20px}
  .logo-img{width:96px;height:96px}
  .brand-title{font-size:20px;letter-spacing:3px}
  .result-prediction{font-size:52px}
  .main-balance b{font-size:17px}
}
/* Reduced motion */
@media (prefers-reduced-motion:reduce){
  .petal,.logo-img,.brand-title,.info-avatar,.result-outcome,.hist-row.jackpot{animation:none!important}
}
</style>
</head>
<body>
<div class="sakura-layer" id="sakura"></div>
<div id="app"></div>
<script>
// ══════════════════════════════════════════════════
// STATE
// ══════════════════════════════════════════════════
const app = document.getElementById('app');
const LOGO_URL = 'https://raw.githubusercontent.com/nguyenha783255-wq/LOGO-LC79/main/IMG_20260901_094944_094.jpg';

const S = {
  step: 'login',               // login | info | base_bet | target | main
  tab: 'main',                 // main | history
  user: '', nickname: '', balance: 0,
  authToken: '', device: '', loading: false,
  error: '', success: '',
  config: { base_bet:0, profit_stop:0, target_win:0, auto:false, paused:false, lose_streak:0, mode:'double', max_lose_streak:4, onboarded:false },
  history: [], stats: { wins:0, losses:0, total:0, winrate:0, profit:0 },
  pendingPred: null, pendingSession: null, pendingConf: null, pendingBetAmount: null,
  workerAlive: false,
  lastSettledSession: null,
  // Setup inputs
  setupBaseBet: 0, setupTarget: 0,
};

// Device fingerprint
(function() {
  const d = [navigator.userAgent, navigator.language, screen.width+'x'+screen.height, new Date().getTimezoneOffset()].join('|');
  let h = 0; for (let i = 0; i < d.length; i++) h = ((h << 5) - h) + d.charCodeAt(i), h |= 0;
  S.device = 'ONI-' + Math.abs(h).toString(16).toUpperCase().slice(0, 8);
})();

// ══════════════════════════════════════════════════
// SAKURA PETALS
// ══════════════════════════════════════════════════
function spawnSakura() {
  const layer = document.getElementById('sakura');
  if (!layer) return;
  const count = window.innerWidth < 600 ? 12 : 20;
  for (let i = 0; i < count; i++) {
    const petal = document.createElement('div');
    petal.className = 'petal';
    petal.style.left = Math.random() * 100 + '%';
    const dur = 8 + Math.random() * 8;
    petal.style.animationDuration = dur + 's';
    petal.style.animationDelay = (Math.random() * dur) + 's';
    const size = 8 + Math.random() * 8;
    petal.style.width = size + 'px';
    petal.style.height = size + 'px';
    layer.appendChild(petal);
  }
}

// ══════════════════════════════════════════════════
// UTILS
// ══════════════════════════════════════════════════
const fmt = n => (n || 0).toLocaleString('vi-VN');
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

// ══════════════════════════════════════════════════
// RENDER ROUTER
// ══════════════════════════════════════════════════
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

// ══════════════════════════════════════════════════
// LOGIN SCREEN
// ══════════════════════════════════════════════════
function renderLogin() {
  app.innerHTML = `
    <div class="login-screen">
      <div class="login-card">
        <div class="logo-wrap">
          <img src="${LOGO_URL}" alt="DENIUS" class="logo-img" onerror="this.style.display='none'">
        </div>
        <div class="brand-title">DENIUS</div>
        <div class="brand-sub"><span class="jp-accent">お兄ちゃん</span> · AUTO BOT</div>
        <div class="field">
          <label>👤 TÀI KHOẢN</label>
          <input id="in_u" type="text" placeholder="Nhập tài khoản game..." autocomplete="username" value="${esc(S.user)}">
        </div>
        <div class="field">
          <label>🔒 MẬT KHẨU</label>
          <input id="in_p" type="password" placeholder="••••••••" autocomplete="current-password">
        </div>
        <button class="btn-main btn-sakura" id="btn_login" ${S.loading ? 'disabled' : ''}>
          ${S.loading ? 'ĐANG XÁC THỰC' : 'ĐĂNG NHẬP'}
        </button>
        ${S.error ? `<div class="msg err">⚠️ ${esc(S.error)}</div>` : ''}
        <div class="login-foot">
          <b>V2.0 ONIICHAN EDITION</b> · Admin <b>@DENIUS09</b>
        </div>
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
    const r = await api('verify', { user: u, pass: p, device: S.device });
    if (!r.ok) { S.loading = false; S.error = r.msg || 'Đăng nhập thất bại'; render(); return; }
    Object.assign(S, {
      user: r.user, nickname: r.nickname, balance: r.balance,
      config: r.config, history: r.history || [],
      authToken: r.auth_token, workerAlive: !!r.worker_alive, loading: false,
    });
    // Routing
    if (S.config.onboarded && S.config.base_bet > 0) {
      S.step = 'main'; S.tab = 'main';
    } else {
      S.step = 'info';
    }
    render();
    startTick();
  } catch (e) {
    S.loading = false; S.error = 'Lỗi: ' + e.message; render();
  }
}

// ══════════════════════════════════════════════════
// INFO SCREEN (after login)
// ══════════════════════════════════════════════════
function renderInfo() {
  const initial = (S.nickname || '?')[0].toUpperCase();
  app.innerHTML = `
    <div class="info-screen">
      <div class="info-card">
        <button class="info-close" id="btn_info_close" title="Đóng">✕</button>
        <div class="info-head">
          <div class="info-avatar">${esc(initial)}</div>
          <div class="info-greet">ようこそ、お兄ちゃん</div>
          <div class="info-name">${esc(S.nickname)}</div>
          <div class="info-tag">ACCOUNT VERIFIED</div>
        </div>
        <div class="info-stats">
          <div class="info-stat">
            <span class="lbl">💰 SỐ DƯ</span>
            <span class="val">${fmt(S.balance)}đ</span>
          </div>
          <div class="info-stat">
            <span class="lbl">🔑 TÀI KHOẢN</span>
            <span class="val">${esc(S.user)}</span>
          </div>
          <div class="info-stat">
            <span class="lbl">📱 DEVICE</span>
            <span class="val small">${esc(S.device)}</span>
          </div>
        </div>
      </div>
    </div>
  `;
  document.getElementById('btn_info_close').onclick = () => {
    S.step = 'base_bet';
    render();
  };
}

// ══════════════════════════════════════════════════
// BASE BET SCREEN
// ══════════════════════════════════════════════════
function renderBaseBet() {
  const bal = S.balance || 0;
  const suggested = Math.max(1000, Math.min(bal > 0 ? Math.floor(bal * 0.02 / 1000) * 1000 : 10000, 100000));
  app.innerHTML = `
    <div class="setup-screen">
      <div class="setup-card">
        <div class="setup-step">BƯỚC 1 / 2</div>
        <div class="setup-title">Vốn Cược Mỗi Tay</div>
        <div class="setup-sub">Nhập số tiền bạn muốn đặt cho mỗi phiên.<br>Số dư hiện tại: <b style="color:var(--gold-bright)">${fmt(bal)}đ</b></div>
        <div class="field">
          <label>💰 SỐ VỐN (VNĐ)</label>
          <input id="in_base" type="number" inputmode="numeric" placeholder="VD: 10000" value="${S.setupBaseBet || suggested}" min="1000" step="1000">
        </div>
        <button class="btn-main btn-sakura" id="btn_base_next">TIẾP TỤC →</button>
        ${S.error ? `<div class="msg err">⚠️ ${esc(S.error)}</div>` : ''}
        <div class="setup-hint">
          💎 Hệ thống dùng <b>gấp thếp X2</b> tự động khi thua.<br>
          Tối đa <b>4 tay sai</b> — sau đó tự reset về vốn gốc.
        </div>
      </div>
    </div>
  `;
  const inp = document.getElementById('in_base');
  inp.focus(); inp.select();
  document.getElementById('btn_base_next').onclick = () => {
    const v = parseInt(inp.value) || 0;
    if (v < 1000) { S.error = 'Vốn tối thiểu 1.000đ'; render(); return; }
    S.error = ''; S.setupBaseBet = v; S.step = 'target'; render();
  };
  inp.onkeydown = e => { if (e.key === 'Enter') document.getElementById('btn_base_next').click(); };
}

// ══════════════════════════════════════════════════
// TARGET SCREEN
// ══════════════════════════════════════════════════
function renderTarget() {
  const bal = S.balance || 0;
  const suggested = Math.max(10000, Math.floor(bal * 0.1 / 1000) * 1000 || 100000);
  app.innerHTML = `
    <div class="setup-screen">
      <div class="setup-card">
        <div class="setup-step">BƯỚC 2 / 2</div>
        <div class="setup-title">Mục Tiêu Lợi Nhuận</div>
        <div class="setup-sub">Nhập số tiền lãi bạn muốn đạt.<br>Khi đạt mục tiêu, bot tự động dừng.</div>
        <div class="field">
          <label>🎯 MỤC TIÊU (VNĐ)</label>
          <input id="in_target" type="number" inputmode="numeric" placeholder="VD: 500000" value="${S.setupTarget || suggested}" min="10000" step="10000">
        </div>
        <button class="btn-main btn-sakura" id="btn_target_start" ${S.loading ? 'disabled' : ''}>
          ${S.loading ? 'ĐANG KHỞI ĐỘNG' : '🚀 BẮT ĐẦU AUTO'}
        </button>
        ${S.error ? `<div class="msg err">⚠️ ${esc(S.error)}</div>` : ''}
        <div class="setup-hint">
          ⚙️ <b>Cấu hình tự động:</b><br>
          • Chế độ: <b>X2 khi thua</b> (Martingale)<br>
          • Tối đa: <b>4 tay sai</b><br>
          • Vốn mỗi tay: <b>${fmt(S.setupBaseBet)}đ</b>
        </div>
      </div>
    </div>
  `;
  const inp = document.getElementById('in_target');
  inp.focus(); inp.select();
  document.getElementById('btn_target_start').onclick = async () => {
    const v = parseInt(inp.value) || 0;
    if (v < 10000) { S.error = 'Mục tiêu tối thiểu 10.000đ'; render(); return; }
    S.error = ''; S.setupTarget = v;
    await startAuto();
  };
  inp.onkeydown = e => { if (e.key === 'Enter') document.getElementById('btn_target_start').click(); };
}

async function startAuto() {
  S.loading = true; render();
  try {
    const r = await api('setup', {
      user: S.user,
      base_bet: S.setupBaseBet,
      target_win: S.setupTarget,
      profit_stop: S.setupTarget,
    });
    if (!r.ok) { S.loading = false; S.error = r.msg || 'Không thể bắt đầu'; render(); return; }
    S.config = r.config;
    S.loading = false;
    S.step = 'main'; S.tab = 'main';
    render();
    startTick();
  } catch (e) {
    S.loading = false; S.error = 'Lỗi: ' + e.message; render();
  }
}

// ══════════════════════════════════════════════════
// MAIN SCREEN
// ══════════════════════════════════════════════════
function renderMain() {
  const p = S.pendingPred;
  const predCls = p === 'Tài' ? 'tai' : (p === 'Xỉu' ? 'xiu' : 'wait');
  const predTxt = p || 'ĐANG CHỜ';
  const lastH = S.history[0] || null;
  const showResult = lastH && (S.lastSettledSession !== lastH.session || true);

  app.innerHTML = `
    <div class="main-screen">
      <div class="main-header">
        <img src="${LOGO_URL}" alt="DENIUS" class="main-logo" onerror="this.style.display='none'">
        <div class="main-brand">
          <h1>DENIUS</h1>
          <small>お兄ちゃん · ${esc(S.nickname)}</small>
        </div>
        <div class="main-balance">
          <small>SỐ DƯ</small>
          <b id="bal_val">${fmt(S.balance)}</b>
        </div>
      </div>

      <div class="result-card">
        <div class="result-session">PHIÊN #${S.pendingSession || '—'}</div>
        <div class="result-label">${p ? 'DỰ ĐOÁN' : 'ĐANG PHÂN TÍCH'}</div>
        <div class="result-prediction ${predCls}" id="pred_val">${predTxt}</div>
        <div class="result-outcome ${lastH ? 'show' : ''}" id="outcome_box">
          ${lastH ? renderOutcome(lastH) : ''}
        </div>
      </div>

      <div class="bet-box">
        <div>
          <div class="bet-box-label">SỐ TIỀN CƯỢC</div>
          <div class="bet-box-value" id="bet_val">${S.pendingBetAmount ? fmt(S.pendingBetAmount) + 'đ' : '—'}</div>
        </div>
        <div class="bet-box-streak">
          <small>CHUỖI THUA</small>
          <b>${S.config.lose_streak || 0}/4</b>
        </div>
      </div>
    </div>
    <div class="bottom-nav">
      <button class="nav-btn on" id="nav_main">🎯 Chính</button>
      <button class="nav-btn" id="nav_history">📜 Lịch sử</button>
    </div>
  `;
  document.getElementById('nav_main').onclick = () => { S.tab = 'main'; render(); };
  document.getElementById('nav_history').onclick = () => { S.tab = 'history'; render(); };
}

function renderOutcome(h) {
  if (!h) return '';
  const win = h.win;
  const dice = (h.dices || []).join('-');
  const delta = win ? '+' + fmt(Math.floor(h.amount * 0.98)) : '-' + fmt(h.amount);
  return `
    <div class="big ${win ? 'win' : 'lose'}">${win ? '🎉 THẮNG' : '💔 THUA'}</div>
    <div class="detail">
      🎲 ${dice} · ${h.pred === 'Tài' ? 'TÀI' : 'XỈU'} → ${h.result === 'TAI' ? 'TÀI' : 'XỈU'}
      <br><b>${delta}đ</b>
      ${h.jackpot ? '<br>✨ JACKPOT ✨' : ''}
    </div>
  `;
}

// ══════════════════════════════════════════════════
// HISTORY SCREEN
// ══════════════════════════════════════════════════
function renderHistory() {
  const hist = S.history || [];
  app.innerHTML = `
    <div class="history-screen">
      <div class="history-header">
        <div class="history-title">📜 LỊCH SỬ CƯỢC</div>
        <div class="history-count">${hist.length} phiên</div>
      </div>
      <div class="hist-list" id="hist_list">
        ${hist.length === 0 ? `
          <div class="empty-state">
            <span class="icon">🌸</span>
            <div class="title">Chưa có lịch sử</div>
            <div class="sub">Bắt đầu AUTO để ghi nhận</div>
          </div>
        ` : hist.slice(0, 100).map(h => {
          const win = h.win;
          const cls = win ? 'win' : 'lose';
          const jackpot = h.jackpot ? 'jackpot' : '';
          const dice = (h.dices || []).join('-');
          const delta = win ? '+' + fmt(Math.floor(h.amount * 0.98)) : '-' + fmt(h.amount);
          return `
            <div class="hist-row ${cls} ${jackpot}">
              <div class="hist-sid">#${h.session}</div>
              <div class="hist-mid">
                <div class="row1">
                  ${h.pred === 'Tài' ? '🔵' : '🔴'} ${h.pred === 'Tài' ? 'TÀI' : 'XỈU'}
                  → ${h.result === 'TAI' ? '🔵 TÀI' : '🔴 XỈU'}
                  ${h.jackpot ? '🎉' : ''}
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
      <button class="nav-btn on" id="nav_history2">📜 Lịch sử</button>
    </div>
  `;
  document.getElementById('nav_main2').onclick = () => { S.tab = 'main'; render(); };
  document.getElementById('nav_history2').onclick = () => { S.tab = 'history'; render(); };
}

// ══════════════════════════════════════════════════
// API
// ══════════════════════════════════════════════════
async function api(action, data = {}) {
  if (S.authToken) data.auth_token = S.authToken;
  const fd = new FormData(); fd.append('action', action);
  for (const k in data) fd.append(k, data[k]);
  const r = await fetch(location.pathname + '?action=' + action, { method: 'POST', body: fd });
  return r.json();
}
async function getStatus() {
  const r = await fetch(location.pathname + '?action=status&user=' + encodeURIComponent(S.user) + '&auth_token=' + encodeURIComponent(S.authToken));
  return r.json();
}

// ══════════════════════════════════════════════════
// TICK (Anti-reset 100% via client polling)
// ══════════════════════════════════════════════════
let tickInFlight = false;
async function tick() {
  if (!S.user || !S.authToken || tickInFlight) return;
  tickInFlight = true;
  try {
    await api('tick', { user: S.user }).catch(() => {});
    const j = await getStatus();
    if (!j.ok) return;
    const oldBal = S.balance;
    S.balance = j.balance || 0;
    S.history = j.history || [];
    S.workerAlive = !!j.worker_alive;
    S.stats = j.stats || S.stats;
    S.pendingPred = j.pending_pred;
    S.pendingSession = j.pending_session;
    S.pendingConf = j.pending_conf;
    S.pendingBetAmount = j.pending_bet_amount;
    if (j.config) Object.assign(S.config, {
      auto: j.config.auto, paused: j.config.paused,
      lose_streak: j.config.lose_streak, base_bet: j.config.base_bet,
      profit_stop: j.config.profit_stop, target_win: j.config.target_win,
    });

    // Update only if step is main (avoid re-render on other steps)
    if (S.step === 'main') {
      if (S.tab === 'main') {
        // Update DOM in place to avoid flash
        const bv = document.getElementById('bal_val');
        if (bv) {
          bv.textContent = fmt(S.balance);
          if (S.balance !== oldBal) {
            bv.classList.add('updating');
            setTimeout(() => bv.classList.remove('updating'), 400);
          }
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
          if (bv2.textContent !== newTxt) {
            bv2.textContent = newTxt;
            bv2.classList.add('pulse');
            setTimeout(() => bv2.classList.remove('pulse'), 600);
          }
        }
        // Outcome box
        const ob = document.getElementById('outcome_box');
        if (ob && S.history[0]) {
          const lastH = S.history[0];
          ob.innerHTML = renderOutcome(lastH);
          ob.classList.add('show');
        }
      } else if (S.tab === 'history') {
        // Re-render history if changed
        const hl = document.getElementById('hist_list');
        if (hl && S.history.length) {
          const currKeys = S.history.map(h => h.session).join(',');
          if (hl.dataset.keys !== currKeys) {
            hl.dataset.keys = currKeys;
            hl.innerHTML = S.history.slice(0, 100).map(h => {
              const win = h.win;
              const cls = win ? 'win' : 'lose';
              const jackpot = h.jackpot ? 'jackpot' : '';
              const dice = (h.dices || []).join('-');
              const delta = win ? '+' + fmt(Math.floor(h.amount * 0.98)) : '-' + fmt(h.amount);
              return `<div class="hist-row ${cls} ${jackpot}">
                <div class="hist-sid">#${h.session}</div>
                <div class="hist-mid">
                  <div class="row1">${h.pred === 'Tài' ? '🔵' : '🔴'} ${h.pred === 'Tài' ? 'TÀI' : 'XỈU'} → ${h.result === 'TAI' ? '🔵 TÀI' : '🔴 XỈU'} ${h.jackpot ? '🎉' : ''}</div>
                  <div class="row2">🎲 ${dice} · ${h.ts}</div>
                </div>
                <div class="hist-amount ${cls}">${delta}</div>
              </div>`;
            }).join('');
          }
        }
      }
    }
  } catch (e) {} finally {
    tickInFlight = false;
  }
}

function startTick() {
  tick();
  setInterval(tick, 2500);
  // Extra keepalive — Render 15min anti-sleep
  setInterval(() => {
    if (S.user) fetch(location.pathname + '?action=keepalive&u=' + encodeURIComponent(S.user) + '&t=' + Date.now()).catch(() => {});
  }, 60000);
  // Immediate resume when tab visible again
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible' && S.user) tick();
  });
}

// ══════════════════════════════════════════════════
// BOOT
// ══════════════════════════════════════════════════
spawnSakura();
render();
</script>
</body>
</html>
<?php }
