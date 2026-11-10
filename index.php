<?php
/**
 * ============================================================
 *  👑 DENIUS AUTO WEB — BOSS EDITION v1.0
 *  Chuyển đổi từ Denius Auto Telegram Bot (v7.1)
 *  Boss: DENIUS | Admin: @DENIUS09
 *  ------------------------------------------------------------
 *  FIX CRITICAL: Prediction và Bet dùng CÙNG 1 nguồn ttoan
 *                → Không còn lệch hướng cược
 *  UI: Obsidian + Gold Platinum — KHÔNG trùng file 2
 * ============================================================
 */

// ═══════════ [0] CONFIG ═══════════
$CFG = [
    'version' => '1.0.0-boss',
    'game' => [
        'login_url'    => 'https://apifo88daigia.tele68.com/api?c=3&un={USER}&pw={PASS_MD5}&cp=R&cl=R&pf=web&at=',
        'lobby_url'    => 'https://wlb.tele68.com/v1/lobby/auth/login?cp=R&cl=R&pf=web&at=',
        'ws_host'      => 'wtx.tele68.com',
        'ws_path'      => '/tx/',
        'ws_ns'        => '/tx',
        'sessions_api' => 'https://wtx.tele68.com/v1/tx/sessions',
    ],
    'security' => [
        'hmac_secret' => 'DENIUS_BOSS_SECRET_' . __FILE__,
        'session_ttl' => 86400,
    ],
    'worker' => [
        'loop_sleep'     => 1,
        'resume_timeout' => 1800,
        'max_runtime'    => 3000,
        'self_respawn'   => true,
        'respawn_buffer' => 15,
    ],
    'default_config' => [
        'base_bet'        => 10000,
        'profit_stop'     => 0,
        'win_target'      => 50,
        'mode'            => 'fixed',      // fixed | double
        'max_lose_streak' => 3,
        'auto'            => false,
        'paused'          => false,
        'lose_streak'     => 0,
    ],
    'max_history' => 500,
];

const DATA_DIR = __DIR__ . '/.data';
const KEY_DIR  = DATA_DIR . '/by_key';

// ═══════════ [1] BOOTSTRAP ═══════════
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

// ═══════════ [2] AUTH ═══════════
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

// ═══════════ [3] STORAGE ═══════════
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
function key_resolve(string $userOrKey): string {
    $idx = DATA_DIR . '/user_index.json';
    if (is_file($idx)) {
        $m = json_decode(file_get_contents($idx), true) ?: [];
        if (isset($m[strtolower($userOrKey)])) return $m[strtolower($userOrKey)];
    }
    return $userOrKey;
}

// ═══════════ [4] GAME LOGIN + SESSIONS ═══════════
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
        'http' => ['timeout'=>5,'ignore_errors'=>true,'header'=>"User-Agent: Mozilla/5.0\r\nAccept: application/json\r\n"],
        'ssl'  => ['verify_peer'=>false,'verify_peer_name'=>false],
    ]);
    $raw = @file_get_contents($CFG['game']['sessions_api'], false, $ctx);
    if (!$raw) return null;
    $j = json_decode($raw, true);
    return is_array($j) && isset($j['list']) ? $j : null;
}

// ═══════════ [5] TTOAN ALGORITHM — SINGLE SOURCE OF TRUTH ═══════════
// Port từ file 2 — đây là BỘ NÃO DUY NHẤT cho cả predict lẫn bet.

const TTOAN_TONG_DIEM_MEO = [
    3=>['kq'=>'Xỉu','xs'=>0.70], 4=>['kq'=>'Tài','xs'=>0.60], 5=>['kq'=>'Tài','xs'=>0.70],
    6=>['kq'=>'Xỉu','xs'=>0.60], 7=>['kq'=>'Tài','xs'=>0.80], 8=>['kq'=>'Xỉu','xs'=>0.80],
    9=>['kq'=>'Xỉu','xs'=>0.70], 10=>['kq'=>'Tài','xs'=>0.80], 11=>['kq'=>'Xỉu','xs'=>0.60],
    12=>['kq'=>'Tài','xs'=>0.80], 13=>['kq'=>'Tài','xs'=>0.80], 14=>['kq'=>'Xỉu','xs'=>0.60],
    15=>['kq'=>'Xỉu','xs'=>0.70], 16=>['kq'=>'Tài','xs'=>0.60], 17=>['kq'=>'Xỉu','xs'=>0.60],
    18=>['kq'=>'Xỉu','xs'=>0.80],
];
const TTOAN_CAU_PATTERNS = [
    '1-1'=>['desc'=>'Cầu 1-1','w'=>0.85],'1-2'=>['desc'=>'Cầu 1-2','w'=>0.80],
    '2-1'=>['desc'=>'Cầu 2-1','w'=>0.80],'2-2'=>['desc'=>'Cầu 2-2','w'=>0.85],
    '2-3'=>['desc'=>'Cầu 2-3','w'=>0.75],'3-2'=>['desc'=>'Cầu 3-2','w'=>0.75],
    '3-3'=>['desc'=>'Cầu 3-3','w'=>0.70],'3-4'=>['desc'=>'Cầu 3-4','w'=>0.65],
    '4-3'=>['desc'=>'Cầu 4-3','w'=>0.65],'4-4'=>['desc'=>'Cầu 4-4','w'=>0.60],
    '1-3'=>['desc'=>'Cầu 1-3','w'=>0.70],'3-1'=>['desc'=>'Cầu 3-1','w'=>0.70],
    '1-4'=>['desc'=>'Cầu 1-4','w'=>0.65],'4-1'=>['desc'=>'Cầu 4-1','w'=>0.65],
    'bệt'=>['desc'=>'Cầu bệt','w'=>0.50],'đảo'=>['desc'=>'Cầu đảo','w'=>0.75],
    'cầu nghiêng'=>['desc'=>'Cầu nghiêng','w'=>0.70],'cầu lặp'=>['desc'=>'Cầu lặp','w'=>0.85],
    'cầu đan'=>['desc'=>'Cầu đan','w'=>0.75],
];

function _ttoan_rand(): float { return (float)mt_rand() / (float)(mt_getrandmax()+1); }

function ttoan_detect_streak_and_break(array $history): array {
    $h = array_values($history);
    if (count($h)===0) return ['streak'=>0,'currentResult'=>null,'breakProb'=>0.0];
    $streak = 1;
    $cur = $h[count($h)-1]['ket_qua'];
    for ($i=count($h)-2; $i>=0; $i--) { if ($h[$i]['ket_qua']===$cur) $streak++; else break; }
    $last15 = array_map(fn($it)=>$it['ket_qua'], array_slice($h, -15));
    if (count($last15)===0) return ['streak'=>$streak,'currentResult'=>$cur,'breakProb'=>0.0];
    $sw = 0;
    for ($i=1;$i<count($last15);$i++) if ($last15[$i]!==$last15[$i-1]) $sw++;
    $tc = count(array_filter($last15, fn($r)=>$r==='Tài'));
    $xc = count($last15) - $tc;
    $imb = abs($tc-$xc) / count($last15);
    $bp = 0.0;
    if ($streak>=8)      $bp = min(0.6 + $sw/15 + $imb*0.15, 0.9);
    elseif ($streak>=5)  $bp = min(0.35 + $sw/10 + $imb*0.25, 0.85);
    elseif ($streak>=3 && $sw>=7) $bp = 0.3;
    return ['streak'=>$streak,'currentResult'=>$cur,'breakProb'=>$bp];
}
function ttoan_evaluate_model_performance(array $history, string $name, array $mp, int $lb=10): float {
    $h = array_values($history);
    if (!isset($mp[$name]) || count($h)<2) return 1.0;
    $lb = min($lb, count($h)-1);
    $correct = 0;
    for ($i=0;$i<$lb;$i++) {
        $sid = $h[count($h)-($i+2)]['phien'];
        $pred = $mp[$name][$sid] ?? 0;
        $actual = $h[count($h)-($i+1)]['ket_qua'];
        if (($pred===1 && $actual==='Tài') || ($pred===2 && $actual==='Xỉu')) $correct++;
    }
    $ratio = $lb > 0 ? 1 + ($correct - $lb/2) / ($lb/2) : 1.0;
    return max(0.5, min(1.5, $ratio));
}
function ttoan_smart_bridge_break(array $history): array {
    $h = array_values($history);
    if (count($h)<3) return ['prediction'=>0,'breakProb'=>0.0,'reason'=>'Không đủ dữ liệu'];
    $sb = ttoan_detect_streak_and_break($h);
    $streak = $sb['streak']; $cur = $sb['currentResult']; $bp = $sb['breakProb'];
    $l20r = array_map(fn($it)=>$it['ket_qua'], array_slice($h,-20));
    $l20s = array_map(fn($it)=>$it['tong']??0, array_slice($h,-20));
    $fBP = $bp; $reason = '';
    $avg = array_sum($l20s) / (count($l20s) ?: 1);
    $dev = 0.0; foreach ($l20s as $s) $dev += abs($s-$avg);
    $sd = $dev / (count($l20s) ?: 1);
    $l5 = array_slice($l20r, -5);
    $pc = [];
    for ($i=0;$i<=count($l20r)-3;$i++) {
        $p = implode(',', array_slice($l20r,$i,3));
        $pc[$p] = ($pc[$p]??0) + 1;
    }
    $mcp = null;
    if (count($pc)>0) { arsort($pc); $mcp = [key($pc), current($pc)]; }
    $hasRep = ($mcp!==null && $mcp[1]>=3);
    $l5All = count($l5)>0;
    foreach ($l5 as $r) if ($r!==$cur) { $l5All=false; break; }
    if ($streak>=6) { $fBP = min($fBP+0.15,0.9); $reason="[Bẻ Cầu] Chuỗi $streak $cur dài"; }
    elseif ($streak>=4 && $sd>3) { $fBP = min($fBP+0.10,0.85); $reason=sprintf("[Bẻ Cầu] Biến động %.1f", $sd); }
    elseif ($hasRep && $l5All) { $fBP = min($fBP+0.05,0.8); $reason="[Bẻ Cầu] Mẫu lặp {$mcp[0]}"; }
    else { $fBP = max($fBP-0.15,0.15); $reason='[Bẻ Cầu] Không có mẫu mạnh'; }
    $pred = ($fBP>0.65) ? ($cur==='Tài'?2:1) : ($cur==='Tài'?1:2);
    return ['prediction'=>$pred,'breakProb'=>$fBP,'reason'=>$reason];
}
function ttoan_trend_and_prob(array $history): int {
    $h = array_values($history);
    if (count($h)<3) return 0;
    $sb = ttoan_detect_streak_and_break($h);
    if ($sb['streak']>=5) {
        if ($sb['breakProb']>0.75) return $sb['currentResult']==='Tài'?2:1;
        return $sb['currentResult']==='Tài'?1:2;
    }
    $l15 = array_map(fn($it)=>$it['ket_qua'], array_slice($h,-15));
    if (count($l15)===0) return 0;
    $tw=0.0; $xw=0.0;
    foreach ($l15 as $i=>$r) { $w=pow(1.2,$i); if ($r==='Tài') $tw+=$w; else $xw+=$w; }
    $tot = $tw+$xw;
    $l10 = array_slice($l15,-10);
    $pats = [];
    if (count($l10)>=4) for ($i=0;$i<=count($l10)-4;$i++) $pats[] = implode(',', array_slice($l10,$i,4));
    $pc = []; foreach ($pats as $p) $pc[$p]=($pc[$p]??0)+1;
    $mc = null; if (count($pc)>0) { arsort($pc); $mc=[key($pc),current($pc)]; }
    if ($mc!==null && $mc[1]>=3) {
        $parts = explode(',',$mc[0]);
        return ($parts[count($parts)-1]!==$l10[count($l10)-1]) ? 1 : 2;
    }
    if ($tot>0 && abs($tw-$xw)/$tot >= 0.25) return $tw>$xw?2:1;
    return $l15[count($l15)-1]==='Xỉu'?1:2;
}
function ttoan_short_pattern(array $history): int {
    $h = array_values($history);
    if (count($h)<3) return 0;
    $sb = ttoan_detect_streak_and_break($h);
    if ($sb['streak']>=4) {
        if ($sb['breakProb']>0.75) return $sb['currentResult']==='Tài'?2:1;
        return $sb['currentResult']==='Tài'?1:2;
    }
    $l8 = array_map(fn($it)=>$it['ket_qua'], array_slice($h,-8));
    if (count($l8)===0) return 0;
    $pats=[];
    if (count($l8)>=3) for ($i=0;$i<=count($l8)-3;$i++) $pats[]=implode(',',array_slice($l8,$i,3));
    $pc=[]; foreach ($pats as $p) $pc[$p]=($pc[$p]??0)+1;
    $mc=null; if (count($pc)>0) { arsort($pc); $mc=[key($pc),current($pc)]; }
    if ($mc!==null && $mc[1]>=2) {
        $parts=explode(',',$mc[0]);
        return ($parts[count($parts)-1]!==$l8[count($l8)-1]) ? 1 : 2;
    }
    return $l8[count($l8)-1]==='Xỉu'?1:2;
}
function ttoan_mean_deviation(array $history): int {
    $h = array_values($history);
    if (count($h)<3) return 0;
    $sb = ttoan_detect_streak_and_break($h);
    if ($sb['streak']>=4) {
        if ($sb['breakProb']>0.75) return $sb['currentResult']==='Tài'?2:1;
        return $sb['currentResult']==='Tài'?1:2;
    }
    $l12 = array_map(fn($it)=>$it['ket_qua'], array_slice($h,-12));
    if (count($l12)===0) return 0;
    $tc = count(array_filter($l12, fn($r)=>$r==='Tài'));
    $xc = count($l12)-$tc;
    $imb = abs($tc-$xc)/count($l12);
    if ($imb<0.35) return $l12[count($l12)-1]==='Xỉu'?1:2;
    return $xc>$tc?1:2;
}
function ttoan_recent_switch(array $history): int {
    $h = array_values($history);
    if (count($h)<3) return 0;
    $sb = ttoan_detect_streak_and_break($h);
    if ($sb['streak']>=4) {
        if ($sb['breakProb']>0.75) return $sb['currentResult']==='Tài'?2:1;
        return $sb['currentResult']==='Tài'?1:2;
    }
    $l10 = array_map(fn($it)=>$it['ket_qua'], array_slice($h,-10));
    if (count($l10)===0) return 0;
    $sw=0;
    for ($i=1;$i<count($l10);$i++) if ($l10[$i]!==$l10[$i-1]) $sw++;
    $last = $l10[count($l10)-1];
    return $last==='Xỉu'?1:2;
}
function ttoan_is_bad_pattern(array $history): bool {
    $h = array_values($history);
    if (count($h)<3) return false;
    $l15 = array_map(fn($it)=>$it['ket_qua'], array_slice($h,-15));
    if (count($l15)===0) return false;
    $sw=0; for ($i=1;$i<count($l15);$i++) if ($l15[$i]!==$l15[$i-1]) $sw++;
    $sb = ttoan_detect_streak_and_break($h);
    return ($sw>=9 || $sb['streak']>=10);
}
function ttoan_ai_htdd_logic(array $history): array {
    $h = array_values($history);
    if (count($h)<3) {
        $p = _ttoan_rand()<0.5?'Tài':'Xỉu';
        return ['prediction'=>$p,'reason'=>'Không đủ lịch sử, dự đoán ngẫu nhiên','source'=>'AI HTDD'];
    }
    $l5 = array_map(fn($it)=>$it['ket_qua'], array_slice($h,-5));
    $l5s = array_map(fn($it)=>$it['tong']??0, array_slice($h,-5));
    $tc = count(array_filter($l5, fn($r)=>$r==='Tài'));
    $xc = count($l5)-$tc;
    $l3 = array_map(fn($it)=>$it['ket_qua'], array_slice($h,-3));
    if (implode(',',$l3)==='Tài,Xỉu,Tài') return ['prediction'=>'Xỉu','reason'=>'Mẫu 1T1X','source'=>'AI HTDD'];
    if (implode(',',$l3)==='Xỉu,Tài,Xỉu') return ['prediction'=>'Tài','reason'=>'Mẫu 1X1T','source'=>'AI HTDD'];
    if (count($h)>=4) {
        $l4 = array_map(fn($it)=>$it['ket_qua'], array_slice($h,-4));
        if (implode(',',$l4)==='Tài,Tài,Xỉu,Xỉu') return ['prediction'=>'Tài','reason'=>'Mẫu 2T2X','source'=>'AI HTDD'];
        if (implode(',',$l4)==='Xỉu,Xỉu,Tài,Tài') return ['prediction'=>'Xỉu','reason'=>'Mẫu 2X2T','source'=>'AI HTDD'];
    }
    if (count($h)>=9) {
        $l6 = array_slice($h,-6);
        $allT=true; $allX=true;
        foreach ($l6 as $it) { if ($it['ket_qua']!=='Tài') $allT=false; if ($it['ket_qua']!=='Xỉu') $allX=false; }
        if ($allT) return ['prediction'=>'Xỉu','reason'=>'Chuỗi Tài 6 phiên','source'=>'AI HTDD'];
        if ($allX) return ['prediction'=>'Tài','reason'=>'Chuỗi Xỉu 6 phiên','source'=>'AI HTDD'];
    }
    $avg = array_sum($l5s)/(count($l5s)?:1);
    if ($avg>10) return ['prediction'=>'Tài','reason'=>sprintf('Điểm TB cao (%.1f)',$avg),'source'=>'AI HTDD'];
    if ($avg<8)  return ['prediction'=>'Xỉu','reason'=>sprintf('Điểm TB thấp (%.1f)',$avg),'source'=>'AI HTDD'];
    if ($tc>$xc+1) return ['prediction'=>'Xỉu','reason'=>"Tài đa số $tc/".count($l5),'source'=>'AI HTDD'];
    if ($xc>$tc+1) return ['prediction'=>'Tài','reason'=>"Xỉu đa số $xc/".count($l5),'source'=>'AI HTDD'];
    $totT = count(array_filter($h, fn($it)=>$it['ket_qua']==='Tài'));
    $totX = count($h)-$totT;
    if ($totT>$totX+2) return ['prediction'=>'Xỉu','reason'=>'Tổng Tài nhiều','source'=>'AI HTDD'];
    if ($totX>$totT+2) return ['prediction'=>'Tài','reason'=>'Tổng Xỉu nhiều','source'=>'AI HTDD'];
    return ['prediction'=>_ttoan_rand()<0.5?'Tài':'Xỉu','reason'=>'Cân bằng','source'=>'AI HTDD'];
}
function ttoan_phan_tich_cau(array $history): array {
    $h = array_values($history);
    if (count($h)<3) return ['cau'=>'Khong xac dinh','weight'=>0.0,'streaks'=>[]];
    $rs = array_map(fn($it)=>$it['ket_qua'], array_slice($h,-30));
    $streaks=[]; $cs=1; $ct=$rs[0];
    for ($i=1;$i<count($rs);$i++) {
        if ($rs[$i]===$ct) $cs++;
        else { $streaks[]=['type'=>$ct,'count'=>$cs]; $ct=$rs[$i]; $cs=1; }
    }
    $streaks[] = ['type'=>$ct,'count'=>$cs];
    $cau='Khong xac dinh'; $w=0.5;
    $mx=0; foreach ($streaks as $s) if ($s['count']>$mx) $mx=$s['count'];
    if ($mx>=6) { $cau='bệt'; $w=0.5; }
    $cnt11=0; for ($i=0;$i<count($streaks)-1;$i++) if ($streaks[$i]['count']===1 && $streaks[$i+1]['count']===1) $cnt11++;
    if ($cnt11>=3) { $cau='1-1'; $w=0.85; }
    $cnt22=0; for ($i=0;$i<count($streaks)-1;$i++) if ($streaks[$i]['count']===2 && $streaks[$i+1]['count']===2) $cnt22++;
    if ($cnt22>=2) { $cau='2-2'; $w=0.85; }
    $cnt12=0; for ($i=0;$i<count($streaks)-1;$i++) if ($streaks[$i]['count']===1 && $streaks[$i+1]['count']===2) $cnt12++;
    if ($cnt12>=2) { $cau='1-2'; $w=0.80; }
    $cnt21=0; for ($i=0;$i<count($streaks)-1;$i++) if ($streaks[$i]['count']===2 && $streaks[$i+1]['count']===1) $cnt21++;
    if ($cnt21>=2) { $cau='2-1'; $w=0.80; }
    $cnt32=0; for ($i=0;$i<count($streaks)-1;$i++) if ($streaks[$i]['count']===3 && $streaks[$i+1]['count']===2) $cnt32++;
    if ($cnt32>=2) { $cau='3-2'; $w=0.75; }
    $cnt23=0; for ($i=0;$i<count($streaks)-1;$i++) if ($streaks[$i]['count']===2 && $streaks[$i+1]['count']===3) $cnt23++;
    if ($cnt23>=2) { $cau='2-3'; $w=0.75; }
    $cnt33=0; for ($i=0;$i<count($streaks)-1;$i++) if ($streaks[$i]['count']===3 && $streaks[$i+1]['count']===3) $cnt33++;
    if ($cnt33>=2) { $cau='3-3'; $w=0.70; }
    $cntDao=0; for ($i=0;$i<count($streaks)-2;$i++) if ($streaks[$i]['count']===$streaks[$i+2]['count'] && $streaks[$i]['type']!==$streaks[$i+2]['type']) $cntDao++;
    if ($cntDao>=2) { $cau='đảo'; $w=0.75; }
    $l10 = array_slice($rs,-10);
    $t10 = count(array_filter($l10, fn($r)=>$r==='Tài'));
    $x10 = count($l10)-$t10;
    if (abs($t10-$x10)>=6) { $cau='cầu nghiêng'; $w=0.70; }
    $p3=[]; for ($i=0;$i<=count($rs)-3;$i++) $p3[]=implode(',',array_slice($rs,$i,3));
    $pc3=[]; foreach ($p3 as $p) $pc3[$p]=($pc3[$p]??0)+1;
    $mp3=null; if (count($pc3)>0) { arsort($pc3); $mp3=[key($pc3),current($pc3)]; }
    if ($mp3!==null && $mp3[1]>=4) { $cau='cầu lặp'; $w=0.85; }
    $cntDan=0;
    for ($i=0;$i<count($rs)-4;$i++) {
        $sl = array_slice($rs,$i,5);
        if ($sl[0]!==$sl[1] && $sl[1]===$sl[3] && $sl[0]===$sl[2] && $sl[2]!==$sl[4]) $cntDan++;
    }
    if ($cntDan>=2) { $cau='cầu đan'; $w=0.75; }
    return ['cau'=>$cau,'weight'=>$w,'streaks'=>$streaks];
}

/**
 * ══════════════════════════════════════════════════════════════
 *  🎯 ttoan_generate_prediction — NGUỒN DUY NHẤT
 *  Trả: ['prediction'=>'Tài'|'Xỉu', 'doTinCay'=>int, 'giaiThich'=>str]
 * ══════════════════════════════════════════════════════════════
 */
function ttoan_generate_prediction(array $history, ?array &$modelPredictions = null): array {
    $h = array_values($history);
    $hasExt = ($modelPredictions !== null);
    if ($hasExt) $mp = $modelPredictions;
    else { static $st = []; $mp = $st; }
    if (!is_array($mp)) $mp = [];
    if (!isset($mp['trend'])) {
        $mp = ['trend'=>[],'short'=>[],'mean'=>[],'switch'=>[],'bridge'=>[]];
    }
    if (count($h)===0) {
        if ($hasExt) $modelPredictions = $mp; else { /* static */ }
        $p = _ttoan_rand()<0.5?'Tài':'Xỉu';
        return ['prediction'=>$p,'doTinCay'=>50,'giaiThich'=>'Không đủ lịch sử'];
    }
    $sid = $h[count($h)-1]['phien'];
    $tong = $h[count($h)-1]['tong'];
    $last = $h[count($h)-1]['ket_qua'];
    $fb = ($last==='Tài') ? 2 : 1;

    $trendP  = count($h)<5 ? $fb : ttoan_trend_and_prob($h);
    $shortP  = count($h)<5 ? $fb : ttoan_short_pattern($h);
    $meanP   = count($h)<5 ? $fb : ttoan_mean_deviation($h);
    $switchP = count($h)<5 ? $fb : ttoan_recent_switch($h);
    $bridgeP = count($h)<5 ? ['prediction'=>$fb,'breakProb'=>0.0,'reason'=>'Lịch sử ngắn'] : ttoan_smart_bridge_break($h);
    $aiP = ttoan_ai_htdd_logic($h);
    $cau = ttoan_phan_tich_cau($h);
    $meo = TTOAN_TONG_DIEM_MEO[$tong] ?? ['kq'=>'Không xác định','xs'=>0.5];

    $mp['trend'][$sid]  = $trendP;
    $mp['short'][$sid]  = $shortP;
    $mp['mean'][$sid]   = $meanP;
    $mp['switch'][$sid] = $switchP;
    $mp['bridge'][$sid] = $bridgeP['prediction'];

    $perf = [
        'trend'  => ttoan_evaluate_model_performance($h,'trend',$mp),
        'short'  => ttoan_evaluate_model_performance($h,'short',$mp),
        'mean'   => ttoan_evaluate_model_performance($h,'mean',$mp),
        'switch' => ttoan_evaluate_model_performance($h,'switch',$mp),
        'bridge' => ttoan_evaluate_model_performance($h,'bridge',$mp),
    ];
    $w = [
        'trend'=>0.15*$perf['trend'],'short'=>0.15*$perf['short'],'mean'=>0.15*$perf['mean'],
        'switch'=>0.15*$perf['switch'],'bridge'=>0.15*$perf['bridge'],
        'aihtdd'=>0.15,'cau'=>0.10,'tongDiem'=>0.10,
    ];
    $ts=0.0; $xs=0.0;
    if ($trendP===1)  $ts+=$w['trend'];  elseif ($trendP===2)  $xs+=$w['trend'];
    if ($shortP===1)  $ts+=$w['short'];  elseif ($shortP===2)  $xs+=$w['short'];
    if ($meanP===1)   $ts+=$w['mean'];   elseif ($meanP===2)   $xs+=$w['mean'];
    if ($switchP===1) $ts+=$w['switch']; elseif ($switchP===2) $xs+=$w['switch'];
    if ($bridgeP['prediction']===1) $ts+=$w['bridge']; elseif ($bridgeP['prediction']===2) $xs+=$w['bridge'];
    if ($aiP['prediction']==='Tài') $ts+=$w['aihtdd']; else $xs+=$w['aihtdd'];

    $cauInfo = TTOAN_CAU_PATTERNS[$cau['cau']] ?? ['desc'=>'Không xác định','w'=>0.5];
    $cauPred = null;
    if ($cau['cau']==='1-1')       $cauPred = ($last==='Tài')?'Xỉu':'Tài';
    elseif ($cau['cau']==='2-2')   $cauPred = ($last==='Xỉu')?'Tài':'Xỉu';
    elseif ($cau['cau']==='1-2')   $cauPred = 'Tài';
    elseif ($cau['cau']==='2-1')   $cauPred = 'Xỉu';
    elseif ($cau['cau']==='bệt')   $cauPred = $last;
    elseif ($cau['cau']==='đảo')   $cauPred = ($last==='Tài')?'Xỉu':'Tài';
    elseif ($cau['cau']==='cầu nghiêng') {
        $l10c = array_map(fn($it)=>$it['ket_qua'], array_slice($h,-10));
        $t10c = count(array_filter($l10c, fn($r)=>$r==='Tài'));
        $cauPred = ($t10c>5)?'Xỉu':'Tài';
    } else $cauPred = $last;

    if ($cauPred==='Tài') $ts += $w['cau'] * $cau['weight'];
    else                  $xs += $w['cau'] * $cau['weight'];

    if ($meo['kq']==='Tài') $ts += $w['tongDiem'] * $meo['xs'];
    elseif ($meo['kq']==='Xỉu') $xs += $w['tongDiem'] * $meo['xs'];

    if (ttoan_is_bad_pattern($h)) { $ts*=0.8; $xs*=0.8; }
    $l10 = array_map(fn($it)=>$it['ket_qua'], array_slice($h,-10));
    $l10t = count(array_filter($l10, fn($r)=>$r==='Tài'));
    if ($l10t>=7) $xs += 0.15;
    elseif ($l10t<=3) $ts += 0.15;
    if ($bridgeP['breakProb']>0.65) {
        if ($bridgeP['prediction']===1) $ts += 0.2; else $xs += 0.2;
    }
    $totS = $ts+$xs;
    $tp = $totS>0 ? ($ts/$totS)*100 : 50.0;
    $xp = $totS>0 ? ($xs/$totS)*100 : 50.0;
    $final = ($ts>$xs) ? 'Tài' : 'Xỉu';
    $conf = (int)round(max($tp,$xp));
    $ex = sprintf('[Cầu: %s] | [Tổng %s: %s %d%%] | %s | %s | Tài: %.1f%% - Xỉu: %.1f%%',
        $cauInfo['desc'], $tong, $meo['kq'], (int)round($meo['xs']*100),
        $aiP['reason'], $bridgeP['reason'], $tp, $xp);

    if ($hasExt) $modelPredictions = $mp;
    else { /* static update skipped */ }
    return ['prediction'=>$final,'doTinCay'=>$conf,'giaiThich'=>$ex];
}

// ═══════════ [6] TINY WEBSOCKET CLIENT ═══════════
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

// ═══════════ [7] WS BET — DÙNG pending_pred (FIX CRITICAL) ═══════════
function do_ws_bet(string $key, array $s, array &$actions): bool {
    global $CFG;
    if (empty($s['token'])) return false;
    // 🎯 LẤY PREDICTION TỪ STATE — CHÍNH LÀ CÁI ĐÃ HIỂN THỊ CHO ÔNG CHỦ
    $pred = $s['pending_pred'] ?? null;
    if (!$pred) { key_log($key,'warn','⚠️ Không có pending_pred để đặt'); return false; }
    // Map Tài/Xỉu → TAI/XIU
    $side = ($pred === 'Tài' || $pred === 'T' || $pred === 'TAI') ? 'TAI' : 'XIU';
    $pendingSession = (int)$s['pending_session'];
    $amount = (int)($s['pending_bet_amount'] ?? $s['config']['base_bet'] ?? 10000);
    if ($amount < 1000) $amount = 1000;

    $wsPath = rtrim($CFG['game']['ws_path'],'/') . '/?EIO=4&transport=websocket';
    $ws = new TinyWS($CFG['game']['ws_host'], 443, $wsPath, ['Authorization: Bearer '.$s['token']]);
    if (!$ws->connect()) {
        key_log($key,'error','❌ WS fail: '.$ws->error);
        return false;
    }
    $auth = json_encode(['token'=>$s['token']], JSON_UNESCAPED_UNICODE);
    $opened = false; $joined = false; $betDone = false; $betAck = false;
    $deadline = microtime(true) + 20;

    while (microtime(true) < $deadline) {
        $frames = $ws->readOneFrame(1);
        if ($frames===null) { key_log($key,'warn','⚠️ WS đóng'); break; }
        if ($frames===[]) continue;
        foreach ($frames as $pkt) {
            if ($pkt==='' || $pkt===null) continue;
            if (str_starts_with($pkt,'0{')) {
                $opened = true;
                $ws->sendRaw('40/tx,'.$auth);
                continue;
            }
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
                    $logMsg = "💰 ĐẶT #$pendingSession [$side] × ".number_format($amount)." — KHỚP DỰ ĐOÁN ($pred)";
                    key_log($key,'success',$logMsg);
                    $actions[] = ['type'=>'bet','msg'=>$logMsg];
                    key_update($key, function($dd) use ($pendingSession,$amount) {
                        $dd['bet_session'] = $pendingSession;
                        $dd['bet_amount'] = $amount;
                        return $dd;
                    });
                    // Wait for ack
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
                                    key_update($key, function($dd) use ($m2) {
                                        $dd['balance'] = $m2[1]['postBalance'];
                                        return $dd;
                                    });
                                }
                            }
                        }
                    }
                    $ws->close();
                    if (!$betAck) {
                        key_log($key,'warn','⚠️ Đã gửi lệnh nhưng chưa có bet-result');
                    }
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

// ═══════════ [8] WORKER CORE ═══════════
function worker_step(string $key): array {
    $actions = [];
    $s = key_load($key);
    if (!$s) return $actions;
    $cfg = $s['config'] ?? [];

    // Check profit stop
    $pStop = max(0, (int)($cfg['profit_stop'] ?? 0));
    $pNow = (int)($s['profit_total'] ?? 0);
    if ($pStop>0 && $pNow >= $pStop && empty($s['pending_pred'])) {
        key_update($key, fn($d) => array_merge($d, ['config'=>array_merge($d['config'],['auto'=>false,'paused'=>true])]));
        key_log($key,'success','🏆 ĐẠT CHỐT LỜI '.number_format($pNow).'/'.number_format($pStop));
        return $actions;
    }
    // Check win target
    $wTarget = max(1, (int)($cfg['win_target'] ?? 50));
    if ((int)($s['win_count_total'] ?? 0) >= $wTarget && empty($s['pending_pred'])) {
        key_update($key, fn($d) => array_merge($d, ['config'=>array_merge($d['config'],['auto'=>false,'paused'=>true])]));
        key_log($key,'success','🏁 ĐỦ MỤC TIÊU '.($s['win_count_total']).'/'.$wTarget);
        return $actions;
    }
    if (empty($cfg['auto']) || !empty($cfg['paused'])) return $actions;

    // Fetch sessions
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

    // Process results
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

            if (($s['pending_session'] ?? null) == $sid && !empty($s['pending_pred'])) {
                $pred = $s['pending_pred'];
                $win = (($pred==='Tài'||$pred==='T') && $result==='TAI') || (($pred==='Xỉu'||$pred==='X') && $result==='XIU');

                // Jackpot detect
                $isJackpot = (count(array_unique($dices))===1 && $dices[0]!=0);

                key_update($key, function($d) use ($sid,$pred,$result,$dices,$win,$isJackpot,$tong) {
                    $c = $d['config'];
                    $st = (int)($c['lose_streak'] ?? 0);
                    $mx = (int)($c['max_lose_streak'] ?? 3);
                    if ($win) {
                        $st = 0;
                        $c['paused'] = false;
                        $d['win_count_total'] = (int)($d['win_count_total'] ?? 0) + 1;
                    } else {
                        $d['loss_count_total'] = (int)($d['loss_count_total'] ?? 0) + 1;
                        $st++;
                        if (($c['mode'] ?? 'fixed')==='double' && $st>=$mx) $st=0;
                    }
                    $c['lose_streak'] = $st;

                    $betAmt = (int)($d['bet_amount'] ?? $c['base_bet'] ?? 10000);
                    $bal = (int)($d['balance'] ?? 0);
                    if ($win) $bal += intval($betAmt*0.98);
                    else $bal -= $betAmt;
                    $d['balance'] = $bal;
                    $profitDelta = $win ? intval($betAmt*0.98) : -$betAmt;
                    $d['profit_total'] = (int)($d['profit_total'] ?? 0) + $profitDelta;

                    $d['history'] = $d['history'] ?? [];
                    array_unshift($d['history'], [
                        'ts' => date('H:i:s d/m'),
                        'session' => $sid,
                        'pred' => $pred,
                        'result' => $result,
                        'dices' => $dices,
                        'tong' => $tong,
                        'win' => $win,
                        'amount' => $betAmt,
                        'balance_after' => $bal,
                        'streak' => $st,
                        'jackpot' => $isJackpot,
                    ]);
                    $d['history'] = array_slice($d['history'], 0, $GLOBALS['CFG']['max_history'] ?? 500);
                    $d['pending_pred'] = null;
                    $d['pending_session'] = null;
                    $d['pending_bet_amount'] = null;
                    $d['bet_session'] = null;
                    $d['bet_amount'] = 0;

                    // Pattern 10
                    $sym = ($result==='TAI')?'T':'X';
                    $p10 = ($d['pattern_10'] ?? '') . $sym;
                    if (strlen($p10)>10) $p10 = substr($p10,-10);
                    $d['pattern_10'] = $p10;
                    $d['config'] = $c;
                    return $d;
                });

                $icon = $win ? '✅' : '❌';
                $diceStr = implode('-', $dices);
                $logMsg = "$icon Phiên #$sid: Dự đoán ".($pred)." — Kết quả $result ($diceStr)".($isJackpot?' 🎉 JACKPOT!':'');
                key_log($key, $win?'success':'error', $logMsg);
                $actions[] = ['type'=>'result','msg'=>$logMsg];
                $s = key_load($key);
            }
        }
        key_update($key, fn($d) => array_merge($d, ['last_session_id'=>$latestId]));
    }

    // Clean stale pending
    if (!empty($s['pending_session']) && (int)$s['pending_session'] <= $latestId) {
        key_update($key, function($d) {
            $d['pending_pred'] = null; $d['pending_session'] = null;
            $d['pending_bet_amount'] = null; $d['bet_session'] = null; $d['bet_amount'] = 0;
            return $d;
        });
        $s = key_load($key);
    }

    // Compute new prediction
    $cfg = $s['config'];
    if (!empty($cfg['auto']) && empty($cfg['paused']) && empty($s['pending_pred'])) {
        // Build history for ttoan (chronological: oldest → newest)
        $hseq = [];
        $hist = array_reverse($s['history'] ?? []);
        foreach ($hist as $h) {
            $r = $h['result'] ?? '';
            if ($r==='TAI') $hseq[] = ['phien'=>$h['session'],'ket_qua'=>'Tài','tong'=>$h['tong']??0,'xuc_xac'=>$h['dices']??[]];
            elseif ($r==='XIU') $hseq[] = ['phien'=>$h['session'],'ket_qua'=>'Xỉu','tong'=>$h['tong']??0,'xuc_xac'=>$h['dices']??[]];
        }
        // If empty, use sessions API to seed
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

        // 🎯 TÍNH PREDICTION BẰNG TTOAN
        $mpState = $s['model_predictions'] ?? [];
        $ai = ttoan_generate_prediction($hseq, $mpState);
        $predStr = $ai['prediction']; // 'Tài' | 'Xỉu'
        $conf = $ai['doTinCay'];

        // Bet amount theo mode
        $baseBet = max(1000, (int)($cfg['base_bet'] ?? 10000));
        $betAmt = $baseBet;
        if (($cfg['mode'] ?? 'fixed') === 'double' && (int)($cfg['lose_streak'] ?? 0) > 0) {
            $st = min(6, (int)$cfg['lose_streak']);
            $betAmt = $baseBet * (2 ** $st);
        }
        // Cap by balance
        $bal = (int)($s['balance'] ?? 0);
        if ($betAmt > $bal && $bal > 0) $betAmt = max(1000, $bal);

        // Save pending — ĐÂY LÀ CÁI SẼ HIỂN THỊ VÀ CŨNG LÀ CÁI SẼ CƯỢC
        key_update($key, function($d) use ($predStr,$latestId,$conf,$betAmt,$mpState) {
            $d['pending_pred'] = $predStr;
            $d['pending_session'] = $latestId + 1;
            $d['pending_conf'] = $conf;
            $d['pending_bet_amount'] = $betAmt;
            $d['model_predictions'] = $mpState;
            return $d;
        });

        $confStr = number_format($conf, 1);
        $logMsg = "🎯 Dự đoán phiên #".($latestId+1).": $predStr (conf $confStr%) — cược ".number_format($betAmt)."đ";
        key_log($key,'info',$logMsg);
        $actions[] = ['type'=>'predict','msg'=>$logMsg];
        $s = key_load($key);
    }

    // Place bet if pending
    $cfg = $s['config'];
    if (!empty($s['pending_pred']) && !empty($cfg['auto']) && empty($cfg['paused'])) {
        if (($s['bet_session'] ?? null) != $s['pending_session']) {
            key_log($key,'info',"🔓 Đặt cược phiên #{$s['pending_session']} ({$s['pending_pred']})...");
            do_ws_bet($key, $s, $actions);
        }
    }
    return $actions;
}

function worker_heartbeat(string $key, string $status='running'): void {
    key_update($key, function($d) use ($status) {
        $d['worker'] = [
            'last_beat' => time(), 'pid' => getmypid(), 'status' => $status,
            'started_at' => $d['worker']['started_at'] ?? time(),
        ];
        return $d;
    });
}
function worker_alive(string $key): bool {
    global $CFG;
    $s = key_load($key);
    $w = $s['worker'] ?? [];
    if (empty($w['last_beat'])) return false;
    $to = $CFG['worker']['resume_timeout'] ?? 1800;
    return (time() - (int)$w['last_beat']) < $to;
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
    else {
        @ob_end_clean();
        header('Connection: close');
        header('Content-Length: 0');
        @flush(); @ob_end_flush();
    }
    @ignore_user_abort(true);
    @set_time_limit(0);
    @ini_set('memory_limit','256M');
    if (!worker_lock($key)) return;
    $sleep = (int)($CFG['worker']['loop_sleep'] ?? 1);
    $deadline = time() + $max;
    $lastBeat = 0;
    $selfRespawn = !empty($CFG['worker']['self_respawn']);
    $buf = (int)($CFG['worker']['respawn_buffer'] ?? 15);
    worker_heartbeat($key,'running');
    key_log($key,'info','🚀 Worker PID='.getmypid()." max={$max}s");
    while (time() < $deadline) {
        $s = key_load($key);
        if (!$s) { key_log($key,'info','🛑 State xoá'); break; }
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
    $scheme = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS']!=='off') ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $path = $_SERVER['SCRIPT_NAME'] ?? '/index.php';
    $url = "$scheme://$host$path?action=worker&key=".urlencode($key)."&max=3000";
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
            $r = "GET {$p} HTTP/1.1\r\nHost: {$h}\r\nConnection: Close\r\n\r\n";
            @fwrite($fp,$r); @fclose($fp);
            return;
        }
    }
    try {
        $ctx = stream_context_create(['http'=>['timeout'=>0.5]]);
        @file_get_contents($url,false,$ctx);
    } catch (Throwable $e) {}
}

// ═══════════ [9] ROUTER ═══════════
$action = $_GET['action'] ?? $_POST['action'] ?? '';
if ($action==='') { render_ui(); exit; }

if ($action==='cron') {
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

if ($action==='worker') {
    $key = trim($_GET['key'] ?? '');
    if (!$key) { http_response_code(400); echo 'missing key'; exit; }
    $max = (int)($_GET['max'] ?? 3000);
    run_worker_daemon($key, $max);
    exit;
}

header('Content-Type: application/json; charset=utf-8');
try {
    switch ($action) {
        case 'verify':
            $u = trim($_POST['user'] ?? ''); $p = trim($_POST['pass'] ?? '');
            $dev = trim($_POST['device'] ?? 'WEB-BOSS');
            if (!$u || !$p) { echo json_encode(['ok'=>false,'msg'=>'Vui lòng nhập đủ tài khoản/mật khẩu']); exit; }
            $key = $u;
            $existing = key_load($key);
            $canResume = !empty($existing['user']) && !empty($existing['token']);
            $gl = game_login($u, $p);
            if (isset($gl['_error'])) {
                if ($canResume) {
                    $gl = ['nickname'=>$existing['nickname']??$u,'token'=>$existing['token'],'money'=>$existing['balance']??0];
                    key_log($key,'info','♻️ Resume session cũ');
                } else {
                    echo json_encode(['ok'=>false,'msg'=>$gl['_error']]); exit;
                }
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
                'config'=>$s['config'],'history'=>$s['history'],'logs'=>$s['logs'],
                'auth_token'=>issue_token($u),'worker_alive'=>worker_alive($key),
                'resumed'=>$canResume,
            ]); exit;

        case 'config':
            $u = trim($_POST['user'] ?? ''); $tk = trim($_POST['auth_token'] ?? '');
            if (!require_auth($u,$tk)) { echo json_encode(['ok'=>false,'msg'=>'Unauthorized']); exit; }
            $key = key_resolve($u);
            $s = key_load($key); $c = $s['config'];
            $oldAuto = $c['auto'] ?? false;
            if (isset($_POST['base_bet']))    $c['base_bet'] = max(1000, (int)$_POST['base_bet']);
            if (isset($_POST['profit_stop'])) $c['profit_stop'] = max(0, (int)$_POST['profit_stop']);
            if (isset($_POST['mode']))        $c['mode'] = in_array($_POST['mode'],['fixed','double'],true) ? $_POST['mode'] : 'fixed';
            if (isset($_POST['max_lose']))    $c['max_lose_streak'] = max(1,min(10,(int)$_POST['max_lose']));
            if (isset($_POST['win_target']))  $c['win_target'] = max(1,(int)$_POST['win_target']);
            if (isset($_POST['auto']))        $c['auto'] = $_POST['auto']==='1';
            if (isset($_POST['paused']))      $c['paused'] = $_POST['paused']==='1';
            $s['config'] = $c;
            if (!$oldAuto && $c['auto']) {
                key_log($key,'info','▶ Auto BẬT');
                if (!worker_alive($key)) {
                    $lp = KEY_DIR.'/'.hash('sha256',strtolower($key)).'.lock';
                    @unlink($lp);
                    spawn_worker_async($key);
                }
            }
            key_save($key, $s);
            echo json_encode(['ok'=>true,'config'=>$c,'worker_alive'=>worker_alive($key)]);
            exit;

        case 'status':
            $u = trim($_GET['user'] ?? ''); $tk = trim($_GET['auth_token'] ?? '');
            if (!require_auth($u,$tk)) { echo json_encode(['ok'=>false,'msg'=>'Unauthorized']); exit; }
            $key = key_resolve($u);
            $s = key_load($key);
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
                'ok'=>true,
                'nickname'=>$s['nickname'] ?? '',
                'balance'=>$s['balance'] ?? 0,
                'config'=>$s['config'] ?? [],
                'history'=>array_slice($s['history'] ?? [], 0, 100),
                'logs'=>array_slice($s['logs'] ?? [], 0, 60),
                'pending_pred'=>$s['pending_pred'] ?? null,
                'pending_session'=>$s['pending_session'] ?? null,
                'pending_conf'=>$s['pending_conf'] ?? null,
                'pending_bet_amount'=>$s['pending_bet_amount'] ?? null,
                'last_session_id'=>$s['last_session_id'] ?? 0,
                'win_count_total'=>$wins,
                'loss_count_total'=>$losses,
                'profit_total'=>$profit,
                'stats'=>[
                    'wins'=>$wins,'losses'=>$losses,'total'=>$tot,
                    'winrate'=>$tot>0?round($wins/$tot*100,1):0,
                    'profit'=>$profit,
                ],
                'worker_alive'=>worker_alive($key),
                'worker'=>$s['worker'] ?? null,
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
            if (!worker_alive($key)) {
                try { worker_step($key); } catch (Throwable $e) { key_log($key,'error','fallback: '.$e->getMessage()); }
            }
            $s2 = key_load($key);
            echo json_encode([
                'ok'=>true,
                'worker_alive'=>worker_alive($key),
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

        case 'kick_worker':
            $u = trim($_POST['user'] ?? ''); $tk = trim($_POST['auth_token'] ?? '');
            if (!require_auth($u,$tk)) { echo json_encode(['ok'=>false,'msg'=>'Unauthorized']); exit; }
            $key = key_resolve($u);
            $lp = KEY_DIR.'/'.hash('sha256',strtolower($key)).'.lock';
            @unlink($lp);
            spawn_worker_async($key);
            echo json_encode(['ok'=>true,'worker_alive'=>worker_alive($key)]); exit;

        case 'clear_logs':
            $u = trim($_POST['user'] ?? ''); $tk = trim($_POST['auth_token'] ?? '');
            if (!require_auth($u,$tk)) { echo json_encode(['ok'=>false,'msg'=>'Unauthorized']); exit; }
            $key = key_resolve($u);
            $s = key_load($key); $s['logs'] = []; key_save($key, $s);
            echo json_encode(['ok'=>true]); exit;
    }
    echo json_encode(['ok'=>false,'msg'=>'Action lạ']);
} catch (Throwable $e) {
    echo json_encode(['ok'=>false,'msg'=>'Lỗi: '.$e->getMessage()]);
}
exit;

// ═══════════ [10] UI — DENIUS PREMIUM (OBSIDIAN + GOLD) ═══════════
function render_ui(): void { ?>
<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<meta name="theme-color" content="#0a0b10">
<title>DENIUS AUTO — Boss Edition</title>
<style>
:root{
  --obsidian:#0a0b10; --onyx:#12141c; --onyx-2:#1a1d28;
  --gold:#d4af37; --gold-bright:#f0c850; --gold-dim:rgba(212,175,55,0.15);
  --gold-line:rgba(212,175,55,0.22);
  --emerald:#00d68f; --emerald-glow:rgba(0,214,143,0.35);
  --ruby:#ff3b5c; --ruby-glow:rgba(255,59,92,0.35);
  --sapphire:#3b82f6; --sapphire-glow:rgba(59,130,246,0.35);
  --text:#f2f4f8; --text-dim:#a8b0c2; --muted:#5c6378;
  --border:rgba(255,255,255,0.06); --border-strong:rgba(212,175,55,0.22);
  --radius:16px; --radius-lg:22px;
}
*{margin:0;padding:0;box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html,body{min-height:100%;background:var(--obsidian);color:var(--text);overflow-x:hidden;
  font-family:-apple-system,BlinkMacSystemFont,"Inter","Segoe UI",system-ui,sans-serif;
  -webkit-font-smoothing:antialiased;user-select:none}
body{background-image:
  radial-gradient(ellipse at 10% 0%,rgba(212,175,55,0.07),transparent 45%),
  radial-gradient(ellipse at 90% 100%,rgba(59,130,246,0.05),transparent 45%);
  background-attachment:fixed}
#app{min-height:100vh;display:flex;flex-direction:column}
/* ── LOGIN ── */
.login-wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.login-card{width:100%;max-width:420px;background:linear-gradient(160deg,var(--onyx),#0e1018);border:1px solid var(--border-strong);border-radius:var(--radius-lg);padding:36px 28px;box-shadow:0 30px 80px -20px rgba(0,0,0,0.9),0 0 60px -30px var(--gold-dim);position:relative;overflow:hidden;animation:fadeUp 0.6s cubic-bezier(0.34,1.56,0.64,1)}
.login-card::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--gold),transparent);opacity:0.6}
@keyframes fadeUp{from{opacity:0;transform:translateY(30px)}to{opacity:1;transform:translateY(0)}}
.crown{text-align:center;font-size:44px;margin-bottom:8px;filter:drop-shadow(0 0 20px rgba(212,175,55,0.4));animation:float 3s ease-in-out infinite}
@keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-6px)}}
.brand{text-align:center;font-size:26px;font-weight:900;letter-spacing:6px;background:linear-gradient(90deg,var(--gold-bright),var(--gold),#b8860b);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:6px}
.brand-sub{text-align:center;font-size:10px;letter-spacing:3px;color:var(--text-dim);text-transform:uppercase;margin-bottom:28px;font-weight:600}
.field{margin-bottom:14px}
.field label{display:flex;align-items:center;gap:6px;font-size:10px;font-weight:700;color:var(--text-dim);text-transform:uppercase;letter-spacing:1.2px;margin-bottom:6px}
.field input{width:100%;padding:13px 15px;background:rgba(10,11,16,0.8);border:1px solid rgba(255,255,255,0.08);border-radius:12px;color:var(--text);font-size:14px;outline:none;transition:all 0.25s;font-family:inherit}
.field input:focus{border-color:var(--gold);background:rgba(212,175,55,0.03);box-shadow:0 0 0 3px rgba(212,175,55,0.1)}
.field input::placeholder{color:var(--muted)}
.btn{width:100%;padding:14px;border:none;border-radius:12px;font-size:13px;font-weight:800;letter-spacing:1.5px;text-transform:uppercase;cursor:pointer;transition:all 0.25s;font-family:inherit;position:relative;overflow:hidden;margin-top:8px}
.btn-primary{background:linear-gradient(135deg,var(--gold-bright),var(--gold));color:#0a0b10;box-shadow:0 8px 24px -8px var(--gold-dim)}
.btn-primary:hover:not(:disabled){transform:translateY(-2px);box-shadow:0 12px 32px -8px rgba(212,175,55,0.5)}
.btn-primary:disabled{opacity:0.5;cursor:not-allowed}
.btn-primary:disabled::after{content:'';position:absolute;width:16px;height:16px;top:50%;right:20px;margin-top:-8px;border-radius:50%;border:2px solid rgba(10,11,16,0.3);border-top-color:#0a0b10;animation:spin 0.7s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.msg{margin-top:14px;padding:11px 14px;border-radius:10px;font-size:12px;display:flex;align-items:center;gap:8px;animation:slideDown 0.3s}
.msg.err{background:rgba(255,59,92,0.1);border:1px solid rgba(255,59,92,0.3);color:#ff8fa3}
.msg.ok{background:rgba(0,214,143,0.1);border:1px solid rgba(0,214,143,0.3);color:var(--emerald)}
@keyframes slideDown{from{opacity:0;transform:translateY(-8px)}to{opacity:1;transform:translateY(0)}}
.login-foot{margin-top:20px;text-align:center;font-size:10px;color:var(--muted);line-height:1.7}
.login-foot b{color:var(--gold)}
/* ── DASHBOARD ── */
.dashboard{max-width:1200px;margin:0 auto;padding:20px;width:100%}
.dash-header{display:flex;align-items:center;justify-content:space-between;padding:18px 22px;background:linear-gradient(135deg,rgba(26,29,40,0.9),rgba(18,20,28,0.95));border:1px solid var(--border-strong);border-radius:var(--radius-lg);margin-bottom:18px;gap:14px;flex-wrap:wrap}
.dash-brand{display:flex;align-items:center;gap:12px;min-width:0}
.brand-icon{width:44px;height:44px;border-radius:12px;background:linear-gradient(135deg,var(--gold-bright),var(--gold),#b8860b);display:flex;align-items:center;justify-content:center;font-size:22px;box-shadow:0 4px 20px rgba(212,175,55,0.3);flex-shrink:0;position:relative}
.brand-icon::after{content:'';position:absolute;bottom:-2px;right:-2px;width:10px;height:10px;border-radius:50%;background:var(--emerald);border:2px solid var(--onyx);box-shadow:0 0 8px var(--emerald-glow)}
.brand-icon.offline::after{background:var(--ruby);box-shadow:0 0 8px var(--ruby-glow)}
.brand-text h1{font-size:15px;font-weight:900;letter-spacing:2px;background:linear-gradient(90deg,var(--gold-bright),var(--gold));-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
.brand-text small{font-size:10px;color:var(--text-dim);letter-spacing:0.5px;display:block;margin-top:2px}
.header-right{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.worker-badge{display:inline-flex;align-items:center;gap:6px;padding:5px 12px;border-radius:20px;font-size:10px;font-weight:800;letter-spacing:0.8px}
.worker-badge.on{background:rgba(0,214,143,0.1);color:var(--emerald);border:1px solid rgba(0,214,143,0.3)}
.worker-badge.on .dot{width:6px;height:6px;border-radius:50%;background:var(--emerald);box-shadow:0 0 8px var(--emerald-glow);animation:pulse 1.5s infinite}
.worker-badge.off{background:rgba(255,59,92,0.1);color:var(--ruby);border:1px solid rgba(255,59,92,0.3)}
@keyframes pulse{50%{opacity:0.4}}
.balance-box{text-align:right}
.balance-box small{font-size:9px;color:var(--text-dim);letter-spacing:1.5px;font-weight:700;display:block}
.balance-box b{font-size:20px;font-weight:900;color:var(--gold-bright);font-family:"SF Mono",Consolas,monospace;text-shadow:0 0 16px rgba(212,175,55,0.4)}
/* Grid layout */
.dash-grid{display:grid;grid-template-columns:1fr;gap:16px}
@media(min-width:900px){.dash-grid{grid-template-columns:1fr 1fr}.dash-grid .col-span-full{grid-column:1/-1}}
.panel{background:linear-gradient(160deg,rgba(26,29,40,0.85),rgba(18,20,28,0.9));border:1px solid var(--border);border-radius:var(--radius-lg);padding:20px;backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);position:relative;overflow:hidden}
.panel-title{font-size:11px;font-weight:800;color:var(--text-dim);text-transform:uppercase;letter-spacing:1.5px;margin-bottom:14px;display:flex;align-items:center;gap:8px}
.panel-title::after{content:'';flex:1;height:1px;background:linear-gradient(90deg,var(--gold-line),transparent)}
.panel-title .icon{font-size:14px}
/* Prediction card */
.pred-card{background:linear-gradient(145deg,rgba(212,175,55,0.06),rgba(26,29,40,0.9));border:1px solid var(--gold-line)}
.pred-main{text-align:center;padding:16px 0 8px}
.pred-label{font-size:10px;letter-spacing:2px;color:var(--text-dim);text-transform:uppercase;font-weight:700;margin-bottom:10px}
.pred-value{font-size:52px;font-weight:900;line-height:1;margin-bottom:10px;transition:all 0.4s}
.pred-value.tai{background:linear-gradient(135deg,#63b3ed,#3b82f6);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;text-shadow:0 0 40px rgba(59,130,246,0.4);filter:drop-shadow(0 0 24px rgba(59,130,246,0.4))}
.pred-value.xiu{background:linear-gradient(135deg,#fc8181,#ff3b5c);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;text-shadow:0 0 40px rgba(255,59,92,0.4);filter:drop-shadow(0 0 24px rgba(255,59,92,0.4))}
.pred-value.wait{color:var(--muted);font-size:32px}
.pred-meta{display:flex;justify-content:center;gap:20px;margin-top:14px;flex-wrap:wrap}
.pred-meta-item{text-align:center}
.pred-meta-item small{font-size:9px;color:var(--text-dim);display:block;letter-spacing:1px;text-transform:uppercase;font-weight:600}
.pred-meta-item b{font-size:14px;font-weight:800;color:var(--gold-bright);display:block;margin-top:3px;font-family:monospace}
.conf-bar{height:6px;border-radius:3px;background:rgba(255,255,255,0.05);overflow:hidden;margin-top:14px}
.conf-bar>i{display:block;height:100%;background:linear-gradient(90deg,var(--ruby),var(--gold),var(--emerald));border-radius:3px;transition:width 0.4s;box-shadow:0 0 12px rgba(212,175,55,0.5)}
/* Chart */
.chart-container{padding:12px 0 0}
#flow-chart{width:100%;display:block;border-radius:8px}
.chart-legend{display:flex;justify-content:space-between;margin-top:10px;font-size:10px;color:var(--text-dim);flex-wrap:wrap;gap:8px}
.legend-item{display:flex;align-items:center;gap:5px}
.legend-dot{width:8px;height:8px;border-radius:50%}
.legend-dot.win{background:var(--emerald);box-shadow:0 0 6px var(--emerald-glow)}
.legend-dot.lose{background:var(--ruby);box-shadow:0 0 6px var(--ruby-glow)}
/* Stats grid */
.stats-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}
@media(min-width:520px){.stats-grid{grid-template-columns:repeat(4,1fr)}}
.stat-card{background:rgba(10,11,16,0.6);border:1px solid var(--border);border-radius:12px;padding:14px 12px;text-align:center}
.stat-card small{display:block;font-size:9px;color:var(--text-dim);text-transform:uppercase;letter-spacing:1px;font-weight:700;margin-bottom:5px}
.stat-card b{display:block;font-size:18px;font-weight:900;font-family:"SF Mono",monospace;overflow-wrap:anywhere}
.stat-card.win b{color:var(--emerald)}
.stat-card.lose b{color:var(--ruby)}
.stat-card.rate b{color:var(--gold-bright)}
.stat-card.profit b{color:var(--emerald)}
.stat-card.profit.negative b{color:var(--ruby)}
/* Config */
.cfg-row{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:11px 0;border-bottom:1px solid rgba(255,255,255,0.04);min-height:44px}
.cfg-row:last-child{border-bottom:none}
.cfg-label{font-size:12px;color:var(--text);font-weight:600;display:flex;align-items:center;gap:8px;flex:1;min-width:0}
.cfg-label .icon{color:var(--gold);font-size:14px;flex-shrink:0}
.cfg-input{width:120px;padding:8px 11px;background:rgba(10,11,16,0.8);border:1px solid rgba(255,255,255,0.08);border-radius:9px;color:var(--gold-bright);font-size:12px;font-weight:700;text-align:right;font-family:monospace;outline:none;transition:all 0.2s}
.cfg-input:focus{border-color:var(--gold);box-shadow:0 0 0 3px rgba(212,175,55,0.1)}
.cfg-select{padding:8px 30px 8px 11px;background:rgba(10,11,16,0.8);border:1px solid rgba(255,255,255,0.08);border-radius:9px;color:var(--text);font-size:12px;font-weight:600;outline:none;appearance:none;background-image:url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='10' height='10' viewBox='0 0 24 24' fill='none' stroke='%23d4af37' stroke-width='3'><polyline points='6 9 12 15 18 9'/></svg>");background-repeat:no-repeat;background-position:right 10px center;cursor:pointer;font-family:inherit;min-width:140px}
.cfg-select:focus{border-color:var(--gold)}
.cfg-select option{background:var(--onyx-2);color:var(--text)}
/* Auto button */
.auto-btn{width:100%;padding:16px;border:none;border-radius:14px;font-size:14px;font-weight:900;letter-spacing:1.5px;text-transform:uppercase;cursor:pointer;transition:all 0.3s;font-family:inherit;margin-top:16px;position:relative;overflow:hidden}
.auto-btn.on{background:linear-gradient(135deg,#00d68f,#059669);color:#0a0b10;box-shadow:0 8px 28px -8px var(--emerald-glow)}
.auto-btn.on:hover{transform:translateY(-2px);box-shadow:0 12px 36px -8px rgba(0,214,143,0.6)}
.auto-btn.off{background:linear-gradient(135deg,var(--ruby),#b91c1c);color:#fff;box-shadow:0 8px 28px -8px var(--ruby-glow)}
.auto-btn.off:hover{transform:translateY(-2px);box-shadow:0 12px 36px -8px rgba(255,59,92,0.6)}
.auto-btn:disabled{opacity:0.5;cursor:not-allowed;transform:none}
/* History */
.hist-item{display:flex;align-items:center;gap:12px;padding:12px;background:rgba(10,11,16,0.5);border-radius:10px;margin-bottom:8px;border-left:3px solid var(--muted);transition:all 0.2s;font-size:12px}
.hist-item.win{border-left-color:var(--emerald);background:linear-gradient(90deg,rgba(0,214,143,0.05),rgba(10,11,16,0.5))}
.hist-item.lose{border-left-color:var(--ruby);background:linear-gradient(90deg,rgba(255,59,92,0.05),rgba(10,11,16,0.5))}
.hist-item.jackpot{border-left-color:var(--gold-bright);background:linear-gradient(90deg,rgba(212,175,55,0.1),rgba(10,11,16,0.5));animation:jackpotGlow 2s ease-in-out}
@keyframes jackpotGlow{0%,100%{box-shadow:0 0 0 rgba(212,175,55,0)}50%{box-shadow:0 0 20px rgba(212,175,55,0.3)}}
.hist-session{font-family:monospace;color:var(--gold-bright);font-weight:700;min-width:64px;font-size:11px}
.hist-mid{flex:1;min-width:0}
.hist-mid .row1{font-weight:700;font-size:12px;margin-bottom:3px;display:flex;align-items:center;gap:6px;flex-wrap:wrap}
.hist-mid .row2{font-size:10px;color:var(--text-dim);font-family:monospace}
.hist-result{font-weight:900;font-size:13px;min-width:70px;text-align:right}
.hist-result.win{color:var(--emerald)}
.hist-result.lose{color:var(--ruby)}
/* Logs */
.log-item{padding:9px 12px;border-radius:8px;font-size:11px;display:flex;gap:10px;align-items:flex-start;margin-bottom:5px;border-left:3px solid var(--muted);background:rgba(10,11,16,0.4)}
.log-item.info{border-left-color:var(--sapphire);background:linear-gradient(90deg,rgba(59,130,246,0.05),rgba(10,11,16,0.4))}
.log-item.success{border-left-color:var(--emerald);background:linear-gradient(90deg,rgba(0,214,143,0.05),rgba(10,11,16,0.4))}
.log-item.error{border-left-color:var(--ruby);background:linear-gradient(90deg,rgba(255,59,92,0.05),rgba(10,11,16,0.4))}
.log-item.warn{border-left-color:#ffb84d;background:linear-gradient(90deg,rgba(255,184,77,0.05),rgba(10,11,16,0.4))}
.log-ts{font-family:monospace;color:var(--muted);font-size:10px;flex-shrink:0;min-width:72px}
.log-msg{flex:1;color:var(--text);line-height:1.5;word-break:break-word;user-select:text}
/* Empty */
.empty{text-align:center;padding:40px 20px;color:var(--muted);font-size:12px}
.empty-icon{font-size:38px;opacity:0.4;margin-bottom:10px}
/* Tabs */
.tabs{display:flex;gap:4px;background:rgba(10,11,16,0.6);padding:4px;border-radius:12px;margin-bottom:14px}
.tab-btn{flex:1;padding:9px 8px;background:none;border:none;color:var(--text-dim);font-size:11px;font-weight:700;border-radius:9px;cursor:pointer;transition:all 0.2s;text-transform:uppercase;letter-spacing:0.5px;font-family:inherit}
.tab-btn.on{background:linear-gradient(135deg,var(--gold-bright),var(--gold));color:#0a0b10;box-shadow:0 4px 16px -4px var(--gold-dim)}
.tab-btn:not(.on):hover{color:var(--text);background:rgba(255,255,255,0.03)}
.logout-btn{width:100%;padding:12px;background:rgba(255,59,92,0.08);border:1px solid rgba(255,59,92,0.3);color:var(--ruby);border-radius:10px;font-size:11px;font-weight:800;letter-spacing:1px;text-transform:uppercase;cursor:pointer;transition:all 0.2s;font-family:inherit;margin-top:14px}
.logout-btn:hover{background:rgba(255,59,92,0.15);transform:translateY(-1px)}
/* Toast */
#toast{position:fixed;top:20px;right:20px;z-index:9999;display:flex;flex-direction:column;gap:8px;pointer-events:none;max-width:340px}
.toast{padding:12px 18px;border-radius:11px;font-size:12px;font-weight:600;color:#fff;background:rgba(26,29,40,0.98);border:1px solid rgba(255,255,255,0.1);box-shadow:0 12px 32px -8px rgba(0,0,0,0.6);backdrop-filter:blur(12px);animation:toastIn 0.35s cubic-bezier(0.34,1.56,0.64,1);display:flex;align-items:center;gap:10px}
.toast.success{border-color:rgba(0,214,143,0.4);background:linear-gradient(135deg,rgba(0,214,143,0.15),rgba(26,29,40,0.98))}
.toast.error{border-color:rgba(255,59,92,0.4);background:linear-gradient(135deg,rgba(255,59,92,0.15),rgba(26,29,40,0.98))}
.toast.gold{border-color:var(--gold-line);background:linear-gradient(135deg,rgba(212,175,55,0.15),rgba(26,29,40,0.98))}
@keyframes toastIn{from{opacity:0;transform:translateX(100px)}to{opacity:1;transform:translateX(0)}}
@media(max-width:600px){
  .dashboard{padding:12px}
  .dash-header{padding:14px 16px}
  .brand-text h1{font-size:13px;letter-spacing:1.5px}
  .balance-box b{font-size:17px}
  .pred-value{font-size:44px}
  .cfg-input{width:100px}
  .cfg-select{min-width:120px}
  .panel{padding:16px}
}
</style>
</head>
<body>
<div id="app"></div>
<div id="toast"></div>
<script>
const app = document.getElementById('app');
const toastBox = document.getElementById('toast');

const S = {
  loggedIn: false, user: '', nickname: '', balance: 0,
  authToken: '', device: '', loading: false, error: '', success: '',
  config: { base_bet:10000, profit_stop:0, win_target:50, mode:'fixed', max_lose_streak:3, auto:false, paused:false, lose_streak:0 },
  history: [], logs: [], stats: { wins:0, losses:0, total:0, winrate:0, profit:0 },
  pendingPred: null, pendingSession: null, pendingConf: null, pendingBetAmount: null,
  workerAlive: false, workerInfo: null, tab: 'main',
  pattern10: '', tickTimer: null,
};

// Device fingerprint
(function() {
  const d = [navigator.userAgent, navigator.language, screen.width+'x'+screen.height].join('|');
  let h = 0; for (let i = 0; i < d.length; i++) h = ((h << 5) - h) + d.charCodeAt(i), h |= 0;
  S.device = 'DENIUS-' + Math.abs(h).toString(16).toUpperCase().slice(0, 8);
})();

const fmt = n => (n || 0).toLocaleString('vi-VN');
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

function toast(msg, type='info') {
  const el = document.createElement('div');
  el.className = 'toast ' + type;
  el.textContent = msg;
  toastBox.appendChild(el);
  setTimeout(() => { el.style.opacity = '0'; el.style.transform = 'translateX(100px)'; }, 2800);
  setTimeout(() => el.remove(), 3200);
}

// ═══ LOGIN ═══
function renderLogin() {
  app.innerHTML = `
    <div class="login-wrap">
      <div class="login-card">
        <div class="crown">👑</div>
        <div class="brand">DENIUS</div>
        <div class="brand-sub">AUTO · BOSS EDITION</div>
        <div class="field">
          <label>👤 Tài khoản game</label>
          <input id="in_u" type="text" placeholder="Nhập tài khoản..." autocomplete="username">
        </div>
        <div class="field">
          <label>🔒 Mật khẩu</label>
          <input id="in_p" type="password" placeholder="••••••••" autocomplete="current-password">
        </div>
        <button class="btn btn-primary" id="btn_login" ${S.loading ? 'disabled' : ''}>${S.loading ? 'ĐANG XÁC THỰC' : 'ĐĂNG NHẬP NGAY'}</button>
        ${S.error ? `<div class="msg err">⚠️ ${esc(S.error)}</div>` : ''}
        ${S.success ? `<div class="msg ok">✓ ${esc(S.success)}</div>` : ''}
        <div class="login-foot">
          <b>V1.0 BOSS EDITION</b> · Admin <b>@DENIUS09</b><br>
          Dự đoán & cược chạy cùng một nguồn ttoan — không lệch
        </div>
      </div>
    </div>
  `;
  document.getElementById('btn_login').onclick = doLogin;
  document.getElementById('in_p').onkeydown = e => { if (e.key === 'Enter') doLogin(); };
}

async function doLogin() {
  const u = document.getElementById('in_u').value.trim();
  const p = document.getElementById('in_p').value.trim();
  if (!u || !p) { S.error = 'Vui lòng nhập đầy đủ'; renderLogin(); return; }
  S.loading = true; S.error = ''; S.success = ''; renderLogin();
  try {
    const r = await api('verify', { user: u, pass: p, device: S.device });
    if (!r.ok) { S.loading = false; S.error = r.msg || 'Đăng nhập thất bại'; renderLogin(); return; }
    Object.assign(S, {
      loggedIn: true, user: r.user, nickname: r.nickname, balance: r.balance,
      config: r.config, history: r.history || [], logs: r.logs || [],
      authToken: r.auth_token, workerAlive: !!r.worker_alive, loading: false,
    });
    renderDashboard();
    startTick();
    toast('Chào Ông Chủ DENIUS 👑', 'gold');
  } catch (e) {
    S.loading = false; S.error = 'Lỗi: ' + e.message; renderLogin();
  }
}

// ═══ DASHBOARD ═══
function renderDashboard() {
  app.innerHTML = `
    <div class="dashboard">
      <div class="dash-header">
        <div class="dash-brand">
          <div class="brand-icon ${S.workerAlive ? '' : 'offline'}">👑</div>
          <div class="brand-text">
            <h1>DENIUS AUTO</h1>
            <small>BOSS EDITION · ${esc(S.nickname)}</small>
          </div>
        </div>
        <div class="header-right">
          <div class="worker-badge ${S.workerAlive ? 'on' : 'off'}">
            <span class="dot"></span>${S.workerAlive ? 'WORKER ONLINE' : 'WORKER OFFLINE'}
          </div>
          <div class="balance-box">
            <small>SỐ DƯ</small>
            <b id="balance_val">${fmt(S.balance)}</b>
          </div>
        </div>
      </div>
      <div class="tabs">
        <button class="tab-btn ${S.tab==='main'?'on':''}" data-tab="main">🎯 Chính</button>
        <button class="tab-btn ${S.tab==='cfg'?'on':''}" data-tab="cfg">⚙️ Cấu hình</button>
        <button class="tab-btn ${S.tab==='hist'?'on':''}" data-tab="hist">📜 Lịch sử</button>
        <button class="tab-btn ${S.tab==='logs'?'on':''}" data-tab="logs">📋 Logs</button>
      </div>
      <div id="tab-content"></div>
    </div>
  `;
  document.querySelectorAll('.tab-btn').forEach(b => {
    b.onclick = () => { S.tab = b.dataset.tab; renderDashboard(); };
  });
  renderTabContent();
}

function renderTabContent() {
  const box = document.getElementById('tab-content');
  if (!box) return;
  if (S.tab === 'main') box.innerHTML = renderMainTab();
  else if (S.tab === 'cfg') box.innerHTML = renderCfgTab();
  else if (S.tab === 'hist') box.innerHTML = renderHistTab();
  else if (S.tab === 'logs') box.innerHTML = renderLogsTab();
  bindTab();
}

function renderMainTab() {
  const p = S.pendingPred;
  const predCls = p === 'Tài' ? 'tai' : (p === 'Xỉu' ? 'xiu' : 'wait');
  const predTxt = p || 'ĐANG CHỜ';
  const profit = S.stats.profit || 0;
  return `
    <div class="dash-grid">
      <div class="panel pred-card col-span-full">
        <div class="panel-title"><span class="icon">🎯</span>DỰ ĐOÁN PHIÊN KẾ</div>
        <div class="pred-main">
          <div class="pred-value ${predCls}">${predTxt}</div>
          <div class="pred-meta">
            <div class="pred-meta-item">
              <small>Phiên</small>
              <b>#${S.pendingSession || '—'}</b>
            </div>
            <div class="pred-meta-item">
              <small>Độ tin cậy</small>
              <b>${S.pendingConf ? S.pendingConf.toFixed(1)+'%' : '—'}</b>
            </div>
            <div class="pred-meta-item">
              <small>Cược</small>
              <b>${S.pendingBetAmount ? fmt(S.pendingBetAmount)+'đ' : '—'}</b>
            </div>
          </div>
          ${S.pendingConf ? `<div class="conf-bar"><i style="width:${Math.min(100,S.pendingConf)}%"></i></div>` : ''}
        </div>
      </div>
      <div class="panel col-span-full">
        <div class="panel-title"><span class="icon">💎</span>DÒNG TIỀN — MONEY FLOW</div>
        <div class="chart-container">
          <canvas id="flow-chart" width="1000" height="260"></canvas>
          <div class="chart-legend">
            <div class="legend-item"><span class="legend-dot win"></span>Thắng</div>
            <div class="legend-item"><span class="legend-dot lose"></span>Thua</div>
            <div class="legend-item" style="margin-left:auto">📊 ${Math.min(60, S.history.length)} phiên</div>
          </div>
        </div>
      </div>
      <div class="panel">
        <div class="panel-title"><span class="icon">📊</span>THỐNG KÊ</div>
        <div class="stats-grid">
          <div class="stat-card win"><small>Thắng</small><b>${S.stats.wins || 0}</b></div>
          <div class="stat-card lose"><small>Thua</small><b>${S.stats.losses || 0}</b></div>
          <div class="stat-card rate"><small>Tỉ lệ</small><b>${S.stats.winrate || 0}%</b></div>
          <div class="stat-card profit ${profit < 0 ? 'negative' : ''}"><small>Lợi nhuận</small><b>${profit >= 0 ? '+' : ''}${fmt(profit)}</b></div>
        </div>
        <button class="auto-btn ${S.config.auto ? 'on' : 'off'}" id="btn_auto">
          ${S.config.auto ? '🛑 TẮT AUTO' : '▶ BẬT AUTO'}
        </button>
      </div>
      <div class="panel">
        <div class="panel-title"><span class="icon">🎛️</span>TRẠNG THÁI</div>
        <div class="cfg-row">
          <div class="cfg-label"><span class="icon">📡</span>Pattern 10</div>
          <b style="color:var(--gold-bright);font-family:monospace;font-size:13px;letter-spacing:2px">${S.pattern10 || '—'}</b>
        </div>
        <div class="cfg-row">
          <div class="cfg-label"><span class="icon">🔥</span>Chuỗi thua</div>
          <b style="color:var(--ruby);font-family:monospace;font-size:13px">${S.config.lose_streak || 0}/${S.config.max_lose_streak || 3}</b>
        </div>
        <div class="cfg-row">
          <div class="cfg-label"><span class="icon">💰</span>Vốn gốc</div>
          <b style="color:var(--gold-bright);font-family:monospace;font-size:13px">${fmt(S.config.base_bet || 0)}đ</b>
        </div>
        <div class="cfg-row">
          <div class="cfg-label"><span class="icon">🎯</span>Chốt lời</div>
          <b style="color:var(--gold-bright);font-family:monospace;font-size:13px">${S.config.profit_stop ? fmt(S.config.profit_stop)+'đ' : '—'}</b>
        </div>
      </div>
    </div>
  `;
}

function renderCfgTab() {
  return `
    <div class="panel">
      <div class="panel-title"><span class="icon">⚙️</span>CẤU HÌNH CHIẾN LƯỢC</div>
      <div class="cfg-row">
        <div class="cfg-label"><span class="icon">💰</span>Vốn mỗi tay</div>
        <input type="number" class="cfg-input" id="cfg_base" value="${S.config.base_bet}" min="1000" step="1000">
      </div>
      <div class="cfg-row">
        <div class="cfg-label"><span class="icon">🎯</span>Chốt lời (0 = tắt)</div>
        <input type="number" class="cfg-input" id="cfg_profit" value="${S.config.profit_stop}" min="0" step="10000">
      </div>
      <div class="cfg-row">
        <div class="cfg-label"><span class="icon">🏆</span>Mục tiêu phiên thắng</div>
        <input type="number" class="cfg-input" id="cfg_win_target" value="${S.config.win_target}" min="1" step="1">
      </div>
      <div class="cfg-row">
        <div class="cfg-label"><span class="icon">📈</span>Chế độ cược</div>
        <select class="cfg-select" id="cfg_mode">
          <option value="fixed" ${S.config.mode==='fixed'?'selected':''}>Cố định</option>
          <option value="double" ${S.config.mode==='double'?'selected':''}>X2 khi thua (Martingale)</option>
        </select>
      </div>
      <div class="cfg-row">
        <div class="cfg-label"><span class="icon">🛡️</span>Thua tối đa (Martingale)</div>
        <input type="number" class="cfg-input" id="cfg_max_lose" value="${S.config.max_lose_streak}" min="1" max="10">
      </div>
      <button class="logout-btn" id="btn_logout">🚪 ĐĂNG XUẤT</button>
    </div>
  `;
}

function renderHistTab() {
  if (!S.history.length) {
    return `<div class="panel"><div class="empty"><div class="empty-icon">📜</div>Chưa có lịch sử</div></div>`;
  }
  return `
    <div class="panel">
      <div class="panel-title"><span class="icon">📜</span>LỊCH SỬ PHIÊN</div>
      ${S.history.slice(0, 50).map(h => {
        const win = h.win;
        const cls = win ? 'win' : 'lose';
        const jackpot = h.jackpot ? 'jackpot' : '';
        const dice = (h.dices || []).join('-');
        return `
          <div class="hist-item ${cls} ${jackpot}">
            <div class="hist-session">#${h.session}</div>
            <div class="hist-mid">
              <div class="row1">
                ${h.pred === 'Tài' ? '🔵' : h.pred === 'Xỉu' ? '🔴' : '⚪'} ${h.pred || '?'}
                ${h.jackpot ? '<span style="color:var(--gold-bright)">🎉 JACKPOT</span>' : ''}
              </div>
              <div class="row2">🎲 ${dice} · ${h.ts}</div>
            </div>
            <div class="hist-result ${cls}">
              ${win ? '+' : '-'}${fmt(h.amount || 0)}
            </div>
          </div>
        `;
      }).join('')}
    </div>
  `;
}

function renderLogsTab() {
  if (!S.logs.length) {
    return `<div class="panel"><div class="empty"><div class="empty-icon">📋</div>Chưa có log</div></div>`;
  }
  return `
    <div class="panel">
      <div class="panel-title"><span class="icon">📋</span>LOG HOẠT ĐỘNG</div>
      ${S.logs.slice(0, 60).map(l => `
        <div class="log-item ${l.level || 'info'}">
          <span class="log-ts">${esc(l.ts || '')}</span>
          <span class="log-msg">${esc(l.msg || '')}</span>
        </div>
      `).join('')}
    </div>
  `;
}

function bindTab() {
  // Auto button
  const btn = document.getElementById('btn_auto');
  if (btn) btn.onclick = async () => {
    btn.disabled = true;
    const newAuto = !S.config.auto;
    await api('config', { user: S.user, auto: newAuto ? '1' : '0', paused: '0' });
    S.config.auto = newAuto;
    if (newAuto) toast('🚀 AUTO đã bật', 'success');
    else toast('⏸ AUTO đã tắt', 'gold');
    renderTabContent();
  };
  // Cfg inputs
  const bindCfg = (id, key, transform) => {
    const el = document.getElementById(id);
    if (!el) return;
    el.onchange = async () => {
      const v = transform ? transform(el.value) : el.value;
      S.config[key] = v;
      await api('config', { user: S.user, [key === 'max_lose_streak' ? 'max_lose' : key]: v });
      toast('✓ Đã lưu cấu hình', 'success');
    };
  };
  bindCfg('cfg_base', 'base_bet', v => Math.max(1000, parseInt(v) || 1000));
  bindCfg('cfg_profit', 'profit_stop', v => Math.max(0, parseInt(v) || 0));
  bindCfg('cfg_win_target', 'win_target', v => Math.max(1, parseInt(v) || 50));
  bindCfg('cfg_mode', 'mode');
  bindCfg('cfg_max_lose', 'max_lose_streak', v => Math.max(1, Math.min(10, parseInt(v) || 3)));
  const lo = document.getElementById('btn_logout');
  if (lo) lo.onclick = async () => {
    if (!confirm('Đăng xuất sẽ xoá dữ liệu trên server. Tiếp tục?')) return;
    await api('logout', { user: S.user });
    clearInterval(S.tickTimer);
    Object.assign(S, { loggedIn: false, user: '', nickname: '', balance: 0, authToken: '',
      history: [], logs: [], pendingPred: null, pendingSession: null });
    renderLogin();
  };
}

// ═══ API ═══
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

// ═══ TICK ═══
let tickInFlight = false;
async function tick() {
  if (!S.loggedIn || tickInFlight) return;
  tickInFlight = true;
  try {
    await api('tick', { user: S.user }).catch(() => {});
    const j = await getStatus();
    if (!j.ok) return;
    S.balance = j.balance || 0;
    S.history = j.history || [];
    S.logs = j.logs || [];
    S.workerAlive = !!j.worker_alive;
    S.workerInfo = j.worker || null;
    S.stats = j.stats || S.stats;
    S.pattern10 = j.pattern_10 || '';
    S.pendingPred = j.pending_pred;
    S.pendingSession = j.pending_session;
    S.pendingConf = j.pending_conf;
    S.pendingBetAmount = j.pending_bet_amount;
    if (j.config) {
      Object.assign(S.config, {
        auto: j.config.auto, paused: j.config.paused,
        lose_streak: j.config.lose_streak, mode: j.config.mode,
        max_lose_streak: j.config.max_lose_streak,
        base_bet: j.config.base_bet, profit_stop: j.config.profit_stop,
        win_target: j.config.win_target,
      });
    }
    // Update DOM
    const bv = document.getElementById('balance_val');
    if (bv) bv.textContent = fmt(S.balance);
    const wb = document.querySelector('.worker-badge');
    if (wb) {
      wb.className = 'worker-badge ' + (S.workerAlive ? 'on' : 'off');
      wb.innerHTML = `<span class="dot"></span>${S.workerAlive ? 'WORKER ONLINE' : 'WORKER OFFLINE'}`;
    }
    const bi = document.querySelector('.brand-icon');
    if (bi) bi.classList.toggle('offline', !S.workerAlive);
    // Only re-render tab if history/logs count changed
    if (S.tab === 'main' || S.tab === 'hist' || S.tab === 'logs') {
      renderTabContent();
    }
  } catch (e) {} finally {
    tickInFlight = false;
  }
}

function startTick() {
  if (S.tickTimer) clearInterval(S.tickTimer);
  tick();
  S.tickTimer = setInterval(tick, 2500);
}

// ═══ MONEY FLOW CHART ═══
let chartAnim = null;
function drawChart() {
  const canvas = document.getElementById('flow-chart');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  const rect = canvas.getBoundingClientRect();
  const w = Math.max(300, Math.floor(rect.width)), h = 260;
  canvas.width = w * dpr; canvas.height = h * dpr;
  canvas.style.height = h + 'px';
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, h);

  // Get history with balance, chronological
  const raw = (S.history || []).slice(0, 60).reverse()
    .filter(h => h && h.balance_after != null);
  if (raw.length < 2) {
    ctx.fillStyle = 'rgba(168,176,194,0.5)';
    ctx.font = '13px system-ui'; ctx.textAlign = 'center';
    ctx.fillText('Chờ dữ liệu dòng tiền...', w / 2, h / 2);
    return;
  }
  const padL = 62, padR = 16, padT = 20, padB = 34;
  const cw = w - padL - padR, ch = h - padT - padB;
  const vals = raw.map(r => r.balance_after);
  let mn = Math.min(...vals), mx = Math.max(...vals);
  if (mn === mx) { mn -= 1; mx += 1; }
  const range = mx - mn;
  mn -= range * 0.08; mx += range * 0.08;
  const X = i => padL + (cw * i / Math.max(1, raw.length - 1));
  const Y = v => padT + ch * (1 - (v - mn) / (mx - mn));

  // Grid
  ctx.strokeStyle = 'rgba(212,175,55,0.08)';
  ctx.lineWidth = 1;
  ctx.fillStyle = 'rgba(168,176,194,0.5)';
  ctx.font = '10px "SF Mono",monospace';
  ctx.textAlign = 'right';
  for (let g = 0; g <= 4; g++) {
    const v = mn + (mx - mn) * g / 4;
    const y = Y(v);
    ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(w - padR, y); ctx.stroke();
    ctx.fillText(fmt(Math.round(v)), padL - 8, y + 3);
  }

  // X labels
  ctx.textAlign = 'center';
  const labels = Math.min(5, raw.length);
  for (let i = 0; i < labels; i++) {
    const idx = Math.round(i * (raw.length - 1) / Math.max(1, labels - 1));
    const ts = String(raw[idx].ts || '');
    const hm = ts.length >= 5 ? ts.slice(0, 5) : '';
    ctx.fillText(hm, X(idx), h - 12);
  }

  // Animate
  if (chartAnim) cancelAnimationFrame(chartAnim);
  const start = performance.now(), dur = 800;
  function frame(now) {
    const prog = Math.min(1, (now - start) / dur);
    const ease = 1 - Math.pow(1 - prog, 3);
    const upto = Math.max(1, Math.floor((raw.length - 1) * ease));

    // Clear plot area
    ctx.clearRect(padL - 1, padT - 1, cw + 2, ch + 2);

    // Area fill
    const areaGrad = ctx.createLinearGradient(0, padT, 0, padT + ch);
    areaGrad.addColorStop(0, 'rgba(212,175,55,0.20)');
    areaGrad.addColorStop(1, 'rgba(212,175,55,0.01)');
    ctx.beginPath();
    ctx.moveTo(X(0), padT + ch);
    for (let i = 0; i <= upto; i++) ctx.lineTo(X(i), Y(raw[i].balance_after));
    ctx.lineTo(X(upto), padT + ch);
    ctx.closePath();
    ctx.fillStyle = areaGrad;
    ctx.fill();

    // Line
    const lineGrad = ctx.createLinearGradient(padL, 0, w - padR, 0);
    lineGrad.addColorStop(0, '#d4af37');
    lineGrad.addColorStop(0.5, '#f0c850');
    lineGrad.addColorStop(1, '#00d68f');
    ctx.strokeStyle = lineGrad;
    ctx.lineWidth = 2.4;
    ctx.shadowColor = 'rgba(212,175,55,0.5)';
    ctx.shadowBlur = 12;
    ctx.beginPath();
    ctx.moveTo(X(0), Y(raw[0].balance_after));
    for (let i = 1; i <= upto; i++) ctx.lineTo(X(i), Y(raw[i].balance_after));
    ctx.stroke();
    ctx.shadowBlur = 0;

    // Dots
    for (let i = 0; i <= upto; i++) {
      const win = raw[i].win;
      const isLast = i === upto;
      ctx.beginPath();
      ctx.arc(X(i), Y(raw[i].balance_after), isLast ? 5 : 3.5, 0, Math.PI * 2);
      if (win) {
        ctx.fillStyle = '#00d68f';
        ctx.shadowColor = 'rgba(0,214,143,0.7)';
      } else {
        ctx.fillStyle = '#ff3b5c';
        ctx.shadowColor = 'rgba(255,59,92,0.7)';
      }
      ctx.shadowBlur = isLast ? 12 : 6;
      ctx.fill();
      ctx.shadowBlur = 0;
      // White ring on last
      if (isLast) {
        ctx.strokeStyle = 'rgba(255,255,255,0.7)';
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.arc(X(i), Y(raw[i].balance_after), 5, 0, Math.PI * 2);
        ctx.stroke();
      }
    }

    // Current value
    if (upto >= raw.length - 1) {
      const last = raw[raw.length - 1];
      ctx.fillStyle = 'rgba(240,200,80,0.95)';
      ctx.font = 'bold 12px "SF Mono",monospace';
      ctx.textAlign = 'right';
      ctx.fillText(fmt(last.balance_after), X(raw.length - 1) - 10, Y(last.balance_after) - 8);
    }

    if (prog < 1) chartAnim = requestAnimationFrame(frame);
  }
  chartAnim = requestAnimationFrame(frame);
}

// ═══ Poll for chart update ═══
setInterval(() => {
  if (S.loggedIn && S.tab === 'main') {
    if (document.getElementById('flow-chart')) drawChart();
  }
}, 2500);

// ═══ BOOT ═══
renderLogin();
</script>
</body>
</html>
<?php }
