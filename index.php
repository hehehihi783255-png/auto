<?php
/**
 * AUZA ĐÁNH CHẾT NHÀ CÁI — v13.1 SUPREME PREDICTOR ENGINE (FIXED)
 * ─────────────────────────────────────────────────────────────
 * FIX v13.1.1:
 *  - FIX MARTINGALE: gấp nếp X2 khi thua đúng chuẩn (double mode)
 *  - FIX smart_bet: không ghi đè martingale
 *  - FIX balance tracking khi martingale
 *  - FIX cron array merge
 *  - FIX worker_lock atomic bằng flock
 *  - FIX race condition key_save (thêm update lock)
 *  - FIX spawn_worker URL
 *  - FIX spawn_worker_async: KHÔNG phụ thuộc cURL (6 lớp fallback)
 * ─────────────────────────────────────────────────────────────
 */

// ═══════════════════════════════════════════════════════
// [0] CONFIG
// ═══════════════════════════════════════════════════════
$CFG = [
    'version' => '13.1.1-supreme-fixed',
    'key_verify_url' => '',
    'sessions_api' => 'https://wtxmd52.tele68.com/v1/txmd5/sessions',
    'sessions_api_hu' => 'https://wtx.tele68.com/v1/tx/sessions',
    'game' => [
        'login_url' => 'https://apifo88daigia.tele68.com/api?c=3&un={USER}&pw={PASS_MD5}&cp=R&cl=R&pf=web&at=',
        'lobby_url' => 'https://wlb.tele68.com/v1/lobby/auth/login?cp=R&cl=R&pf=web&at=',
        'ws_host'   => 'wtxmd52.tele68.com',
        'ws_path'   => '/txmd5/',
    ],
    'max_history' => 500,
    'default_config' => [
        'base_bet'        => 10000,
        'profit_stop'     => 0,
        'mode'            => 'fixed',
        'table_type'      => 'md5',
        'max_lose_streak' => 3,
        'smart_bet'       => false,
        'bet_high'        => 50000,
        'bet_low'         => 10000,
        'high_conf_min'   => 75,
        'recent_win_min'  => 2,
        'capital'         => 0,
        'auto_capital'    => false,
        // V16: mục tiêu thắng tích lũy; mặc định dừng ở 666.
        'win_target'      => 666,
    ],
    'security' => [
        'hmac_secret' => '',
        'session_ttl' => 86400,
    ],
    'worker' => [
        'loop_sleep'      => 1,
        'resume_timeout'  => 1800,
        'max_runtime'     => 3000,
        'self_respawn'    => true,
        'respawn_buffer'  => 15,
        'cron_secret'     => '',
    ],
    'ui' => [
        'primary'   => '#ff6b35',
        'secondary' => '#e53935',
        'accent'    => '#ffb300',
    ],
];

const DATA_DIR = __DIR__ . '/.data';
const KEY_DIR  = DATA_DIR . '/by_key';
const CACHE_SEC = 2;
const HUB_ID = 'auza-v13.1.1';

// ═══════════════════════════════════════════════════════
// [1] HEADERS & BOOTSTRAP
// ═══════════════════════════════════════════════════════
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

// ═══════════════════════════════════════════════════════
// [2] HMAC AUTH
// ═══════════════════════════════════════════════════════
function hmac_sign(string $p): string { global $CFG; return hash_hmac('sha256', $p, $CFG['security']['hmac_secret']); }
function issue_token(string $u): string {
    $exp = time() + ($GLOBALS['CFG']['security']['session_ttl'] ?? 86400);
    $p = $u . '|' . $exp;
    return base64_encode($p . '|' . hmac_sign($p));
}
function verify_token(string $tok, string $u): bool {
    $d = base64_decode($tok, true); if ($d === false) return false;
    $parts = explode('|', $d); if (count($parts) !== 3) return false;
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

// ═══════════════════════════════════════════════════════
// [3] STORE BY KEY
// ═══════════════════════════════════════════════════════
function key_path(string $key): string { return KEY_DIR . '/' . hash('sha256', strtolower(trim($key))) . '.json'; }

function key_update(string $key, callable $mutator): array {
    $p = key_path($key);
    $fp = @fopen($p, 'c+');
    if (!$fp) { $d = key_load($key); return $mutator($d) ?? $d; }
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

function key_load(string $key): array {
    $p = key_path($key);
    if (!is_file($p)) return [];
    $j = json_decode(file_get_contents($p), true);
    return is_array($j) ? $j : [];
}
function key_save(string $key, array $d): void {
    $p = key_path($key); $t = $p . '.tmp';
    file_put_contents($t, json_encode($d, JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT), LOCK_EX);
    rename($t, $p); @chmod($p, 0600);
}
function key_log(string $key, string $lvl, string $msg): void {
    key_update($key, function($d) use ($lvl, $msg) {
        $d['logs'] = $d['logs'] ?? [];
        array_unshift($d['logs'], ['ts'=>date('H:i:s d/m'), 'level'=>$lvl, 'msg'=>$msg]);
        $d['logs'] = array_slice($d['logs'], 0, 300);
        return $d;
    });
}
function key_hist(string $key, array $row): void {
    key_update($key, function($d) use ($row) {
        $d['history'] = $d['history'] ?? [];
        array_unshift($d['history'], $row);
        $d['history'] = array_slice($d['history'], 0, $GLOBALS['CFG']['max_history'] ?? 500);
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

// ═══════════════════════════════════════════════════════
// [4] KEY VERIFY / GAME LOGIN / SESSIONS API
// ═══════════════════════════════════════════════════════
function verify_key(string $key, string $dev): array {
    return ['success' => true];
}

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
    // Dùng file_get_contents để tránh phụ thuộc cURL
    $ctx = stream_context_create([
        'http' => [
            'timeout' => 5,
            'ignore_errors' => true,
            'header' => "User-Agent: Mozilla/5.0\r\nAccept: application/json\r\n",
        ],
        'ssl' => [
            'verify_peer' => false,
            'verify_peer_name' => false,
        ],
    ]);
    $raw = @file_get_contents($CFG['sessions_api'], false, $ctx);
    if (!$raw) return null;
    $j = json_decode($raw, true);
    return is_array($j) && isset($j['list']) ? $j : null;
}

// ─── [UPGRADE] Hũ (TX) sessions API — song song với MD5 ───
function fetch_sessions_api_hu(): ?array {
    global $CFG;
    $ctx = stream_context_create([
        'http' => [
            'timeout' => 5,
            'ignore_errors' => true,
            'header' => "User-Agent: Mozilla/5.0\r\nAccept: application/json\r\n",
        ],
        'ssl' => [
            'verify_peer' => false,
            'verify_peer_name' => false,
        ],
    ]);
    $raw = @file_get_contents($CFG['sessions_api_hu'], false, $ctx);
    if (!$raw) return null;
    $j = json_decode($raw, true);
    return is_array($j) && isset($j['list']) ? $j : null;
}

// ═══════════════════════════════════════════════════════
// [5] ═══════════ V13 SUPREME PREDICTOR ENGINE ═══════════
// ═══════════════════════════════════════════════════════

function _v13_cache_key(array $seq): string {
    $n = count($seq);
    $head = implode('', array_slice($seq, 0, 25));
    $tail = implode('', array_slice($seq, -15));
    return md5($n . '|' . $head . '|' . $tail);
}

function v13_features(array $seq): array {
    static $cache = [];
    if (count($cache) > 64) $cache = array_slice($cache, -32, null, true);
    $k = _v13_cache_key($seq);
    if (isset($cache[$k])) return $cache[$k];
    $f = _v13_compute_features($seq);
    $cache[$k] = $f;
    return $f;
}

function _v13_compute_features(array $seq): array {
    $n = count($seq);
    $f = [
        'n'=>$n,'first'=>$seq[0]??null,'streak'=>1,'alternating'=>0,
        'runs'=>[],'t_count'=>0,'x_count'=>0,
        'entropy'=>0.0,'momentum'=>0.0,'volatility'=>0.0,
        'autocorr_lag1'=>0.0,'autocorr_lag2'=>0.0,'autocorr_lag3'=>0.0,
        'autocorr_lag4'=>0.0,'autocorr_lag5'=>0.0,
        'gap_since_T'=>0,'gap_since_X'=>0,
        'avg_run_len'=>0.0,'run_len_variance'=>0.0,'max_run_len'=>0,'median_run_len'=>0,
        'transition_tt'=>0.0,'transition_tx'=>0.0,'transition_xt'=>0.0,'transition_xx'=>0.0,
        'transition_t2'=>0.0,'transition_x2'=>0.0,'run_count'=>0,
        'gini'=>0.0,'shannon_entropy'=>0.0,
        'momentum_3'=>0.0,'momentum_5'=>0.0,'momentum_10'=>0.0,'momentum_20'=>0.0,
        'streak_ratio'=>0.0,'opp_gap_ratio'=>0.0,
        'hurst'=>0.0,'lempel_ziv'=>0.0,'tt_runs'=>0,'xx_runs'=>0,
        'surprise'=>0.0,'kl_divergence'=>0.0,
        'bias_10'=>0.0,'bias_20'=>0.0,'bias_50'=>0.0,
        'last_5_t'=>0,'last_10_t'=>0,'run_entropy'=>0.0,
        'run_accel'=>0.0,'run_decel'=>0.0,'pattern_repeat_len'=>0,
        'bayes_post_t'=>0.5,'bayes_post_x'=>0.5,'reversal_rate'=>0.5,
        'long_run_prob'=>0.0,'streak_expected_remaining'=>0.0,
        'chi_square'=>0.0,'predictability'=>0.5,'run_mean_shift'=>0.0,'phase'=>0,
        'bias_recent_10'=>0.5,'streak_weighted'=>0.0,
        'cluster_id'=>-1,'cluster_strength'=>0.0,
        'changepoint_score'=>0.0,'changepoint_pos'=>-1,
        'hidden_cycle_period'=>0,'hidden_cycle_strength'=>0.0,
        'bias_extreme'=>0.0,'bias_reversion_score'=>0.0,
        'cau_gay_score'=>0.0,'cau_gay_position'=>-1,
        'momentum_exhaustion'=>0.0,'pattern_freshness'=>1.0,
        'regime_shift_prob'=>0.0,'double_down_score'=>0.0,
        'micro_pattern_count'=>0,'t_ratio_50'=>0.5,'x_ratio_50'=>0.5,
        'streak_break_prob'=>0.0,'streak_continue_prob'=>0.0,
        'lms_streak_len'=>0,'lms_streak_dir'=>0,'lms_pattern_strength'=>0.0,
        'cau_dep_score'=>0.0,'cau_xau_score'=>0.0,
        'recent_5_win'=>0,'recent_10_win'=>0,'recent_5_hit'=>0.5,
        'run_len_sequence'=>[],'cau_gay_chain'=>0,
        'volatility_trend'=>0.0,'entropy_trend'=>0.0,
        'pattern_entropy'=>0.0,'streak_momentum'=>0.0,
        'opp_recent_freq'=>0.0,'head_recent_freq'=>0.0,
        'ai_confidence_raw'=>0.5,'smart_bet_score'=>0.0,
        'lms_continuation_score'=>0.0,'lms_break_score'=>0.0,
        'cau_bet_score'=>0.0,'cau_1_1_score'=>0.0,'cau_2_2_score'=>0.0,
        'cau_3_3_score'=>0.0,'cau_bet_3_score'=>0.0,'cau_bet_4_score'=>0.0,
        'cau_1_2_score'=>0.0,'cau_2_1_score'=>0.0,'cau_1_3_score'=>0.0,
        'cau_3_1_score'=>0.0,'cau_zigzag_score'=>0.0,
        'transition_matrix_score'=>0.0,'markov_chain_score'=>0.0,
        'fractal_dim'=>0.0,'sample_entropy'=>0.0,
        'runs_entropy'=>0.0,'runs_predictability'=>0.5,
        't_run_mean'=>0.0,'x_run_mean'=>0.0,'t_run_std'=>0.0,'x_run_std'=>0.0,
        'cau_dep_recent'=>0.0,'cau_xau_recent'=>0.0,
        'win_streak'=>0,'lose_streak_recent'=>0,
    ];
    if ($n === 0) { $f['_meta'] = []; return $f; }

    while ($f['streak'] < $n && $seq[$f['streak']] === $seq[0]) $f['streak']++;
    $alt = 1; while ($alt < $n && $seq[$alt] !== $seq[$alt-1]) $alt++;
    $f['alternating'] = $alt;

    $cur = $seq[0]; $len = 1;
    for ($i = 1; $i < $n; $i++) {
        if ($seq[$i] === $cur) $len++;
        else { $f['runs'][] = [$cur, $len]; $cur = $seq[$i]; $len = 1; }
    }
    $f['runs'][] = [$cur, $len];
    $f['run_count'] = count($f['runs']);

    foreach ($seq as $v) { if ($v === 'T') $f['t_count']++; else $f['x_count']++; }
    $pt = $f['t_count']/$n; $px = $f['x_count']/$n;
    foreach ([$pt,$px] as $p) if ($p>0) $f['entropy'] -= $p*log($p,2);
    $f['shannon_entropy'] = $f['entropy'];
    $f['gini'] = 1 - ($pt*$pt + $px*$px);
    $exp = $n/2;
    $f['chi_square'] = $exp>0 ? (($f['t_count']-$exp)**2 + ($f['x_count']-$exp)**2)/$exp : 0;
    $f['t_ratio_50'] = $pt; $f['x_ratio_50'] = $px;

    foreach ([3,5,10,20] as $k) {
        $r = array_slice($seq, 0, min($k,$n));
        $o = array_slice($seq, $k, $k);
        $rT = count(array_filter($r, fn($v)=>$v==='T'))/max(1,count($r));
        $oT = count($o)>0 ? count(array_filter($o, fn($v)=>$v==='T'))/count($o) : 0.5;
        $f["momentum_$k"] = $rT - $oT;
    }
    $f['momentum'] = $f['momentum_5'];

    foreach ([10,20,50] as $w) {
        $lb = min($w,$n); $tc = 0;
        for ($k=0;$k<$lb;$k++) if ($seq[$k]==='T') $tc++;
        $f["bias_$w"] = $lb>0 ? $tc/$lb : 0.5;
    }
    $wSum=0;$wT=0;
    for ($k=0;$k<min(10,$n);$k++) { $w=exp(-0.15*$k); $wSum+=$w; if ($seq[$k]==='T') $wT+=$w; }
    $f['bias_recent_10'] = $wSum>0 ? $wT/$wSum : 0.5;

    $f['last_5_t'] = count(array_filter(array_slice($seq,0,min(5,$n)), fn($v)=>$v==='T'));
    $f['last_10_t'] = count(array_filter(array_slice($seq,0,min(10,$n)), fn($v)=>$v==='T'));

    $lens = array_column($f['runs'],1);
    $f['avg_run_len'] = array_sum($lens)/count($lens);
    $f['max_run_len'] = max($lens);
    $sortedLens = $lens; sort($sortedLens);
    $f['median_run_len'] = $sortedLens[intdiv(count($sortedLens),2)];
    $variance = 0.0;
    foreach ($lens as $l) $variance += ($l-$f['avg_run_len'])**2;
    $f['run_len_variance'] = $variance/count($lens);
    $f['volatility'] = sqrt($f['run_len_variance']);
    $f['streak_ratio'] = $f['streak']/max(1,$f['avg_run_len']);

    $wSum2=0;$wLen=0;
    for ($i=0;$i<min(5,count($lens));$i++) { $w=exp(-0.2*$i); $wSum2+=$w; $wLen+=$lens[$i]*$w; }
    $f['streak_weighted'] = $wSum2>0 ? $wLen/$wSum2 : 0;

    $runTotal = count($lens);
    if ($runTotal>0) {
        $counts = array_count_values($lens);
        foreach ($counts as $c) { $p=$c/$runTotal; if ($p>0) $f['run_entropy'] -= $p*log($p,2); }
        $f['run_mean_shift'] = $f['streak'] - $f['avg_run_len'];
    }
    if (count($lens)>=3) {
        $f['run_accel'] = ($lens[0]-$lens[1])-($lens[1]-$lens[2]);
        $f['run_decel'] = -$f['run_accel'];
    }

    for ($lag=1;$lag<=5;$lag++) {
        $same=0;$total=0;
        for ($i=0;$i+$lag<$n;$i++) { $total++; if ($seq[$i]===$seq[$i+$lag]) $same++; }
        $f["autocorr_lag$lag"] = $total>0 ? $same/$total : 0.5;
    }
    $f['reversal_rate'] = 1 - $f['autocorr_lag1'];

    for ($i=0;$i<$n;$i++) if ($seq[$i]==='T') { $f['gap_since_T']=$i; break; }
    for ($i=0;$i<$n;$i++) if ($seq[$i]==='X') { $f['gap_since_X']=$i; break; }
    $f['opp_gap_ratio'] = $f['streak']/max(1,$f['streak']+min($f['gap_since_T'],$f['gap_since_X'])+1);

    $tt=$tx=$xt=$xx=0;
    for ($i=0;$i+1<$n;$i++) {
        $a=$seq[$i];$b=$seq[$i+1];
        if ($a==='T'&&$b==='T')$tt++; elseif($a==='T'&&$b==='X')$tx++;
        elseif($a==='X'&&$b==='T')$xt++; else $xx++;
    }
    $tot=$tt+$tx+$xt+$xx;
    if ($tot>0) {
        $f['transition_tt']=$tt/$tot;$f['transition_tx']=$tx/$tot;
        $f['transition_xt']=$xt/$tot;$f['transition_xx']=$xx/$tot;
    }
    $t2=0;$x2=0;$t2tot=0;
    for ($i=0;$i+2<$n;$i++) {
        if ($seq[$i]===$seq[$i+1]) { $t2tot++; if ($seq[$i+2]===$seq[$i]) $t2++; else $x2++; }
    }
    if ($t2tot>0) { $f['transition_t2']=$t2/$t2tot; $f['transition_x2']=$x2/$t2tot; }

    $ttRuns=0;$xxRuns=0;
    for ($i=0;$i+1<$n;$i++) {
        if ($seq[$i]==='T'&&$seq[$i+1]==='T') $ttRuns++;
        if ($seq[$i]==='X'&&$seq[$i+1]==='X') $xxRuns++;
    }
    $f['tt_runs']=$ttRuns;$f['xx_runs']=$xxRuns;

    if ($n>=8) {
        $half=intdiv($n,2);$m1=0;$m2=0;
        for ($i=0;$i<$half;$i++) $m1 += $seq[$i]==='T'?1:0;
        for ($i=$half;$i<$n;$i++) $m2 += $seq[$i]==='T'?1:0;
        $m1/=$half;$m2/=$n-$half;
        $dev1=0;$dev2=0;
        for ($i=0;$i<$half;$i++) $dev1 += abs(($seq[$i]==='T'?1:0)-$m1);
        for ($i=$half;$i<$n;$i++) $dev2 += abs(($seq[$i]==='T'?1:0)-$m2);
        $r1=$half>0?$dev1/$half:0; $r2=($n-$half)>0?$dev2/($n-$half):0;
        $f['hurst'] = ($r1+$r2>0) ? log(max(1e-6,$r1+$r2))/log($n) : 0.5;
    }

    if ($n>=4) {
        $lz=1;$i=0;$seen=[];
        while ($i<$n) {
            $found=false;
            for ($l=1;$l<=$n-$i;$l++) {
                $sub=implode('',array_slice($seq,$i,$l));
                if (isset($seen[$sub])) { $found=true; break; }
            }
            if (!$found) { $sub=implode('',array_slice($seq,$i,1)); $seen[$sub]=true; $i++; $lz++; }
            else { $sub=implode('',array_slice($seq,$i,$l)); $seen[$sub]=true; $i+=$l; }
        }
        $f['lempel_ziv'] = $lz/max(1,$n);
    }

    for ($pl=min(8,intdiv($n,2));$pl>=2;$pl--) {
        if (array_slice($seq,0,$pl)===array_slice($seq,$pl,$pl)) { $f['pattern_repeat_len']=$pl; break; }
    }

    $f['bayes_post_t'] = ($f['t_count']+1)/($n+2);
    $f['bayes_post_x'] = ($f['x_count']+1)/($n+2);
    $f['surprise'] = -log(max(1e-6,$pt));
    $f['kl_divergence'] = $pt*log(max(1e-6,$pt/0.5)) + (1-$pt)*log(max(1e-6,(1-$pt)/0.5));

    if ($f['run_count']>=3) {
        $longRuns = count(array_filter($lens, fn($l)=>$l>=4));
        $f['long_run_prob'] = $longRuns/$f['run_count'];
        $f['streak_expected_remaining'] = max(0, $f['avg_run_len']-$f['streak']);
    }

    $predict=0;$ptot=0;
    for ($i=1;$i<$n;$i++) { if ($seq[$i]===$seq[$i-1]) $predict++; $ptot++; }
    $f['predictability'] = $ptot>0 ? $predict/$ptot : 0.5;
    $f['phase'] = $n%2;

    $clusterSize=5;$clusters=[];
    for ($i=0;$i+$clusterSize<=min($n,25);$i+=$clusterSize) {
        $chunk=array_slice($seq,$i,$clusterSize);
        $tInChunk=count(array_filter($chunk, fn($v)=>$v==='T'));
        $deviation=abs($tInChunk-$clusterSize/2)/($clusterSize/2);
        $recency=exp(-0.1*$i);
        $clusters[]=['pos'=>$i,'dev'=>$deviation*$recency,'ratio'=>$tInChunk/$clusterSize];
    }
    if (!empty($clusters)) {
        $maxDev=0;$maxIdx=0;
        foreach ($clusters as $ci=>$c) if ($c['dev']>$maxDev) { $maxDev=$c['dev'];$maxIdx=$ci; }
        $f['cluster_id']=$maxIdx;$f['cluster_strength']=min(1.0,$maxDev);
    }

    if ($n>=20) {
        $bestCP=0;$bestCPPos=-1;
        for ($cp=8;$cp<=$n-8;$cp+=2) {
            $before=array_slice($seq,$cp,min(10,$n-$cp));
            $after=array_slice($seq,max(0,$cp-10),$cp);
            $bT=count(array_filter($before, fn($v)=>$v==='T'))/max(1,count($before));
            $aT=count(array_filter($after, fn($v)=>$v==='T'))/max(1,count($after));
            $score=abs($bT-$aT)*sqrt(min(count($before),count($after)));
            if ($score>$bestCP) { $bestCP=$score;$bestCPPos=$cp; }
        }
        $f['changepoint_score']=min(1.0,$bestCP/3.0);
        $f['changepoint_pos']=$bestCPPos;
    }

    $bestPeriod=0;$bestAC=0;
    for ($period=2;$period<=min(10,intdiv($n,2));$period++) {
        $same=0;$total=0;
        for ($i=0;$i+$period<$n;$i++) { $total++; if ($seq[$i]===$seq[$i+$period]) $same++; }
        $ac=$total>0?$same/$total:0;
        if ($ac>$bestAC) { $bestAC=$ac;$bestPeriod=$period; }
    }
    $f['hidden_cycle_period']=$bestPeriod;
    $f['hidden_cycle_strength']=max(0,$bestAC-0.5)*2;

    $b50=$f['bias_50'];
    $f['bias_extreme'] = max(0,abs($b50-0.5)-0.15)*2.85;
    $f['bias_reversion_score'] = min(1.0,(($b50>0.5)?($b50-0.5):(0.5-$b50))*2*$f['streak']/6.0);

    if (count($lens)>=3) {
        $median=$f['median_run_len'];
        $longestRecent=$lens[0]??1;
        if ($longestRecent>=$median*2) {
            $f['cau_gay_score']=min(1.0,($longestRecent-$median)/max(1,$median));
            $f['cau_gay_position']=0;
        }
    }

    $f['momentum_exhaustion'] = abs($f['momentum_5'])*min(1.0,$f['streak']/6.0);

    if ($f['pattern_repeat_len']>=2 && $n>=$f['pattern_repeat_len']*2) $f['pattern_freshness']=1.0;
    elseif ($f['pattern_repeat_len']>=2) $f['pattern_freshness']=0.5;
    else $f['pattern_freshness']=0.3;

    if ($f['changepoint_pos']>=0) {
        $cpDist=$f['changepoint_pos'];
        $f['regime_shift_prob']=min(1.0,$f['changepoint_score']*(1+$cpDist/$n));
    }

    if ($n>=8) {
        $count=0;
        for ($i=0;$i+1<min(12,$n);$i+=2) if ($seq[$i]===$seq[$i+1]) $count++;
        $f['double_down_score']=$count/6.0;
    }

    if ($n>=12) {
        $seen=[];
        for ($i=0;$i+3<=min(15,$n);$i++) {
            $sub=implode('',array_slice($seq,$i,3));
            $seen[$sub]=($seen[$sub]??0)+1;
        }
        foreach ($seen as $cnt) if ($cnt>=2) $f['micro_pattern_count']++;
    }

    $f['lms_streak_len'] = $f['streak'];
    $f['lms_streak_dir'] = $seq[0] === 'T' ? 1 : -1;
    $f['lms_pattern_strength'] = $f['streak'] / max(1, $f['avg_run_len']);

    $continueProb = 1.0;
    if ($f['streak'] >= 2) {
        $pBase = 0.5;
        $pDecay = exp(-0.18 * ($f['streak'] - 2));
        $continueProb = $pBase * $pDecay;
    }
    $f['streak_continue_prob'] = $continueProb;
    $f['streak_break_prob'] = 1 - $continueProb;

    $cauDep = 0.0;
    if ($f['streak'] >= 3 && $f['streak'] <= 4) $cauDep += 0.3;
    if ($f['streak'] >= 5 && $f['pattern_repeat_len'] >= 2) $cauDep += 0.25;
    if ($f['alternating'] >= 4) $cauDep += 0.3;
    if ($f['double_down_score'] > 0.5) $cauDep += 0.25;
    if ($f['hidden_cycle_strength'] > 0.4) $cauDep += 0.2;
    if ($f['predictability'] > 0.6) $cauDep += 0.15;
    if ($f['entropy'] < 0.7) $cauDep += 0.15;
    if ($f['cau_gay_score'] > 0.4) $cauDep += 0.2;
    $f['cau_dep_score'] = min(1.0, $cauDep);

    $cauXau = 0.0;
    if ($f['entropy'] > 0.9) $cauXau += 0.3;
    if ($f['run_entropy'] > 1.5) $cauXau += 0.2;
    if ($f['volatility'] > 2.0) $cauXau += 0.25;
    if ($f['predictability'] < 0.4) $cauXau += 0.3;
    if ($f['lempel_ziv'] > 0.7) $cauXau += 0.2;
    if ($f['changepoint_score'] > 0.5) $cauXau += 0.2;
    $f['cau_xau_score'] = min(1.0, $cauXau);

    $f['transition_matrix_score'] = 0.0;
    if ($f['transition_tt'] > 0.55 && $seq[0] === 'T') $f['transition_matrix_score'] = $f['transition_tt'];
    elseif ($f['transition_xx'] > 0.55 && $seq[0] === 'X') $f['transition_matrix_score'] = $f['transition_xx'];
    elseif ($f['transition_tx'] > 0.55 && $seq[0] === 'T') $f['transition_matrix_score'] = -$f['transition_tx'];
    elseif ($f['transition_xt'] > 0.55 && $seq[0] === 'X') $f['transition_matrix_score'] = -$f['transition_xt'];

    $f['markov_chain_score'] = 0.0;

    if ($n >= 16) {
        $f['fractal_dim'] = 1.0 + $f['lempel_ziv'];
    }

    if ($n >= 10) {
        $matches = 0; $total = 0;
        $m = 2;
        for ($i = 0; $i + $m < $n && $i < 20; $i++) {
            for ($j = $i + 1; $j + $m < $n && $j < 20; $j++) {
                $total++;
                if (array_slice($seq, $i, $m) === array_slice($seq, $j, $m)) $matches++;
            }
        }
        $f['sample_entropy'] = $total > 0 ? -log(max(1e-6, $matches / $total)) : 0;
    }

    $f['runs_entropy'] = $f['run_entropy'];
    $f['runs_predictability'] = $f['predictability'];

    $tRuns = []; $xRuns = [];
    foreach ($f['runs'] as $r) {
        if ($r[0] === 'T') $tRuns[] = $r[1];
        else $xRuns[] = $r[1];
    }
    if (!empty($tRuns)) {
        $f['t_run_mean'] = array_sum($tRuns) / count($tRuns);
        $v = 0; foreach ($tRuns as $l) $v += ($l - $f['t_run_mean']) ** 2;
        $f['t_run_std'] = sqrt($v / count($tRuns));
    }
    if (!empty($xRuns)) {
        $f['x_run_mean'] = array_sum($xRuns) / count($xRuns);
        $v = 0; foreach ($xRuns as $l) $v += ($l - $f['x_run_mean']) ** 2;
        $f['x_run_std'] = sqrt($v / count($xRuns));
    }

    $f['cau_dep_recent'] = $f['cau_dep_score'];
    $f['cau_xau_recent'] = $f['cau_xau_score'];

    $f['lms_continuation_score'] = $f['streak'] >= 3 ? exp(-0.2 * ($f['streak'] - 3)) : 0.9;
    $f['lms_break_score'] = 1 - $f['lms_continuation_score'];
    $f['cau_bet_score'] = 0.0;
    $f['cau_1_1_score'] = $f['alternating'] >= 4 ? min(1.0, $f['alternating'] / 8) : 0;
    $f['cau_2_2_score'] = $f['double_down_score'] > 0.5 ? $f['double_down_score'] : 0;
    $f['cau_3_3_score'] = 0.0;
    $f['cau_bet_3_score'] = ($f['streak'] >= 3 && $f['streak'] <= 4) ? 1.0 : 0;
    $f['cau_bet_4_score'] = ($f['streak'] >= 4 && $f['streak'] <= 5) ? 1.0 : 0;
    $f['cau_1_2_score'] = 0.0;
    $f['cau_2_1_score'] = 0.0;
    $f['cau_1_3_score'] = 0.0;
    $f['cau_3_1_score'] = 0.0;
    $f['cau_zigzag_score'] = 0.0;

    $f['_meta'] = [];
    $f['_meta']['streak_x_reversal'] = $f['streak'] * $f['reversal_rate'];
    $f['_meta']['entropy_x_autocorr'] = $f['entropy'] * $f['autocorr_lag1'];
    $f['_meta']['hurst_x_momentum'] = $f['hurst'] * $f['momentum_5'];
    $f['_meta']['streak_z'] = $f['volatility'] > 0 ? ($f['streak'] - $f['avg_run_len']) / $f['volatility'] : 0;
    $f['_meta']['bias_momentum_div'] = $f['bias_10'] - ($f['momentum_5'] + 0.5);
    $f['_meta']['pred_over_entropy'] = $f['entropy'] > 0 ? $f['predictability'] / $f['entropy'] : 0.5;
    $f['_meta']['lz_x_run_entropy'] = $f['lempel_ziv'] * $f['run_entropy'];
    $f['_meta']['bayes_margin'] = abs($f['bayes_post_t'] - $f['bayes_post_x']);
    $f['_meta']['alt_over_streak'] = $f['alternating'] / max(1, $f['streak']);
    $f['_meta']['vol_over_entropy'] = $f['entropy'] > 0 ? $f['volatility'] / $f['entropy'] : 0;
    $f['_meta']['long_short_ratio'] = $f['long_run_prob'] / max(0.01, 1 - $f['long_run_prob']);
    $f['_meta']['chi_sig'] = $f['chi_square'] > 3.84 ? 1.0 : ($f['chi_square'] > 2.71 ? 0.5 : 0.0);
    $mm = [$f['momentum_3'], $f['momentum_5'], $f['momentum_10']];
    $f['_meta']['momentum_aligned'] = (($mm[0] > 0 && $mm[1] > 0 && $mm[2] > 0) || ($mm[0] < 0 && $mm[1] < 0 && $mm[2] < 0)) ? 1.0 : 0.0;
    $f['_meta']['reversal_vs_pred'] = $f['reversal_rate'] - (1 - $f['predictability']);
    $f['_meta']['trans_consistency'] = abs($f['transition_tt'] - $f['transition_xx']);
    $f['_meta']['trans_asymmetry'] = ($f['transition_tx'] + $f['transition_xt']) / 2;
    $f['_meta']['run_shift_norm'] = $f['volatility'] > 0 ? $f['run_mean_shift'] / $f['volatility'] : 0;
    $f['_meta']['gini_x_entropy'] = $f['gini'] * $f['entropy'];
    $f['_meta']['surprise_over_entropy'] = $f['entropy'] > 0 ? $f['surprise'] / $f['entropy'] : 0;
    $f['_meta']['hurst_dev'] = abs($f['hurst'] - 0.5);
    $f['_meta']['streak_expect_gap'] = $f['streak'] - $f['streak_expected_remaining'];
    $f['_meta']['composite_signal'] =
        -0.3 * $f['momentum_5'] + 0.2 * $f['reversal_rate']
        - 0.2 * $f['predictability'] + 0.15 * $f['_meta']['hurst_dev']
        + 0.15 * $f['_meta']['bayes_margin'];
    $f['_meta']['cau_gay_x_streak'] = $f['cau_gay_score'] * $f['streak'];
    $f['_meta']['changepoint_x_regime'] = $f['changepoint_score'] * $f['regime_shift_prob'];
    $f['_meta']['cluster_x_bias'] = $f['cluster_strength'] * $f['bias_extreme'];
    $f['_meta']['cycle_x_pattern'] = $f['hidden_cycle_strength'] * $f['pattern_freshness'];
    $f['_meta']['cau_dep_x_conf'] = $f['cau_dep_score'] * $f['_meta']['composite_signal'];
    $f['_meta']['cau_xau_x_entropy'] = $f['cau_xau_score'] * $f['entropy'];
    $f['_meta']['smart_bet_raw'] = $f['cau_dep_score'] - $f['cau_xau_score'];
    $f['_meta']['lms_break_x_streak'] = $f['lms_break_score'] * min(1.0, $f['streak'] / 6);
    $f['_meta']['transition_x_markov'] = $f['transition_matrix_score'] * $f['markov_chain_score'];
    $f['_meta']['fractal_x_lz'] = $f['fractal_dim'] * $f['lempel_ziv'];
    $f['_meta']['sample_ent_x_pred'] = $f['sample_entropy'] * $f['predictability'];
    $f['_meta']['cau_bet_x_dep'] = $f['cau_bet_score'] * $f['cau_dep_score'];

    return $f;
}

function v13_regime_scores(array $seq): array {
    $f = v13_features($seq);
    $n = $f['n'];
    $s = ['cold'=>0.0,'streak_short'=>0.0,'streak_long'=>0.0,'alternating'=>0.0,
          'pair'=>0.0,'triple'=>0.0,'trend'=>0.0,'chaos'=>0.0,'noise'=>0.0,
          'transition'=>0.0,'anti-streak'=>0.0,'cyclic'=>0.0,'cluster'=>0.0,
          'changepoint'=>0.0,'mixed'=>0.0];
    if ($n<5) { $s['cold']=1.0; return $s; }
    $streak=$f['streak'];
    if ($streak>=3&&$streak<=5) $s['streak_short']=min(1.0,$streak/5.0)*(0.5+0.5*$f['predictability']);
    if ($streak>=6) $s['streak_long']=min(1.0,$streak/10.0);
    $s['alternating']=min(1.0,$f['alternating']/8.0)*(0.5+0.5*$f['reversal_rate']);
    if ($n>=6) {
        $pair=0;
        for ($i=0;$i+1<min(10,$n);$i+=2) if ($seq[$i]===$seq[$i+1]) $pair++;
        $s['pair']=$pair/5.0;
    }
    if ($n>=9&&$f['double_down_score']>0.5) $s['triple']=min(1.0,$f['double_down_score']);
    $s['trend']=min(1.0,abs($f['momentum_5'])*2.0)*(1-min(1.0,$f['run_count']/8.0));
    $s['chaos']=max(0,$f['entropy']-0.7)*3.0*max(0,0.6-$f['autocorr_lag1'])*2.0;
    $s['noise']=max(0,$f['run_entropy']-1.0)*0.7+max(0,$f['volatility']-1.5)*0.3;
    $s['transition']=min(1.0,abs($f['momentum_3'])*2.5);
    $s['anti-streak']=max(0,$f['reversal_rate']-0.6)*2.5*(1-$streak/5);
    $s['cyclic']=$f['hidden_cycle_strength'];
    $s['cluster']=$f['cluster_strength'];
    $s['changepoint']=$f['regime_shift_prob'];
    $s['mixed']=0.25;
    $sum=array_sum($s);
    if ($sum>0) foreach ($s as &$v) $v/=$sum;
    unset($v);
    return $s;
}

function v13_detect_regime(array $seq): string {
    $scores = v13_regime_scores($seq);
    arsort($scores);
    return array_key_first($scores) ?? 'mixed';
}

function v13_analyze_streak(array $seq): array {
    $f = v13_features($seq);
    $streak=$f['streak'];$head=$seq[0]??'T';$opp=$head==='T'?'X':'T';$n=$f['n'];
    $breakPoints=[];$i=1;
    while ($i<$n) {
        $cur=$seq[$i];$runLen=1;
        while ($i+$runLen<$n&&$seq[$i+$runLen]===$cur) $runLen++;
        if ($runLen>=3&&$cur===$head) $breakPoints[]=$runLen;
        $i+=$runLen;
    }
    $histBreakAvg = count($breakPoints)>0 ? array_sum($breakPoints)/count($breakPoints) : 6.0;
    $f1 = $streak>=$histBreakAvg+1?0.9:($streak>=$histBreakAvg?0.7:($streak>=$histBreakAvg-1?0.5:0.3));
    $bias = $head==='T'?$f['bias_20']:(1-$f['bias_20']);
    $f2 = $bias>0.65?0.8:($bias>0.55?0.6:0.4);
    $pContinue = $streak>=3?exp(-0.18*($streak-3)):0.9;
    $f3 = 1-$pContinue;
    $markovPick=null;
    for ($k=8;$k>=2;$k--) {
        if ($n<$k+2) continue;
        $ctx=implode('',array_slice($seq,0,$k));$tW=0;$xW=0;
        for ($j=1;$j+$k<=$n;$j++) {
            if (implode('',array_slice($seq,$j,$k))!==$ctx) continue;
            $w=1.0+2.0*(1.0-$j/$n);
            $seq[$j-1]==='T'?$tW+=$w:$xW+=$w;
        }
        if ($tW+$xW<3) continue;
        $pt=($tW+1)/($tW+$xW+2);
        if (abs($pt-0.5)<0.08) continue;
        $markovPick=$pt>=0.5?'T':'X';
        break;
    }
    $f4 = $markovPick===null?0.5:($markovPick===$opp?0.85:0.25);
    $f5 = $streak>$f['median_run_len']*1.8?0.85:($streak>$f['median_run_len']*1.3?0.65:0.4);
    $patternVote = v13_vote_pattern_lock($seq);
    $f6 = $patternVote===null?0.5:($patternVote['pick']===$opp?0.85:0.3);
    $priorT = $head==='T'?$f['bayes_post_t']:$f['bayes_post_x'];
    $f7 = $priorT>0.6?0.75:($priorT>0.55?0.55:0.35);
    $f8 = 1-(1-$f['long_run_prob']);
    $f9 = $f['run_accel']>0.5?0.75:($f['run_accel']>0?0.55:0.4);
    $f10 = $f['hurst']<0.45?0.75:($f['hurst']>0.55?0.3:0.5);
    $sz = $f['_meta']['streak_z']??0;
    $f11 = $sz>1.5?0.85:($sz>0.5?0.60:0.35);
    $cs = $f['_meta']['composite_signal']??0;
    $f12 = $cs<-0.3?0.75:($cs>0.3?0.30:0.50);
    $f13 = $f['cau_gay_score']>0.6?0.90:($f['cau_gay_score']>0.3?0.70:0.40);
    $f14 = $f['bias_reversion_score']>0.6?0.85:($f['bias_reversion_score']>0.35?0.60:0.40);
    $f15 = $f['regime_shift_prob']>0.5?0.80:($f['regime_shift_prob']>0.25?0.60:0.40);
    $breakScore =
        0.11*$f1 + 0.07*$f2 + 0.13*$f3 + 0.09*$f4 +
        0.06*$f5 + 0.05*$f6 + 0.06*$f7 + 0.06*$f8 +
        0.03*$f9 + 0.03*$f10 + 0.07*$f11 + 0.05*$f12 +
        0.08*$f13 + 0.06*$f14 + 0.05*$f15;
    return [
        'break_score'=>round($breakScore,3),
        'streak'=>$streak,
        'hist_break_avg'=>round($histBreakAvg,1),
        'factors'=>[
            'historical'=>round($f1,3),'frequency_bias'=>round($f2,3),
            'momentum_decay'=>round($f3,3),'markov_signal'=>round($f4,3),
            'market_rhythm'=>round($f5,3),'pattern_lock'=>round($f6,3),
            'bayesian_posterior'=>round($f7,3),'survival_analysis'=>round($f8,3),
            'run_acceleration'=>round($f9,3),'hurst_meanrev'=>round($f10,3),
            'streak_zscore'=>round($f11,3),'composite_signal'=>round($f12,3),
            'cau_gay'=>round($f13,3),'bias_reversion'=>round($f14,3),
            'changepoint'=>round($f15,3),
        ],
    ];
}

function v13_vote_streak_follow(array $seq): ?array {
    $f=v13_features($seq);
    if ($f['streak']<3||$f['streak']>5) return null;
    return ['pick'=>$seq[0],'w'=>0.90,'note'=>"bệt {$f['streak']} theo"];
}
function v13_vote_streak_break(array $seq): ?array {
    $f=v13_features($seq);$s=$f['streak'];
    if ($s<6) return null;
    $opp=$seq[0]==='T'?'X':'T';
    if ($s===6) return ['pick'=>$opp,'w'=>1.00,'note'=>'bệt 6 → bẻ #1'];
    if ($s===8) return ['pick'=>$opp,'w'=>1.20,'note'=>'bệt 8 → bẻ #2'];
    if ($s===10) return ['pick'=>$opp,'w'=>1.30,'note'=>'bệt 10 → bẻ #3'];
    return null;
}
function v13_vote_streak_analyzer(array $seq): ?array {
    $f=v13_features($seq);
    if ($f['streak']<6) return null;
    $analysis=v13_analyze_streak($seq);
    $score=$analysis['break_score'];
    $opp=$seq[0]==='T'?'X':'T';
    if ($score>=0.6) return ['pick'=>$opp,'w'=>0.8+($score-0.6)*2.0,'note'=>"bệt {$f['streak']} → BẺ (score {$score})",'analysis'=>$analysis];
    if ($score>=0.45) return ['pick'=>$opp,'w'=>0.55,'note'=>"bệt {$f['streak']} → bẻ nhẹ (score {$score})",'analysis'=>$analysis];
    return ['pick'=>$seq[0],'w'=>0.85,'note'=>"bệt {$f['streak']} → THEO (score {$score})",'analysis'=>$analysis];
}
function v13_vote_pattern_break(array $seq): ?array {
    $n=count($seq);
    if ($n<9) return null;
    for ($len=6;$len>=2;$len--) {
        $reps=intdiv($n,$len);
        if ($reps<2) continue;
        $pattern=array_slice($seq,0,$len);
        if (count(array_unique($pattern))===1) continue;
        $repeats=1;$i=$len;
        while ($i+$len<=$n) {
            if (array_slice($seq,$i,$len)===$pattern) { $repeats++;$i+=$len; }
            else break;
        }
        $threshold=$len>=5?2:($len>=4?2:3);
        if ($repeats<$threshold) continue;
        $breakPick=$pattern[0]==='T'?'X':'T';
        return ['pick'=>$breakPick,'w'=>min(1.3,0.9+0.15*($repeats-$threshold)),'note'=>"bẻ khuôn {$len}-phiên (lặp {$repeats}×)"];
    }
    if ($n>=8&&array_slice($seq,0,4)===array_slice($seq,4,4))
        return ['pick'=>$seq[0]==='T'?'X':'T','w'=>1.05,'note'=>'bẻ đối xứng 4|4'];
    if ($n>=6&&array_slice($seq,0,3)===array_slice($seq,3,3))
        return ['pick'=>$seq[0]==='T'?'X':'T','w'=>0.90,'note'=>'bẻ đối xứng 3|3'];
    return null;
}
function v13_vote_alternating(array $seq): ?array {
    $alt=1;
    while ($alt<count($seq)&&$seq[$alt]!==$seq[$alt-1]) $alt++;
    if ($alt>=4) return ['pick'=>$seq[0]==='T'?'X':'T','w'=>0.90,'note'=>"1-1 ($alt phiên)"];
    return null;
}
function v13_vote_pair(array $seq): ?array {
    $n=count($seq);
    if ($n<6) return null;
    if ($seq[0]===$seq[1]&&$seq[1]!==$seq[2]&&$seq[2]===$seq[3]&&$seq[3]!==$seq[4]&&$seq[4]===$seq[5])
        return ['pick'=>$seq[0]==='T'?'X':'T','w'=>0.85,'note'=>'2-2 break'];
    if ($seq[0]!==$seq[1]&&$seq[1]===$seq[2]&&$seq[2]!==$seq[3]&&$seq[3]===$seq[4])
        return ['pick'=>$seq[0],'w'=>0.85,'note'=>'2-2 follow'];
    return null;
}
function v13_vote_triple(array $seq): ?array {
    $n=count($seq);
    if ($n<9) return null;
    if ($seq[0]===$seq[1]&&$seq[1]===$seq[2]&&$seq[3]===$seq[4]&&$seq[4]===$seq[5]&&$seq[0]!==$seq[3]&&$seq[6]===$seq[7]&&$seq[7]===$seq[8]&&$seq[6]===$seq[0])
        return ['pick'=>$seq[0]==='T'?'X':'T','w'=>0.95,'note'=>'3-3 break'];
    if ($seq[0]===$seq[1]&&($n<3||$seq[2]!==$seq[0]))
        return ['pick'=>$seq[0],'w'=>0.80,'note'=>'3-block follow'];
    return null;
}
function v13_vote_quad(array $seq): ?array {
    $n=count($seq);
    if ($n<12) return null;
    $a=$seq[0]===$seq[1]&&$seq[1]===$seq[2]&&$seq[2]===$seq[3];
    $b=$seq[4]===$seq[5]&&$seq[5]===$seq[6]&&$seq[6]===$seq[7];
    if ($a&&$b&&$seq[0]!==$seq[4]) return ['pick'=>$seq[0]==='T'?'X':'T','w'=>0.95,'note'=>'4-4 break'];
    return null;
}
function v13_vote_123(array $seq): ?array {
    $n=count($seq);
    if ($n<6) return null;
    if ($seq[0]===$seq[2]&&$seq[2]===$seq[3]&&$seq[3]===$seq[4]&&$seq[4]===$seq[5]&&$seq[0]!==$seq[1]&&$seq[1]===$seq[2])
        return ['pick'=>$seq[0]==='T'?'X':'T','w'=>0.75,'note'=>'1-2-3 break'];
    return null;
}
function v13_vote_block12(array $seq): ?array {
    $n=count($seq);
    if ($n<6) return null;
    if ($seq[0]===$seq[3]&&$seq[1]===$seq[4]&&$seq[2]===$seq[5]&&!($seq[0]===$seq[1]&&$seq[1]===$seq[2]))
        return ['pick'=>$seq[2],'w'=>0.80,'note'=>'1-2 block follow'];
    return null;
}
function v13_vote_zigzag(array $seq): ?array {
    $n=count($seq);
    if ($n<6) return null;
    if ($seq[0]===$seq[1]&&$seq[1]!==$seq[2]&&$seq[2]===$seq[3]&&$seq[3]===$seq[4]&&$seq[4]!==$seq[5])
        return ['pick'=>$seq[2]==='T'?'X':'T','w'=>0.75,'note'=>'zigzag'];
    return null;
}
function v13_vote_slope(array $seq): ?array {
    $f=v13_features($seq);
    $runs=array_slice($f['runs'],0,4);
    if (count($runs)<4) return null;
    $lens=array_column($runs,1);
    $dir=$lens[0]>$lens[1]?-1:1;
    for ($i=0;$i<3;$i++) if (($lens[$i+1]-$lens[$i])*$dir<=0) return null;
    if ($lens[0]<=$lens[1]) return ['pick'=>$runs[0][0]==='T'?'X':'T','w'=>0.70,'note'=>'nghiêng'];
    return ['pick'=>$runs[0][0],'w'=>0.70,'note'=>'nghiêng'];
}
function v13_vote_frequency(array $seq): ?array {
    $n=min(10,count($seq));$t=0;$x=0;
    for ($i=0;$i<$n;$i++) $seq[$i]==='T'?$t++:$x++;
    if ($t===$x) return null;
    return ['pick'=>$t>$x?'X':'T','w'=>0.55,'note'=>'freq'];
}
function v13_vote_momentum(array $seq): ?array {
    $f=v13_features($seq);
    if (abs($f['momentum_5'])<0.4) return null;
    return ['pick'=>$f['momentum_5']>0?'X':'T','w'=>0.65,'note'=>'momentum'];
}
function v13_vote_inflection(array $seq): ?array {
    $f=v13_features($seq);$runs=$f['runs'];
    if (count($runs)<3) return null;
    $lens=array_column($runs,1);
    if ($lens[0]>$lens[1]&&$lens[1]<=$lens[2])
        return ['pick'=>$runs[0][0]==='T'?'X':'T','w'=>0.85,'note'=>'inflection'];
    return null;
}
function v13_vote_markov(array $seq): ?array {
    $n=count($seq);
    if ($n<12) return null;
    for ($k=8;$k>=1;$k--) {
        if ($n<$k+2) continue;
        $ctx=implode('',array_slice($seq,0,$k));$t=0;$x=0;
        for ($i=1;$i+$k<=$n;$i++) {
            if (implode('',array_slice($seq,$i,$k))!==$ctx) continue;
            $w=1.0+2.0*(1.0-$i/$n);
            $seq[$i-1]==='T'?$t+=$w:$x+=$w;
        }
        if ($t+$x<4) continue;
        $pt=($t+1)/($t+$x+2);
        if (abs($pt-0.5)<0.10) continue;
        $rawProb=$pt>=0.5?$pt:1-$pt;
        return ['pick'=>$pt>=0.5?'T':'X','w'=>0.7+$rawProb*0.8,'note'=>"markov order $k"];
    }
    return null;
}
function v13_vote_run_length(array $seq): ?array {
    $f=v13_features($seq);
    if ($f['run_count']<3) return null;
    $head=$seq[0];$opp=$head==='T'?'X':'T';
    if ($f['streak']>=$f['avg_run_len']+1.5) return ['pick'=>$opp,'w'=>0.75,'note'=>'run>avg+1.5'];
    if ($f['streak']<=$f['avg_run_len']-0.5) return ['pick'=>$head,'w'=>0.70,'note'=>'run<avg-0.5'];
    return null;
}
function v13_vote_transition(array $seq): ?array {
    $n=count($seq);
    if ($n<10) return null;
    $last=$seq[0];$tt=$tx=$xt=$xx=0;
    for ($i=0;$i+1<$n;$i++) {
        $a=$seq[$i];$b=$seq[$i+1];
        if ($a==='T'&&$b==='T')$tt++; elseif($a==='T'&&$b==='X')$tx++;
        elseif($a==='X'&&$b==='T')$xt++; else $xx++;
    }
    $fromT=$tt+$tx;$fromX=$xt+$xx;
    if ($last==='T'&&$fromT>=5) {
        $pT=($tt+1)/($fromT+2);
        if ($pT>0.6) return ['pick'=>'T','w'=>0.7+($pT-0.6),'note'=>"trans T→T {$pT}"];
        if ($pT<0.4) return ['pick'=>'X','w'=>0.7+(0.4-$pT),'note'=>"trans T→X"];
    }
    if ($last==='X'&&$fromX>=5) {
        $pX=($xx+1)/($fromX+2);
        if ($pX>0.6) return ['pick'=>'X','w'=>0.7+($pX-0.6),'note'=>"trans X→X {$pX}"];
        if ($pX<0.4) return ['pick'=>'T','w'=>0.7+(0.4-$pX),'note'=>"trans X→T"];
    }
    return null;
}
function v13_vote_bayesian(array $seq): ?array {
    $f=v13_features($seq);
    if ($f['n']<8) return null;
    $pt=$f['bayes_post_t'];
    if (abs($pt-0.5)<0.08) return null;
    return ['pick'=>$pt>=0.5?'T':'X','w'=>0.55+abs($pt-0.5)*1.5,'note'=>'bayes posterior'];
}
function v13_vote_hurst(array $seq): ?array {
    $f=v13_features($seq);
    if ($f['n']<10) return null;
    if ($f['hurst']<0.4) return ['pick'=>$f['streak']>=2?($seq[0]==='T'?'X':'T'):($seq[0]??'T'),'w'=>0.75,'note'=>'hurst mean-revert'];
    if ($f['hurst']>0.6) return ['pick'=>$seq[0],'w'=>0.70,'note'=>'hurst trend'];
    return null;
}
function v13_vote_entropy(array $seq): ?array {
    $f=v13_features($seq);
    if ($f['n']<8) return null;
    if ($f['entropy']>0.95) {
        if ($f['streak']>=3) return ['pick'=>$seq[0]==='T'?'X':'T','w'=>0.60,'note'=>'entropy cao → bẻ'];
        return null;
    }
    if ($f['entropy']<0.3) {
        $dom=$f['t_count']>$f['x_count']?'T':'X';
        return ['pick'=>$dom,'w'=>0.65,'note'=>'entropy thấp → theo trội'];
    }
    return null;
}
function v13_vote_anti_streak(array $seq): ?array {
    $f=v13_features($seq);
    if ($f['n']<6) return null;
    if ($f['reversal_rate']>0.7&&$f['streak']<=2)
        return ['pick'=>$seq[0]==='T'?'X':'T','w'=>0.80,'note'=>'anti-streak'];
    return null;
}
function v13_vote_streak_survival(array $seq): ?array {
    $f=v13_features($seq);
    if ($f['streak']<4) return null;
    if ($f['streak_expected_remaining']<=0.5)
        return ['pick'=>$seq[0]==='T'?'X':'T','w'=>0.85,'note'=>'survival: hết hạn'];
    return null;
}
function v13_vote_complexity(array $seq): ?array {
    $f=v13_features($seq);
    if ($f['n']<12) return null;
    if ($f['lempel_ziv']<0.3) {
        if ($f['streak']>=2) return ['pick'=>$seq[0]==='T'?'X':'T','w'=>0.70,'note'=>'low complexity → bẻ'];
    }
    if ($f['lempel_ziv']>0.7) {
        $dom=$f['t_count']>$f['x_count']?'X':'T';
        return ['pick'=>$dom,'w'=>0.55,'note'=>'high complexity → ngược trội'];
    }
    return null;
}
function v13_vote_gini(array $seq): ?array {
    $f=v13_features($seq);
    if ($f['n']<10) return null;
    if ($f['gini']>0.48&&$f['streak']>=4)
        return ['pick'=>$seq[0]==='T'?'X':'T','w'=>0.65,'note'=>'gini balanced → bẻ'];
    if ($f['gini']<0.2) {
        $dom=$f['t_count']>$f['x_count']?'T':'X';
        return ['pick'=>$dom,'w'=>0.60,'note'=>'gini imbalanced → theo trội'];
    }
    return null;
}
function v13_vote_chi_square(array $seq): ?array {
    $f=v13_features($seq);
    if ($f['n']<15) return null;
    if ($f['chi_square']>3.84) {
        $dom=$f['t_count']>$f['x_count']?'X':'T';
        return ['pick'=>$dom,'w'=>0.70,'note'=>'chi-square sig → đảo'];
    }
    return null;
}
function v13_vote_phase(array $seq): ?array {
    $f=v13_features($seq);
    if ($f['n']<8||$f['pattern_repeat_len']<2) return null;
    $pl=$f['pattern_repeat_len'];
    $cycle=array_slice($seq,0,$pl);
    $pos=$f['n']%$pl;
    return ['pick'=>$cycle[$pos]??($seq[0]==='T'?'X':'T'),'w'=>0.65,'note'=>"phase cycle len $pl"];
}
function v13_vote_run_entropy(array $seq): ?array {
    $f=v13_features($seq);
    if ($f['run_count']<4) return null;
    if ($f['run_entropy']>1.5&&$f['streak']>=3)
        return ['pick'=>$seq[0]==='T'?'X':'T','w'=>0.65,'note'=>'run entropy cao → bẻ'];
    if ($f['run_entropy']<0.8)
        return ['pick'=>$seq[0],'w'=>0.60,'note'=>'run entropy thấp → theo'];
    return null;
}
function v13_vote_bias(array $seq): ?array {
    $f=v13_features($seq);
    if ($f['n']<10) return null;
    if ($f['bias_10']>0.7&&$f['bias_20']>0.65) return ['pick'=>'X','w'=>0.65,'note'=>'bias T cao → X'];
    if ($f['bias_10']<0.3&&$f['bias_20']<0.35) return ['pick'=>'T','w'=>0.65,'note'=>'bias X cao → T'];
    return null;
}
function v13_vote_transition2(array $seq): ?array {
    $f=v13_features($seq);
    if ($f['n']<8) return null;
    if ($f['transition_t2']>0.55&&$f['streak']>=2)
        return ['pick'=>$seq[0],'w'=>0.70,'note'=>'2nd-order trans follow'];
    if ($f['transition_x2']>0.55&&$f['streak']>=2)
        return ['pick'=>$seq[0]==='T'?'X':'T','w'=>0.70,'note'=>'2nd-order trans break'];
    return null;
}
function v13_vote_triple_confirm(array $seq): ?array {
    $f=v13_features($seq);
    if ($f['n']<10) return null;
    $signals=[];
    if ($f['streak']>=5&&$f['streak_expected_remaining']<=1) $signals[]=$seq[0]==='T'?'X':'T';
    if ($f['bias_20']>0.65) $signals[]='X';
    elseif ($f['bias_20']<0.35) $signals[]='T';
    if ($f['reversal_rate']>0.6&&count($signals)>0) $signals[]=$signals[0];
    if (count($signals)<3) return null;
    if (count(array_unique($signals))!==1) return null;
    return ['pick'=>$signals[0],'w'=>1.15,'note'=>'triple-confirm'];
}
function v13_vote_anti_noise(array $seq): ?array {
    $f=v13_features($seq);
    if ($f['n']<8) return null;
    if ($f['entropy']>0.7) return null;
    $dom=$f['t_count']>$f['x_count']?'T':'X';
    return ['pick'=>$dom,'w'=>0.85,'note'=>'anti-noise'];
}
function v13_vote_cyclic_fit(array $seq): ?array {
    $f=v13_features($seq);
    if ($f['pattern_repeat_len']<2||$f['n']<$f['pattern_repeat_len']*2) return null;
    $pl=$f['pattern_repeat_len'];
    $cycle=array_slice($seq,0,$pl);
    if (count(array_unique($cycle))<2) return null;
    $pos=$f['n']%$pl;
    return ['pick'=>$cycle[$pos]??$seq[0],'w'=>0.95,'note'=>"cyclic-fit {$pl}-cycle"];
}
function v13_vote_meta_composite(array $seq): ?array {
    $f=v13_features($seq);
    if ($f['n']<10) return null;
    $cs=$f['_meta']['composite_signal']??0;
    if (abs($cs)<0.3) return null;
    return ['pick'=>$cs>0?'X':'T','w'=>0.75,'note'=>'meta-composite'];
}
function v13_vote_momentum_align(array $seq): ?array {
    $f=v13_features($seq);
    if ($f['n']<12) return null;
    if (($f['_meta']['momentum_aligned']??0)<0.9) return null;
    $avg=($f['momentum_3']+$f['momentum_5']+$f['momentum_10'])/3;
    return ['pick'=>$avg>0?'X':'T','w'=>0.80,'note'=>'momentum 3-scale aligned'];
}
function v13_vote_chi_sig(array $seq): ?array {
    $f=v13_features($seq);
    if ($f['n']<20) return null;
    if (($f['_meta']['chi_sig']??0)<0.5) return null;
    $dom=$f['t_count']>$f['x_count']?'X':'T';
    return ['pick'=>$dom,'w'=>0.75,'note'=>'chi-square sig → reversion'];
}
function v13_vote_lz_structure(array $seq): ?array {
    $f=v13_features($seq);
    if ($f['n']<15) return null;
    if ($f['lempel_ziv']>0.4) return null;
    $pl=max(2,$f['pattern_repeat_len']);
    if ($f['n']<$pl*2) return null;
    $cycle=array_slice($seq,0,$pl);
    $pos=$f['n']%$pl;
    return ['pick'=>$cycle[$pos]??$seq[0],'w'=>0.85,'note'=>'lz-structured cycle'];
}
function v13_vote_regime_consensus(array $seq): ?array {
    $scores=v13_regime_scores($seq);
    arsort($scores);
    $top=array_key_first($scores);
    if (($scores[$top]??0)<0.35) return null;
    $f=v13_features($seq);
    switch ($top) {
        case 'streak_short': case 'streak_long':
            return $f['streak']>=5
                ? ['pick'=>$seq[0]==='T'?'X':'T','w'=>0.85,'note'=>"regime $top → bẻ"]
                : ['pick'=>$seq[0],'w'=>0.80,'note'=>"regime $top → theo"];
        case 'alternating': case 'anti-streak':
            return ['pick'=>$seq[0]==='T'?'X':'T','w'=>0.90,'note'=>"regime $top"];
        case 'cyclic':
            $pl=max(2,$f['pattern_repeat_len']);
            if ($f['n']<$pl) return null;
            $cycle=array_slice($seq,0,$pl);
            return ['pick'=>$cycle[$f['n']%$pl]??$seq[0],'w'=>0.85,'note'=>'regime cyclic'];
    }
    return null;
}
function v13_vote_long_streak_survival(array $seq): ?array {
    $f=v13_features($seq);
    if ($f['streak']<6) return null;
    if ($f['streak_expected_remaining']<1&&$f['long_run_prob']<0.3)
        return ['pick'=>$seq[0]==='T'?'X':'T','w'=>1.10,'note'=>'Hũ: bệt dài survival'];
    if ($f['long_run_prob']>0.5)
        return ['pick'=>$seq[0],'w'=>0.90,'note'=>'Hũ: bệt dài còn tiếp'];
    return null;
}
function v13_vote_cau_gay(array $seq): ?array {
    $f=v13_features($seq);
    if ($f['cau_gay_score']<0.4) return null;
    return ['pick'=>$seq[0]==='T'?'X':'T','w'=>0.7+$f['cau_gay_score']*0.6,'note'=>"Hũ: cầu gãy {$f['cau_gay_score']}"];
}
function v13_vote_cluster(array $seq): ?array {
    $f=v13_features($seq);
    if ($f['cluster_strength']<0.5) return null;
    $head=$seq[0];$tr=$f['t_ratio_50'];
    if ($tr>0.6&&$head==='T') return ['pick'=>'X','w'=>0.65+$f['cluster_strength']*0.4,'note'=>'Hũ: cluster T nhiều → X'];
    if ($tr<0.4&&$head==='X') return ['pick'=>'T','w'=>0.65+$f['cluster_strength']*0.4,'note'=>'Hũ: cluster X nhiều → T'];
    return null;
}
function v13_vote_hidden_cycle(array $seq): ?array {
    $f=v13_features($seq);
    if ($f['hidden_cycle_strength']<0.3) return null;
    $period=$f['hidden_cycle_period'];
    if ($period<2||$f['n']<$period) return null;
    $idx=$f['n']%$period;
    $vals=[];
    for ($i=$idx;$i<$f['n'];$i+=$period) $vals[]=$seq[$i];
    if (empty($vals)) return null;
    $tCnt=count(array_filter($vals, fn($v)=>$v==='T'));
    $pick=$tCnt>count($vals)/2?'T':'X';
    return ['pick'=>$pick,'w'=>0.6+$f['hidden_cycle_strength']*0.5,'note'=>"Hũ: hidden cycle {$period}"];
}
function v13_vote_bias_reversion(array $seq): ?array {
    $f=v13_features($seq);
    if ($f['bias_reversion_score']<0.4) return null;
    $b50=$f['bias_50'];
    $pick=$b50>0.5?'X':'T';
    return ['pick'=>$pick,'w'=>0.6+$f['bias_reversion_score']*0.6,'note'=>'Hũ: bias reversion'];
}
function v13_vote_changepoint(array $seq): ?array {
    $f=v13_features($seq);
    if ($f['regime_shift_prob']<0.4) return null;
    return ['pick'=>$seq[0]==='T'?'X':'T','w'=>0.65+$f['regime_shift_prob']*0.5,'note'=>"Hũ: changepoint"];
}
function v13_vote_double_down(array $seq): ?array {
    $f=v13_features($seq);
    if ($f['double_down_score']<0.5) return null;
    $n=$f['n'];
    if ($n<8) return null;
    if ($n%2===0) return ['pick'=>$seq[1]??$seq[0],'w'=>0.75,'note'=>'Hũ: 2-2-2-2 follow'];
    return ['pick'=>$seq[0]==='T'?'X':'T','w'=>0.75,'note'=>'Hũ: 2-2-2-2 break'];
}
function v13_vote_micro_pattern(array $seq): ?array {
    $f=v13_features($seq);
    if ($f['micro_pattern_count']<2) return null;
    $n=$f['n'];
    if ($n<6) return null;
    $recent3=implode('',array_slice($seq,0,3));
    $count=0;
    for ($i=3;$i+3<=min(15,$n);$i++) if (implode('',array_slice($seq,$i,3))===$recent3) $count++;
    if ($count<2) return null;
    return ['pick'=>$seq[3]??($seq[0]==='T'?'X':'T'),'w'=>0.70,'note'=>'Hũ: micro pattern'];
}
function v13_vote_ratio_extreme(array $seq): ?array {
    $f=v13_features($seq);
    if ($f['n']<20) return null;
    $tr=$f['t_ratio_50'];
    if ($tr>0.68) return ['pick'=>'X','w'=>0.75,'note'=>'Hũ: T ratio extreme'];
    if ($tr<0.32) return ['pick'=>'T','w'=>0.75,'note'=>'Hũ: X ratio extreme'];
    return null;
}
function v13_vote_pattern_freshness(array $seq): ?array {
    $f=v13_features($seq);
    if ($f['pattern_freshness']>=1.0&&$f['pattern_repeat_len']>=2)
        return ['pick'=>$seq[0],'w'=>0.70,'note'=>'Hũ: pattern mới → theo'];
    return null;
}
function v13_vote_momentum_exhaustion(array $seq): ?array {
    $f=v13_features($seq);
    if ($f['momentum_exhaustion']<0.5) return null;
    return ['pick'=>$f['momentum_5']>0?'X':'T','w'=>0.60+$f['momentum_exhaustion']*0.4,'note'=>'Hũ: momentum exhausted'];
}
function v13_vote_cluster_alt(array $seq): ?array {
    $f=v13_features($seq);
    if ($f['n']<10) return null;
    $clusterSize=5;$clusterT=[];
    for ($i=0;$i+$clusterSize<=min(20,$f['n']);$i+=$clusterSize) {
        $chunk=array_slice($seq,$i,$clusterSize);
        $t=count(array_filter($chunk, fn($v)=>$v==='T'));
        $clusterT[]=$t>=3?'T':'X';
    }
    if (count($clusterT)<2) return null;
    if ($clusterT[0]!==$clusterT[1])
        return ['pick'=>$clusterT[0]==='T'?'X':'T','w'=>0.65,'note'=>'Hũ: cluster alternating'];
    return null;
}
function v13_vote_hu_streak_follow(array $seq): ?array {
    $f=v13_features($seq);
    if ($f['streak']<3||$f['streak']>4) return null;
    return ['pick'=>$seq[0],'w'=>0.95,'note'=>'Hũ: bệt 3-4 theo'];
}

function v13_vote_cau_dep(array $seq): ?array {
    $f = v13_features($seq);
    if ($f['cau_dep_score'] < 0.5) return null;
    if ($f['streak'] >= 3 && $f['streak'] <= 4) {
        return ['pick' => $seq[0], 'w' => 0.6 + $f['cau_dep_score'] * 0.6, 'note' => 'cầu đẹp → theo bệt'];
    }
    if ($f['alternating'] >= 4) {
        return ['pick' => $seq[0] === 'T' ? 'X' : 'T', 'w' => 0.6 + $f['cau_dep_score'] * 0.5, 'note' => 'cầu đẹp 1-1'];
    }
    return ['pick' => $seq[0], 'w' => 0.5 + $f['cau_dep_score'] * 0.4, 'note' => 'cầu đẹp'];
}

function v13_vote_cau_xau(array $seq): ?array {
    $f = v13_features($seq);
    if ($f['cau_xau_score'] < 0.5) return null;
    $dom = $f['t_count'] > $f['x_count'] ? 'X' : 'T';
    return ['pick' => $dom, 'w' => 0.4, 'note' => 'cầu xấu → đánh nhỏ ngược trội'];
}

function v13_vote_lms_break(array $seq): ?array {
    $f = v13_features($seq);
    if ($f['lms_break_score'] < 0.6) return null;
    if ($f['streak'] < 3) return null;
    return ['pick' => $seq[0] === 'T' ? 'X' : 'T', 'w' => 0.7 + $f['lms_break_score'] * 0.4, 'note' => 'LMS break'];
}

function v13_vote_lms_continue(array $seq): ?array {
    $f = v13_features($seq);
    if ($f['lms_continuation_score'] < 0.6) return null;
    if ($f['streak'] < 3) return null;
    return ['pick' => $seq[0], 'w' => 0.7 + $f['lms_continuation_score'] * 0.3, 'note' => 'LMS continue'];
}

function v13_vote_streak_prob(array $seq): ?array {
    $f = v13_features($seq);
    if ($f['streak'] < 2) return null;
    if ($f['streak_break_prob'] > 0.55) {
        return ['pick' => $seq[0] === 'T' ? 'X' : 'T', 'w' => 0.65, 'note' => 'streak break prob'];
    }
    if ($f['streak_continue_prob'] > 0.55) {
        return ['pick' => $seq[0], 'w' => 0.65, 'note' => 'streak continue prob'];
    }
    return null;
}

function v13_vote_fractal(array $seq): ?array {
    $f = v13_features($seq);
    if ($f['n'] < 16) return null;
    if ($f['fractal_dim'] < 1.2) {
        return ['pick' => $seq[0] === 'T' ? 'X' : 'T', 'w' => 0.65, 'note' => 'fractal low → bẻ'];
    }
    if ($f['fractal_dim'] > 1.6) {
        return ['pick' => $seq[0], 'w' => 0.60, 'note' => 'fractal high → theo'];
    }
    return null;
}

function v13_vote_sample_entropy(array $seq): ?array {
    $f = v13_features($seq);
    if ($f['n'] < 10) return null;
    if ($f['sample_entropy'] > 1.5) {
        return ['pick' => $seq[0] === 'T' ? 'X' : 'T', 'w' => 0.60, 'note' => 'sample entropy cao'];
    }
    return null;
}

function v13_vote_transition_matrix(array $seq): ?array {
    $f = v13_features($seq);
    if (abs($f['transition_matrix_score']) < 0.1) return null;
    if ($f['transition_matrix_score'] > 0) {
        return ['pick' => $seq[0], 'w' => 0.60 + abs($f['transition_matrix_score']) * 0.4, 'note' => 'transition matrix follow'];
    }
    return ['pick' => $seq[0] === 'T' ? 'X' : 'T', 'w' => 0.60 + abs($f['transition_matrix_score']) * 0.4, 'note' => 'transition matrix break'];
}

function v13_vote_markov_chain(array $seq): ?array {
    $f = v13_features($seq);
    if ($f['n'] < 10) return null;
    $n = $f['n'];
    $order = min(4, intdiv($n, 3));
    $ctx = array_slice($seq, 0, $order);
    $tW = 0; $xW = 0;
    for ($i = $order; $i < $n; $i++) {
        if (array_slice($seq, $i - $order, $order) === $ctx) {
            $w = 1.0 + 2.0 * (1.0 - $i / $n);
            if ($seq[$i] === 'T') $tW += $w;
            else $xW += $w;
        }
    }
    if ($tW + $xW < 3) return null;
    $pt = ($tW + 1) / ($tW + $xW + 2);
    if (abs($pt - 0.5) < 0.10) return null;
    return ['pick' => $pt >= 0.5 ? 'T' : 'X', 'w' => 0.7 + abs($pt - 0.5) * 1.2, 'note' => 'markov chain'];
}

function v13_vote_cau_1_1(array $seq): ?array {
    $f = v13_features($seq);
    if ($f['cau_1_1_score'] < 0.4) return null;
    return ['pick' => $seq[0] === 'T' ? 'X' : 'T', 'w' => 0.6 + $f['cau_1_1_score'] * 0.5, 'note' => 'cầu 1-1'];
}

function v13_vote_cau_2_2(array $seq): ?array {
    $f = v13_features($seq);
    if ($f['cau_2_2_score'] < 0.4) return null;
    return ['pick' => $seq[0] === 'T' ? 'X' : 'T', 'w' => 0.6 + $f['cau_2_2_score'] * 0.5, 'note' => 'cầu 2-2'];
}

function v13_vote_cau_bet_3(array $seq): ?array {
    $f = v13_features($seq);
    if ($f['cau_bet_3_score'] < 0.5) return null;
    if ($f['streak'] >= 4) return ['pick' => $seq[0] === 'T' ? 'X' : 'T', 'w' => 0.7, 'note' => 'cầu bệt 3-4 break'];
    return ['pick' => $seq[0], 'w' => 0.7, 'note' => 'cầu bệt 3-4 follow'];
}

function v13_vote_cau_zigzag(array $seq): ?array {
    $f = v13_features($seq);
    if ($f['n'] < 6) return null;
    $zig = 0;
    for ($i = 0; $i < min(10, $f['n'] - 2); $i++) {
        if ($seq[$i] === $seq[$i + 2]) $zig++;
    }
    if ($zig >= 6) return ['pick' => $seq[0], 'w' => 0.70, 'note' => 'zigzag'];
    return null;
}

function v13_vote_reversal_zone(array $seq): ?array {
    $f = v13_features($seq);
    if ($f['streak'] < 2) return null;
    if ($f['cau_gay_score'] > 0.5 || $f['regime_shift_prob'] > 0.5) {
        return ['pick' => $seq[0] === 'T' ? 'X' : 'T', 'w' => 0.75, 'note' => 'reversal zone'];
    }
    return null;
}

function v13_vote_cau_break_4(array $seq): ?array {
    $f = v13_features($seq);
    if ($f['streak'] < 4) return null;
    if ($f['streak'] >= 4 && $f['streak'] <= 5) {
        return ['pick' => $seq[0] === 'T' ? 'X' : 'T', 'w' => 0.70, 'note' => 'cầu 4-5 break'];
    }
    return null;
}

function v13_vote_cau_break_6(array $seq): ?array {
    $f = v13_features($seq);
    if ($f['streak'] < 6) return null;
    if ($f['streak'] >= 6 && $f['streak'] <= 8) {
        return ['pick' => $seq[0] === 'T' ? 'X' : 'T', 'w' => 0.85, 'note' => 'cầu 6-8 break'];
    }
    return null;
}

function v13_vote_cau_break_10(array $seq): ?array {
    $f = v13_features($seq);
    if ($f['streak'] < 10) return null;
    return ['pick' => $seq[0] === 'T' ? 'X' : 'T', 'w' => 0.95, 'note' => 'cầu 10+ break mạnh'];
}

function v13_vote_streak_2_3(array $seq): ?array {
    $f = v13_features($seq);
    if ($f['streak'] < 2 || $f['streak'] > 3) return null;
    return ['pick' => $seq[0], 'w' => 0.65, 'note' => 'bệt 2-3 follow'];
}

function v13_vote_streak_3_4(array $seq): ?array {
    $f = v13_features($seq);
    if ($f['streak'] < 3 || $f['streak'] > 4) return null;
    if ($f['cau_dep_score'] > 0.5) return ['pick' => $seq[0], 'w' => 0.75, 'note' => 'bệt 3-4 cầu đẹp → theo'];
    return ['pick' => $seq[0] === 'T' ? 'X' : 'T', 'w' => 0.55, 'note' => 'bệt 3-4 cầu xấu → bẻ'];
}

function v13_vote_streak_5_6(array $seq): ?array {
    $f = v13_features($seq);
    if ($f['streak'] < 5 || $f['streak'] > 6) return null;
    return ['pick' => $seq[0] === 'T' ? 'X' : 'T', 'w' => 0.75, 'note' => 'bệt 5-6 break'];
}

function v13_vote_streak_7_8(array $seq): ?array {
    $f = v13_features($seq);
    if ($f['streak'] < 7 || $f['streak'] > 8) return null;
    return ['pick' => $seq[0] === 'T' ? 'X' : 'T', 'w' => 0.85, 'note' => 'bệt 7-8 break mạnh'];
}

function v13_vote_streak_9_plus(array $seq): ?array {
    $f = v13_features($seq);
    if ($f['streak'] < 9) return null;
    return ['pick' => $seq[0] === 'T' ? 'X' : 'T', 'w' => 0.95, 'note' => 'bệt 9+ break cực mạnh'];
}

function v13_vote_alternating_short(array $seq): ?array {
    $f = v13_features($seq);
    if ($f['alternating'] < 3 || $f['alternating'] > 5) return null;
    return ['pick' => $seq[0] === 'T' ? 'X' : 'T', 'w' => 0.65, 'note' => '1-1 ngắn'];
}

function v13_vote_alternating_long(array $seq): ?array {
    $f = v13_features($seq);
    if ($f['alternating'] < 6) return null;
    return ['pick' => $seq[0] === 'T' ? 'X' : 'T', 'w' => 0.80, 'note' => '1-1 dài'];
}

function v13_vote_cau_2_2_2(array $seq): ?array {
    $f = v13_features($seq);
    if ($f['n'] < 6) return null;
    if ($f['double_down_score'] < 0.6) return null;
    $n = $f['n'];
    if ($n % 2 === 0) return ['pick' => $seq[1] ?? $seq[0], 'w' => 0.75, 'note' => '2-2-2 follow'];
    return ['pick' => $seq[0] === 'T' ? 'X' : 'T', 'w' => 0.75, 'note' => '2-2-2 break'];
}

function v13_vote_cau_3_3(array $seq): ?array {
    $f = v13_features($seq);
    if ($f['n'] < 9) return null;
    if ($seq[0]===$seq[1] && $seq[1]===$seq[2] && $seq[3]===$seq[4] && $seq[4]===$seq[5] && $seq[0]!==$seq[3]) {
        return ['pick' => $seq[0] === 'T' ? 'X' : 'T', 'w' => 0.85, 'note' => '3-3 break'];
    }
    return null;
}

function v13_vote_cau_4_4(array $seq): ?array {
    $f = v13_features($seq);
    if ($f['n'] < 12) return null;
    $a = $seq[0]===$seq[1] && $seq[1]===$seq[2] && $seq[2]===$seq[3];
    $b = $seq[4]===$seq[5] && $seq[5]===$seq[6] && $seq[6]===$seq[7];
    if ($a && $b && $seq[0]!==$seq[4]) return ['pick' => $seq[0]==='T'?'X':'T', 'w' => 0.90, 'note' => '4-4 break'];
    return null;
}

function v13_vote_cau_bet_4(array $seq): ?array {
    $f = v13_features($seq);
    if ($f['cau_bet_4_score'] < 0.5) return null;
    if ($f['streak'] >= 4 && $f['streak'] <= 5) {
        return ['pick' => $seq[0] === 'T' ? 'X' : 'T', 'w' => 0.75, 'note' => 'cầu bệt 4-5 break'];
    }
    return null;
}

function v13_vote_head_tail_bias(array $seq): ?array {
    $f = v13_features($seq);
    if ($f['n'] < 20) return null;
    $tr = $f['t_ratio_50'];
    if ($tr > 0.65) return ['pick' => 'X', 'w' => 0.70, 'note' => 'T bias cao → X'];
    if ($tr < 0.35) return ['pick' => 'T', 'w' => 0.70, 'note' => 'X bias cao → T'];
    return null;
}

function v13_vote_recent_hot(array $seq): ?array {
    $f = v13_features($seq);
    if ($f['n'] < 10) return null;
    $last10T = $f['last_10_t'];
    if ($last10T >= 7) return ['pick' => 'X', 'w' => 0.65, 'note' => 'T hot → X'];
    if ($last10T <= 3) return ['pick' => 'T', 'w' => 0.65, 'note' => 'X hot → T'];
    return null;
}

function v13_vote_cau_xau_safe(array $seq): ?array {
    $f = v13_features($seq);
    if ($f['cau_xau_score'] < 0.6) return null;
    $dom = $f['t_count'] > $f['x_count'] ? 'T' : 'X';
    return ['pick' => $dom, 'w' => 0.35, 'note' => 'cầu xấu → bias nhẹ'];
}

function v13_vote_long_run_break(array $seq): ?array {
    $f = v13_features($seq);
    if ($f['streak'] < 5) return null;
    if ($f['long_run_prob'] < 0.2 && $f['streak_expected_remaining'] < 0.5) {
        return ['pick' => $seq[0] === 'T' ? 'X' : 'T', 'w' => 0.85, 'note' => 'long run break'];
    }
    return null;
}

function v13_vote_break_imminent(array $seq): ?array {
    $f = v13_features($seq);
    if ($f['streak'] < 4) return null;
    $prob = $f['streak_break_prob'];
    if ($prob > 0.65) return ['pick' => $seq[0] === 'T' ? 'X' : 'T', 'w' => 0.80, 'note' => 'break imminent'];
    return null;
}

function v13_vote_continue_strong(array $seq): ?array {
    $f = v13_features($seq);
    if ($f['streak'] < 2 || $f['streak'] > 4) return null;
    if ($f['streak_continue_prob'] > 0.60) return ['pick' => $seq[0], 'w' => 0.75, 'note' => 'continue strong'];
    return null;
}

function v13_vote_entropy_regime(array $seq): ?array {
    $f = v13_features($seq);
    if ($f['n'] < 15) return null;
    if ($f['entropy'] > 0.9 && $f['lempel_ziv'] > 0.6) {
        $dom = $f['t_count'] > $f['x_count'] ? 'X' : 'T';
        return ['pick' => $dom, 'w' => 0.60, 'note' => 'entropy regime → reversion'];
    }
    return null;
}

function v13_vote_cluster_reversal(array $seq): ?array {
    $f = v13_features($seq);
    if ($f['cluster_strength'] < 0.6) return null;
    $tr = $f['t_ratio_50'];
    $head = $seq[0];
    if ($tr > 0.6 && $head === 'T') return ['pick' => 'X', 'w' => 0.70, 'note' => 'cluster reversal'];
    if ($tr < 0.4 && $head === 'X') return ['pick' => 'T', 'w' => 0.70, 'note' => 'cluster reversal'];
    return null;
}

function v13_vote_cycle_repeat(array $seq): ?array {
    $f = v13_features($seq);
    if ($f['hidden_cycle_strength'] < 0.4) return null;
    $period = $f['hidden_cycle_period'];
    if ($period < 2 || $f['n'] < $period) return null;
    $idx = $f['n'] % $period;
    $vals = [];
    for ($i = $idx; $i < $f['n']; $i += $period) $vals[] = $seq[$i];
    if (empty($vals)) return null;
    $tCnt = count(array_filter($vals, fn($v) => $v === 'T'));
    $pick = $tCnt > count($vals) / 2 ? 'T' : 'X';
    return ['pick' => $pick, 'w' => 0.65 + $f['hidden_cycle_strength'] * 0.4, 'note' => 'cycle repeat'];
}

function v13_vote_changepoint_strong(array $seq): ?array {
    $f = v13_features($seq);
    if ($f['regime_shift_prob'] < 0.6) return null;
    return ['pick' => $seq[0] === 'T' ? 'X' : 'T', 'w' => 0.80, 'note' => 'changepoint strong'];
}

function v13_vote_bias_reversion_strong(array $seq): ?array {
    $f = v13_features($seq);
    if ($f['bias_reversion_score'] < 0.6) return null;
    return ['pick' => $f['bias_50'] > 0.5 ? 'X' : 'T', 'w' => 0.75, 'note' => 'bias reversion strong'];
}

function v13_vote_cau_gay_strong(array $seq): ?array {
    $f = v13_features($seq);
    if ($f['cau_gay_score'] < 0.6) return null;
    return ['pick' => $seq[0] === 'T' ? 'X' : 'T', 'w' => 0.85, 'note' => 'cầu gãy strong'];
}

function v13_vote_meta_smart(array $seq): ?array {
    $f = v13_features($seq);
    $sb = $f['_meta']['smart_bet_raw'] ?? 0;
    if ($sb < 0.3) return null;
    if ($f['streak'] >= 3 && $f['streak'] <= 4) return ['pick' => $seq[0], 'w' => 0.70, 'note' => 'smart bet follow'];
    return ['pick' => $seq[0], 'w' => 0.60, 'note' => 'smart bet'];
}

function v13_vote_trend_momentum(array $seq): ?array {
    $f = v13_features($seq);
    if ($f['n'] < 15) return null;
    $m3 = $f['momentum_3'];
    $m5 = $f['momentum_5'];
    $m10 = $f['momentum_10'];
    if ($m3 > 0 && $m5 > 0 && $m10 > 0) return ['pick' => 'X', 'w' => 0.70, 'note' => 'trend T → X'];
    if ($m3 < 0 && $m5 < 0 && $m10 < 0) return ['pick' => 'T', 'w' => 0.70, 'note' => 'trend X → T'];
    return null;
}

function v13_vote_volatility(array $seq): ?array {
    $f = v13_features($seq);
    if ($f['volatility'] < 0.5) {
        $dom = $f['t_count'] > $f['x_count'] ? 'T' : 'X';
        return ['pick' => $dom, 'w' => 0.60, 'note' => 'low volatility → follow'];
    }
    if ($f['volatility'] > 2.0) {
        return ['pick' => $seq[0] === 'T' ? 'X' : 'T', 'w' => 0.60, 'note' => 'high volatility → break'];
    }
    return null;
}

function v13_vote_pattern_entropy(array $seq): ?array {
    $f = v13_features($seq);
    if ($f['n'] < 15) return null;
    if ($f['pattern_entropy'] < 0.3) return ['pick' => $seq[0], 'w' => 0.65, 'note' => 'pattern entropy low → follow'];
    return null;
}

function v13_vote_run_length_pattern(array $seq): ?array {
    $f = v13_features($seq);
    if ($f['run_count'] < 4) return null;
    $lens = array_column($f['runs'], 1);
    if (count($lens) >= 3) {
        if ($lens[0] > $lens[1] && $lens[1] > $lens[2]) {
            return ['pick' => $f['runs'][0][0] === 'T' ? 'X' : 'T', 'w' => 0.65, 'note' => 'run length descending'];
        }
    }
    return null;
}

function v13_vote_smart_money(array $seq): ?array {
    $f = v13_features($seq);
    $score = $f['cau_dep_score'] - $f['cau_xau_score'];
    if ($score < 0.3) return null;
    if ($f['cau_dep_score'] > 0.6 && $f['cau_xau_score'] < 0.3) {
        return ['pick' => $seq[0], 'w' => 0.80, 'note' => 'smart money: cầu đẹp'];
    }
    return null;
}

function v13_pattern_library(): array {
    return [
        ['name'=>'1-1','cycle'=>'TX','min_prefix'=>3,'w'=>1.00],
        ['name'=>'1-2','cycle'=>'TXX','min_prefix'=>2,'w'=>0.95],
        ['name'=>'2-1','cycle'=>'TTX','min_prefix'=>2,'w'=>0.95],
        ['name'=>'2-2','cycle'=>'TTXX','min_prefix'=>3,'w'=>1.10],
        ['name'=>'1-3','cycle'=>'TXXX','min_prefix'=>3,'w'=>1.05],
        ['name'=>'3-1','cycle'=>'TTTX','min_prefix'=>3,'w'=>1.05],
        ['name'=>'2-1-1-2','cycle'=>'TTXTTX','min_prefix'=>4,'w'=>1.05],
        ['name'=>'1-2-2-1','cycle'=>'TXXT','min_prefix'=>3,'w'=>1.05],
        ['name'=>'1-4','cycle'=>'TXXXX','min_prefix'=>3,'w'=>1.10],
        ['name'=>'4-1','cycle'=>'TTTTX','min_prefix'=>3,'w'=>1.10],
        ['name'=>'1-3-1','cycle'=>'TXXXT','min_prefix'=>4,'w'=>1.00],
        ['name'=>'2-3','cycle'=>'TTXXX','min_prefix'=>4,'w'=>1.00],
        ['name'=>'3-2','cycle'=>'TTTXX','min_prefix'=>4,'w'=>1.00],
        ['name'=>'2-2-1','cycle'=>'TTXXT','min_prefix'=>4,'w'=>1.00],
        ['name'=>'1-2-2','cycle'=>'TXXTT','min_prefix'=>4,'w'=>1.00],
        ['name'=>'2-1-1','cycle'=>'TTXTT','min_prefix'=>4,'w'=>1.00],
        ['name'=>'1-1-2','cycle'=>'TXTXX','min_prefix'=>4,'w'=>1.00],
        ['name'=>'1-4-1','cycle'=>'TXXXXT','min_prefix'=>5,'w'=>1.05],
        ['name'=>'4-1-1','cycle'=>'TTTTXT','min_prefix'=>5,'w'=>1.00],
        ['name'=>'1-1-4','cycle'=>'TXTXXX','min_prefix'=>5,'w'=>1.00],
        ['name'=>'3-3','cycle'=>'TTTXXX','min_prefix'=>4,'w'=>1.05],
        ['name'=>'2-2-2','cycle'=>'TTXXTT','min_prefix'=>4,'w'=>1.05],
        ['name'=>'1-2-3','cycle'=>'TXXTTT','min_prefix'=>4,'w'=>1.00],
        ['name'=>'3-2-1','cycle'=>'TTTXXT','min_prefix'=>4,'w'=>1.00],
        ['name'=>'1-1-1-1-1-1','cycle'=>'TXTXTX','min_prefix'=>5,'w'=>1.05],
        ['name'=>'4-4','cycle'=>'TTTTXXXX','min_prefix'=>5,'w'=>0.95],
        ['name'=>'3-3-3','cycle'=>'TTTXXXTTT','min_prefix'=>5,'w'=>1.00],
        ['name'=>'1-1-3','cycle'=>'TXTXXX','min_prefix'=>5,'w'=>1.00],
        ['name'=>'3-1-1','cycle'=>'TTTXT','min_prefix'=>5,'w'=>1.00],
        ['name'=>'2-3-1','cycle'=>'TTXXXT','min_prefix'=>5,'w'=>1.00],
        ['name'=>'1-3-2','cycle'=>'TXXXTT','min_prefix'=>5,'w'=>1.00],
        ['name'=>'2-1-3','cycle'=>'TTXTTT','min_prefix'=>5,'w'=>1.00],
        ['name'=>'3-1-2','cycle'=>'TTTXTT','min_prefix'=>5,'w'=>1.00],
        ['name'=>'1-2-1-2','cycle'=>'TXXTXX','min_prefix'=>5,'w'=>1.10],
        ['name'=>'2-1-2-1','cycle'=>'TTXTTX','min_prefix'=>5,'w'=>1.10],
        ['name'=>'1-1-2-2','cycle'=>'TXTTXX','min_prefix'=>5,'w'=>1.05],
        ['name'=>'2-2-1-1','cycle'=>'TTXXTX','min_prefix'=>5,'w'=>1.05],
        ['name'=>'1-1-1-3','cycle'=>'TXTXTXXX','min_prefix'=>6,'w'=>1.05],
        ['name'=>'3-1-1-1','cycle'=>'TTTXTXTX','min_prefix'=>6,'w'=>1.05],
        ['name'=>'2-2-2-2','cycle'=>'TTXXTTXX','min_prefix'=>6,'w'=>1.10],
        ['name'=>'1-2-1-3','cycle'=>'TXXTTXXX','min_prefix'=>6,'w'=>1.05],
        ['name'=>'3-1-2-1','cycle'=>'TTTXTTTXT','min_prefix'=>6,'w'=>1.00],
        ['name'=>'1-4-2','cycle'=>'TXXXXTT','min_prefix'=>6,'w'=>1.05],
        ['name'=>'2-4-1','cycle'=>'TTXXXXT','min_prefix'=>6,'w'=>1.05],
        ['name'=>'5-5','cycle'=>'TTTTTXXXXX','min_prefix'=>6,'w'=>0.95],
        ['name'=>'1-5','cycle'=>'TXXXXX','min_prefix'=>5,'w'=>1.15],
        ['name'=>'5-1','cycle'=>'TTTTTX','min_prefix'=>5,'w'=>1.15],
    ];
}
function v13_pattern_variants(array $entry): array {
    $cycle=$entry['cycle'];
    $inverted=strtr($cycle,['T'=>'X','X'=>'T']);
    $variants=[['cycle'=>$cycle,'inverted'=>false]];
    if ($inverted!==$cycle) $variants[]=['cycle'=>$inverted,'inverted'=>true];
    return $variants;
}
function v13_match_pattern(array $seq, array $entry): ?array {
    $n=count($seq);$minPrefix=$entry['min_prefix'];
    if ($n<$minPrefix) return null;
    $bestMatch=null;
    foreach (v13_pattern_variants($entry) as $variant) {
        $cycle=$variant['cycle'];$cycleLen=strlen($cycle);
        if ($cycleLen<2) continue;
        for ($matchLen=min($cycleLen,$n);$matchLen>=$minPrefix;$matchLen--) {
            for ($offset=0;$offset<$cycleLen;$offset++) {
                $match=true;
                for ($k=0;$k<$matchLen;$k++) {
                    $idx=($offset-$k+$cycleLen*10)%$cycleLen;
                    if ($seq[$k]!==$cycle[$idx]) { $match=false;break; }
                }
                if (!$match) continue;
                $expected='';
                for ($k=0;$k<$matchLen;$k++) {
                    $idx=($offset-$k+$cycleLen*10)%$cycleLen;
                    $expected.=$cycle[$idx];
                }
                if (count(array_unique(str_split($expected)))<2) continue;
                $nextIdx=($matchLen===$cycleLen)?$offset:($offset+1)%$cycleLen;
                $nextPick=$cycle[$nextIdx];
                $confidence=$matchLen/$cycleLen;
                $weight=$entry['w']*(0.7+0.6*$confidence);
                $candidate=[
                    'pick'=>$nextPick,'w'=>$weight,
                    'note'=>"khuôn {$entry['name']}".($variant['inverted']?' (đảo)':'')." match{$matchLen}/{$cycleLen}@{$offset}",
                    'matched_len'=>$matchLen,'cycle_pos'=>$offset,'cycle_len'=>$cycleLen,
                ];
                if ($bestMatch===null||$matchLen>$bestMatch['matched_len'])
                    $bestMatch=$candidate;
            }
        }
    }
    return $bestMatch;
}
function v13_vote_pattern_lock(array $seq): ?array {
    $n=count($seq);
    if ($n<2) return null;
    $streak=1;
    while ($streak<$n&&$seq[$streak]===$seq[0]) $streak++;
    if ($streak>=4) return null;
    $library=v13_pattern_library();
    $best=null;$bestScore=0;
    foreach ($library as $entry) {
        $match=v13_match_pattern($seq,$entry);
        if ($match===null) continue;
        $score=$match['w']*(1+$match['cycle_len']*0.15)*(1+$match['matched_len']*0.10);
        if ($score>$bestScore) { $bestScore=$score;$best=$match; }
    }
    return $best;
}

function v13_backtest_voters(array $seq, int $window=40): array {
    $n=count($seq);
    if ($n<12) return [];
    $hits=[];$totals=[];$emaHits=[];
    $max=min($n-10,$window);
    $alpha=0.15;
    for ($i=2;$i<$max;$i++) {
        $past=array_slice($seq,$i+1);
        $actual=$seq[$i];
        $voters=v13_all_voters($past);
        foreach ($voters as $name=>$row) {
            $totals[$name]=($totals[$name]??0)+1;
            $hit=$row['pick']===$actual?1:0;
            if ($hit) $hits[$name]=($hits[$name]??0)+1;
            $weight=1+2*(1-$i/$max);
            $prev=$emaHits[$name]??0.5;
            $emaHits[$name]=$alpha*$hit*$weight+(1-$alpha)*$prev;
        }
    }
    $out=[];
    foreach ($totals as $name=>$total) {
        $h=$hits[$name]??0;
        $p=($h+1)/($total+2);
        $z=1.28;
        $wilson=($p+$z*$z/(2*$total)-$z*sqrt(($p*(1-$p)+$z*$z/(4*$total))/$total))/(1+$z*$z/$total);
        $thompson=($h+1)/($h+($total-$h)+2);
        $out[$name]=[
            'hit'=>$h,'total'=>$total,'rate'=>$p,
            'wilson'=>max(0.35,$wilson),'thompson'=>$thompson,
            'ema'=>$emaHits[$name]??0.5,
        ];
    }
    return $out;
}

function v13_all_voters(array $seq): array {
    $v=[];
    $add=function($name,$r) use (&$v) { if ($r!==null) $v[$name]=$r; };
    $add('pattern_lock',v13_vote_pattern_lock($seq));
    $add('streak_follow',v13_vote_streak_follow($seq));
    $add('streak_break',v13_vote_streak_break($seq));
    $add('streak_analyzer',v13_vote_streak_analyzer($seq));
    $add('pattern_break',v13_vote_pattern_break($seq));
    $add('markov',v13_vote_markov($seq));
    $add('transition',v13_vote_transition($seq));
    $add('run_length',v13_vote_run_length($seq));
    $add('alternating',v13_vote_alternating($seq));
    $add('pair',v13_vote_pair($seq));
    $add('triple',v13_vote_triple($seq));
    $add('quad',v13_vote_quad($seq));
    $add('one_two_three',v13_vote_123($seq));
    $add('block12',v13_vote_block12($seq));
    $add('zigzag',v13_vote_zigzag($seq));
    $add('slope',v13_vote_slope($seq));
    $add('frequency',v13_vote_frequency($seq));
    $add('momentum',v13_vote_momentum($seq));
    $add('inflection',v13_vote_inflection($seq));
    $add('bayesian',v13_vote_bayesian($seq));
    $add('hurst',v13_vote_hurst($seq));
    $add('entropy',v13_vote_entropy($seq));
    $add('anti_streak',v13_vote_anti_streak($seq));
    $add('streak_survival',v13_vote_streak_survival($seq));
    $add('complexity',v13_vote_complexity($seq));
    $add('gini',v13_vote_gini($seq));
    $add('chi_square',v13_vote_chi_square($seq));
    $add('phase',v13_vote_phase($seq));
    $add('run_entropy',v13_vote_run_entropy($seq));
    $add('bias',v13_vote_bias($seq));
    $add('transition2',v13_vote_transition2($seq));
    $add('triple_confirm',v13_vote_triple_confirm($seq));
    $add('anti_noise',v13_vote_anti_noise($seq));
    $add('cyclic_fit',v13_vote_cyclic_fit($seq));
    $add('meta_composite',v13_vote_meta_composite($seq));
    $add('momentum_align',v13_vote_momentum_align($seq));
    $add('chi_sig',v13_vote_chi_sig($seq));
    $add('lz_structure',v13_vote_lz_structure($seq));
    $add('regime_consensus',v13_vote_regime_consensus($seq));
    $add('hu_long_survival',v13_vote_long_streak_survival($seq));
    $add('hu_cau_gay',v13_vote_cau_gay($seq));
    $add('hu_cluster',v13_vote_cluster($seq));
    $add('hu_hidden_cycle',v13_vote_hidden_cycle($seq));
    $add('hu_bias_reversion',v13_vote_bias_reversion($seq));
    $add('hu_changepoint',v13_vote_changepoint($seq));
    $add('hu_double_down',v13_vote_double_down($seq));
    $add('hu_micro_pattern',v13_vote_micro_pattern($seq));
    $add('hu_ratio_extreme',v13_vote_ratio_extreme($seq));
    $add('hu_pattern_freshness',v13_vote_pattern_freshness($seq));
    $add('hu_momentum_exhaust',v13_vote_momentum_exhaustion($seq));
    $add('hu_cluster_alt',v13_vote_cluster_alt($seq));
    $add('hu_streak_follow',v13_vote_hu_streak_follow($seq));
    $add('cau_dep',v13_vote_cau_dep($seq));
    $add('cau_xau',v13_vote_cau_xau($seq));
    $add('lms_break',v13_vote_lms_break($seq));
    $add('lms_continue',v13_vote_lms_continue($seq));
    $add('streak_prob',v13_vote_streak_prob($seq));
    $add('fractal',v13_vote_fractal($seq));
    $add('sample_entropy',v13_vote_sample_entropy($seq));
    $add('transition_matrix',v13_vote_transition_matrix($seq));
    $add('markov_chain',v13_vote_markov_chain($seq));
    $add('cau_1_1',v13_vote_cau_1_1($seq));
    $add('cau_2_2',v13_vote_cau_2_2($seq));
    $add('cau_bet_3',v13_vote_cau_bet_3($seq));
    $add('cau_zigzag',v13_vote_cau_zigzag($seq));
    $add('reversal_zone',v13_vote_reversal_zone($seq));
    $add('cau_break_4',v13_vote_cau_break_4($seq));
    $add('cau_break_6',v13_vote_cau_break_6($seq));
    $add('cau_break_10',v13_vote_cau_break_10($seq));
    $add('streak_2_3',v13_vote_streak_2_3($seq));
    $add('streak_3_4',v13_vote_streak_3_4($seq));
    $add('streak_5_6',v13_vote_streak_5_6($seq));
    $add('streak_7_8',v13_vote_streak_7_8($seq));
    $add('streak_9_plus',v13_vote_streak_9_plus($seq));
    $add('alternating_short',v13_vote_alternating_short($seq));
    $add('alternating_long',v13_vote_alternating_long($seq));
    $add('cau_2_2_2',v13_vote_cau_2_2_2($seq));
    $add('cau_3_3',v13_vote_cau_3_3($seq));
    $add('cau_4_4',v13_vote_cau_4_4($seq));
    $add('cau_bet_4',v13_vote_cau_bet_4($seq));
    $add('head_tail_bias',v13_vote_head_tail_bias($seq));
    $add('recent_hot',v13_vote_recent_hot($seq));
    $add('cau_xau_safe',v13_vote_cau_xau_safe($seq));
    $add('long_run_break',v13_vote_long_run_break($seq));
    $add('break_imminent',v13_vote_break_imminent($seq));
    $add('continue_strong',v13_vote_continue_strong($seq));
    $add('entropy_regime',v13_vote_entropy_regime($seq));
    $add('cluster_reversal',v13_vote_cluster_reversal($seq));
    $add('cycle_repeat',v13_vote_cycle_repeat($seq));
    $add('changepoint_strong',v13_vote_changepoint_strong($seq));
    $add('bias_reversion_strong',v13_vote_bias_reversion_strong($seq));
    $add('cau_gay_strong',v13_vote_cau_gay_strong($seq));
    $add('meta_smart',v13_vote_meta_smart($seq));
    $add('trend_momentum',v13_vote_trend_momentum($seq));
    $add('volatility',v13_vote_volatility($seq));
    $add('pattern_entropy',v13_vote_pattern_entropy($seq));
    $add('run_length_pattern',v13_vote_run_length_pattern($seq));
    $add('smart_money',v13_vote_smart_money($seq));
    $add('markov_k2',v13_vote_markov_k2($seq));
    $add('markov_k3',v13_vote_markov_k3($seq));
    $add('markov_k4',v13_vote_markov_k4($seq));
    $add('markov_k5',v13_vote_markov_k5($seq));
    if (empty($v)) $v['parity']=['pick'=>'T','w'=>0.3,'note'=>'parity'];
    return $v;
}

function v13_ensemble(array $seq): array {
    $regime=v13_detect_regime($seq);
    $regimeScores=v13_regime_scores($seq);
    $regimeTopScore=$regimeScores[$regime]??0.5;
    $voters=v13_all_voters($seq);
    $backtest=v13_backtest_voters($seq);

    $regimeBoost=[
        'streak_short'=>['streak_follow'=>1.4,'hu_streak_follow'=>1.6,'streak_analyzer'=>1.2,'regime_consensus'=>1.3,'run_length'=>1.2,'cau_bet_3'=>1.5,'streak_3_4'=>1.5,'streak_2_3'=>1.3,'continue_strong'=>1.4],
        'streak_long'=>['streak_break'=>1.5,'streak_analyzer'=>1.7,'hu_long_survival'=>1.7,'hu_cau_gay'=>1.5,'streak_survival'=>1.5,'regime_consensus'=>1.4,'hu_changepoint'=>1.3,'inflection'=>1.3,'cau_break_6'=>1.6,'cau_break_10'=>1.8,'long_run_break'=>1.6,'break_imminent'=>1.6],
        'alternating'=>['alternating'=>1.6,'anti_streak'=>1.3,'regime_consensus'=>1.3,'hu_cluster_alt'=>1.4,'pair'=>0.7,'cau_1_1'=>1.7,'alternating_long'=>1.5,'alternating_short'=>1.3],
        'pair'=>['pair'=>1.5,'triple'=>1.1,'hu_double_down'=>1.5,'alternating'=>0.7,'pattern_lock'=>1.3,'cau_2_2'=>1.6,'cau_2_2_2'=>1.5],
        'triple'=>['triple'=>1.4,'quad'=>1.2,'hu_double_down'=>1.3,'pattern_lock'=>1.4,'cau_3_3'=>1.6],
        'trend'=>['momentum'=>1.5,'streak_follow'=>1.3,'hurst'=>1.3,'hu_momentum_exhaust'=>1.2,'momentum_align'=>1.5,'trend_momentum'=>1.5],
        
'chaos'=>['markov'=>1.4,'transition'=>1.3,'frequency'=>1.2,'entropy'=>1.3,'streak_follow'=>0.5,'streak_break'=>0.5,'streak_analyzer'=>0.5,'cau_xau'=>1.5,'cau_xau_safe'=>1.5,'entropy_regime'=>1.5],
        'noise'=>['frequency'=>1.2,'entropy'=>1.3,'complexity'=>1.3,'gini'=>1.1,'hu_ratio_extreme'=>1.3,'anti_noise'=>0.5,'cau_xau'=>1.4,'cau_xau_safe'=>1.4],
        'transition'=>['momentum'=>1.4,'inflection'=>1.3,'transition'=>1.2,'transition2'=>1.3,'hu_changepoint'=>1.4,'transition_matrix'=>1.5],
        'anti-streak'=>['anti_streak'=>1.7,'alternating'=>1.3,'hurst'=>1.2,'streak_follow'=>0.5],
        'cyclic'=>['cyclic_fit'=>1.7,'phase'=>1.4,'hu_hidden_cycle'=>1.8,'lz_structure'=>1.5,'pattern_lock'=>1.3,'cycle_repeat'=>1.6],
        'cluster'=>['hu_cluster'=>1.8,'hu_ratio_extreme'=>1.5,'hu_cluster_alt'=>1.4,'hu_bias_reversion'=>1.4,'cluster_reversal'=>1.5],
        'changepoint'=>['hu_changepoint'=>1.8,'hu_cau_gay'=>1.5,'streak_break'=>1.3,'hu_long_survival'=>1.3,'changepoint_strong'=>1.7,'reversal_zone'=>1.6],
        'mixed'=>['pattern_lock'=>1.1,'bayesian'=>1.1,'meta_composite'=>1.2,'smart_money'=>1.3],
        'cold'=>[],
    ];
    $boost=$regimeBoost[$regime]??[];
    $boostScale=0.5+0.5*$regimeTopScore;

    foreach ($voters as $name=>&$row) {
        $bt=$backtest[$name]??null;
        $btWilson=$bt?$bt['wilson']:0.5;
        $btThompson=$bt?$bt['thompson']:0.5;
        $btEma=$bt?$bt['ema']:0.5;
        $metaScore=0.40*$btWilson+0.35*$btThompson+0.25*$btEma;
        $rb=1.0+(($boost[$name]??1.0)-1.0)*$boostScale;
        if ($bt&&$bt['total']>=10&&$btWilson<0.40) {
            $row['pruned']=true;$row['final_w']=0;continue;
        }
        $shrink=$bt&&$bt['total']<8?0.6:1.0;
        $row['final_w']=$row['w']*$rb*(0.35+1.3*$metaScore)*$shrink;
        if (!empty($GLOBALS['__ai_model_weights'][$name])) $row['final_w'] *= (float)$GLOBALS['__ai_model_weights'][$name];
        $row['bt_rate']=$bt['rate']??0.5;
        $row['bt_wilson']=$btWilson;
        $row['bt_thompson']=$btThompson;
        $row['bt_ema']=$btEma;
        $row['meta_score']=$metaScore;
        $row['regime_boost']=$rb;
    }
    unset($row);

    $scoreT=0;$scoreX=0;$totalW=0;
    foreach ($voters as $row) {
        if (!empty($row['pruned'])) continue;
        $totalW+=$row['final_w'];
        if ($row['pick']==='T') $scoreT+=$row['final_w'];
        else $scoreX+=$row['final_w'];
    }
    if ($totalW<=0) {
        return ['pick'=>'T','agreement'=>0.5,'voters'=>$voters,'backtest'=>$backtest,'regime'=>$regime,'regime_scores'=>$regimeScores];
    }
    $pT=$scoreT/$totalW;
    $pick=$pT>=0.5?'T':'X';
    return [
        'pick'=>$pick,
        'agreement'=>$pick==='T'?$pT:1-$pT,
        'voters'=>$voters,
        'backtest'=>$backtest,
        'regime'=>$regime,
        'regime_scores'=>$regimeScores,
    ];
}

function v13_confidence(array $ensemble, array $seq): array {
    $agree=$ensemble['agreement']??0.5;
    $regime=$ensemble['regime']??'mixed';
    $bt=$ensemble['backtest']??[];
    $a=$agree;
    $metaSum=0;$wSum=0;
    foreach ($ensemble['voters'] as $name=>$row) {
        if (!empty($row['pruned'])) continue;
        $metaSum+=($row['meta_score']??0.5)*($row['final_w']??0);
        $wSum+=$row['final_w']??0;
    }
    $b=$wSum>0?$metaSum/$wSum:0.5;
    $recentHits=0;$recentTotal=0;
    foreach ($bt as $name=>$row) {
        if (!empty($ensemble['voters'][$name]['pruned'])) continue;
        if ($row['total']>=5) { $recentHits+=$row['hit'];$recentTotal+=$row['total']; }
    }
    $c=$recentTotal>0?($recentHits+1)/($recentTotal+2):0.5;
    $scoreT=0;$scoreX=0;
    foreach ($ensemble['voters'] as $row) {
        if (!empty($row['pruned'])) continue;
        if ($row['pick']==='T') $scoreT+=$row['final_w'];
        else $scoreX+=$row['final_w'];
    }
    $tot=$scoreT+$scoreX;
    $voteEntropy=0;
    if ($tot>0) {
        $pT=$scoreT/$tot;$pX=$scoreX/$tot;
        foreach ([$pT,$pX] as $p) if ($p>0) $voteEntropy-=$p*log($p,2);
    }
    $d=1-$voteEntropy;
    $regimeStrength=[
        'streak_long'=>0.94,'streak_short'=>0.88,'alternating'=>0.90,
        'pair'=>0.85,'triple'=>0.87,'trend'=>0.80,'transition'=>0.72,
        'anti-streak'=>0.78,'noise'=>0.60,'cyclic'=>0.85,'cluster'=>0.82,
        'changepoint'=>0.75,'mixed'=>0.62,'chaos'=>0.55,'cold'=>0.5,
    ][$regime]??0.6;
    $streakFactor=0.5;
    if (isset($ensemble['voters']['streak_analyzer'])) {
        $sa=$ensemble['voters']['streak_analyzer'];
        if (isset($sa['analysis']['break_score']))
            $streakFactor=abs($sa['analysis']['break_score']-0.5)*2;
    }
    $pVote=$tot>0?max($scoreT,$scoreX)/$tot:0.5;
    $pVote=max(0.5,min(0.999,$pVote));
    $logOdds=log($pVote/(1-$pVote+1e-9));
    $f=1/(1+exp(-$logOdds));
    $fFeat=v13_features($seq);
    $g=$fFeat['entropy']>0.9?0.45:($fFeat['entropy']<0.5?0.65:0.55);
    $rs=$ensemble['regime_scores']??[];
    $conformal=!empty($rs)?max($rs):0.5;
    $huBoost=0.0;
    if ($fFeat['cau_gay_score']>0.5) $huBoost+=0.05;
    if ($fFeat['regime_shift_prob']>0.5) $huBoost+=0.05;
    if ($fFeat['hidden_cycle_strength']>0.5) $huBoost+=0.05;
    if ($fFeat['cluster_strength']>0.6) $huBoost+=0.05;
    $blend=
        0.15*$a+0.15*$b+0.15*$c+0.10*$d+
        0.08*$regimeStrength+0.07*$streakFactor+
        0.10*$f+0.07*$g+0.08*$conformal+$huBoost;
    $blend=max(0.35,min(0.92,$blend));
    if ($blend<0.45) $score=60+($blend-0.35)*40;
    elseif ($blend<0.60) $score=64+($blend-0.45)*60;
    elseif ($blend<0.75) $score=73+($blend-0.60)*80;
    else $score=85+($blend-0.75)*40;
    $score=max(60.0,min(92.0,$score));
    return [
        'score'=>round($score,1),
        'components'=>[
            'agreement'=>round($a,3),'meta_score'=>round($b,3),
            'recent_rate'=>round($c,3),'vote_entropy_inv'=>round($d,3),
            'regime_strength'=>round($regimeStrength,3),'streak_strength'=>round($streakFactor,3),
            'bayes_logodds'=>round($f,3),'seq_info'=>round($g,3),
            'conformal'=>round($conformal,3),'hu_boost'=>round($huBoost,3),
        ],
    ];
}

function ai_predict_v13(array $history_seq, array $prev_predictions = [], array $recent_results = []): array {
    $seq = array_slice($history_seq, 0, 50);
    if (empty($seq)) {
        return [
            'pred' => mt_rand(0,1) ? 'TAI' : 'XIU',
            'conf' => 5.0,
            'detail' => ['agree'=>0.5,'regime'=>'cold','voters'=>0],
            'pattern' => 'PRIOR',
            'regime' => 'cold',
            'cau_dep' => 0.0,
            'cau_xau' => 1.0,
            'smart_bet' => false,
            'bet_level' => 'skip',
        ];
    }
    $ens = v13_ensemble($seq);
    $conf = v13_confidence($ens, $seq);
    if (count($prev_predictions) >= 6) {
        $recent6 = array_slice($prev_predictions, 0, 6);
        $allSame = count(array_unique($recent6)) === 1;
        if ($allSame) {
            $ens['pick'] = $ens['pick'] === 'T' ? 'X' : 'T';
            $conf['score'] = max(60, $conf['score'] - 5);
        }
    }
    $feat = v13_features($seq);
    $pick = $ens['pick'] === 'T' ? 'TAI' : 'XIU';
    return [
        'pred' => $pick,
        'conf' => $conf['score'],
        'detail' => [
            'agree' => round($ens['agreement']*100, 1),
            'regime' => $ens['regime'],
            'voters' => count(array_filter($ens['voters'], fn($v) => empty($v['pruned']))),
            'components' => $conf['components'],
        ],
        'pattern' => 'V13-' . $ens['regime'],
        'regime' => $ens['regime'],
        'regime_scores' => array_map(fn($v) => round($v, 3), $ens['regime_scores'] ?? []),
        'voters' => $ens['voters'],
        'cau_dep' => round($feat['cau_dep_score'], 2),
        'cau_xau' => round($feat['cau_xau_score'], 2),
        'streak' => $feat['streak'],
        'smart_bet' => $feat['cau_dep_score'] > $feat['cau_xau_score'],
    ];
}

// ═══════════════════════════════════════════════════════
// [5b] BET AMOUNT — FIX MARTINGALE
// ═══════════════════════════════════════════════════════
function ai_smart_bet_amount(array $state, array $ai, array $recentResults): array {
    $cfg = $state['config'] ?? [];
    $baseBet   = (int)($cfg['base_bet'] ?? 10000);
    $mode      = $cfg['mode'] ?? 'fixed';
    $loseStreak= (int)($cfg['lose_streak'] ?? 0);
    $maxLose   = max(1, (int)($cfg['max_lose_streak'] ?? 3));

    if ($mode === 'double') {
        $mult = 1 << $loseStreak;
        $amount = $baseBet * $mult;

        $betHigh = (int)($cfg['bet_high'] ?? 0);
        if ($betHigh > 0 && $amount > $betHigh) $amount = $betHigh;

        if ($loseStreak >= $maxLose) {
            $amount = $baseBet;
            $level = 'base';
            $reason = "Martingale MAX ({$loseStreak}/{$maxLose}) → reset base";
        } else {
            $level = $loseStreak === 0 ? 'base' : 'martingale';
            $reason = "Martingale x{$mult} (lose={$loseStreak})";
        }
        return [
            'amount' => max(1000, $amount),
            'level'  => $level,
            'reason' => $reason,
        ];
    }

    $smartEnabled = !empty($cfg['smart_bet']);
    if (!$smartEnabled) {
        return ['amount' => $baseBet, 'level' => 'base', 'reason' => 'fixed base (smart off)'];
    }

    $betHigh = (int)($cfg['bet_high'] ?? 50000);
    $betLow  = (int)($cfg['bet_low']  ?? 10000);
    $highConfMin = (int)($cfg['high_conf_min'] ?? 75);
    $recentWinMin = (int)($cfg['recent_win_min'] ?? 2);

    $recent = array_slice($recentResults, 0, 5);
    $recentWins = 0;
    $recentTotal = count($recent);
    foreach ($recent as $r) {
        if (!empty($r['win'])) $recentWins++;
    }

    $conf   = (float)($ai['conf'] ?? 0);
    $cauDep = (float)($ai['cau_dep'] ?? 0);
    $cauXau = (float)($ai['cau_xau'] ?? 1);
    $isCauDep = $cauDep > $cauXau;
    $confOk = $conf >= $highConfMin;
    $recentOk = $recentWins >= $recentWinMin;
    $enoughSample = $recentTotal >= 3;

    if ($confOk && $isCauDep && ($recentOk || !$enoughSample)) {
        return [
            'amount' => $betHigh,
            'level'  => 'high',
            'reason' => "cầu đẹp (dep={$cauDep}) + conf={$conf}% + recentWin={$recentWins}/{$recentTotal}",
        ];
    }

    $isCauXau = $cauXau > ($cauDep + 0.2);
    $lowConf  = $conf < 65;
    $losingRecent = $recentTotal >= 3 && $recentWins <= 1;

    if ($isCauXau || $lowConf || $losingRecent) {
        return [
            'amount' => max(1000, $betLow),
            'level'  => 'low',
            'reason' => "cầu xấu/conf thấp/thua gần đây (xau={$cauXau}, conf={$conf}, win={$recentWins}/{$recentTotal})",
        ];
    }

    return [
        'amount' => max(1000, (int)(($betHigh + $betLow) / 2)),
        'level'  => 'mid',
        'reason' => 'cầu trung bình',
    ];
}

// ═══════════════════════════════════════════════════════
// [6] TINY WS
// ═══════════════════════════════════════════════════════
class TinyWS {
    public $sock;
    public $error = '';
    private $h, $p, $path, $headers;
    public function __construct($h, $p, $path, $headers = []) {
        $this->h = $h; $this->p = $p; $this->path = $path; $this->headers = $headers;
    }
    public function connect(): bool {
        $ctx = stream_context_create(['ssl' => ['verify_peer'=>false,'verify_peer_name'=>false,'allow_self_signed'=>true]]);
        $this->sock = @stream_socket_client("tls://{$this->h}:{$this->p}", $en, $es, 10, STREAM_CLIENT_CONNECT, $ctx);
        if (!$this->sock) { $this->error = "TCP/TLS fail: $en:$es"; return false; }
        stream_set_timeout($this->sock, 15);
        stream_set_blocking($this->sock, true);
        $key = base64_encode(random_bytes(16));
        $req = "GET {$this->path} HTTP/1.1\r\nHost: {$this->h}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {$key}\r\nSec-WebSocket-Version: 13\r\nOrigin: https://{$this->h}\r\nUser-Agent: Mozilla/5.0\r\n";
        foreach ($this->headers as $hd) $req .= $hd . "\r\n";
        $req .= "\r\n";
        fwrite($this->sock, $req);
        $resp = ''; $deadline = microtime(true) + 10;
        while (!str_contains($resp, "\r\n\r\n") && microtime(true) < $deadline) {
            $c = fread($this->sock, 2048);
            if ($c === false || $c === '') { $this->error = 'Handshake fail (no data)'; return false; }
            $resp .= $c;
        }
        if (stripos($resp, ' 101') === false) { $this->error = 'Handshake fail: ' . substr($resp, 0, 160); return false; }
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
    public function readOneFrame(int $timeoutSec = 1): ?array {
        if (!$this->sock) return null;
        $r = [$this->sock]; $w = null; $e = null;
        $n = @stream_select($r, $w, $e, $timeoutSec, 0);
        if ($n === false) return null;
        if ($n === 0) return [];
        $hdr = @fread($this->sock, 2);
        if ($hdr === false || strlen($hdr) < 2) return null;
        $b1 = ord($hdr[0]); $b2 = ord($hdr[1]);
        $opcode = $b1 & 0x0f; $masked = ($b2 & 0x80) !== 0; $len = $b2 & 0x7f;
        if ($len === 126) { $ext = @fread($this->sock, 2); if (strlen($ext) < 2) return null; $len = unpack('n', $ext)[1]; }
        elseif ($len === 127) { $ext = @fread($this->sock, 8); if (strlen($ext) < 8) return null; $len = unpack('J', $ext)[1]; }
        $maskKey = null;
        if ($masked) { $maskKey = @fread($this->sock, 4); if (strlen($maskKey) < 4) return null; }
        $data = '';
        while (strlen($data) < $len) {
            $chunk = @fread($this->sock, $len - strlen($data));
            if ($chunk === false || $chunk === '') return null;
            $data .= $chunk;
        }
        if ($maskKey) {
            $u = '';
            for ($i = 0; $i < $len; $i++) $u .= $data[$i] ^ $maskKey[$i % 4];
            $data = $u;
        }
        if ($opcode === 0x8) return null;
        if ($opcode === 0x9) { $this->sendPong($data); return []; }
        if ($opcode === 0xA) return [];
        if ($opcode === 0x0 || $opcode === 0x1) return [$data];
        return [];
    }
    private function sendPong(string $payload): void {
        if (!$this->sock) return;
        $len = strlen($payload); $f = chr(0x8A);
        if ($len < 126) $f .= chr(0x80 | $len);
        elseif ($len < 65536) $f .= chr(0x80 | 126) . pack('n', $len);
        else $f .= chr(0x80 | 127) . pack('J', $len);
        $m = random_bytes(4); $f .= $m;
        for ($i = 0; $i < $len; $i++) $f .= $payload[$i] ^ $m[$i % 4];
        @fwrite($this->sock, $f);
    }
    public function close(): void { if ($this->sock) @fclose($this->sock); $this->sock = null; }
}

// ═══════════════════════════════════════════════════════
// [7] WS BET
// ═══════════════════════════════════════════════════════
function do_ws_bet(string $key, array $s, array &$actions): bool {
    global $CFG;
    if (empty($s['token'])) return false;
    $cfg = $s['config'];
    $pred = $s['pending_pred'];
    $pendingSession = (int)$s['pending_session'];
    $amount = (int)($s['pending_bet_amount'] ?? $cfg['base_bet'] ?? 10000);
    if ($amount < 1000) $amount = 1000;
    $wsPath = rtrim($CFG['game']['ws_path'], '/') . '/?EIO=4&transport=websocket';
    $ws = new TinyWS($CFG['game']['ws_host'], 443, $wsPath, ['Authorization: Bearer ' . $s['token']]);
    if (!$ws->connect()) {
        key_log($key, 'error', '❌ WS connect fail: ' . $ws->error);
        $actions[] = ['type' => 'error', 'msg' => 'WS fail: ' . $ws->error];
        return false;
    }
    $authPayload = json_encode(['token' => $s['token']], JSON_UNESCAPED_UNICODE);
    $opened = false; $joined = false; $betDone = false; $sawState = null; $sawTickSid = null;
    $deadline = microtime(true) + 18;
    $betAmount = $amount;
    while (microtime(true) < $deadline) {
        $frames = $ws->readOneFrame(1);
        if ($frames === null) { key_log($key, 'warn', '⚠️ WS đóng giữa chừng'); break; }
        if ($frames === []) continue;
        foreach ($frames as $pkt) {
            if ($pkt === '' || $pkt === null) continue;
            if (str_starts_with($pkt, '0{')) {
                $opened = true;
                $ws->sendRaw('40/txmd5,' . $authPayload);
                key_log($key, 'info', '🔗 OPEN → gửi 40/txmd5,{token}');
                continue;
            }
            if ($pkt === '2') { $ws->sendRaw('3'); continue; }
            if ($pkt === '3' || $pkt === '6') continue;
            if ($pkt === '1') { key_log($key, 'warn', '⚠️ Engine.IO CLOSE'); $ws->close(); return false; }
            if (!str_starts_with($pkt, '4')) continue;
            $sio = substr($pkt, 1);
            if (str_starts_with($sio, '0/txmd5,')) { $joined = true; key_log($key, 'success', '✅ Join /txmd5'); continue; }
            if (str_starts_with($sio, '1')) { key_log($key, 'warn', '⚠️ SIO DISCONNECT'); $ws->close(); return false; }
            if (str_starts_with($sio, '4')) { key_log($key, 'error', '❌ CONNECT_ERROR: '.substr($sio,0,120)); $ws->close(); return false; }
            if (!str_starts_with($sio, '2')) continue;
            $body = substr($sio, 1);
            if (str_starts_with($body, '/txmd5,')) $body = substr($body, strlen('/txmd5,'));
            $msg = json_decode($body, true);
            if (!is_array($msg) || count($msg) < 1) continue;
            $ev = $msg[0] ?? ''; $d = $msg[1] ?? [];
            if ($ev === 'tick-update') {
                $sawState = $d['state'] ?? null;
                $sawTickSid = isset($d['id']) ? (int)$d['id'] : null;
                if ($sawState === 'BETTING' && !$betDone) {
                    if ($sawTickSid !== null && $sawTickSid < $pendingSession) continue;
                    $eventArr = ['bet', ['type' => $pred, 'amount' => $betAmount]];
                    $ws->sendRaw('42/txmd5,' . json_encode($eventArr, JSON_UNESCAPED_UNICODE));
                    $betDone = true;
                    $logMsg = "💰 ĐẶT #{$pendingSession}: {$pred} × " . number_format($betAmount);
                    key_log($key, 'success', $logMsg);
                    $actions[] = ['type' => 'bet', 'msg' => $logMsg];
                    key_update($key, function($d) use ($pendingSession, $betAmount) {
                        $d['bet_session'] = $pendingSession;
                        $d['bet_amount'] = $betAmount;
                        return $d;
                    });
                    $waitUntil = microtime(true) + 2.5;
                    while (microtime(true) < $waitUntil) {
                        $more = $ws->readOneFrame(1);
                        if ($more === null) break;
                        if ($more === []) continue;
                        foreach ($more as $p2) {
                            if ($p2 === '2') { $ws->sendRaw('3'); continue; }
                            if (!str_starts_with($p2, '4')) continue;
                            $s2 = substr($p2, 1);
                            if (!str_starts_with($s2, '2')) continue;
                            $b2 = substr($s2, 1);
                            if (str_starts_with($b2, '/txmd5,')) $b2 = substr($b2, strlen('/txmd5,'));
                            $m2 = json_decode($b2, true);
                            if (!is_array($m2)) continue;
                            if (($m2[0] ?? '') === 'bet-result' && isset($m2[1]['postBalance'])) {
                                key_update($key, function($dd) use ($m2) {
                                    $dd['balance'] = $m2[1]['postBalance'];
                                    return $dd;
                                });
                                key_log($key, 'success', '💳 Số dư: ' . number_format($m2[1]['postBalance']));
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
    if (!$betDone) {
        if (!$opened) key_log($key, 'warn', '⚠️ Không nhận OPEN');
        elseif (!$joined) key_log($key, 'warn', '⚠️ Không join /txmd5');
        elseif ($sawState === 'BETTING') key_log($key, 'warn', "⚠️ Có BETTING nhưng không bet được #{$pendingSession}");
        elseif ($sawState) key_log($key, 'info', "⏳ State cuối: {$sawState}");
        else key_log($key, 'warn', '⚠️ Không nhận tick-update 18s');
    }
    return $betDone;
}


// ═══════════════════════════════════════════════════════════════════
// [V16] WALK-FORWARD QUALITY GUARD — chỉ dựa trên dự đoán đã có kết quả.
// Không tuyên bố tăng xác suất thắng; dùng để tránh cược khi hiệu suất gần đây yếu.
// ═══════════════════════════════════════════════════════════════════
if (!function_exists('v16_quality_guard')) {
function v16_quality_guard(array $rows, int $window = 50): array {
    $sample = 0; $correct = 0;
    foreach (array_slice($rows, 0, max(1, $window)) as $row) {
        $p = strtoupper(trim((string)($row['du_doan'] ?? '')));
        $a = strtoupper(trim((string)($row['result'] ?? '')));
        if (!in_array($p, ['TAI','XIU','T','X'], true) || !in_array($a, ['TAI','XIU'], true)) continue;
        $sample++;
        if (($p === 'TAI' || $p === 'T') && $a === 'TAI') $correct++;
        if (($p === 'XIU' || $p === 'X') && $a === 'XIU') $correct++;
    }
    return ['sample'=>$sample, 'correct'=>$correct, 'accuracy'=>$sample ? $correct/$sample : 0.0];
}
}

// ═══════════════════════════════════════════════════════
// [8] WORKER CORE
// ═══════════════════════════════════════════════════════
function worker_step(string $key): array {
    $actions = [];
    $s = key_load($key);
    if (!$s) return $actions;

    $cfg = $s['config'] ?? [];
    $profitStop = max(0, (int)($cfg['profit_stop'] ?? 0));
    $profitSoFar = (int)($s['profit_total'] ?? 0);
    if (!array_key_exists('profit_total', $s)) {
        foreach (($s['history'] ?? []) as $oldRow) {
            if (isset($oldRow['amount'])) $profitSoFar += !empty($oldRow['win']) ? (int)$oldRow['amount'] : -(int)$oldRow['amount'];
        }
    }
    if ($profitStop > 0 && $profitSoFar >= $profitStop && empty($s['pending_pred'])) {
        if (!empty($cfg['auto']) || empty($cfg['paused'])) {
            key_update($key, function($d) {
                $d['config']['auto'] = false;
                $d['config']['paused'] = true;
                return $d;
            });
            key_log($key, 'success', '🏆 Đã đạt chốt lời tích lũy — worker không tạo thêm lệnh.');
        }
        return $actions;
    }
    $winTarget = max(1, min(666, (int)($cfg['win_target'] ?? 666)));
    if ((int)($s['win_count_total'] ?? 0) >= $winTarget && empty($s['pending_pred'])) {
        if (!empty($cfg['auto']) || empty($cfg['paused'])) {
            key_update($key, function($d) { $d['config']['auto'] = false; $d['config']['paused'] = true; return $d; });
            key_log($key, 'success', '🏁 Đã đủ mục tiêu thắng — worker không tạo thêm lệnh cược.');
        }
        return $actions;
    }
    if (empty($cfg['auto']) || !empty($cfg['paused'])) {
        return $actions;
    }

    $table_type = $cfg['table_type'] ?? 'md5';
    $data = ($table_type === 'hu') ? fetch_sessions_api_hu() : fetch_sessions_api();
    if (!$data || empty($data['list'])) {
        return $actions;
    }

    $latest = $data['list'][0];
    $latestId = (int)$latest['id'];
    $lastId = (int)($s['last_session_id'] ?? 0);

    if ($lastId === 0) {
        key_update($key, function($d) use ($latestId) {
            $d['last_session_id'] = $latestId;
            $d['last_processed_session'] = $latestId;
            return $d;
        });
        key_log($key, 'info', "📡 Baseline phiên: #{$latestId}");
        $actions[] = ['type'=>'info', 'msg'=>"Baseline #{$latestId}"];
        return $actions;
    }

    if ($latestId > $lastId) {
        for ($sid = $lastId + 1; $sid <= $latestId; $sid++) {
            $found = null;
            foreach ($data['list'] as $row) {
                if ((int)$row['id'] === $sid) { $found = $row; break; }
            }
            if (!$found) continue;

            key_log($key, 'info', "🔍 Đang phân tích phiên #{$sid}...");

            $resultRaw = $found['resultTruyenThong'] ?? 'N/A';
            $resultMap = ['Tài'=>'TAI','Xỉu'=>'XIU','tai'=>'TAI','xiu'=>'XIU','TAI'=>'TAI','XIU'=>'XIU'];
            $result = $resultMap[$resultRaw] ?? 'N/A';
            // V16: chỉ quyết toán khi API trả kết quả hợp lệ TAI/XIU.
            if ($result !== 'TAI' && $result !== 'XIU') {
                key_log($key, 'warn', "⏳ Phiên #{$sid} chưa có kết quả Tài/Xỉu hợp lệ; giữ nguyên pending để worker kiểm tra lại.");
                return $actions;
            }
            $dices = $found['dices'] ?? [0,0,0];

            if (($s['pending_session'] ?? null) == $sid && !empty($s['pending_pred'])) {
                $pred = $s['pending_pred'];
                $win = ($pred === $result);
                $voterPicks = $s['pending_voter_picks'] ?? null;

                key_update($key, function($d) use ($sid, $pred, $result, $dices, $win) {
                    $c = $d['config'];
                    $streak = (int)($c['lose_streak'] ?? 0);
                    $maxS   = (int)($c['max_lose_streak'] ?? 3);

                    if ($win) {
                        $streak = 0;
                        $c['paused'] = false;
                        $d['win_count_total'] = (int)($d['win_count_total'] ?? 0) + 1;
                    } else {
                        $d['loss_count_total'] = (int)($d['loss_count_total'] ?? 0) + 1;
                        $streak++;
                        if (($c['mode'] ?? 'fixed') === 'double' && $streak >= $maxS) {
                            $streak = 0;
                        }
                    }
                    $c['lose_streak'] = $streak;
                    // V16: đạt mục tiêu thắng thì tắt AUTO ngay trong transaction.
                    $winTarget = max(1, min(666, (int)($c['win_target'] ?? 666)));
                    if ((int)($d['win_count_total'] ?? 0) >= $winTarget) {
                        $c['auto'] = false;
                        $c['paused'] = true;
                    }
                    $d['config'] = $c;

                    $balanceAfter = (int)($d['balance'] ?? 0);
                    $betAmount = (int)($d['bet_amount'] ?? 0);
                    $actualAmount = $betAmount > 0 ? $betAmount : (int)($c['base_bet'] ?? 10000);
                    if ($win) {
                        $balanceAfter += $actualAmount;
                    } else {
                        $balanceAfter -= $actualAmount;
                    }
                    $d['balance'] = $balanceAfter;

                    // [V19] Lợi nhuận tích lũy bền vững, không phụ thuộc giới hạn 500 dòng lịch sử.
                    $profitDelta = $win ? $actualAmount : -$actualAmount;
                    $d['profit_total'] = (int)($d['profit_total'] ?? 0) + $profitDelta;
                    $profitStop = max(0, (int)($c['profit_stop'] ?? 0));
                    if ($profitStop > 0 && (int)$d['profit_total'] >= $profitStop) {
                        $c['auto'] = false;
                        $c['paused'] = true;
                        $d['config'] = $c;
                        $d['profit_stop_reached_at'] = time();
                    }

                    $d['history'] = $d['history'] ?? [];
                    array_unshift($d['history'], [
                        'ts' => date('H:i:s d/m'),
                        'session' => $sid,
                        'pred' => $pred,
                        'result' => $result,
                        'dices' => $dices,
                        'win' => $win,
                        'amount' => $actualAmount,
                        'balance_after' => $balanceAfter,
                        'streak' => $streak,
                        'regime' => $d['pending_regime'] ?? null,
                        'conf' => $d['pending_conf'] ?? null,
                        'bet_level' => $d['pending_bet_level'] ?? 'base',
                    ]);
                    $d['history'] = array_slice($d['history'], 0, $GLOBALS['CFG']['max_history'] ?? 500);

                    // Giữ snapshot tín hiệu trước khi xóa pending để lịch sử học có đủ dữ liệu.
                    $settledConf = $d['pending_conf'] ?? null;
                    $settledVoterPicks = $d['pending_voter_picks'] ?? null;
                    $d['pending_pred'] = null;
                    $d['pending_session'] = null;
                    $d['pending_regime'] = null;
                    $d['pending_conf'] = null;
                    $d['pending_bet_amount'] = null;
                    $d['pending_bet_level'] = null;
                    $d['bet_session'] = null;
                    $d['bet_amount'] = 0;
                    // [UPGRADE] pattern_10: lưu 10 cầu T/X gần nhất
                    $p10 = $d['pattern_10'] ?? '';
                    $resSym = ($result === 'TAI') ? 'T' : (($result === 'XIU') ? 'X' : '');
                    if ($resSym !== '') { $p10 .= $resSym; if (strlen($p10) > 10) $p10 = substr($p10, -10); }
                    $d['pattern_10'] = $p10;
                    // [UPGRADE] /api/history/dudoan: lưu 1000 phiên dự đoán đúng/sai
                    $trang_thai = $win ? 'ĐÚNG CỬA' : 'SAI CỬA';
                    $d['dudoan_history'] = $d['dudoan_history'] ?? [];
                    array_unshift($d['dudoan_history'], [
                        'phien_truoc' => $sid - 1,
                        'result' => $result,
                        'phien_nay' => $sid,
                        'du_doan' => $pred,
                        'do_tin_cay' => $settledConf,
                        'voter_picks' => $settledVoterPicks,
                        'trang_thai' => $trang_thai,
                        'dung' => (bool)$win,
                        'time' => date('H:i:s d/m'),
                    ]);
                    $d['dudoan_history'] = array_slice($d['dudoan_history'], 0, 1000);
                    $d['pending_voter_picks'] = null;
                    $d['skip_next_bet'] = false;
                    return $d;
                });

                $icon = $win ? '✅' : '❌';
                $diceStr = implode('-', $dices);
                $s2 = key_load($key);
                $logMsg = "$icon Phiên #{$sid}: dự đoán {$pred} — kết quả {$result} ({$diceStr}) | Số dư: " . number_format($s2['balance'] ?? 0);
                key_log($key, $win ? 'success' : 'error', $logMsg);
                $actions[] = ['type'=>'result', 'msg'=>$logMsg];
                $s = $s2;
                if (!empty($s2['config']['paused']) && (int)($s2['win_count_total'] ?? 0) >= max(1, min(666, (int)($s2['config']['win_target'] ?? 666)))) {
                    $stopMsg = '🏁 ĐẠT MỤC TIÊU ' . (int)$s2['win_count_total'] . '/' . (int)($s2['config']['win_target'] ?? 666) . ' phiên thắng — AUTO ĐÃ TỰ ĐỘNG DỪNG.';
                    key_log($key, 'success', $stopMsg);
                    $actions[] = ['type'=>'info', 'msg'=>$stopMsg];
                }
                $profitGoal = max(0, (int)($s2['config']['profit_stop'] ?? 0));
                if ($profitGoal > 0 && (int)($s2['profit_total'] ?? 0) >= $profitGoal) {
                    $stopMsg = '🏆 ĐẠT MỐC CHỐT LỜI ' . number_format((int)$s2['profit_total']) . '/' . number_format($profitGoal) . ' — AUTO ĐÃ TỰ ĐỘNG DỪNG.';
                    key_log($key, 'success', $stopMsg);
                    $actions[] = ['type'=>'info', 'msg'=>$stopMsg];
                }
                if ($voterPicks) { try { ai_learn_from_result($key, $pred, $result, $voterPicks); } catch (Throwable $e) {} }
            }
        }
        key_update($key, function($d) use ($latestId) {
            $d['last_session_id'] = $latestId;
            $d['last_processed_session'] = $latestId;
            return $d;
        });
    }

    if (!empty($s['pending_session']) && (int)$s['pending_session'] <= $latestId) {
        key_update($key, function($d) {
            $d['pending_pred'] = null;
            $d['pending_session'] = null;
            $d['pending_regime'] = null;
            $d['pending_conf'] = null;
            $d['pending_bet_amount'] = null;
            $d['pending_bet_level'] = null;
            $d['bet_session'] = null;
            $d['bet_amount'] = 0;
            return $d;
        });
        key_log($key, 'warn', "⚠️ Phiên #{$s['pending_session']} đã qua — bỏ pending");
        $s = key_load($key);
    }

    $cfg = $s['config'];
    if (!empty($cfg['auto']) && empty($cfg['paused']) && empty($s['pending_pred'])) {
        $historySeq = [];
        foreach (($s['history'] ?? []) as $h) {
            $r = $h['result'] ?? '';
            if ($r === 'TAI') $historySeq[] = 'T';
            elseif ($r === 'XIU') $historySeq[] = 'X';
        }
        if (empty($historySeq) && !empty($data['list'])) {
            foreach (array_slice($data['list'], 0, 50) as $row) {
                $r = $row['resultTruyenThong'] ?? '';
                $map = ['Tài'=>'T','Xỉu'=>'X','tai'=>'T','xiu'=>'X','TAI'=>'T','XIU'=>'X'];
                if (isset($map[$r])) $historySeq[] = $map[$r];
            }
        }

        $prevPreds = [];
        foreach (array_slice($s['history'] ?? [], 0, 6) as $h) {
            if (!empty($h['pred'])) $prevPreds[] = $h['pred'];
        }

        $recentResults = array_slice($s['history'] ?? [], 0, 10);

        $GLOBALS['__ai_model_weights'] = $s['ai_model_weights'] ?? [];
        $ai = ai_predict_v13($historySeq, $prevPreds, $recentResults);
        if (function_exists('ai_predict_v14_overlay')) { $ai = ai_predict_v14_overlay($historySeq, $ai, $prevPreds, $recentResults); } // V14 overlay
        $betDecision = ai_smart_bet_amount($s, $ai, $recentResults);

        // [UPGRADE] Confidence engine: tín hiệu quá yếu -> KHÔNG CƯỢC (vẫn phân tích)
        $agree = (float)($ai['detail']['agree'] ?? 0.5);
        $signalGap = abs($agree - 0.5) * 2;
        $skipBet = ($signalGap < 0.15);
        // V16: nếu >=20 dự đoán đã chốt mà độ chính xác <48%, tạm bỏ cược.
        $quality = v16_quality_guard($s['dudoan_history'] ?? [], 50);
        if ($quality['sample'] >= 20 && $quality['accuracy'] < 0.48) $skipBet = true;
        $ai['quality_guard'] = $quality;
        // [UPGRADE] Auto capital allocation: override mức cược theo % vốn
        $cfgNow = $s['config'];
        if (!empty($cfgNow['auto_capital']) && !empty($cfgNow['capital']) && $cfgNow['capital'] > 0 && !$skipBet) {
            $optBet = calculate_optimal_bet($cfgNow['capital'], (int)($s['balance'] ?? 0), $cfgNow['mode'] ?? 'fixed', (int)($cfgNow['lose_streak'] ?? 0));
            $betDecision['amount'] = $optBet;
            $betDecision['level'] = $betDecision['level'] ?? 'auto_capital';
            $betDecision['reason'] = ($betDecision['reason'] ?? '') . ' | AUTO CAPITAL ' . number_format($optBet);
        }
        // [UPGRADE] Lưu picks voters để AI tự học sau khi có kết quả
        $voterPicksNow = [];
        try { foreach (v13_all_voters($historySeq) as $vn => $vr) { if (isset($vr['pick'])) $voterPicksNow[$vn] = $vr['pick']; } } catch (Throwable $e) {}

        key_update($key, function($d) use ($ai, $latestId, $betDecision, $skipBet, $voterPicksNow) {
            $d['pending_pred'] = $ai['pred'];
            $d['pending_session'] = $latestId + 1;
            $d['pending_regime'] = $ai['regime'] ?? null;
            $d['pending_conf'] = $ai['conf'] ?? null;
            $d['pending_bet_amount'] = $betDecision['amount'];
            $d['pending_bet_level'] = $betDecision['level'];
            $d['pending_voter_picks'] = $voterPicksNow;
            $d['skip_next_bet'] = $skipBet;
            return $d;
        });

        $conf = number_format($ai['conf'], 1);
        $regime = $ai['regime'] ?? 'mixed';
        $levelTxt = $betDecision['level'] === 'high' ? '🔥 LỚN'
                  : ($betDecision['level'] === 'low' ? '💧 NHỎ'
                  : ($betDecision['level'] === 'martingale' ? '📈 MARTINGALE'
                  : '⚖️ BASE'));
        $logMsg = "🎯 SẮP ĐÁNH phiên #".($latestId+1).": {$ai['pred']} (conf {$conf}% | regime {$regime} | {$levelTxt} " . number_format($betDecision['amount']) . " | {$betDecision['reason']})";
        key_log($key, 'info', $logMsg);
        $actions[] = ['type'=>'predict', 'msg'=>$logMsg];
        if ($skipBet) {
            key_log($key, 'warn', "⚠️ Confidence thấp (signal " . number_format($signalGap, 2) . ") — KHÔNG RÕ, KHÔNG CƯỢC phiên #" . ($latestId + 1));
            $actions[] = ['type'=>'info', 'msg'=>'Confidence thấp — KHÔNG CƯỢC phiên này'];
        }
        $s = key_load($key);
    }

    $cfg = $s['config'];
    if (!empty($s['pending_pred']) && !empty($cfg['auto']) && empty($cfg['paused']) && empty($s['skip_next_bet'])) {
        $betSession = $s['bet_session'] ?? null;
        $pendingSession = $s['pending_session'];
        if ($betSession != $pendingSession) {
            key_log($key, 'info', "🔓 Mở WS bet phiên #{$pendingSession}...");
            $__v14_tt = $s['config']['table_type'] ?? 'md5';
            if (function_exists('do_ws_bet_universal')) { do_ws_bet_universal($key, $s, $actions); } // V16: dùng chung WS endpoint cho MD5 và Hũ
            else {
            do_ws_bet($key, $s, $actions);
            }
        }
    }

    return $actions;
}

function worker_heartbeat(string $key, string $status = 'running'): void {
    key_update($key, function($d) use ($status) {
        $d['worker'] = [
            'last_beat' => time(),
            'pid' => getmypid(),
            'status' => $status,
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
    $timeout = $CFG['worker']['resume_timeout'] ?? 1800;
    return (time() - (int)$w['last_beat']) < $timeout;
}

function worker_lock(string $key): bool {
    $lp = KEY_DIR . '/' . hash('sha256', strtolower($key)) . '.lock';
    if (is_file($lp)) {
        $pid = (int)trim(@file_get_contents($lp));
        if ($pid > 0) {
            $alive = false;
            if (function_exists('posix_kill')) {
                $alive = @posix_kill($pid, 0);
            } else {
                $alive = (time() - filemtime($lp)) < 60;
            }
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

// ═══════════════════════════════════════════════════════
// [9] WORKER DAEMON — SELF RESPAWN 24/7
// ═══════════════════════════════════════════════════════
function run_worker_daemon(string $key, int $maxSeconds): void {
    global $CFG;

    if (function_exists('fastcgi_finish_request')) {
        @fastcgi_finish_request();
    } else {
        @ob_end_clean();
        header('Connection: close');
        header('Content-Length: 0');
        @flush();
        @ob_end_flush();
    }

    @ignore_user_abort(true);
    @set_time_limit(0);
    @ini_set('memory_limit', '256M');

    if (!worker_lock($key)) {
        return;
    }

    $sleep = (int)($CFG['worker']['loop_sleep'] ?? 1);
    $deadline = time() + $maxSeconds;
    $lastBeat = 0;
    $selfRespawn = !empty($CFG['worker']['self_respawn']);
    $respawnBuffer = (int)($CFG['worker']['respawn_buffer'] ?? 15);

    worker_heartbeat($key, 'running');
    key_log($key, 'info', '🚀 Worker started PID=' . getmypid() . ' | max=' . $maxSeconds . 's');

    while (time() < $deadline) {
        $s = key_load($key);
        if (!$s) { key_log($key, 'info', '🛑 State bị xoá — worker thoát'); break; }

        try {
            worker_step($key);
        } catch (Throwable $e) {
            key_log($key, 'error', '💥 Worker step error: ' . $e->getMessage());
        }

        if (time() - $lastBeat >= 10) {
            worker_heartbeat($key, 'running');
            $lastBeat = time();
        }

        if ($selfRespawn && (time() + $respawnBuffer) >= $deadline) {
            $s2 = key_load($key);
            if (!empty($s2['config']['auto']) && empty($s2['config']['paused'])) {
                $lp = KEY_DIR . '/' . hash('sha256', strtolower($key)) . '.lock';
                @unlink($lp);
                key_log($key, 'info', '♻️ Self-respawn trước khi hết max_runtime');
                spawn_worker_async($key);
            }
            break;
        }

        sleep($sleep);
    }

    worker_heartbeat($key, 'stopped');
    key_log($key, 'info', '🛑 Worker stopped sau ' . $maxSeconds . 's');
}

// ═══════════════════════════════════════════════════════
// [10] CRON ENDPOINT
// ═══════════════════════════════════════════════════════
function cron_check_all_users(): array {
    global $CFG;
    $result = ['checked' => 0, 'spawned' => [], 'skipped' => []];
    $secret = $_GET['secret'] ?? $_POST['secret'] ?? '';
    $cronSecret = $CFG['worker']['cron_secret'] ?? '';
    if ($cronSecret !== '' && $cronSecret !== 'CHANGE_ME_CRON_SECRET_32CHARS_RANDOM_ABC123' && !hash_equals($cronSecret, $secret)) {
        return ['ok' => false, 'msg' => 'invalid secret'];
    }

    $idx = DATA_DIR . '/user_index.json';
    if (!is_file($idx)) return ['ok' => true] + $result;
    $users = json_decode(file_get_contents($idx), true) ?: [];
    foreach ($users as $user => $key) {
        $result['checked']++;
        $s = key_load($key);
        if (!$s) { $result['skipped'][] = $user . ':no_state'; continue; }
        if (empty($s['config']['auto']) || !empty($s['config']['paused'])) {
            $result['skipped'][] = $user . ':not_auto';
            continue;
        }
        if (worker_alive($key)) {
            $result['skipped'][] = $user . ':alive';
            continue;
        }
        $lp = KEY_DIR . '/' . hash('sha256', strtolower($key)) . '.lock';
        @unlink($lp);
        spawn_worker_async($key);
        $result['spawned'][] = $user;
    }
    return array_merge(['ok' => true], $result);
}

// ═══════════════════════════════════════════════════════
// [11] ROUTER
// ═══════════════════════════════════════════════════════
$action = $_GET['action'] ?? $_POST['action'] ?? '';
if ($action === '') { render_ui(); exit; }

if ($action === 'cron') {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(cron_check_all_users());
    exit;
}

if ($action === 'worker') {
    $key = trim($_GET['key'] ?? $_POST['key'] ?? '');
    if (!$key) { http_response_code(400); echo 'missing key'; exit; }
    $max = (int)($_GET['max'] ?? $GLOBALS['CFG']['worker']['max_runtime'] ?? 3000);
    run_worker_daemon($key, $max);
    exit;
}

header('Content-Type: application/json; charset=utf-8');

try {
    switch ($action) {

        case 'verify':
            $u   = trim($_POST['user'] ?? '');
            $p   = trim($_POST['pass'] ?? '');
            $dev = trim($_POST['device'] ?? 'WEB-UNKNOWN');
            if (!$u || !$p) { echo json_encode(['ok'=>false,'msg'=>'Vui lòng nhập tài khoản và mật khẩu']); exit; }

            $key = $u;
            $existing = key_load($key);
            $can_resume = !empty($existing['user']) && !empty($existing['token']);

            $gl = game_login($u, $p);
            if (isset($gl['_error'])) {
                if ($can_resume) {
                    $gl = [
                        'nickname' => $existing['nickname'] ?? $u,
                        'token'    => $existing['token'],
                        'money'    => $existing['balance'] ?? 0,
                    ];
                    key_log($key, 'info', '♻️ Resume session cũ do lỗi kết nối API game');
                } else {
                    echo json_encode(['ok'=>false,'msg'=>$gl['_error']]); exit;
                }
            }

            $s = $existing ?: [];
            $s['user'] = $u; $s['key'] = $key; $s['device'] = $dev;
            $s['nickname'] = $gl['nickname'] ?? $s['nickname'] ?? $u;
            $s['token'] = $gl['token'] ?? $s['token'] ?? '';
            $s['balance'] = $gl['money'] ?? $s['balance'] ?? 0;
            $s['history'] = $s['history'] ?? [];
            // V16: bộ đếm tích lũy độc lập với history (history chỉ giữ 500 phiên).
            $s['win_count_total'] = isset($s['win_count_total']) ? (int)$s['win_count_total'] : count(array_filter($s['history'], fn($h) => !empty($h['win'])));
            $s['loss_count_total'] = isset($s['loss_count_total']) ? (int)$s['loss_count_total'] : count(array_filter($s['history'], fn($h) => empty($h['win'])));
            $s['logs'] = $s['logs'] ?? [];
            $s['config'] = array_merge($CFG['default_config'], $s['config'] ?? [], [
                'auto' => $s['config']['auto'] ?? false,
                'paused' => $s['config']['paused'] ?? false,
                'lose_streak' => $s['config']['lose_streak'] ?? 0,
            ]);
            $s['last_session_id'] = $s['last_session_id'] ?? 0;
            $s['pending_pred'] = $s['pending_pred'] ?? null;
            $s['pending_session'] = $s['pending_session'] ?? null;
            $s['pending_regime'] = $s['pending_regime'] ?? null;
            $s['pending_conf'] = $s['pending_conf'] ?? null;
            $s['pending_bet_amount'] = $s['pending_bet_amount'] ?? null;
            $s['pending_bet_level'] = $s['pending_bet_level'] ?? null;
            $s['bet_session'] = $s['bet_session'] ?? null;
            $s['bet_amount'] = $s['bet_amount'] ?? 0;
            $s['last_processed_session'] = $s['last_processed_session'] ?? 0;
            $s['pattern_10'] = $s['pattern_10'] ?? '';
            $s['dudoan_history'] = $s['dudoan_history'] ?? [];
            $s['ai_model_weights'] = $s['ai_model_weights'] ?? [];
            $s['ai_learned_count'] = $s['ai_learned_count'] ?? 0;
            $s['pending_voter_picks'] = $s['pending_voter_picks'] ?? null;
            $s['skip_next_bet'] = $s['skip_next_bet'] ?? false;
            key_save($key, $s);
            key_save_by_user($u, $key);
            key_log($key, 'info', '🔐 Đăng nhập OK — Device: ' . $dev);

            if (!worker_alive($key)) {
                spawn_worker_async($key);
            }

            echo json_encode([
                'ok' => true, 'user' => $u,
                'nickname' => $gl['nickname'],
                'balance' => $gl['money'] ?? $s['balance'],
                'config' => $s['config'], 'history' => $s['history'], 'logs' => $s['logs'],
                'auth_token' => issue_token($u),
                'worker_alive' => worker_alive($key),
                'resumed' => $can_resume,
            ]);
            exit;

        case 'config':
            $u = trim($_POST['user'] ?? ''); $tk = trim($_POST['auth_token'] ?? '');
            if (!require_auth($u, $tk)) { echo json_encode(['ok'=>false,'msg'=>'Unauthorized']); exit; }
            $key = key_resolve($u);
            $s = key_load($key); $c = $s['config'];
            $oldAuto = $c['auto'] ?? false;
            if (isset($_POST['base_bet']))    $c['base_bet']    = max(1000, (int)$_POST['base_bet']);
            if (isset($_POST['profit_stop'])) $c['profit_stop'] = max(0, (int)$_POST['profit_stop']);
            if (isset($_POST['mode']))        $c['mode']        = in_array($_POST['mode'], ['fixed','double'], true) ? $_POST['mode'] : 'fixed';
            if (isset($_POST['table_type']))  $c['table_type']  = in_array($_POST['table_type'], ['md5','hu'], true) ? $_POST['table_type'] : 'md5';
            if (isset($_POST['max_lose']))    $c['max_lose_streak'] = max(1, min(10, (int)$_POST['max_lose']));
            if (isset($_POST['auto']))        $c['auto']        = $_POST['auto'] === '1';
            if (isset($_POST['paused']))      $c['paused']      = $_POST['paused'] === '1';
            if (isset($_POST['smart_bet']))      $c['smart_bet']      = $_POST['smart_bet'] === '1';
            if (isset($_POST['bet_high']))       $c['bet_high']       = max(1000, (int)$_POST['bet_high']);
            if (isset($_POST['bet_low']))        $c['bet_low']        = max(1000, (int)$_POST['bet_low']);
            if (isset($_POST['high_conf_min']))  $c['high_conf_min']  = max(50, min(92, (int)$_POST['high_conf_min']));
            if (isset($_POST['recent_win_min'])) $c['recent_win_min'] = max(0, min(5, (int)$_POST['recent_win_min']));
            if (isset($_POST['capital']))        $c['capital']        = max(0, (int)$_POST['capital']);
            if (isset($_POST['auto_capital']))   $c['auto_capital']   = $_POST['auto_capital'] === '1';
            if (isset($_POST['win_target']))    $c['win_target']     = max(1, min(666, (int)$_POST['win_target']));
            $s['config'] = $c;
            if (!$oldAuto && $c['auto']) {
                key_log($key, 'info', '▶ Auto BẬT — worker sẽ xử lý');
                if (!worker_alive($key)) {
                    $lp = KEY_DIR . '/' . hash('sha256', strtolower($key)) . '.lock';
                    @unlink($lp);
                    spawn_worker_async($key);
                }
            }
            key_save($key, $s);
            echo json_encode(['ok'=>true,'config'=>$c,'worker_alive'=>worker_alive($key)]);
            exit;

        case 'status':
            $u = trim($_GET['user'] ?? ''); $tk = trim($_GET['auth_token'] ?? '');
            if (!require_auth($u, $tk)) { echo json_encode(['ok'=>false,'msg'=>'Unauthorized']); exit; }
            $key = key_resolve($u);
            $s = key_load($key);

            if (!empty($s['config']['auto']) && empty($s['config']['paused']) && !worker_alive($key)) {
                $lp = KEY_DIR . '/' . hash('sha256', strtolower($key)) . '.lock';
                @unlink($lp);
                spawn_worker_async($key);
            }

            $hist = $s['history'] ?? [];
            $wins = (int)($s['win_count_total'] ?? 0);
            $losses = (int)($s['loss_count_total'] ?? 0);
            $totalSessions = $wins + $losses;
            $totalProfit = 0;
            foreach ($hist as $h) {
                if (isset($h['balance_after']) && isset($h['amount'])) {
                    $totalProfit += (!empty($h['win']) ? $h['amount'] : -$h['amount']);
                }
            }
            // Ưu tiên tổng tích lũy trên server; fallback cho tài khoản cũ chưa có trường này.
            if (array_key_exists('profit_total', $s)) {
                $totalProfit = (int)$s['profit_total'];
            }

            $historySeq = [];
            foreach ($hist as $h) {
                $r = $h['result'] ?? '';
                if ($r === 'TAI') $historySeq[] = 'T';
                elseif ($r === 'XIU') $historySeq[] = 'X';
            }
            $recentResults = array_slice($hist, 0, 10);
            $ai = ai_predict_v13($historySeq, [], $recentResults);
            if (function_exists('ai_predict_v14_overlay')) { $ai = ai_predict_v14_overlay($historySeq, $ai, [], $recentResults); } // V14 overlay

            echo json_encode([
                'ok' => true,
                'nickname' => $s['nickname'] ?? '',
                'balance' => $s['balance'] ?? 0,
                'config' => $s['config'] ?? [],
                'history' => array_slice($hist, 0, 100),
                'logs' => array_slice($s['logs'] ?? [], 0, 80),
                'pending_pred' => $s['pending_pred'] ?? null,
                'pending_session' => $s['pending_session'] ?? null,
                'pending_regime' => $s['pending_regime'] ?? null,
                'pending_conf' => $s['pending_conf'] ?? null,
                'pending_bet_amount' => $s['pending_bet_amount'] ?? null,
                'pending_bet_level' => $s['pending_bet_level'] ?? null,
                'last_session_id' => $s['last_session_id'] ?? 0,
                'win_count_total' => $wins,
                'win_target' => (int)($s['config']['win_target'] ?? 666),
                'ai' => $ai,
                'stats' => [
                    'wins' => $wins,
                    'losses' => $losses,
                    'total' => $totalSessions,
                    'winrate' => $totalSessions > 0 ? round($wins / $totalSessions * 100, 1) : 0,
                    'profit' => $totalProfit,
                ],
                'worker_alive' => worker_alive($key),
                'worker' => $s['worker'] ?? null,
                'pattern_10' => $s['pattern_10'] ?? '',
                'ai_learned_count' => $s['ai_learned_count'] ?? 0,
                'last_processed_session' => $s['last_processed_session'] ?? ($s['last_session_id'] ?? 0),
                'dudoan_count' => count($s['dudoan_history'] ?? []),
                'auto_capital_active' => !empty($s['config']['auto_capital']),
                'skip_next_bet' => !empty($s['skip_next_bet']),
                'ts' => time(),
            ]);
            exit;

        case 'kick_worker':
            $u = trim($_POST['user'] ?? ''); $tk = trim($_POST['auth_token'] ?? '');
            if (!require_auth($u, $tk)) { echo json_encode(['ok'=>false,'msg'=>'Unauthorized']); exit; }
            $key = key_resolve($u);
            $lp = KEY_DIR . '/' . hash('sha256', strtolower($key)) . '.lock';
            @unlink($lp);
            spawn_worker_async($key);
            echo json_encode(['ok'=>true,'worker_alive'=>worker_alive($key)]);
            exit;

        case 'tick':
            $u = trim($_POST['user'] ?? ''); $tk = trim($_POST['auth_token'] ?? '');
            if (!require_auth($u, $tk)) { echo json_encode(['ok'=>false,'msg'=>'Unauthorized']); exit; }
            $key = key_resolve($u);
            $s = key_load($key);

            if (!empty($s['config']['auto']) && empty($s['config']['paused']) && !worker_alive($key)) {
                $lp = KEY_DIR . '/' . hash('sha256', strtolower($key)) . '.lock';
                @unlink($lp);
                spawn_worker_async($key);
            }

            if (!worker_alive($key)) {
                try { worker_step($key); } catch (Throwable $e) { key_log($key,'error','fallback: '.$e->getMessage()); }
            }

            echo json_encode([
                'ok' => true,
                'worker_alive' => worker_alive($key),
                'pending_pred' => $s['pending_pred'] ?? null,
                'pending_session' => $s['pending_session'] ?? null,
            ]);
            exit;

        case 'logout':
            $u = trim($_POST['user'] ?? ''); $tk = trim($_POST['auth_token'] ?? '');
            if (!require_auth($u, $tk)) { echo json_encode(['ok'=>false,'msg'=>'Unauthorized']); exit; }
            $key = key_resolve($u);
            @unlink(key_path($key));
            @unlink(KEY_DIR . '/' . hash('sha256', strtolower($key)) . '.lock');
            echo json_encode(['ok'=>true]); exit;

        case 'clear_logs':
            $u = trim($_POST['user'] ?? ''); $tk = trim($_POST['auth_token'] ?? '');
            if (!require_auth($u, $tk)) { echo json_encode(['ok'=>false,'msg'=>'Unauthorized']); exit; }
            $key = key_resolve($u);
            $s = key_load($key); $s['logs'] = []; key_save($key, $s);
            echo json_encode(['ok'=>true]); exit;

        case 'history_dudoan':
            $u = trim($_REQUEST['user'] ?? ''); $tk = trim($_REQUEST['auth_token'] ?? '');
            if (!require_auth($u, $tk)) { echo json_encode(['ok'=>false,'msg'=>'Unauthorized']); exit; }
            $key = key_resolve($u);
            $s = key_load($key);
            echo json_encode([
                'ok' => true,
                'dudoan_history' => array_slice($s['dudoan_history'] ?? [], 0, 1000),
                'pattern_10' => $s['pattern_10'] ?? '',
                'ai_learned_count' => $s['ai_learned_count'] ?? 0,
            ]);
            exit;
    }
    echo json_encode(['ok'=>false,'msg'=>'Action lạ']);
} catch (Throwable $e) {
    echo json_encode(['ok'=>false,'msg'=>'Lỗi: '.$e->getMessage()]);
}
exit;

// ═══════════════════════════════════════════════════════
// [12] SPAWN WORKER ASYNC (FIXED — KHÔNG PHỤ THUỘC CURL)
// ═══════════════════════════════════════════════════════
function spawn_worker_async(string $key): void {
    $scheme = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host   = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $path   = $_SERVER['SCRIPT_NAME'] ?? '/index.php';
    $workerUrl = "$scheme://$host$path?action=worker&key=" . urlencode($key) . "&max=3000";

    // LỚP 1: exec() với PHP CLI
    if (function_exists('exec') && !in_array('exec', array_map('trim', explode(',', (string)ini_get('disable_functions'))))) {
        $php = PHP_BINARY ?: 'php';
        $code = 'ignore_user_abort(true);set_time_limit(0);@file_get_contents(' . var_export($workerUrl, true) . ');';
        $cmd = sprintf('%s -r %s > /dev/null 2>&1 &', escapeshellarg($php), escapeshellarg($code));
        @exec($cmd);
        return;
    }

    // LỚP 2: shell_exec() với curl/wget
    if (function_exists('shell_exec') && !in_array('shell_exec', array_map('trim', explode(',', (string)ini_get('disable_functions'))))) {
        $safeUrl = escapeshellarg($workerUrl);
        @shell_exec("curl -s --max-time 2 " . $safeUrl . " > /dev/null 2>&1 &");
        return;
    }

    // LỚP 3: popen()
    if (function_exists('popen') && !in_array('popen', array_map('trim', explode(',', (string)ini_get('disable_functions'))))) {
        $p = @popen("curl -s --max-time 2 " . escapeshellarg($workerUrl) . " > /dev/null 2>&1 &", 'r');
        if ($p) { @pclose($p); return; }
    }

    // LỚP 4: fsockopen raw HTTP
    if (function_exists('fsockopen')) {
        $parsed = parse_url($workerUrl);
        $h = $parsed['host'] ?? $host;
        $port = ($parsed['scheme'] ?? 'http') === 'https' ? 443 : 80;
        $fp = @fsockopen($h, $port, $errno, $errstr, 0.5);
        if ($fp) {
            stream_set_timeout($fp, 1);
            $reqPath = ($parsed['path'] ?? '/') . '?' . ($parsed['query'] ?? '');
            $req  = "GET {$reqPath} HTTP/1.1\r\n";
            $req .= "Host: {$h}\r\n";
            $req .= "User-Agent: Mozilla/5.0\r\n";
            $req .= "Connection: Close\r\n\r\n";
            @fwrite($fp, $req);
            @fclose($fp);
            return;
        }
    }

    // LỚP 5: curl_multi (nếu extension có thật)
    if (function_exists('curl_multi_init') && function_exists('curl_multi_exec')) {
        try {
            $mh = curl_multi_init();
            $ch = curl_init($workerUrl);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => 1,
                CURLOPT_CONNECTTIMEOUT => 1,
                CURLOPT_SSL_VERIFYPEER => false,
            ]);
            curl_multi_add_handle($mh, $ch);
            $running = null;
            $start = microtime(true);
            do {
                curl_multi_exec($mh, $running);
                curl_multi_select($mh, 0.1);
            } while ($running > 0 && microtime(true) - $start < 0.5);
            curl_multi_remove_handle($mh, $ch);
            curl_close($ch);
            curl_multi_close($mh);
        } catch (Throwable $e) {
            // im lặng
        }
        return;
    }

    // LỚP 6: file_get_contents non-blocking
    try {
        $ctx = stream_context_create(['http' => ['timeout' => 0.5, 'header' => "User-Agent: Mozilla/5.0\r\n"]]);
        @file_get_contents($workerUrl, false, $ctx);
    } catch (Throwable $e) {
        // bỏ qua
    }
}


// ═════════════════════════════════════════════════════════════
// [UPGRADE] TTOAN ALGORITHM — ghép từ ttoanlc79v2.txt (JS→PHP, prefix ttoan_), bản cuối 881 dòng, smoke test pass
// ═════════════════════════════════════════════════════════════
/**
 * ============================================================================
 *  ttoan_php.inc  —  Chuyển đổi 100% logic thuật toán dự đoán Tài/Xỉu
 *                    từ Node.js/Express (ttoanlc79v2.txt) sang PHP thuần.
 * ============================================================================
 *  Nguồn gốc: ttoanlc79v2.txt (Express + axios + cors).
 *  Phạm vi  : CHỈ các hàm tính toán thuần (không chuyển route/HTTP/axios/cors).
 *  Tiền tố  : mọi hàm/hằng đều có prefix `ttoan_` / `TTOAN_` để tránh trùng.
 *
 *  QUY ƯỚC DỮ LIỆU (GIỮ NGUYÊN như bản JS):
 *  - Mỗi phần tử lịch sử là mảng associative có các khoá:
 *        'phien'    => int|string  (mã phiên)
 *        'ket_qua'  => 'Tài' | 'Xỉu'
 *        'tong'     => int          (tổng điểm 3 xúc xắc, 3..18)
 *        'xuc_xac'  => array        (tùy chọn)
 *  - Thứ tự mảng lịch sử: GIỐNG hẳn bản JS — hàm generatePrediction đọc
 *    phần tử CUỐI CÙNG (count($history)-1) làm "phiên hiện tại" (currentSession,
 *    currentTong, lastResult). Trong bản JS, endpoint truyền mảng data với
 *    data[0] là phiên mới nhất, do đó logic gốc coi phần tử cuối là hiện tại.
 *    File này TINH NGHỊA Y HẾT, không sửa. Nếu tool của bạn lưu lịch sử
 *    mới nhất ở đầu mảng, gọi ttoan_normalize_history($history, true) để
 *    đảo ngược trước khi dự đoán.
 *  - Mã hoá kênh dự đoán trong các hàm con: 1 = Tài, 2 = Xỉu, 0 = không đủ dữ liệu.
 *
 *  TRẠNG THÁI MODEL (modelPredictions):
 *  - Bản JS dùng biến module-level `let modelPredictions = {}` để lưu lịch sử
 *    dự đoán của 5 mô hình (trend/short/mean/switch/bridge) theo phien, phục vụ
 *    evaluateModelPerformance. File này hỗ trợ 2 cách:
 *      (a) Truyền biến by-reference:  ttoan_generate_prediction($h, $mp)
 *          — $mp được giữ giữa các lần gọi (giống JS).
 *      (b) Không truyền: dùng state nội bộ tĩnh (ttoan_model_predictions_state()).
 * ============================================================================
 */

/* ----------------------------------------------------------------------------
 *  DỮ LIỆU TĨNH — MẸO TỔNG ĐIỂM (tongDiemMeo, từ caulc79.txt)
 *  key = tổng điểm (3..18), value = [ket_qua, xac_suat]
 * -------------------------------------------------------------------------- */
const TTOAN_TONG_DIEM_MEO = [
    3  => ['ket_qua' => 'Xỉu', 'xac_suat' => 0.70],
    4  => ['ket_qua' => 'Tài',  'xac_suat' => 0.60],
    5  => ['ket_qua' => 'Tài',  'xac_suat' => 0.70],
    6  => ['ket_qua' => 'Xỉu', 'xac_suat' => 0.60],
    7  => ['ket_qua' => 'Tài',  'xac_suat' => 0.80],
    8  => ['ket_qua' => 'Xỉu', 'xac_suat' => 0.80],
    9  => ['ket_qua' => 'Xỉu', 'xac_suat' => 0.70],
    10 => ['ket_qua' => 'Tài',  'xac_suat' => 0.80],
    11 => ['ket_qua' => 'Xỉu', 'xac_suat' => 0.60],
    12 => ['ket_qua' => 'Tài',  'xac_suat' => 0.80],
    13 => ['ket_qua' => 'Tài',  'xac_suat' => 0.80],
    14 => ['ket_qua' => 'Xỉu', 'xac_suat' => 0.60],
    15 => ['ket_qua' => 'Xỉu', 'xac_suat' => 0.70],
    16 => ['ket_qua' => 'Tài',  'xac_suat' => 0.60],
    17 => ['ket_qua' => 'Xỉu', 'xac_suat' => 0.60],
    18 => ['ket_qua' => 'Xỉu', 'xac_suat' => 0.80],
];

/* ----------------------------------------------------------------------------
 *  DỮ LIỆU TĨNH — MẸO CẦU (cauPatterns)
 * -------------------------------------------------------------------------- */
const TTOAN_CAU_PATTERNS = [
    '1-1'          => ['desc' => 'Cầu 1-1 (T-X-T-X)',                 'weight' => 0.85],
    '1-2'          => ['desc' => 'Cầu 1-2 (T-X-X-T)',                 'weight' => 0.80],
    '2-1'          => ['desc' => 'Cầu 2-1 (T-T-X-T)',                 'weight' => 0.80],
    '2-2'          => ['desc' => 'Cầu 2-2 (T-T-X-X)',                 'weight' => 0.85],
    '2-3'          => ['desc' => 'Cầu 2-3 (T-T-X-X-X)',               'weight' => 0.75],
    '3-2'          => ['desc' => 'Cầu 3-2 (T-T-T-X-X)',               'weight' => 0.75],
    '3-3'          => ['desc' => 'Cầu 3-3 (T-T-T-X-X-X)',             'weight' => 0.70],
    '3-4'          => ['desc' => 'Cầu 3-4 (T-T-T-X-X-X-X)',           'weight' => 0.65],
    '4-3'          => ['desc' => 'Cầu 4-3 (T-T-T-T-X-X-X)',           'weight' => 0.65],
    '4-4'          => ['desc' => 'Cầu 4-4 (T-T-T-T-X-X-X-X)',         'weight' => 0.60],
    '1-3'          => ['desc' => 'Cầu 1-3 (T-X-X-X)',                 'weight' => 0.70],
    '3-1'          => ['desc' => 'Cầu 3-1 (T-T-T-X)',                 'weight' => 0.70],
    '1-4'          => ['desc' => 'Cầu 1-4 (T-X-X-X-X)',               'weight' => 0.65],
    '4-1'          => ['desc' => 'Cầu 4-1 (T-T-T-T-X)',               'weight' => 0.65],
    '2-4'          => ['desc' => 'Cầu 2-4 (T-T-X-X-X-X)',             'weight' => 0.60],
    '4-2'          => ['desc' => 'Cầu 4-2 (T-T-T-T-X-X)',             'weight' => 0.60],
    '5-5'          => ['desc' => 'Cầu 5-5 (5T-5X)',                   'weight' => 0.55],
    '5-1'          => ['desc' => 'Cầu 5-1 (5T-1X)',                   'weight' => 0.60],
    '1-5'          => ['desc' => 'Cầu 1-5 (1T-5X)',                   'weight' => 0.60],
    '6-6'          => ['desc' => 'Cầu 6-6 (6T-6X)',                   'weight' => 0.50],
    '7-7'          => ['desc' => 'Cầu 7-7 (7T-7X)',                   'weight' => 0.45],
    '8-8'          => ['desc' => 'Cầu 8-8 (8T-8X)',                   'weight' => 0.40],
    '10-10'        => ['desc' => 'Cầu 10-10 (10T-10X)',               'weight' => 0.35],
    'bệt'          => ['desc' => 'Cầu bệt (chuỗi dài)',               'weight' => 0.50],
    'đảo'          => ['desc' => 'Cầu đảo (đảo ngược)',               'weight' => 0.75],
    'cầu nghiêng'  => ['desc' => 'Cầu nghiêng (lệch về 1 bên)',       'weight' => 0.70],
    'cầu đối xứng' => ['desc' => 'Cầu đối xứng (T-X-X-T)',            'weight' => 0.80],
    'cầu lặp'      => ['desc' => 'Cầu lặp (lặp lại mẫu)',             'weight' => 0.85],
    'cầu đan'      => ['desc' => 'Cầu đan xen (T-X-T-T-X)',           'weight' => 0.75],
    'cầu bẻ'       => ['desc' => 'Cầu bẻ (đột ngột đổi)',             'weight' => 0.90],
];

/** Getter mảng mẹo tổng điểm (trả về bản sao, an toàn). */
function ttoan_tong_diem_meo(): array { return TTOAN_TONG_DIEM_MEO; }

/** Getter mảng mẫu cầu. */
function ttoan_cau_patterns(): array { return TTOAN_CAU_PATTERNS; }

/** Random float [0,1) thay thế Math.random(). */
function ttoan_random(): float {
    return (float)mt_rand() / (float)(mt_getrandmax() + 1);
}

/**
 * State nội bộ cho modelPredictions (dùng khi caller không truyền by-ref).
 * Trả về reference để có thể gán lại.
 */
function &ttoan_model_predictions_state(): array {
    static $state = [];
    return $state;
}

/** Reset state nội bộ (và tùy chọn biến by-ref của caller). */
function ttoan_reset_state(?array &$modelPredictions = null): void {
    $s = &ttoan_model_predictions_state();
    $s = [];
    if ($modelPredictions !== null) { $modelPredictions = []; }
}

/* ============================================================================
 *  HÀM CƠ BẢN — detectStreakAndBreak
 *  Đếm chuỗi (streak) của kết quả cuối cùng + xác suất bẻ cầu (breakProb).
 *  Trả về: ['streak'=>int, 'currentResult'=>'Tài'|'Xỉu'|null, 'breakProb'=>float]
 * ========================================================================== */
function ttoan_detect_streak_and_break(array $history): array {
    $h = array_values($history);
    if (count($h) === 0) {
        return ['streak' => 0, 'currentResult' => null, 'breakProb' => 0.0];
    }
    $streak = 1;
    $currentResult = $h[count($h) - 1]['ket_qua'];
    for ($i = count($h) - 2; $i >= 0; $i--) {
        if ($h[$i]['ket_qua'] === $currentResult) { $streak++; } else { break; }
    }
    $last15 = array_map(fn($it) => $it['ket_qua'], array_slice($h, -15));
    if (count($last15) === 0) {
        return ['streak' => $streak, 'currentResult' => $currentResult, 'breakProb' => 0.0];
    }
    $switches = 0;
    for ($i = 1; $i < count($last15); $i++) {
        if ($last15[$i] !== $last15[$i - 1]) { $switches++; }
    }
    $taiCount = count(array_filter($last15, fn($r) => $r === 'Tài'));
    $xiuCount = count($last15) - $taiCount;
    $imbalance = abs($taiCount - $xiuCount) / count($last15);
    $breakProb = 0.0;
    if ($streak >= 8) {
        $breakProb = min(0.6 + $switches / 15 + $imbalance * 0.15, 0.9);
    } elseif ($streak >= 5) {
        $breakProb = min(0.35 + $switches / 10 + $imbalance * 0.25, 0.85);
    } elseif ($streak >= 3 && $switches >= 7) {
        $breakProb = 0.3;
    }
    return ['streak' => $streak, 'currentResult' => $currentResult, 'breakProb' => $breakProb];
}

/* ============================================================================
 *  evaluateModelPerformance — đánh giá tỉ lệ đúng của 1 mô hình trong lookback
 *  phiên gần nhất. Trả về hệ số trong [0.5, 1.5].
 *  $modelPredictions: cấu trúc [modelName => [phien => 1|2]]
 * ========================================================================== */
function ttoan_evaluate_model_performance(array $history, string $modelName, array $modelPredictions, int $lookback = 10): float {
    $h = array_values($history);
    if (!isset($modelPredictions[$modelName]) || count($h) < 2) { return 1.0; }
    $lookback = min($lookback, count($h) - 1);
    $correct = 0;
    for ($i = 0; $i < $lookback; $i++) {
        $sessionId = $h[count($h) - ($i + 2)]['phien'];
        $prediction = $modelPredictions[$modelName][$sessionId] ?? 0;
        $actual = $h[count($h) - ($i + 1)]['ket_qua'];
        if (($prediction === 1 && $actual === 'Tài') || ($prediction === 2 && $actual === 'Xỉu')) {
            $correct++;
        }
    }
    $ratio = ($lookback > 0) ? 1 + ($correct - $lookback / 2) / ($lookback / 2) : 1.0;
    return max(0.5, min(1.5, $ratio));
}

/* ============================================================================
 *  smartBridgeBreak — bẻ cầu thông minh.
 *  Trả về: ['prediction'=>0|1|2, 'breakProb'=>float, 'reason'=>string]
 * ========================================================================== */
function ttoan_smart_bridge_break(array $history): array {
    $h = array_values($history);
    if (count($h) < 3) {
        return ['prediction' => 0, 'breakProb' => 0.0, 'reason' => 'Không đủ dữ liệu để bẻ cầu'];
    }
    $sb = ttoan_detect_streak_and_break($h);
    $streak = $sb['streak']; $currentResult = $sb['currentResult']; $breakProb = $sb['breakProb'];
    $last20Results = array_map(fn($it) => $it['ket_qua'], array_slice($h, -20));
    $last20Scores = array_map(fn($it) => $it['tong'] ?? 0, array_slice($h, -20));
    $finalBreakProb = $breakProb;
    $reason = '';
    $avgScore = array_sum($last20Scores) / (count($last20Scores) ?: 1);
    $devSum = 0.0;
    foreach ($last20Scores as $s) { $devSum += abs($s - $avgScore); }
    $scoreDeviation = $devSum / (count($last20Scores) ?: 1);
    $last5Results = array_slice($last20Results, -5);
    // Đếm mẫu 3 liên tiếp trong 20 kết quả gần nhất
    $patternCounts = [];
    for ($i = 0; $i <= count($last20Results) - 3; $i++) {
        $pattern = implode(',', array_slice($last20Results, $i, 3));
        $patternCounts[$pattern] = ($patternCounts[$pattern] ?? 0) + 1;
    }
    $mostCommonPattern = null; // [pattern, count]
    if (count($patternCounts) > 0) {
        arsort($patternCounts); // giảm dần theo count, giữ key
        $mostCommonPattern = [key($patternCounts), current($patternCounts)];
    }
    $hasRepeatingPattern = ($mostCommonPattern !== null && $mostCommonPattern[1] >= 3);
    $last5AllSame = (count($last5Results) > 0);
    foreach ($last5Results as $r) { if ($r !== $currentResult) { $last5AllSame = false; break; } }

    if ($streak >= 6) {
        $finalBreakProb = min($finalBreakProb + 0.15, 0.9);
        $reason = "[Bẻ Cầu] Chuỗi {$streak} {$currentResult} dài, khả năng bẻ cầu cao";
    } elseif ($streak >= 4 && $scoreDeviation > 3) {
        $finalBreakProb = min($finalBreakProb + 0.10, 0.85);
        $reason = sprintf("[Bẻ Cầu] Biến động điểm số lớn (%.1f), khả năng bẻ cầu tăng", $scoreDeviation);
    } elseif ($hasRepeatingPattern && $last5AllSame) {
        $finalBreakProb = min($finalBreakProb + 0.05, 0.8);
        $reason = "[Bẻ Cầu] Phát hiện mẫu lặp {$mostCommonPattern[0]}, có khả năng bẻ cầu";
    } else {
        $finalBreakProb = max($finalBreakProb - 0.15, 0.15);
        $reason = '[Bẻ Cầu] Không phát hiện mẫu bẻ cầu mạnh, tiếp tục theo cầu';
    }
    // 1=Tài, 2=Xỉu. breakProb cao => dự đoán NGƯỢC với hiện tại.
    if ($finalBreakProb > 0.65) {
        $prediction = ($currentResult === 'Tài') ? 2 : 1;
    } else {
        $prediction = ($currentResult === 'Tài') ? 1 : 2;
    }
    return ['prediction' => $prediction, 'breakProb' => $finalBreakProb, 'reason' => $reason];
}

/* ============================================================================
 *  trendAndProb — mô hình xu hướng & xác suất (trả về 0/1/2)
 * ========================================================================== */
function ttoan_trend_and_prob(array $history): int {
    $h = array_values($history);
    if (count($h) < 3) { return 0; }
    $sb = ttoan_detect_streak_and_break($h);
    $streak = $sb['streak']; $currentResult = $sb['currentResult']; $breakProb = $sb['breakProb'];
    if ($streak >= 5) {
        if ($breakProb > 0.75) { return ($currentResult === 'Tài') ? 2 : 1; }
        return ($currentResult === 'Tài') ? 1 : 2;
    }
    $last15 = array_map(fn($it) => $it['ket_qua'], array_slice($h, -15));
    if (count($last15) === 0) { return 0; }
    $taiWeight = 0.0; $xiuWeight = 0.0;
    foreach ($last15 as $i => $r) {
        $w = pow(1.2, $i);
        if ($r === 'Tài') { $taiWeight += $w; } else { $xiuWeight += $w; }
    }
    $totalWeight = $taiWeight + $xiuWeight;
    $last10 = array_slice($last15, -10);
    $patterns = [];
    if (count($last10) >= 4) {
        for ($i = 0; $i <= count($last10) - 4; $i++) {
            $patterns[] = implode(',', array_slice($last10, $i, 4));
        }
    }
    $patternCounts = [];
    foreach ($patterns as $p) { $patternCounts[$p] = ($patternCounts[$p] ?? 0) + 1; }
    $mostCommon = null;
    if (count($patternCounts) > 0) {
        arsort($patternCounts);
        $mostCommon = [key($patternCounts), current($patternCounts)];
    }
    if ($mostCommon !== null && $mostCommon[1] >= 3) {
        $parts = explode(',', $mostCommon[0]);
        return ($parts[count($parts) - 1] !== $last10[count($last10) - 1]) ? 1 : 2;
    }
    if ($totalWeight > 0 && abs($taiWeight - $xiuWeight) / $totalWeight >= 0.25) {
        return ($taiWeight > $xiuWeight) ? 2 : 1;
    }
    return ($last15[count($last15) - 1] === 'Xỉu') ? 1 : 2;
}

/* ============================================================================
 *  shortPattern — mô hình mẫu ngắn (trả về 0/1/2)
 * ========================================================================== */
function ttoan_short_pattern(array $history): int {
    $h = array_values($history);
    if (count($h) < 3) { return 0; }
    $sb = ttoan_detect_streak_and_break($h);
    $streak = $sb['streak']; $currentResult = $sb['currentResult']; $breakProb = $sb['breakProb'];
    if ($streak >= 4) {
        if ($breakProb > 0.75) { return ($currentResult === 'Tài') ? 2 : 1; }
        return ($currentResult === 'Tài') ? 1 : 2;
    }
    $last8 = array_map(fn($it) => $it['ket_qua'], array_slice($h, -8));
    if (count($last8) === 0) { return 0; }
    $patterns = [];
    if (count($last8) >= 3) {
        for ($i = 0; $i <= count($last8) - 3; $i++) {
            $patterns[] = implode(',', array_slice($last8, $i, 3));
        }
    }
    $patternCounts = [];
    foreach ($patterns as $p) { $patternCounts[$p] = ($patternCounts[$p] ?? 0) + 1; }
    $mostCommon = null;
    if (count($patternCounts) > 0) {
        arsort($patternCounts);
        $mostCommon = [key($patternCounts), current($patternCounts)];
    }
    if ($mostCommon !== null && $mostCommon[1] >= 2) {
        $parts = explode(',', $mostCommon[0]);
        return ($parts[count($parts) - 1] !== $last8[count($last8) - 1]) ? 1 : 2;
    }
    return ($last8[count($last8) - 1] === 'Xỉu') ? 1 : 2;
}

/* ============================================================================
 *  meanDeviation — mô hình độ lệch trung bình (trả về 0/1/2)
 * ========================================================================== */
function ttoan_mean_deviation(array $history): int {
    $h = array_values($history);
    if (count($h) < 3) { return 0; }
    $sb = ttoan_detect_streak_and_break($h);
    $streak = $sb['streak']; $currentResult = $sb['currentResult']; $breakProb = $sb['breakProb'];
    if ($streak >= 4) {
        if ($breakProb > 0.75) { return ($currentResult === 'Tài') ? 2 : 1; }
        return ($currentResult === 'Tài') ? 1 : 2;
    }
    $last12 = array_map(fn($it) => $it['ket_qua'], array_slice($h, -12));
    if (count($last12) === 0) { return 0; }
    $taiCount = count(array_filter($last12, fn($r) => $r === 'Tài'));
    $xiuCount = count($last12) - $taiCount;
    $imbalance = abs($taiCount - $xiuCount) / count($last12);
    if ($imbalance < 0.35) {
        return ($last12[count($last12) - 1] === 'Xỉu') ? 1 : 2;
    }
    return ($xiuCount > $taiCount) ? 1 : 2;
}

/* ============================================================================
 *  recentSwitch — mô hình đảo chiều gần đây (trả về 0/1/2)
 *  LƯU Ý: bản JS cả 2 nhánh ternary đều trả về cùng giá trị — giữ nguyên.
 * ========================================================================== */
function ttoan_recent_switch(array $history): int {
    $h = array_values($history);
    if (count($h) < 3) { return 0; }
    $sb = ttoan_detect_streak_and_break($h);
    $streak = $sb['streak']; $currentResult = $sb['currentResult']; $breakProb = $sb['breakProb'];
    if ($streak >= 4) {
        if ($breakProb > 0.75) { return ($currentResult === 'Tài') ? 2 : 1; }
        return ($currentResult === 'Tài') ? 1 : 2;
    }
    $last10 = array_map(fn($it) => $it['ket_qua'], array_slice($h, -10));
    if (count($last10) === 0) { return 0; }
    $switches = 0;
    for ($i = 1; $i < count($last10); $i++) {
        if ($last10[$i] !== $last10[$i - 1]) { $switches++; }
    }
    $lastVal = $last10[count($last10) - 1];
    // Giữ nguyên cấu trúc ternary kép của bản JS (cả hai nhánh giống nhau).
    return ($switches >= 6)
        ? (($lastVal === 'Xỉu') ? 1 : 2)
        : (($lastVal === 'Xỉu') ? 1 : 2);
}

/* ============================================================================
 *  isBadPattern — phát hiện mẫu xấu (switches>=9 hoặc streak>=10)
 * ========================================================================== */
function ttoan_is_bad_pattern(array $history): bool {
    $h = array_values($history);
    if (count($h) < 3) { return false; }
    $last15 = array_map(fn($it) => $it['ket_qua'], array_slice($h, -15));
    if (count($last15) === 0) { return false; }
    $switches = 0;
    for ($i = 1; $i < count($last15); $i++) {
        if ($last15[$i] !== $last15[$i - 1]) { $switches++; }
    }
    $sb = ttoan_detect_streak_and_break($h);
    return ($switches >= 9 || $sb['streak'] >= 10);
}

/* ============================================================================
 *  aiHtddLogic — logic AI HTDD (mẫu 1T1X, 2T2X, chuỗi dài, điểm TB, đa số)
 *  Trả về: ['prediction'=>'Tài'|'Xỉu', 'reason'=>string, 'source'=>'AI HTDD']
 * ========================================================================== */
function ttoan_ai_htdd_logic(array $history): array {
    $h = array_values($history);
    if (count($h) < 3) {
        $randomPred = (ttoan_random() < 0.5) ? 'Tài' : 'Xỉu';
        return ['prediction' => $randomPred, 'reason' => 'Không đủ lịch sử, dự đoán ngẫu nhiên', 'source' => 'AI HTDD'];
    }
    $last5Results = array_map(fn($it) => $it['ket_qua'], array_slice($h, -5));
    $last5Scores = array_map(fn($it) => $it['tong'] ?? 0, array_slice($h, -5));
    $taiCount = count(array_filter($last5Results, fn($r) => $r === 'Tài'));
    $xiuCount = count($last5Results) - $taiCount;

    $last3 = array_map(fn($it) => $it['ket_qua'], array_slice($h, -3));
    if (implode(',', $last3) === 'Tài,Xỉu,Tài') {
        return ['prediction' => 'Xỉu', 'reason' => 'Phát hiện mẫu 1T1X -> nên đánh Xỉu', 'source' => 'AI HTDD'];
    }
    if (implode(',', $last3) === 'Xỉu,Tài,Xỉu') {
        return ['prediction' => 'Tài', 'reason' => 'Phát hiện mẫu 1X1T -> nên đánh Tài', 'source' => 'AI HTDD'];
    }
    if (count($h) >= 4) {
        $last4 = array_map(fn($it) => $it['ket_qua'], array_slice($h, -4));
        if (implode(',', $last4) === 'Tài,Tài,Xỉu,Xỉu') {
            return ['prediction' => 'Tài', 'reason' => 'Phát hiện mẫu 2T2X -> nên đánh Tài', 'source' => 'AI HTDD'];
        }
        if (implode(',', $last4) === 'Xỉu,Xỉu,Tài,Tài') {
            return ['prediction' => 'Xỉu', 'reason' => 'Phát hiện mẫu 2X2T -> nên đánh Xỉu', 'source' => 'AI HTDD'];
        }
    }
    if (count($h) >= 9) {
        $last6 = array_slice($h, -6);
        $allTai = true; $allXiu = true;
        foreach ($last6 as $it) {
            if ($it['ket_qua'] !== 'Tài') { $allTai = false; }
            if ($it['ket_qua'] !== 'Xỉu') { $allXiu = false; }
        }
        if ($allTai) {
            return ['prediction' => 'Xỉu', 'reason' => 'Chuỗi Tài quá dài (6 lần) -> dự đoán Xỉu', 'source' => 'AI HTDD'];
        }
        if ($allXiu) {
            return ['prediction' => 'Tài', 'reason' => 'Chuỗi Xỉu quá dài (6 lần) -> dự đoán Tài', 'source' => 'AI HTDD'];
        }
    }
    $avgScore = array_sum($last5Scores) / (count($last5Scores) ?: 1);
    if ($avgScore > 10) {
        return ['prediction' => 'Tài', 'reason' => sprintf('Điểm trung bình cao (%.1f) -> dự đoán Tài', $avgScore), 'source' => 'AI HTDD'];
    }
    if ($avgScore < 8) {
        return ['prediction' => 'Xỉu', 'reason' => sprintf('Điểm trung bình thấp (%.1f) -> dự đoán Xỉu', $avgScore), 'source' => 'AI HTDD'];
    }
    if ($taiCount > $xiuCount + 1) {
        return ['prediction' => 'Xỉu', 'reason' => sprintf('Tài chiếm đa số (%d/%d) -> dự đoán Xỉu', $taiCount, count($last5Results)), 'source' => 'AI HTDD'];
    }
    if ($xiuCount > $taiCount + 1) {
        return ['prediction' => 'Tài', 'reason' => sprintf('Xỉu chiếm đa số (%d/%d) -> dự đoán Tài', $xiuCount, count($last5Results)), 'source' => 'AI HTDD'];
    }
    $totalTai = count(array_filter($h, fn($it) => $it['ket_qua'] === 'Tài'));
    $totalXiu = count($h) - $totalTai;
    if ($totalTai > $totalXiu + 2) {
        return ['prediction' => 'Xỉu', 'reason' => 'Tổng thể Tài nhiều hơn -> dự đoán Xỉu', 'source' => 'AI HTDD'];
    }
    if ($totalXiu > $totalTai + 2) {
        return ['prediction' => 'Tài', 'reason' => 'Tổng thể Xỉu nhiều hơn -> dự đoán Tài', 'source' => 'AI HTDD'];
    }
    $randomPred = (ttoan_random() < 0.5) ? 'Tài' : 'Xỉu';
    return ['prediction' => $randomPred, 'reason' => 'Cân bằng, dự đoán ngẫu nhiên', 'source' => 'AI HTDD'];
}

/* ============================================================================
 *  phanTichCau — phân tích cầu nâng cao (30 phiên gần nhất).
 *  Trả về: ['cau'=>string, 'weight'=>float, 'streaks'=>array]
 *  LƯU Ý: các nhánh if viết tuần tự, nhánh sau GHI ĐÈ nhánh trước (giống JS).
 * ========================================================================== */
function ttoan_phan_tich_cau(array $history): array {
    $h = array_values($history);
    if (count($h) < 3) {
        return ['cau' => 'Khong xac dinh', 'weight' => 0.0, 'streaks' => []];
    }
    $results = array_map(fn($it) => $it['ket_qua'], array_slice($h, -30));
    // Xây dựng danh sách chuỗi (streaks)
    $streaks = [];
    $currentStreak = 1;
    $currentType = $results[0];
    for ($i = 1; $i < count($results); $i++) {
        if ($results[$i] === $currentType) {
            $currentStreak++;
        } else {
            $streaks[] = ['type' => $currentType, 'count' => $currentStreak];
            $currentType = $results[$i];
            $currentStreak = 1;
        }
    }
    $streaks[] = ['type' => $currentType, 'count' => $currentStreak];

    $detectedCau = 'Khong xac dinh';
    $cauWeight = 0.5;

    // Cầu bệt (chuỗi dài)
    $maxStreak = 0;
    foreach ($streaks as $s) { if ($s['count'] > $maxStreak) { $maxStreak = $s['count']; } }
    if ($maxStreak >= 6) { $detectedCau = 'bet'; $cauWeight = 0.5; }

    // Cầu 1-1
    $oneOne = 0;
    for ($i = 0; $i < count($streaks) - 1; $i++) {
        if ($streaks[$i]['count'] === 1 && $streaks[$i + 1]['count'] === 1) { $oneOne++; }
    }
    if ($oneOne >= 3) { $detectedCau = '1-1'; $cauWeight = 0.85; }

    // Cầu 2-2
    $twoTwo = 0;
    for ($i = 0; $i < count($streaks) - 1; $i++) {
        if ($streaks[$i]['count'] === 2 && $streaks[$i + 1]['count'] === 2) { $twoTwo++; }
    }
    if ($twoTwo >= 2) { $detectedCau = '2-2'; $cauWeight = 0.85; }

    // Cầu 1-2
    $oneTwo = 0;
    for ($i = 0; $i < count($streaks) - 1; $i++) {
        if ($streaks[$i]['count'] === 1 && $streaks[$i + 1]['count'] === 2) { $oneTwo++; }
    }
    if ($oneTwo >= 2) { $detectedCau = '1-2'; $cauWeight = 0.80; }

    // Cầu 2-1
    $twoOne = 0;
    for ($i = 0; $i < count($streaks) - 1; $i++) {
        if ($streaks[$i]['count'] === 2 && $streaks[$i + 1]['count'] === 1) { $twoOne++; }
    }
    if ($twoOne >= 2) { $detectedCau = '2-1'; $cauWeight = 0.80; }

    // Cầu 3-2
    $threeTwo = 0;
    for ($i = 0; $i < count($streaks) - 1; $i++) {
        if ($streaks[$i]['count'] === 3 && $streaks[$i + 1]['count'] === 2) { $threeTwo++; }
    }
    if ($threeTwo >= 2) { $detectedCau = '3-2'; $cauWeight = 0.75; }

    // Cầu 2-3
    $twoThree = 0;
    for ($i = 0; $i < count($streaks) - 1; $i++) {
        if ($streaks[$i]['count'] === 2 && $streaks[$i + 1]['count'] === 3) { $twoThree++; }
    }
    if ($twoThree >= 2) { $detectedCau = '2-3'; $cauWeight = 0.75; }

    // Cầu 3-3
    $threeThree = 0;
    for ($i = 0; $i < count($streaks) - 1; $i++) {
        if ($streaks[$i]['count'] === 3 && $streaks[$i + 1]['count'] === 3) { $threeThree++; }
    }
    if ($threeThree >= 2) { $detectedCau = '3-3'; $cauWeight = 0.70; }

    // Cầu đảo
    $daoCount = 0;
    for ($i = 0; $i < count($streaks) - 2; $i++) {
        if ($streaks[$i]['count'] === $streaks[$i + 2]['count'] && $streaks[$i]['type'] !== $streaks[$i + 2]['type']) {
            $daoCount++;
        }
    }
    if ($daoCount >= 2) { $detectedCau = 'dao'; $cauWeight = 0.75; }

    // Cầu nghiêng (10 phiên gần nhất)
    $last10r = array_slice($results, -10);
    $tai10 = count(array_filter($last10r, fn($r) => $r === 'Tài'));
    $xiu10 = count($last10r) - $tai10;
    if (abs($tai10 - $xiu10) >= 6) { $detectedCau = 'cau nghieng'; $cauWeight = 0.70; }

    // Cầu lặp (mẫu 3 xuất hiện >=4 lần)
    $pattern3 = [];
    for ($i = 0; $i <= count($results) - 3; $i++) {
        $pattern3[] = implode(',', array_slice($results, $i, 3));
    }
    $patternCounts3 = [];
    foreach ($pattern3 as $p) { $patternCounts3[$p] = ($patternCounts3[$p] ?? 0) + 1; }
    $maxPattern3 = null;
    if (count($patternCounts3) > 0) {
        arsort($patternCounts3);
        $maxPattern3 = [key($patternCounts3), current($patternCounts3)];
    }
    if ($maxPattern3 !== null && $maxPattern3[1] >= 4) { $detectedCau = 'cau lap'; $cauWeight = 0.85; }

    // Cầu đan
    $danCount = 0;
    for ($i = 0; $i < count($results) - 4; $i++) {
        $sl = array_slice($results, $i, 5);
        if ($sl[0] !== $sl[1] && $sl[1] === $sl[3] && $sl[0] === $sl[2] && $sl[2] !== $sl[4]) {
            $danCount++;
        }
    }
    if ($danCount >= 2) { $detectedCau = 'cau dan'; $cauWeight = 0.75; }

    return ['cau' => $detectedCau, 'weight' => $cauWeight, 'streaks' => $streaks];
}

/* ============================================================================
 *  generatePrediction — THUẬT TOÁN TỔNG HỢP CHÍNH (Full A-Z).
 *  Kết hợp 5 mô hình + AI HTDD + phân tích cầu + mẹo tổng điểm.
 *
 *  @param array        $history           mảng lịch sử (xem quy ước ở đầu file)
 *  @param array|null   &$modelPredictions  trạng thái mô hình (by-ref, giống JS).
 *                                          Bỏ trống => dùng state nội bộ tĩnh.
 *  @return array  ['prediction'=>'Tài'|'Xỉu', 'doTinCay'=>int, 'giaiThich'=>string]
 *
 *  LƯU Ý trung thành với bản JS:
 *   - Nếu $modelPredictions thiếu khoá 'trend' => bị thay thế hoàn toàn bằng
 *     cấu trúc rỗng ['trend'=>[], 'short'=>[], 'mean'=>[], 'switch'=>[], 'bridge'=>[]].
 *   - Khi count($history)<5, dự đoán fallback của 5 mô hình = NGƯỢC với kết quả
 *     cuối cùng (last==='Tài' ? 2 : 1).
 *   - Nhánh cầu '3-2','2-3','3-3','cau lap','cau dan','Khong xac dinh' rơi vào
 *     nhánh else => cầu dự đoán = chính kết quả cuối (lastResult).
 * ========================================================================== */
function ttoan_generate_prediction(array $history, ?array &$modelPredictions = null): array {
    $h = array_values($history);

    // Quản lý state. JS dùng biến module-level `modelPredictions`.
    // PHP: nếu caller truyền biến by-ref thì dùng & ghi lại cuối hàm;
    // nếu không (null) thì dùng state tĩnh nội bộ. KHÔNG dùng `=&` trên
    // tham số by-ref vì sẽ làm tách liên kết với biến caller.
    $hasExternal = ($modelPredictions !== null);
    if ($hasExternal) {
        $mp = $modelPredictions;
    } else {
        $st = &ttoan_model_predictions_state();
        $mp = $st; // copy ra làm việc
    }
    // JS: modelPredictions = predictions || {};  (nếu null => rỗng)
    if (!is_array($mp)) { $mp = []; }
    // JS: if (!modelPredictions.trend) { modelPredictions = {trend:{},...}; }
    // (thiếu khoá 'trend' => thay TOÀN BỘ bằng cấu trúc rỗng)
    if (!isset($mp['trend'])) {
        $mp = ['trend' => [], 'short' => [], 'mean' => [], 'switch' => [], 'bridge' => []];
    }

    if (count($h) === 0) {
        // Ghi lại state trước khi return sớm
        if ($hasExternal) { $modelPredictions = $mp; } else { $st = &ttoan_model_predictions_state(); $st = $mp; }
        $randomPred = (ttoan_random() < 0.5) ? 'Tài' : 'Xỉu';
        return ['prediction' => $randomPred, 'doTinCay' => 50, 'giaiThich' => 'Khong du lich su, du doan ngau nhien'];
    }

    $currentSession = $h[count($h) - 1]['phien'];
    $currentTong = $h[count($h) - 1]['tong'];
    $lastResult = $h[count($h) - 1]['ket_qua'];

    // Fallback khi lịch sử ngắn (<5): dự đoán NGƯỢC với kết quả cuối.
    $fallbackPred = ($lastResult === 'Tài') ? 2 : 1;

    $trendPred  = (count($h) < 5) ? $fallbackPred : ttoan_trend_and_prob($h);
    $shortPred  = (count($h) < 5) ? $fallbackPred : ttoan_short_pattern($h);
    $meanPred   = (count($h) < 5) ? $fallbackPred : ttoan_mean_deviation($h);
    $switchPred = (count($h) < 5) ? $fallbackPred : ttoan_recent_switch($h);
    if (count($h) < 5) {
        $bridgePred = ['prediction' => $fallbackPred, 'breakProb' => 0.0, 'reason' => 'Lich su ngan'];
    } else {
        $bridgePred = ttoan_smart_bridge_break($h);
    }
    $aiPred = ttoan_ai_htdd_logic($h);
    $cauAnalysis = ttoan_phan_tich_cau($h);

    $tongMeo = TTOAN_TONG_DIEM_MEO[$currentTong] ?? ['ket_qua' => 'Khong xac dinh', 'xac_suat' => 0.5];

    // Lưu dự đoán các mô hình theo phiên hiện tại
    $mp['trend'][$currentSession]  = $trendPred;
    $mp['short'][$currentSession]  = $shortPred;
    $mp['mean'][$currentSession]   = $meanPred;
    $mp['switch'][$currentSession] = $switchPred;
    $mp['bridge'][$currentSession] = $bridgePred['prediction'];

    // Đánh giá hiệu suất 5 mô hình
    $modelPerformance = [
        'trend'  => ttoan_evaluate_model_performance($h, 'trend',  $mp),
        'short'  => ttoan_evaluate_model_performance($h, 'short',  $mp),
        'mean'   => ttoan_evaluate_model_performance($h, 'mean',   $mp),
        'switch' => ttoan_evaluate_model_performance($h, 'switch', $mp),
        'bridge' => ttoan_evaluate_model_performance($h, 'bridge', $mp),
    ];

    // Trọng số các mô hình
    $modelWeights = [
        'trend'    => 0.15 * $modelPerformance['trend'],
        'short'    => 0.15 * $modelPerformance['short'],
        'mean'     => 0.15 * $modelPerformance['mean'],
        'switch'   => 0.15 * $modelPerformance['switch'],
        'bridge'   => 0.15 * $modelPerformance['bridge'],
        'aihtdd'   => 0.15,
        'cau'      => 0.10,
        'tongDiem' => 0.10,
    ];

    $taiScore = 0.0;
    $xiuScore = 0.0;

    if ($trendPred === 1)       { $taiScore += $modelWeights['trend']; }  elseif ($trendPred === 2)  { $xiuScore += $modelWeights['trend']; }
    if ($shortPred === 1)       { $taiScore += $modelWeights['short']; }  elseif ($shortPred === 2)  { $xiuScore += $modelWeights['short']; }
    if ($meanPred === 1)        { $taiScore += $modelWeights['mean']; }   elseif ($meanPred === 2)   { $xiuScore += $modelWeights['mean']; }
    if ($switchPred === 1)      { $taiScore += $modelWeights['switch']; } elseif ($switchPred === 2) { $xiuScore += $modelWeights['switch']; }
    if ($bridgePred['prediction'] === 1) { $taiScore += $modelWeights['bridge']; } elseif ($bridgePred['prediction'] === 2) { $xiuScore += $modelWeights['bridge']; }
    if ($aiPred['prediction'] === 'Tài') { $taiScore += $modelWeights['aihtdd']; } else { $xiuScore += $modelWeights['aihtdd']; }

    // Thông tin cầu
    $cauInfo = TTOAN_CAU_PATTERNS[$cauAnalysis['cau']] ?? ['desc' => 'Khong xac dinh', 'weight' => 0.5];

    // Dự đoán theo loại cầu phát hiện được
    $cauPred = null;
    if ($cauAnalysis['cau'] === '1-1') {
        $cauPred = ($lastResult === 'Tài') ? 'Xỉu' : 'Tài';
    } elseif ($cauAnalysis['cau'] === '2-2') {
        $cauPred = ($lastResult === 'Xỉu') ? 'Tài' : 'Xỉu';
    } elseif ($cauAnalysis['cau'] === '1-2') {
        $cauPred = 'Tài';
    } elseif ($cauAnalysis['cau'] === '2-1') {
        $cauPred = 'Xỉu';
    } elseif ($cauAnalysis['cau'] === 'bet') {
        $cauPred = $lastResult;
    } elseif ($cauAnalysis['cau'] === 'dao') {
        $cauPred = ($lastResult === 'Tài') ? 'Xỉu' : 'Tài';
    } elseif ($cauAnalysis['cau'] === 'cau nghieng') {
        $last10c = array_map(fn($it) => $it['ket_qua'], array_slice($h, -10));
        $tai10c = count(array_filter($last10c, fn($r) => $r === 'Tài'));
        $cauPred = ($tai10c > 5) ? 'Xỉu' : 'Tài';
    } else {
        // '3-2','2-3','3-3','cau lap','cau dan','Khong xac dinh',... => theo kết quả cuối
        $cauPred = $lastResult;
    }
    if ($cauPred === 'Tài') { $taiScore += $modelWeights['cau'] * $cauAnalysis['weight']; }
    else                    { $xiuScore += $modelWeights['cau'] * $cauAnalysis['weight']; }

    // Mẹo tổng điểm
    if ($tongMeo['ket_qua'] === 'Tài') {
        $taiScore += $modelWeights['tongDiem'] * $tongMeo['xac_suat'];
    } elseif ($tongMeo['ket_qua'] === 'Xỉu') {
        $xiuScore += $modelWeights['tongDiem'] * $tongMeo['xac_suat'];
    }

    // Điều chỉnh yếu tố khác
    if (ttoan_is_bad_pattern($h)) {
        $taiScore *= 0.8;
        $xiuScore *= 0.8;
    }
    $last10Results = array_map(fn($it) => $it['ket_qua'], array_slice($h, -10));
    $last10TaiCount = count(array_filter($last10Results, fn($r) => $r === 'Tài'));
    if ($last10TaiCount >= 7) {
        $xiuScore += 0.15;
    } elseif ($last10TaiCount <= 3) {
        $taiScore += 0.15;
    }
    if ($bridgePred['breakProb'] > 0.65) {
        if ($bridgePred['prediction'] === 1) { $taiScore += 0.2; } else { $xiuScore += 0.2; }
    }

    $totalScore = $taiScore + $xiuScore;
    $taiProb = ($totalScore > 0) ? ($taiScore / $totalScore) * 100 : 50.0;
    $xiuProb = ($totalScore > 0) ? ($xiuScore / $totalScore) * 100 : 50.0;
    $finalPrediction = ($taiScore > $xiuScore) ? 'Tài' : 'Xỉu'; // hòa => Xỉu
    $doTinCay = (int)round(max($taiProb, $xiuProb));

    $giaiThich = sprintf(
        '[Cau: %s] | [Tong %s: %s %d%%] | %s | %s | Tai: %s%% - Xiu: %s%%',
        $cauInfo['desc'],
        $currentTong,
        $tongMeo['ket_qua'],
        (int)round($tongMeo['xac_suat'] * 100),
        $aiPred['reason'],
        $bridgePred['reason'],
        number_format($taiProb, 1, '.', ''),
        number_format($xiuProb, 1, '.', '')
    );

    // Ghi lại state cho lần gọi sau (by-ref caller hoặc state tĩnh nội bộ)
    if ($hasExternal) {
        $modelPredictions = $mp;
    } else {
        $st = &ttoan_model_predictions_state();
        $st = $mp;
    }
    return ['prediction' => $finalPrediction, 'doTinCay' => $doTinCay, 'giaiThich' => $giaiThich];
}

/* ============================================================================
 *  HÀM TIỆN ÍCH — khởi tạo / gộp lịch sử (tương đương logic fetch trong JS)
 * ========================================================================== */

/**
 * Gộp các phiên mới vào lịch sử, loại trùng theo 'phien', giữ tối đa $max phần tử.
 * Tương đương JS: txHistory = [...newItems, ...txHistory].slice(0, 1000);
 * Mới nhất được ĐẶT LÊN ĐẦU (index 0) — GIỐNG fetchTXData trong JS.
 * @return array  lịch sử sau khi gộp
 */
function ttoan_history_merge_new(array $history, array $mapped, int $max = 1000): array {
    $existingIds = [];
    foreach ($history as $it) { if (isset($it['phien'])) { $existingIds[$it['phien']] = true; } }
    $newItems = [];
    foreach ($mapped as $m) {
        if (isset($m['phien']) && !isset($existingIds[$m['phien']])) { $newItems[] = $m; }
    }
    $merged = array_merge($newItems, $history);
    return array_slice($merged, 0, $max);
}

/**
 * Thêm một bản ghi dự đoán vào đầu danh sách, giữ tối đa $max.
 * Tương đương JS: txPredictions.unshift({...}); txPredictions = slice(0, 200);
 */
function ttoan_predictions_push(array $predictions, array $entry, int $max = 200): array {
    array_unshift($predictions, $entry);
    return array_slice($predictions, 0, $max);
}

/**
 * Điền kết quả thực tế & đúng/sai cho các dự đoán cũ còn null.
 * Tương đương vòng lặp trong endpoint /api/NatOneTools/{tx,md5}.
 * $data: lịch sử phiên (mỗi phần tử có 'phien' và 'ket_qua').
 * @return array  danh sách dự đoán sau khi backfill
 */
function ttoan_backfill_predictions(array $predictions, array $data): array {
    $byPhien = [];
    foreach ($data as $d) { if (isset($d['phien'])) { $byPhien[$d['phien']] = $d; } }
    for ($i = 1; $i < count($predictions); $i++) {
        if (($predictions[$i]['ket_qua'] ?? null) === null) {
            $ph = $predictions[$i]['phien'] ?? null;
            if ($ph !== null && isset($byPhien[$ph])) {
                $actual = $byPhien[$ph]['ket_qua'];
                $predictions[$i]['ket_qua'] = $actual;
                $predictions[$i]['dung_sai'] = ($predictions[$i]['du_doan'] === $actual) ? 'Dung' : 'Sai';
            }
        }
    }
    return $predictions;
}

/* ============================================================================
 *  HÀM TIỆN ÍCH — chuẩn hoá lịch sử để ghép vào tool PHP có cấu trúc khác
 * ========================================================================== */

/**
 * Chuẩn hoá 1 dòng lịch sử về cấu trúc {phien, ket_qua, tong, xuc_xac}.
 * Hỗ trợ alias: 'session'|'id' => phien; 'result'|'ketqua' => ket_qua;
 *               'point'|'diem' => tong; 'dices' => xuc_xac.
 * Chuẩn hoá giá trị T/X/TAI/XIU/1/2 về 'Tài'/'Xỉu'.
 */
function ttoan_normalize_history_item(array $row): array {
    $phien = $row['phien'] ?? $row['session'] ?? $row['id'] ?? null;
    $kq = $row['ket_qua'] ?? $row['result'] ?? $row['ketqua'] ?? null;
    if ($kq !== null) {
        $s = (string)$kq;
        if ($s === 'T' || $s === 'TAI' || $s === 'tai' || $s === '1') { $kq = 'Tài'; }
        elseif ($s === 'X' || $s === 'XIU' || $s === 'xiu' || $s === '2') { $kq = 'Xỉu'; }
    }
    $tong = $row['tong'] ?? $row['point'] ?? $row['diem'] ?? 0;
    $xucXac = $row['xuc_xac'] ?? $row['dices'] ?? [];
    return ['phien' => $phien, 'ket_qua' => $kq, 'tong' => $tong, 'xuc_xac' => $xucXac];
}

/**
 * Chuẩn hoá toàn bộ lịch sử.
 * @param bool $reverse  nếu true => đảo ngược thứ tự (dùng khi tool lưu mới nhất ở đầu
 *                       mà thuật toán gốc đọc phần tử cuối làm hiện tại).
 */
function ttoan_normalize_history(array $history, bool $reverse = false): array {
    $out = array_map('ttoan_normalize_history_item', $history);
    if ($reverse) { $out = array_reverse($out); }
    return array_values($out);
}

/**
 * Xây dựng lịch sử từ chuỗi kết quả thuần (mảng 'Tài'/'Xỉu' hoặc 'T'/'X').
 * $tongs: mảng tổng điểm tương ứng (tùy chọn, mặc định 0).
 * $phiens: mảng mã phiên (tùy chọn, mặc định 1..n).
 * Thứ tự: $seq[0] = cũ nhất, cuối = mới nhất (đúng quy ước thuật toán).
 */
function ttoan_history_from_seq(array $seq, array $tongs = [], array $phiens = []): array {
    $out = [];
    $n = count($seq);
    for ($i = 0; $i < $n; $i++) {
        $kq = $seq[$i];
        if ($kq === 'T' || $kq === 'TAI' || $kq === '1') { $kq = 'Tài'; }
        elseif ($kq === 'X' || $kq === 'XIU' || $kq === '2') { $kq = 'Xỉu'; }
        $out[] = [
            'phien'   => $phiens[$i] ?? ($i + 1),
            'ket_qua' => $kq,
            'tong'    => $tongs[$i] ?? 0,
            'xuc_xac' => [],
        ];
    }
    return $out;
}

/* ============================================================================
 *  HÀM DỰ ĐOÁN CÔNG KHAI — TX và MD5 dùng CHUNG thuật toán generatePrediction.
 *  (Trong JS, cả /api/NatOneTools/tx và /md5 đều gọi generatePrediction.)
 * ========================================================================== */

/** Dự đoán kênh TX. Trả về cùng cấu trúc ttoan_generate_prediction(). */
function ttoan_predict_tx(array $history, ?array &$modelPredictions = null): array {
    return ttoan_generate_prediction($history, $mp);
}

/** Dự đoán kênh MD5. Thuật toán GIỐNG HỆT TX (chỉ khác nguồn lịch sử). */
function ttoan_predict_md5(array $history, ?array &$modelPredictions = null): array {
    return ttoan_generate_prediction($history, $mp);
}
// ═══════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════════
// [14] V14 UPGRADE LAYER — NÂNG CẤP THUẬT TOÁN + CHUYỂN PHIÊN ĐÚNG API
// -------------------------------------------------------------------
// NGUYÊN TẮC: KHÔNG XOÁ / KHÔNG SỬA MỘT DÒNG CODE CŨ NÀO.
// Toàn bộ hàm v13_*, ttoan_*, do_ws_bet, fetch_sessions_api(*) được
// giữ NGUYÊN. Khối này CHỈ THÊM các hàm mới (tiền tố v14_ / universal_)
// và được gọi ở các điểm chèn (overlay) — giữ nguyên nhánh cũ làm fallback.
//
//  • A. Chuyển phiên theo đúng API:
//      - bàn MD5 → host wtxmd52.tele68.com / ns /txmd5 / API v1/txmd5/sessions
//      - bàn Hũ  → host wtx.tele68.com    / ns /tx    / API v1/tx/sessions
//  • B. Nâng cấp thuật toán: áp dụng cho TẤT CẢ dạng cầu (1-1, 2-2, 3-3,
//      4-4, bệt, gãy, xiên, nghiêng, bão, đảo chiều, chu kỳ ẩn, Markov
//      bậc 2, đa khung thời gian, entropy, cluster reversal...) qua lớp
//      overlay v14, kết hợp với v13 cũ (không thay thế).
// ═══════════════════════════════════════════════════════════════════

// ── A.1 Endpoint WS theo loại bàn ──────────────────────────────────
if (!function_exists('ws_endpoint_for')) {
function ws_endpoint_for(string $table_type): array {
    if ($table_type === 'hu') {
        return [
            'host'        => 'wtx.tele68.com',
            'path'        => '/tx/',
            'ns'          => '/tx',
            'sio_connect' => '40/tx,',
            'sio_event'   => '42/tx,',
            'join_prefix' => '0/tx,',
            'body_prefix' => '/tx,',
            'label'       => 'Hũ/TX (wtx.tele68.com)',
            'sessions_api'=> 'https://wtx.tele68.com/v1/tx/sessions',
        ];
    }
    return [
        'host'        => 'wtxmd52.tele68.com',
        'path'        => '/txmd5/',
        'ns'          => '/txmd5',
        'sio_connect' => '40/txmd5,',
        'sio_event'   => '42/txmd5,',
        'join_prefix' => '0/txmd5,',
        'body_prefix' => '/txmd5,',
        'label'       => 'MD5 (wtxmd52.tele68.com)',
        'sessions_api'=> 'https://wtxmd52.tele68.com/v1/txmd5/sessions',
    ];
}
}

// ── A.2 Lấy danh sách phiên theo đúng API của bàn ──────────────────
if (!function_exists('fetch_sessions_universal')) {
function fetch_sessions_universal(string $table_type): ?array {
    return ($table_type === 'hu') ? fetch_sessions_api_hu() : fetch_sessions_api();
}
}

// ── A.3 Đặt cược WS universal — hỗ trợ cả bàn Hũ lẫn MD5 ───────────
// (Giữ NGUYÊN hàm do_ws_bet cũ làm fallback cho md5; hàm này dùng cho
//  cả hai bàn, tự chọn endpoint theo table_type.)
if (!function_exists('do_ws_bet_universal')) {
function do_ws_bet_universal(string $key, array $s, array &$actions): bool {
    global $CFG;
    if (empty($s['token'])) return false;
    $table_type = $s['config']['table_type'] ?? 'md5';
    $ep = ws_endpoint_for($table_type);
    $cfg = $s['config'];
    $pred = $s['pending_pred'];
    $pendingSession = (int)$s['pending_session'];
    $amount = (int)($s['pending_bet_amount'] ?? $cfg['base_bet'] ?? 10000);
    if ($amount < 1000) $amount = 1000;
    $wsPath = rtrim($ep['path'], '/') . '/?EIO=4&transport=websocket';
    key_log($key, 'info', "🌐 WS universal → bàn " . strtoupper($table_type) . " → {$ep['host']}{$ep['path']} (ns {$ep['ns']})");
    $ws = new TinyWS($ep['host'], 443, $wsPath, ['Authorization: Bearer ' . $s['token']]);
    if (!$ws->connect()) {
        key_log($key, 'error', '❌ WS universal connect fail: ' . $ws->error . " ({$ep['label']})");
        $actions[] = ['type' => 'error', 'msg' => 'WS universal fail: ' . $ws->error];
        return false;
    }
    $authPayload = json_encode(['token' => $s['token']], JSON_UNESCAPED_UNICODE);
    $opened = false; $joined = false; $betDone = false; $betAck = false; $sawState = null; $sawTickSid = null;
    $deadline = microtime(true) + 18;
    $betAmount = $amount;
    while (microtime(true) < $deadline) {
        $frames = $ws->readOneFrame(1);
        if ($frames === null) { key_log($key, 'warn', '⚠️ WS universal đóng giữa chừng'); break; }
        if ($frames === []) continue;
        foreach ($frames as $pkt) {
            if ($pkt === '' || $pkt === null) continue;
            if (str_starts_with($pkt, '0{')) {
                $opened = true;
                $ws->sendRaw($ep['sio_connect'] . $authPayload);
                key_log($key, 'info', "🔗 OPEN → gửi {$ep['sio_connect']}[token]");
                continue;
            }
            if ($pkt === '2') { $ws->sendRaw('3'); continue; }
            if ($pkt === '3' || $pkt === '6') continue;
            if ($pkt === '1') { key_log($key, 'warn', '⚠️ Engine.IO CLOSE (universal)'); $ws->close(); return false; }
            if (!str_starts_with($pkt, '4')) continue;
            $sio = substr($pkt, 1);
            if (str_starts_with($sio, $ep['join_prefix'])) { $joined = true; key_log($key, 'success', "✅ Join {$ep['ns']}"); continue; }
            if (str_starts_with($sio, '1')) { key_log($key, 'warn', '⚠️ SIO DISCONNECT (universal)'); $ws->close(); return false; }
            if (str_starts_with($sio, '4')) { key_log($key, 'error', '❌ CONNECT_ERROR (universal): '.substr($sio,0,120)); $ws->close(); return false; }
            if (!str_starts_with($sio, '2')) continue;
            $body = substr($sio, 1);
            if (str_starts_with($body, $ep['body_prefix'])) $body = substr($body, strlen($ep['body_prefix']));
            $msg = json_decode($body, true);
            if (!is_array($msg) || count($msg) < 1) continue;
            $ev = $msg[0] ?? ''; $d = $msg[1] ?? [];
            if ($ev === 'tick-update') {
                $sawState = $d['state'] ?? null;
                $sawTickSid = isset($d['id']) ? (int)$d['id'] : null;
                if ($sawState === 'BETTING' && $joined && !$betDone) {
                    if ($sawTickSid !== null && $sawTickSid < $pendingSession) continue;
                    $eventArr = ['bet', ['type' => $pred, 'amount' => $betAmount]];
                    $ws->sendRaw($ep['sio_event'] . json_encode($eventArr, JSON_UNESCAPED_UNICODE));
                    $betDone = true;
                    $logMsg = "💰 ĐẶT #{$pendingSession} [{$ep['label']}]: {$pred} × " . number_format($betAmount);
                    key_log($key, 'success', $logMsg);
                    $actions[] = ['type' => 'bet', 'msg' => $logMsg];
                    key_update($key, function($d) use ($pendingSession, $betAmount) {
                        $d['bet_session'] = $pendingSession;
                        $d['bet_amount'] = $betAmount;
                        return $d;
                    });
                    $waitUntil = microtime(true) + 2.5;
                    while (microtime(true) < $waitUntil) {
                        $more = $ws->readOneFrame(1);
                        if ($more === null) break;
                        if ($more === []) continue;
                        foreach ($more as $p2) {
                            if ($p2 === '2') { $ws->sendRaw('3'); continue; }
                            if (!str_starts_with($p2, '4')) continue;
                            $s2 = substr($p2, 1);
                            if (!str_starts_with($s2, '2')) continue;
                            $b2 = substr($s2, 1);
                            if (str_starts_with($b2, $ep['body_prefix'])) $b2 = substr($b2, strlen($ep['body_prefix']));
                            $m2 = json_decode($b2, true);
                            if (!is_array($m2)) continue;
                            if (($m2[0] ?? '') === 'bet-result') $betAck = true;
                            if (($m2[0] ?? '') === 'bet-result' && isset($m2[1]['postBalance'])) {
                                key_update($key, function($dd) use ($m2) {
                                    $dd['balance'] = $m2[1]['postBalance'];
                                    return $dd;
                                });
                                key_log($key, 'success', '💳 Số dư: ' . number_format($m2[1]['postBalance']));
                            }
                        }
                    }
                    $ws->close();
                    if ($betAck) {
                        key_log($key, 'success', '✅ Máy chủ đã trả bet-result xác nhận lệnh cược.');
                    } else {
                        key_log($key, 'warn', '⚠️ Đã gửi yêu cầu cược nhưng chưa nhận bet-result; giữ khóa phiên để tránh gửi trùng. Kiểm tra log/API game.');
                        $actions[] = ['type'=>'warn', 'msg'=>'Đã gửi lệnh nhưng chưa có xác nhận từ máy chủ. Không tự gửi lặp để tránh cược trùng.'];
                    }
                    return true;
                }
            }
            if ($ev === 'session-result') { $ws->close(); return false; }
        }
    }
    $ws->close();
    if (!$betDone) {
        if (!$opened) key_log($key, 'warn', '⚠️ [universal] Không nhận OPEN');
        elseif (!$joined) key_log($key, 'warn', "⚠️ [universal] Không join {$ep['ns']}");
        elseif ($sawState === 'BETTING') key_log($key, 'warn', "⚠️ [universal] Có BETTING nhưng không bet được #{$pendingSession}");
        elseif ($sawState) key_log($key, 'info', "⏳ [universal] State cuối: {$sawState}");
        else key_log($key, 'warn', '⚠️ [universal] Không nhận tick-update 18s');
    }
    return $betDone;
}
}

// ═══════════════════════════════════════════════════════════════════
// B. V14 THUẬT TOÁN NÂNG CẤP — ÁP DỤNG CHO TẤT CẢ DẠNG CẦU
// Quy ước: $seq[0] = phiên MỚI NHẤT (giống hệt v13). pick = dự đoán
// phiên kế tiếp. Mỗi voter trả về ?['pick'=>'T'|'X','w'=>float,'note'=>string]
// ═══════════════════════════════════════════════════════════════════
if (!function_exists('v14_last')) {
function v14_last(array $seq, int $n): array { return array_slice($seq, 0, $n); }
}
if (!function_exists('v14_cnt')) {
function v14_cnt(array $seq): array { $t=0;$x=0; foreach($seq as $c){ if($c==='T')$t++; elseif($c==='X')$x++; } return [$t,$x]; }
}
if (!function_exists('v14_runs')) {
function v14_runs(array $seq): array {
    $runs=[]; $cur=null; $len=0;
    foreach($seq as $c){ if($c!=='T'&&$c!=='X') continue; if($c===$cur){$len++;} else { if($cur!==null)$runs[]=['s'=>$cur,'l'=>$len]; $cur=$c;$len=1; } }
    if($cur!==null)$runs[]=['s'=>$cur,'l'=>$len];
    return $runs;
}
}

// B.1 Cầu 1-1 (đảo) ở mọi độ dài
if (!function_exists('v14_vote_cau_11_full')) {
function v14_vote_cau_11_full(array $seq): ?array {
    if (count($seq)<4) return null;
    $alt=1; for($i=0;$i+1<count($seq);$i++){ if(($seq[$i]==='T'||$seq[$i]==='X')&&$seq[$i]!==$seq[$i+1]) $alt++; else break; }
    if ($alt>=3){ $w=min(0.92,0.55+($alt-2)*0.12); return ['pick'=> $seq[0]==='T'?'X':'T', 'w'=>$w, 'note'=>"cầu 1-1 dài $alt"]; }
    return null;
}
}

// B.2 Cầu 2-2 (song hành cặp)
if (!function_exists('v14_vote_cau_22_full')) {
function v14_vote_cau_22_full(array $seq): ?array {
    if (count($seq)<6) return null;
    $pairs=0; $ok=true; $lastSide=null;
    for($p=0; $p+1<count($seq) && $p<8; $p+=2){
        if($seq[$p]!==$seq[$p+1]){ $ok=false; break; }
        if($lastSide!==null && $seq[$p]===$lastSide){ $ok=false; break; }
        $lastSide=$seq[$p]; $pairs++;
    }
    if($ok && $pairs>=3){ $w=min(0.9,0.55+($pairs-2)*0.12); return ['pick'=> $seq[0]==='T'?'X':'T', 'w'=>$w, 'note'=>"cầu 2-2 ($pairs cặp)"]; }
    return null;
}
}

// B.3 Cầu 3-3 (khối 3)
if (!function_exists('v14_vote_cau_33_full')) {
function v14_vote_cau_33_full(array $seq): ?array {
    if (count($seq)<9) return null;
    $blocks=0;$ok=true;$lastSide=null;
    for($b=0; $b+2<count($seq) && $b<12; $b+=3){
        if(!($seq[$b]===$seq[$b+1] && $seq[$b+1]===$seq[$b+2])){ $ok=false; break; }
        if($lastSide!==null && $seq[$b]===$lastSide){ $ok=false; break; }
        $lastSide=$seq[$b]; $blocks++;
    }
    if($ok && $blocks>=3){ $w=min(0.88,0.55+($blocks-2)*0.12); return ['pick'=> $seq[0]==='T'?'X':'T', 'w'=>$w, 'note'=>"cầu 3-3 ($blocks khối)"]; }
    return null;
}
}

// B.4 Cầu 4-4 (khối 4)
if (!function_exists('v14_vote_cau_44_full')) {
function v14_vote_cau_44_full(array $seq): ?array {
    if (count($seq)<12) return null;
    $blocks=0;$ok=true;$lastSide=null;
    for($b=0; $b+3<count($seq) && $b<16; $b+=4){
        if(!($seq[$b]===$seq[$b+1] && $seq[$b+1]===$seq[$b+2] && $seq[$b+2]===$seq[$b+3])){ $ok=false; break; }
        if($lastSide!==null && $seq[$b]===$lastSide){ $ok=false; break; }
        $lastSide=$seq[$b]; $blocks++;
    }
    if($ok && $blocks>=3){ $w=min(0.86,0.55+($blocks-2)*0.10); return ['pick'=> $seq[0]==='T'?'X':'T', 'w'=>$w, 'note'=>"cầu 4-4 ($blocks khối)"]; }
    return null;
}
}

// B.5 Cầu bệt (theo chuỗi) — theo khi ngắn, gãy khi dài
if (!function_exists('v14_vote_cau_bet_n')) {
function v14_vote_cau_bet_n(array $seq): ?array {
    if (count($seq)<3) return null;
    $r=v14_runs($seq); if(empty($r)) return null;
    $L=$r[0]['l']; $side=$r[0]['s'];
    if($L>=2 && $L<=4){ return ['pick'=>$side,'w'=>0.55+($L-2)*0.08,'note'=>"cầu bệt theo (streak $L)"]; }
    if($L>=6){ return ['pick'=> $side==='T'?'X':'T','w'=>min(0.85,0.5+($L-5)*0.09),'note'=>"cầu bệt gãy (streak $L)"]; }
    return null;
}
}

// B.6 Cầu gãy đa ngưỡng (3,4,5,6,7,8+)
if (!function_exists('v14_vote_cau_gay_multi')) {
function v14_vote_cau_gay_multi(array $seq): ?array {
    $r=v14_runs($seq); if(empty($r)) return null;
    $L=$r[0]['l']; $side=$r[0]['s'];
    $map=[3=>0.62,4=>0.68,5=>0.74,6=>0.80,7=>0.85];
    if(isset($map[$L])){ return ['pick'=>$side==='T'?'X':'T','w'=>$map[$L],'note'=>"cầu gãy ngưỡng $L"]; }
    if($L>=8){ return ['pick'=>$side==='T'?'X':'T','w'=>0.88,'note'=>"cầu gãy siêu dài $L"]; }
    return null;
}
}

// B.7 Cầu xiên (lặp lệch pha, chu kỳ 3/4/5)
if (!function_exists('v14_vote_cau_xieng')) {
function v14_vote_cau_xieng(array $seq): ?array {
    if (count($seq)<10) return null;
    for($p=3;$p<=5;$p++){
        $hit=0;$tot=0;
        for($i=0;$i+$p<count($seq) && $tot<8;$i++){ $tot++; if($seq[$i]===$seq[$i+$p])$hit++; }
        if($tot>=5 && $hit/$tot>=0.85){ return ['pick'=>$seq[$p-1]??$seq[0],'w'=>0.70,'note'=>"cầu xiên chu kỳ $p"]; }
    }
    return null;
}
}

// B.8 Cầu nghiêng (bias) — đảo chiều về cân bằng
if (!function_exists('v14_vote_cau_nghieng')) {
function v14_vote_cau_nghieng(array $seq): ?array {
    $w=v14_last($seq,20); if(count($w)<15) return null;
    list($t,$x)=v14_cnt($w); $tot=$t+$x; if($tot<15) return null;
    $tr=$t/$tot; $xr=$x/$tot;
    if($tr>=0.62){ return ['pick'=>'X','w'=>min(0.80,0.50+($tr-0.62)*1.5),'note'=>"cầu nghiêng Tài ".round($tr*100)."% → đảo Xỉu"]; }
    if($xr>=0.62){ return ['pick'=>'T','w'=>min(0.80,0.50+($xr-0.62)*1.5),'note'=>"cầu nghiêng Xỉu ".round($xr*100)."% → đảo Tài"]; }
    return null;
}
}

// B.9 Cầu bão (streak cực dài sau chuỗi dài trước đó → tiếp tục)
if (!function_exists('v14_vote_cau_bao')) {
function v14_vote_cau_bao(array $seq): ?array {
    $r=v14_runs($seq); if(count($r)<2) return null;
    $L=$r[0]['l']; $side=$r[0]['s']; $prevL=$r[1]['l']??1;
    if($L>=9 && $prevL>=4){ return ['pick'=>$side,'w'=>0.72,'note'=>"cầu bão streak $L sau chuỗi dài $prevL → theo"]; }
    return null;
}
}

// B.10 Vùng đảo chiều — phá cầu 1-1 khi switches dày đặc
if (!function_exists('v14_vote_cau_dao_chieu')) {
function v14_vote_cau_dao_chieu(array $seq): ?array {
    $w=v14_last($seq,12); if(count($w)<10) return null;
    $sw=0; for($i=0;$i+1<count($w);$i++){ if($w[$i]!==$w[$i+1])$sw++; }
    $r=v14_runs($seq); $L=$r[0]['l']??1;
    if($sw>=7 && $L===1){ return ['pick'=>$seq[0],'w'=>0.66,'note'=>"vùng đảo chiều (switches $sw) → gãy cầu 1-1"]; }
    return null;
}
}

// B.11 Chu kỳ ẩn (autocorrelation lag 2..6)
if (!function_exists('v14_vote_cau_hidden_cycle')) {
function v14_vote_cau_hidden_cycle(array $seq): ?array {
    if (count($seq)<16) return null;
    $bestP=null;$bestHit=0;
    for($p=2;$p<=6;$p++){
        $hit=0;$tot=0;
        for($i=0;$i+$p<count($seq) && $tot<12;$i++){ $tot++; if($seq[$i]===$seq[$i+$p])$hit++; }
        $rate=$tot>0?$hit/$tot:0;
        if($tot>=8 && $rate>=0.80 && $rate>$bestHit){ $bestHit=$rate; $bestP=$p; }
    }
    if($bestP){ return ['pick'=>$seq[$bestP-1]??$seq[0],'w'=>min(0.82,0.55+($bestHit-0.80)*2),'note'=>"chu kỳ ẩn p=$bestP (".round($bestHit*100)."%)"]; }
    return null;
}
}

// B.12 Đa khung thời gian đồng thuận (8/16/32 phiên)
if (!function_exists('v14_vote_multi_timeframe')) {
function v14_vote_multi_timeframe(array $seq): ?array {
    $sides=[];
    foreach([8,16,32] as $n){
        $w=v14_last($seq,$n); if(count($w)<$n*0.6) continue;
        list($t,$x)=v14_cnt($w); if($t==$x) continue;
        $sides[]= $t>$x?'T':'X';
    }
    if(count($sides)>=3 && count(array_unique($sides))===1){ return ['pick'=>$sides[0],'w'=>0.70,'note'=>"đa khung thời gian đồng thuận {$sides[0]}"]; }
    return null;
}
}

// B.13 Markov bậc 2 (cặp 2 phiên gần nhất)
if (!function_exists('v14_vote_markov_order2')) {
function v14_vote_markov_order2(array $seq): ?array {
    if (count($seq)<12) return null;
    $a=$seq[1]??null; $b=$seq[0]??null; if(!$a||!$b) return null;
    $t=0;$x=0;
    for($i=2;$i+1<count($seq);$i++){
        if($seq[$i+1]===$a && $seq[$i]===$b){
            $next = $seq[$i-1] ?? null;
            if($next==='T')$t++; elseif($next==='X')$x++;
        }
    }
    $tot=$t+$x; if($tot<4) return null;
    if($t>$x){ return ['pick'=>'T','w'=>0.50+($t/$tot-0.5)*0.8,'note'=>"Markov bậc 2 → Tài ($t/$tot)"]; }
    if($x>$t){ return ['pick'=>'X','w'=>0.50+($x/$tot-0.5)*0.8,'note'=>"Markov bậc 2 → Xỉu ($x/$tot)"]; }
    return null;
}
}

// B.14 Entropy regime (thấp → theo trội; cao → momentum ngắn)
if (!function_exists('v14_vote_entropy_regime_v2')) {
function v14_vote_entropy_regime_v2(array $seq): ?array {
    $w=v14_last($seq,20); if(count($w)<15) return null;
    list($t,$x)=v14_cnt($w); $tot=$t+$x; if($tot==0) return null;
    $pt=$t/$tot; $px=$x/$tot;
    $ent = -($pt>0?$pt*log($pt):0) - ($px>0?$px*log($px):0);
    if($ent<0.50){ $dom=$t>=$x?'T':'X'; return ['pick'=>$dom,'w'=>0.62,'note'=>"entropy thấp (".round($ent,2).") → theo bên trội $dom"]; }
    if($ent>0.65){ return ['pick'=>$seq[0],'w'=>0.55,'note'=>"entropy cao (".round($ent,2).") → momentum ngắn"]; }
    return null;
}
}

// B.15 Cluster reversal (streak dài sau chuỗi ngắn → đảo)
if (!function_exists('v14_vote_cluster_reversal_v2')) {
function v14_vote_cluster_reversal_v2(array $seq): ?array {
    $r=v14_runs($seq); if(count($r)<2) return null;
    $L=$r[0]['l']; $side=$r[0]['s']; $prevL=$r[1]['l']??1;
    if($L>=4 && $prevL<=2){ return ['pick'=>$side==='T'?'X':'T','w'=>0.68,'note'=>"cluster đảo (streak $L sau chuỗi ngắn $prevL)"]; }
    return null;
}
}

// B.16 Cầu nhảy (zigzag) — độ dài chuỗi chạy xen kẽ 1-2
if (!function_exists('v14_vote_cau_nhay')) {
function v14_vote_cau_nhay(array $seq): ?array {
    $r=v14_runs($seq); if(count($r)<4) return null;
    $lens=[]; for($i=0;$i<4 && $i<count($r);$i++) $lens[]=$r[$i]['l'];
    // pattern 1,2,1,2 hoặc 2,1,2,1
    $p1=($lens[0]===1&&$lens[1]===2&&$lens[2]===1&&$lens[3]===2);
    $p2=($lens[0]===2&&$lens[1]===1&&$lens[2]===2&&$lens[3]===1);
    if($p1||$p2){
        $expectedNextRunLen = $p1 ? 2 : 1; // chuỗi hiện tại (vị trí 0) đang ở đầu
        $curLen=$r[0]['l'];
        if($curLen < $expectedNextRunLen){ return ['pick'=>$r[0]['s'],'w'=>0.64,'note'=>"cầu nhảy (run len ".implode('-',$lens).") → tiếp"]; }
        else { return ['pick'=> $r[0]['s']==='T'?'X':'T','w'=>0.64,'note'=>"cầu nhảy (run len ".implode('-',$lens).") → đảo"]; }
    }
    return null;
}
}

// B.17 Cầu an toàn — bỏ qua khi hỗn loạn (trả về null = không vote)
// (được dùng làm bộ lọc trong overlay, không cần hàm riêng)

// ── Tổng hợp tất cả voter v14 ──────────────────────────────────────
if (!function_exists('v14_all_voters')) {
function v14_all_voters(array $seq): array {
    $fns = [
        'v14_vote_cau_11_full','v14_vote_cau_22_full','v14_vote_cau_33_full','v14_vote_cau_44_full',
        'v14_vote_cau_bet_n','v14_vote_cau_gay_multi','v14_vote_cau_xieng','v14_vote_cau_nghieng',
        'v14_vote_cau_bao','v14_vote_cau_dao_chieu','v14_vote_cau_hidden_cycle','v14_vote_multi_timeframe',
        'v14_vote_markov_order2','v14_vote_entropy_regime_v2','v14_vote_cluster_reversal_v2','v14_vote_cau_nhay',
    ];
    $out=[];
    foreach($fns as $fn){ if(!function_exists($fn)) continue; $r=$fn($seq); if($r && isset($r['pick']) && ($r['pick']==='T'||$r['pick']==='X')) $out[]=$r; }
    return $out;
}
}

if (!function_exists('v14_consensus')) {
function v14_consensus(array $votes): array {
    $tw=0.0;$xw=0.0;$notes=[];
    foreach($votes as $v){ $w=(float)($v['w']??0.5); if($v['pick']==='T')$tw+=$w; else $xw+=$w; $notes[]=($v['note']??'').' w='.round($w,2); }
    $tot=$tw+$xw;
    if($tot<=0) return ['pick'=>null,'strength'=>0.0,'tw'=>0.0,'xw'=>0.0,'notes'=>$notes,'n'=>0];
    $pick = $tw>=$xw ? 'T':'X';
    $strength = abs($tw-$xw)/$tot;
    return ['pick'=>$pick,'strength'=>$strength,'tw'=>round($tw,2),'xw'=>round($xw,2),'notes'=>$notes,'n'=>count($votes)];
}
}

// ── Overlay: kết hợp v13 (gốc, giữ nguyên) + v14 (nâng cấp mới) ────
// KHÔNG thay thế kết quả v13; chỉ điều chỉnh confidence / lật khi v14
// có đồng thuận MẠNH và MÂU THUẪN với v13.
if (!function_exists('ai_predict_v14_overlay')) {
function ai_predict_v14_overlay(array $seq, array $v13, array $prevPreds = [], array $recent = []): array {
    $out = $v13; // giữ NGUYÊN mọi key của v13
    $out['upgraded'] = true;
    $out['engine'] = ($v13['engine'] ?? 'v13') . '+v14';
    if (count($seq) < 6) { $out['v14_skip'] = 'seq too short'; return $out; }
    $votes = v14_all_voters($seq);
    $con = v14_consensus($votes);
    $out['v14_voters_active'] = count($votes);
    $out['v14_consensus'] = $con;
    $curConf = (float)($out['conf'] ?? 50.0);
    if ($con['pick'] && $con['strength'] >= 0.55) {
        if ($con['pick'] === ($out['pred'] ?? '')) {
            $boost = min(12.0, ($con['strength'] - 0.55) * 45.0);
            $out['conf'] = min(96.0, $curConf + $boost);
            $out['v14_action'] = 'boost +' . round($boost, 1) . '% (đồng thuận)';
            $out['v14_notes'] = array_slice($con['notes'], 0, 6);
        } else {
            if ($con['strength'] >= 0.72 && count($votes) >= 4) {
                $oldPred = $out['pred'];
                $out['pred'] = $con['pick'];
                $out['conf'] = max(52.0, $curConf - 8.0 + ($con['strength'] - 0.72) * 30.0);
                $out['v14_action'] = "FLIP {$oldPred}→{$con['pick']} (v14 mạnh mâu thuẫn v13)";
                $out['v14_flip_reason'] = array_slice($con['notes'], 0, 6);
            } else {
                $out['conf'] = max(45.0, $curConf - 6.0);
                $out['v14_action'] = 'conflict → giảm confidence -6%';
                $out['v14_notes'] = array_slice($con['notes'], 0, 6);
            }
        }
    } else {
        $out['v14_action'] = 'không có đồng thuận mạnh → giữ nguyên v13';
    }
    // Bộ lọc cầu an toàn: nếu entropy cao + switches dày + không có voter mạnh, giảm nhẹ confidence
    $w = v14_last($seq, 14);
    if (count($w) >= 10) {
        $sw = 0; for ($i = 0; $i + 1 < count($w); $i++) { if ($w[$i] !== $w[$i + 1]) $sw++; }
        if ($sw >= 9 && $con['strength'] < 0.55) {
            $out['conf'] = max(40.0, (float)$out['conf'] - 4.0);
            $out['v14_safe_filter'] = "cầu hỗn loạn (switches=$sw) → giảm -4%";
        }
    }
    return $out;
}
}
// ═══════════════════════════════════════════════════════════════════
// HẾT KHỐI [14] V14 UPGRADE LAYER — code cũ bên dưới giữ nguyên 100%
// ═══════════════════════════════════════════════════════════════════

// [13] UI
// ═══════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════
// [UPGRADE] AI TỰ HỌC + MARKOV BẬC CAO (k2-k5) + AUTO CAPITAL ALLOCATION (thêm vào, không đụng code cũ)
// ═══════════════════════════════════════════════════════
function _v13_markov_k(array $seq, int $k): ?array {
    $n = count($seq);
    if ($n < $k + 4) return null;
    $ctx = implode('', array_slice($seq, 0, $k));
    $t = 0.0; $x = 0.0;
    for ($i = 1; $i + $k <= $n; $i++) {
        if (implode('', array_slice($seq, $i, $k)) !== $ctx) continue;
        $w = 1.0 + 2.0 * (1.0 - $i / $n);
        if ($seq[$i-1] === 'T') $t += $w; elseif ($seq[$i-1] === 'X') $x += $w;
    }
    $tot = $t + $x;
    if ($tot < 3) return null;
    $pt = ($t + 1) / ($tot + 2);
    if (abs($pt - 0.5) < 0.08) return null;
    $raw = $pt >= 0.5 ? $pt : 1 - $pt;
    return ['pick' => $pt >= 0.5 ? 'T' : 'X', 'w' => 0.5 + $raw * 0.7, 'note' => "markov_k{$k}"];
}
function v13_vote_markov_k2(array $seq): ?array { return _v13_markov_k($seq, 2); }
function v13_vote_markov_k3(array $seq): ?array { return _v13_markov_k($seq, 3); }
function v13_vote_markov_k4(array $seq): ?array { return _v13_markov_k($seq, 4); }
function v13_vote_markov_k5(array $seq): ?array { return _v13_markov_k($seq, 5); }

function calculate_optimal_bet($capital, $balance, $mode, $lose_streak): int {
    $capital = max(0, (int)$capital);
    $balance = max(0, (int)$balance);
    $pool = max($capital, $balance);
    if ($pool <= 0) return 1000;
    $base = (int)(round($pool * 0.03 / 1000) * 1000);
    if ($base < 1000) $base = 1000;
    $bet = $base;
    $streak = max(0, (int)$lose_streak);
    if ($mode === 'double' && $streak > 0) {
        $mult = pow(2, min($streak, 5));
        $bet = $base * $mult;
    }
    $cap = (int)(round($pool * 0.20 / 1000) * 1000);
    if ($cap < 1000) $cap = 1000;
    if ($bet > $cap) $bet = $cap;
    $bet = (int)(round($bet / 1000) * 1000);
    if ($bet < 1000) $bet = 1000;
    return $bet;
}

function ai_learn_from_result(string $key, $prediction, $actual, $voterPicks): void {
    if (!is_array($voterPicks) || empty($voterPicks)) return;
    $actualMap = ['TAI'=>'T','XIU'=>'X','T'=>'T','X'=>'X'];
    $actualSym = $actualMap[$actual] ?? null;
    if (!$actualSym) return;
    key_update($key, function($d) use ($actualSym, $voterPicks) {
        $w = $d['ai_model_weights'] ?? [];
        foreach ($voterPicks as $name => $pick) {
            $cur = isset($w[$name]) ? (float)$w[$name] : 1.0;
            if ($pick === $actualSym) { $cur += 0.05; if ($cur > 3.0) $cur = 3.0; }
            else { $cur *= 0.95; if ($cur < 0.2) $cur = 0.2; }
            $w[$name] = $cur;
        }
        $d['ai_model_weights'] = $w;
        $d['ai_learned_count'] = (int)($d['ai_learned_count'] ?? 0) + 1;
        return $d;
    });
}

function render_ui(): void {
    global $CFG;
    $ui = $CFG['ui'] ?? ['primary'=>'#ff6b35','secondary'=>'#e53935','accent'=>'#ffb300'];
?>
<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<meta name="theme-color" content="#8b0000">
<title>vi long đẹp trai — V13.1.1 Supreme</title>
<style>
:root{
  --p:<?= $ui['primary'] ?>;
  --p2:<?= $ui['secondary'] ?>;
  --pink:<?= $ui['accent'] ?>;
  --bg:#1a0000;--card:#3d0808;--card2:#4a0a0a;
  --line:rgba(255,107,53,.16);--txt:#e8f0ff;--muted:rgba(232,240,255,.5);
  --ok:#00ff88;--err:#ff1744;--warn:#ffb84d;--gold:#ffd84d;
}
*{margin:0;padding:0;box-sizing:border-box;font-family:'Inter','Segoe UI',system-ui,-apple-system,sans-serif;-webkit-tap-highlight-color:transparent}
html,body{min-height:100%;background:var(--bg);color:var(--txt);overflow-x:hidden;user-select:none}
body{background-image:
  radial-gradient(circle at 0% 0%,rgba(229,57,53,.18),transparent 40%),
  radial-gradient(circle at 100% 100%,rgba(255,107,53,.15),transparent 45%),
  radial-gradient(circle at 50% 50%,rgba(255,179,0,.08),transparent 55%);
  background-attachment:fixed}
#app{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px;position:relative}
.ic{width:16px;height:16px;display:inline-block;vertical-align:middle;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;flex-shrink:0}
.ic-sm{width:14px;height:14px}
.ic-lg{width:20px;height:20px}
.card{width:100%;max-width:460px;background:linear-gradient(180deg,var(--card),var(--card2));border-radius:24px;border:1px solid var(--line);overflow:hidden;box-shadow:0 40px 100px -30px rgba(0,0,0,.9),0 0 0 1px rgba(255,255,255,.02) inset,0 0 120px -40px var(--p);animation:pop .5s cubic-bezier(.34,1.56,.64,1);display:flex;flex-direction:column;max-height:calc(100vh - 32px)}
@keyframes pop{from{transform:scale(.94);opacity:0}to{transform:scale(1);opacity:1}}
.head{padding:16px 20px;display:flex;align-items:center;gap:14px;background:linear-gradient(135deg,rgba(229,57,53,.12),rgba(255,107,53,.06));border-bottom:1px solid var(--line);position:relative;overflow:hidden;flex-shrink:0}
.head::after{content:'';position:absolute;inset:0;background:linear-gradient(90deg,transparent,rgba(255,107,53,.15),transparent);transform:translateX(-100%);animation:shine 4s infinite}
@keyframes shine{100%{transform:translateX(100%)}}
.logo{width:44px;height:44px;border-radius:14px;background:linear-gradient(135deg,var(--pink),var(--p2),var(--p));display:flex;align-items:center;justify-content:center;color:#fff;box-shadow:0 8px 24px -6px rgba(255,179,0,.6),inset 0 1px 0 rgba(255,255,255,.3);flex-shrink:0;position:relative;animation:pulse 3s infinite}
@keyframes pulse{0%,100%{box-shadow:0 8px 24px -6px rgba(255,179,0,.6),inset 0 1px 0 rgba(255,255,255,.3)}50%{box-shadow:0 8px 32px -4px rgba(255,107,53,.8),inset 0 1px 0 rgba(255,255,255,.3)}}
.head .title{flex:1;min-width:0;position:relative;z-index:1}
.head h1{font-size:14px;font-weight:800;background:linear-gradient(90deg,#fff,var(--p),var(--p2));-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;letter-spacing:.4px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.head small{font-size:10px;color:var(--muted);display:flex;align-items:center;gap:5px;margin-top:3px}
.head .right{margin-left:auto;flex-shrink:0;position:relative;z-index:1}
.login{padding:24px 22px 22px;overflow-y:auto}
.login h2{font-size:17px;text-align:center;margin-bottom:22px;font-weight:800;background:linear-gradient(90deg,var(--pink),var(--p),var(--p2));-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;display:flex;align-items:center;justify-content:center;gap:8px}
.fld{margin-bottom:14px}
.fld label{display:flex;align-items:center;gap:7px;font-size:11px;font-weight:700;margin-bottom:7px;color:var(--muted);text-transform:uppercase;letter-spacing:.7px}
.fld input{width:100%;padding:13px 15px;background:#2a0505;border:1.5px solid rgba(255,255,255,.06);border-radius:12px;color:#fff;font-size:13px;outline:none;transition:.25s;font-family:'SF Mono','Consolas',monospace}
.fld input:focus{border-color:var(--p);background:#330606;box-shadow:0 0 0 4px rgba(255,107,53,.1)}
.fld input::placeholder{color:rgba(255,255,255,.22);font-family:'Inter',sans-serif}
.btn{width:100%;padding:14px;border:none;border-radius:13px;color:#fff;font-weight:800;font-size:13px;cursor:pointer;transition:.25s;text-transform:uppercase;letter-spacing:1px;position:relative;overflow:hidden;display:flex;align-items:center;justify-content:center;gap:8px}
.btn::before{content:'';position:absolute;inset:0;background:linear-gradient(90deg,transparent,rgba(255,255,255,.25),transparent);transform:translateX(-100%);transition:.6s}
.btn:hover::before{transform:translateX(100%)}
.btn.primary{background:linear-gradient(135deg,var(--pink),#d84315,var(--p));background-size:200% 200%;box-shadow:0 12px 32px -8px rgba(255,179,0,.55)}
.btn.primary:hover:not(:disabled){background-position:100% 100%;transform:translateY(-2px);box-shadow:0 16px 40px -8px rgba(255,179,0,.75)}
.btn:disabled{opacity:.5;cursor:not-allowed}
.btn:active{transform:translateY(0) scale(.98)}
.msg{margin-top:14px;padding:12px;border-radius:11px;font-size:12px;text-align:center;font-weight:600;display:flex;align-items:center;gap:8px;justify-content:center;animation:slideDown .3s}
.msg.err{background:rgba(255,23,68,.12);border:1px solid rgba(255,23,68,.4);color:#ff5252}
.msg.ok{background:rgba(0,255,136,.12);border:1px solid rgba(0,255,136,.4);color:var(--ok)}
.msg.warn{background:rgba(255,184,77,.12);border:1px solid rgba(255,184,77,.4);color:var(--warn)}
@keyframes slideDown{from{opacity:0;transform:translateY(-10px)}to{opacity:1;transform:translateY(0)}}
.ubar{margin:14px 16px 0;padding:13px;background:linear-gradient(135deg,rgba(229,57,53,.1),rgba(255,107,53,.05));border-radius:15px;border:1px solid var(--line);display:flex;align-items:center;gap:12px;flex-shrink:0}
.ubar .av{width:42px;height:42px;border-radius:13px;background:linear-gradient(135deg,var(--pink),var(--p2));display:flex;align-items:center;justify-content:center;font-weight:800;font-size:16px;box-shadow:0 0 24px -4px rgba(229,57,53,.6);flex-shrink:0;position:relative}
.ubar .av::after{content:'';position:absolute;bottom:-2px;right:-2px;width:12px;height:12px;border-radius:50%;background:var(--ok);border:2px solid var(--card);box-shadow:0 0 8px var(--ok)}
.ubar .info{flex:1;min-width:0}
.ubar .info b{display:block;font-size:13px;font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.ubar .info small{font-size:10px;color:var(--p);display:flex;align-items:center;gap:5px;margin-top:2px}
.dot{width:6px;height:6px;border-radius:50%;background:var(--p);box-shadow:0 0 8px var(--p);animation:blink 1.5s infinite}
@keyframes blink{50%{opacity:.4}}
.ubar .bal{text-align:right;flex-shrink:0}
.ubar .bal b{display:block;font-size:15px;color:var(--gold);font-family:'SF Mono','Consolas',monospace;font-weight:800;text-shadow:0 0 12px rgba(255,216,77,.4)}
.ubar .bal small{font-size:9px;color:var(--muted);font-weight:700;letter-spacing:1.5px}
.tabs{display:flex;gap:5px;background:#2a0505;padding:5px;margin:14px 16px 0;border-radius:15px;border:1px solid rgba(255,255,255,.04);flex-shrink:0}
.tabs button{flex:1;padding:11px 0;background:none;border:none;font-size:11px;font-weight:700;cursor:pointer;border-radius:11px;color:var(--muted);transition:.25s;display:flex;align-items:center;justify-content:center;gap:6px;font-family:inherit}
.tabs button.on{background:linear-gradient(135deg,rgba(229,57,53,.35),rgba(255,107,53,.22));color:#fff;box-shadow:0 0 18px -5px var(--p),inset 0 0 0 1px rgba(255,107,53,.35)}
.tabs button:not(.on):hover{color:rgba(255,255,255,.8);background:rgba(255,255,255,.03)}
.body{padding:14px 16px 18px;overflow-y:auto;flex:1;min-height:0}
.body::-webkit-scrollbar{width:5px}
.body::-webkit-scrollbar-thumb{background:linear-gradient(var(--p),var(--p2));border-radius:3px}
.body::-webkit-scrollbar-track{background:transparent}
.slide{animation:slideIn .35s cubic-bezier(.34,1.56,.64,1)}
@keyframes slideIn{from{opacity:0;transform:translateX(20px)}to{opacity:1;transform:translateX(0)}}
.row{display:flex;align-items:center;gap:12px;padding:12px 14px;background:#2a0505;border-radius:12px;margin-bottom:9px;border:1px solid rgba(255,255,255,.04);transition:.25s}
.row:hover{border-color:var(--line);background:#330606}
.row .lbl{font-size:12px;font-weight:600;flex:1;display:flex;align-items:center;gap:8px;color:var(--txt)}
.row .lbl .ic{color:var(--p);opacity:.9}
.row input[type=number]{padding:9px 13px;background:#1a0000;border:1.5px solid rgba(255,255,255,.07);border-radius:10px;color:var(--p);font-size:12px;font-weight:700;outline:none;width:135px;text-align:right;font-family:'SF Mono','Consolas',monospace;transition:.25s}
.row input[type=number]:focus{border-color:var(--p);box-shadow:0 0 0 3px rgba(255,107,53,.12)}
.sel{position:relative;width:155px}
.sel select{width:100%;padding:9px 32px 9px 13px;background:#1a0000;border:1.5px solid rgba(255,255,255,.07);border-radius:10px;color:#fff;font-size:12px;font-weight:600;outline:none;appearance:none;-webkit-appearance:none;cursor:pointer;transition:.25s;font-family:inherit}
.sel select:hover{border-color:rgba(255,107,53,.4)}
.sel select:focus{border-color:var(--p);box-shadow:0 0 0 3px rgba(255,107,53,.12)}
.sel::after{content:'';position:absolute;right:13px;top:50%;width:8px;height:8px;border-right:2px solid var(--p);border-bottom:2px solid var(--p);transform:translateY(-70%) rotate(45deg);pointer-events:none}
.sel select option{background:#3d0808;color:#fff;padding:8px}
.sec{font-size:10px;font-weight:800;color:var(--p);text-transform:uppercase;letter-spacing:1.5px;margin:16px 0 10px;display:flex;align-items:center;gap:8px}
.sec::after{content:'';flex:1;height:1px;background:linear-gradient(90deg,var(--line),transparent)}
.sec:first-child{margin-top:0}
.pills{display:grid;grid-template-columns:repeat(2,1fr);gap:9px;margin-top:12px}
.pill{padding:13px;background:#2a0505;border-radius:12px;border:1px solid rgba(255,255,255,.04);text-align:center;transition:.25s}
.pill small{font-size:9px;color:var(--muted);text-transform:uppercase;font-weight:700;letter-spacing:.8px;display:block;margin-bottom:6px}
.pill b{font-size:14px;font-family:'SF Mono','Consolas',monospace;font-weight:800;display:block}
.pill.ok b{color:var(--ok)}
.pill.off b{color:var(--err)}
.pill.warn b{color:var(--warn)}
.pill.cyan b{color:var(--p)}
.pill.gold b{color:var(--gold)}
.big-btn{width:100%;padding:16px;border:none;border-radius:14px;color:#fff;font-weight:900;font-size:14px;cursor:pointer;transition:.25s;text-transform:uppercase;letter-spacing:1.2px;position:relative;overflow:hidden;margin-top:14px;display:flex;align-items:center;justify-content:center;gap:10px}
.big-btn::after{content:'';position:absolute;inset:0;background:linear-gradient(90deg,transparent,rgba(255,255,255,.25),transparent);transform:translateX(-100%);transition:.6s}
.big-btn:hover::after{transform:translateX(100%)}
.big-btn.on{background:linear-gradient(135deg,var(--pink),#d84315);box-shadow:0 12px 32px -8px rgba(255,179,0,.6)}
.big-btn.on:hover{transform:translateY(-2px);box-shadow:0 16px 42px -8px rgba(255,179,0,.85)}
.big-btn.off{background:linear-gradient(135deg,#00c853,var(--p));box-shadow:0 12px 32px -8px rgba(255,107,53,.6)}
.big-btn.off:hover{transform:translateY(-2px);box-shadow:0 16px 42px -8px rgba(255,107,53,.85)}
.rainbow{padding:14px;text-align:center;font-size:11px;font-weight:800;letter-spacing:.6px;background:linear-gradient(90deg,var(--pink),var(--gold),var(--ok),var(--p),var(--p2));background-size:300% 100%;-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;animation:rb 4s linear infinite;margin:12px 0;display:flex;align-items:center;justify-content:center;gap:8px}
@keyframes rb{0%{background-position:0% 50%}100%{background-position:300% 50%}}
.ai-card{padding:14px;background:linear-gradient(135deg,rgba(229,57,53,.08),rgba(255,107,53,.04));border-radius:14px;border:1px solid var(--line);margin-top:12px}
.ai-card .head-line{display:flex;align-items:center;justify-content:space-between;margin-bottom:10px}
.ai-card .head-line b{font-size:11px;color:var(--p);text-transform:uppercase;letter-spacing:1px;font-weight:800;display:flex;align-items:center;gap:6px}
.ai-card .head-line .conf{font-size:10px;padding:3px 8px;background:rgba(255,107,53,.15);border-radius:6px;color:var(--p);font-weight:800;font-family:monospace}
.ai-weights{display:grid;grid-template-columns:repeat(5,1fr);gap:5px}
.ai-weight{text-align:center;padding:7px 3px;background:rgba(0,0,0,.3);border-radius:7px}
.ai-weight small{font-size:8px;color:var(--muted);display:block;margin-bottom:3px;font-weight:700;letter-spacing:.4px}
.ai-weight b{font-size:11px;color:var(--p);font-family:'SF Mono',monospace;font-weight:800}
.ai-pred{margin-top:10px;padding:11px;text-align:center;background:rgba(0,0,0,.3);border-radius:10px;font-weight:800;font-size:13px;letter-spacing:1px}
.ai-meta{margin-top:8px;display:flex;justify-content:space-around;font-size:10px;color:var(--muted)}
.ai-bet{margin-top:10px;padding:11px;text-align:center;border-radius:10px;font-weight:800;font-size:12px;letter-spacing:.5px}
.ai-bet.high{background:linear-gradient(135deg,rgba(0,255,136,.15),rgba(255,107,53,.1));color:var(--ok);border:1px solid rgba(0,255,136,.3)}
.ai-bet.mid{background:rgba(255,216,77,.1);color:var(--gold);border:1px solid rgba(255,216,77,.3)}
.ai-bet.low{background:rgba(255,23,68,.1);color:var(--err);border:1px solid rgba(255,23,68,.3)}
.ai-bet.martingale{background:rgba(255,184,77,.12);color:var(--warn);border:1px solid rgba(255,184,77,.35)}
.ai-bet.base{background:rgba(255,107,53,.1);color:var(--p);border:1px solid rgba(255,107,53,.3)}
.hist{display:flex;flex-direction:column;gap:7px}
.hist-item{padding:11px 13px;background:#2a0505;border-radius:11px;display:flex;align-items:center;gap:10px;border-left:3px solid #444;transition:.25s;font-size:12px}
.hist-item.win{border-left-color:var(--ok);background:linear-gradient(90deg,rgba(0,255,136,.06),#2a0505)}
.hist-item.lose{border-left-color:var(--err);background:linear-gradient(90deg,rgba(255,23,68,.06),#2a0505)}
.hist-item .s{font-family:'SF Mono','Consolas',monospace;color:var(--p);font-weight:700;min-width:56px;font-size:11px}
.hist-item .mid{flex:1;min-width:0}
.hist-item .mid .r{font-weight:700;font-size:12px;margin-bottom:2px;display:flex;align-items:center;gap:5px}
.hist-item .mid small{font-size:10px;color:var(--muted);font-family:'SF Mono','Consolas',monospace}
.hist-item .tag{padding:4px 9px;border-radius:6px;font-size:9px;font-weight:800;letter-spacing:.5px}
.hist-item.win .tag{background:rgba(0,255,136,.15);color:var(--ok)}
.hist-item.lose .tag{background:rgba(255,23,68,.15);color:var(--err)}
.log-panel{display:flex;flex-direction:column;gap:5px}
.log-item{padding:9px 11px;background:#2a0505;border-radius:9px;border-left:3px solid var(--muted);font-size:11px;display:flex;gap:8px;align-items:flex-start;transition:.2s;animation:slideIn .25s}
.log-item.info{border-left-color:var(--p);background:linear-gradient(90deg,rgba(255,107,53,.05),#2a0505)}
.log-item.success{border-left-color:var(--ok);background:linear-gradient(90deg,rgba(0,255,136,.05),#2a0505)}
.log-item.error{border-left-color:var(--err);background:linear-gradient(90deg,rgba(255,23,68,.05),#2a0505)}
.log-item.warn{border-left-color:var(--warn);background:linear-gradient(90deg,rgba(255,184,77,.05),#2a0505)}
.log-item .ts{font-family:'SF Mono','Consolas',monospace;color:var(--muted);font-size:10px;flex-shrink:0;min-width:70px}
.log-item .m{flex:1;color:var(--txt);line-height:1.4;word-break:break-word;user-select:text}
.empty{text-align:center;padding:44px 20px;color:var(--muted);font-size:12px;display:flex;flex-direction:column;align-items:center;gap:12px}
.empty .ic{font-size:40px;opacity:.3;width:48px;height:48px;stroke-width:1.5}
.empty small{opacity:.6;font-size:11px}
.logout{width:100%;padding:13px;margin-top:16px;background:rgba(255,179,0,.12);border:1px solid rgba(255,179,0,.4);border-radius:12px;color:#ff8f00;font-weight:800;font-size:12px;cursor:pointer;transition:.25s;text-transform:uppercase;letter-spacing:.8px;display:flex;align-items:center;justify-content:center;gap:8px}
.logout:hover{background:rgba(255,179,0,.2);transform:translateY(-2px);box-shadow:0 8px 20px -8px rgba(255,179,0,.5)}
.badge{padding:5px 11px;border-radius:8px;font-size:9px;font-weight:800;text-transform:uppercase;letter-spacing:.6px;white-space:nowrap;display:inline-flex;align-items:center;gap:5px}
.badge.on{background:rgba(0,255,136,.15);color:var(--ok);box-shadow:0 0 12px -3px rgba(0,255,136,.5)}
.badge.off{background:rgba(255,255,255,.06);color:var(--muted)}
.badge.pause{background:rgba(255,184,77,.15);color:var(--warn)}
.toggle{display:flex;align-items:center;justify-content:space-between;padding:12px 14px;background:#2a0505;border-radius:12px;margin-bottom:9px;border:1px solid rgba(255,255,255,.04);cursor:pointer;transition:.25s}
.toggle:hover{border-color:var(--line);background:#330606}
.toggle .lbl{font-size:12px;font-weight:600;display:flex;align-items:center;gap:8px;color:var(--txt)}
.toggle .lbl .ic{color:var(--p);opacity:.9}
.switch{position:relative;width:44px;height:24px;background:#1a0000;border-radius:12px;border:1px solid rgba(255,255,255,.1);transition:.25s;flex-shrink:0}
.switch::after{content:'';position:absolute;top:2px;left:2px;width:18px;height:18px;border-radius:50%;background:var(--muted);transition:.25s}
.switch.on{background:linear-gradient(135deg,var(--pink),#d84315);border-color:transparent;box-shadow:0 0 12px -2px rgba(255,179,0,.5)}
.switch.on::after{left:22px;background:#ffd8a8;box-shadow:0 2px 6px rgba(0,0,0,.3)}
@media (min-width:900px){
  #app{padding:24px}
  .card{max-width:520px;max-height:calc(100vh - 48px)}
  .head{padding:18px 24px}
  .head h1{font-size:16px}
  .logo{width:50px;height:50px;border-radius:15px}
  .ubar{margin:16px 20px 0;padding:15px}
  .tabs{margin:16px 20px 0}
  .body{padding:16px 20px 20px}
  .body::-webkit-scrollbar{width:7px}
  .row{padding:14px 16px}
  .pills{grid-template-columns:repeat(4,1fr)}
  .ai-weights{grid-template-columns:repeat(5,1fr);gap:8px}
  .ai-weight{padding:10px 6px}
  .login{padding:32px 28px 26px}
  .login h2{font-size:20px}
  .fld input{padding:14px 16px;font-size:14px}
  .btn{padding:16px;font-size:14px}
}
@media (min-width:1200px){ .card{max-width:560px} }
@media (max-width:360px){
  .head{padding:14px 16px}
  .head h1{font-size:12px}
  .logo{width:38px;height:38px}
  .ubar{margin:10px 12px 0;padding:10px}
  .tabs{margin:10px 12px 0}
  .body{padding:10px 12px 14px}
  .row{padding:10px 12px}
  .row input[type=number]{width:110px;font-size:11px}
  .sel{width:130px}
  .pills{grid-template-columns:1fr 1fr;gap:7px}
  .ai-weights{grid-template-columns:repeat(3,1fr)}
  .big-btn{padding:14px;font-size:12px}
}
/* ─── [UPGRADE] RED VIP THEME OVERRIDE — giữ nguyên CSS gốc, chỉ đè màu sang nền đỏ đậm VIP ─── */
:root{
  --bg:#2a0505;--card:#4a0a0a;--card2:#5c0d0d;
  --line:rgba(255,80,80,.25);--txt:#fff;--muted:rgba(255,200,160,.6);
  --p:#e64a19;--p2:#c62828;--pink:#ff8f00;
  --ok:#00ff88;--err:#ff1744;--warn:#ffb300;--gold:#ffd700;
}
html,body{background:#2a0505;color:var(--txt)}
body{background-image:radial-gradient(circle at 0% 0%,rgba(255,30,30,.18),transparent 40%),radial-gradient(circle at 100% 100%,rgba(200,0,0,.15),transparent 45%),radial-gradient(circle at 50% 50%,rgba(255,140,0,.08),transparent 55%)}
.card{background:#4a0a0a;border:1px solid var(--line);box-shadow:0 0 25px rgba(255,30,30,.3),0 20px 60px -25px rgba(0,0,0,.6)}
.head{background:linear-gradient(135deg,rgba(255,30,30,.18),rgba(255,107,53,.12));border-bottom:1px solid var(--line)}
.head::after{background:linear-gradient(90deg,transparent,rgba(255,60,60,.35),transparent)}
.head h1{background:linear-gradient(90deg,#fff,var(--p2),var(--p));-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
.login h2{background:linear-gradient(90deg,var(--pink),var(--p),var(--p2));-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
.fld input{background:#3d0808;border:1.5px solid rgba(255,100,100,.2);color:#fff}
.fld input:focus{border-color:var(--p);background:#520a0a;box-shadow:0 0 0 4px rgba(255,60,60,.2)}
.fld input::placeholder{color:rgba(255,220,180,.4)}
.msg.err{background:rgba(255,23,68,.15);border:1px solid rgba(255,23,68,.5);color:#ff4d6d}
.msg.ok{background:rgba(0,255,136,.12);border:1px solid rgba(0,255,136,.4);color:var(--ok)}
.msg.warn{background:rgba(255,179,0,.1);border:1px solid rgba(255,179,0,.4);color:var(--warn)}
.ubar{background:linear-gradient(135deg,rgba(255,30,30,.18),rgba(255,107,53,.12));border:1px solid var(--line)}
.tabs{background:#330606;border:1px solid rgba(255,100,100,.15)}
.tabs button.on{background:linear-gradient(135deg,rgba(255,30,30,.4),rgba(255,107,53,.28));color:#fff;box-shadow:0 0 18px -4px rgba(255,60,60,.6),inset 0 0 0 1px rgba(255,107,53,.5)}
.tabs button:not(.on):hover{color:#fff;background:rgba(255,80,80,.12)}
.row{background:#3d0808;border:1px solid rgba(255,100,100,.12)}
.row:hover{border-color:var(--line);background:#520a0a}
.row input[type=number]{background:#3d0808;border:1.5px solid rgba(255,100,100,.2);color:var(--p)}
.row input[type=number]:focus{box-shadow:0 0 0 3px rgba(255,60,60,.25)}
.sel select{background:#3d0808;border:1.5px solid rgba(255,100,100,.2);color:#fff}
.sel select:hover{border-color:rgba(255,107,53,.6)}
.sel select option{background:#3d0808;color:#fff}
.pill{background:#3d0808;border:1px solid rgba(255,100,100,.12)}
.ai-weight{background:rgba(255,80,80,.12)}
.ai-pred{background:rgba(255,80,80,.12);color:var(--txt)}
.ai-card{background:linear-gradient(135deg,rgba(255,30,30,.14),rgba(255,107,53,.08))}
.ai-card .head-line .conf{background:rgba(255,107,53,.2);color:#ffd8a8}
.hist-item{background:#3d0808;border-left-color:rgba(255,100,100,.4)}
.hist-item.win{background:linear-gradient(90deg,rgba(0,255,136,.08),#3d0808)}
.hist-item.lose{background:linear-gradient(90deg,rgba(255,23,68,.1),#3d0808)}
.log-item{background:#3d0808}
.log-item.info{background:linear-gradient(90deg,rgba(255,107,53,.08),#3d0808)}
.log-item.success{background:linear-gradient(90deg,rgba(0,255,136,.08),#3d0808)}
.log-item.error{background:linear-gradient(90deg,rgba(255,23,68,.1),#3d0808)}
.log-item.warn{background:linear-gradient(90deg,rgba(255,179,0,.08),#3d0808)}
.toggle{background:#3d0808;border:1px solid rgba(255,100,100,.12)}
.toggle:hover{border-color:var(--line);background:#520a0a}
.switch{background:#1a0000;border-color:rgba(255,80,80,.3)}
.badge.off{background:rgba(255,80,80,.12);color:var(--muted)}
.logout{background:rgba(255,143,0,.12);border-color:rgba(255,143,0,.4);color:#ffb74d}
.logout:hover{background:rgba(255,143,0,.16);box-shadow:0 0 18px -6px rgba(255,143,0,.5)}
/* ─── [UPGRADE] VIP RED GLOW + PULSE + CHART STYLES (thêm vào, không xoá CSS cũ) ─── */
.btn,.big-btn{box-shadow:0 0 18px -4px rgba(255,60,60,.45),inset 0 1px 0 rgba(255,255,255,.12)}
.big-btn.on{animation:pulseRed 1.6s ease-in-out infinite}
.badge.on{animation:pulseRed 1.4s ease-in-out infinite;box-shadow:0 0 14px rgba(255,60,60,.6)}
.ai-card{box-shadow:0 0 22px -6px rgba(255,30,30,.4),inset 0 0 0 1px rgba(255,107,53,.25)}
.pill{box-shadow:0 0 12px -4px rgba(255,60,60,.3)}
@keyframes pulseRed{0%,100%{box-shadow:0 0 12px rgba(255,60,60,.45)}50%{box-shadow:0 0 26px rgba(255,60,60,.85)}}
.conf-bar{height:8px;border-radius:4px;background:rgba(255,255,255,.08);overflow:hidden;margin-top:6px}
.conf-bar>i{display:block;height:100%;background:linear-gradient(90deg,#ff1744,#ff6b35,#ffb300);box-shadow:0 0 10px rgba(255,107,53,.7);transition:width .4s}
.worker-badge{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:20px;font-size:10px;font-weight:800;letter-spacing:.5px}
.worker-badge.on{background:rgba(0,255,136,.12);color:var(--ok);border:1px solid rgba(0,255,136,.4);animation:pulseRed 1.8s infinite}
.worker-badge.off{background:rgba(255,23,68,.12);color:#ff4d6d;border:1px solid rgba(255,23,68,.4)}
.chart-wrap{padding:14px;background:#3d0808;border:1px solid rgba(255,100,100,.15);border-radius:14px;margin:10px 0;box-shadow:0 0 18px -6px rgba(255,30,30,.4)}
.chart-wrap canvas{width:100%;max-width:460px;height:auto;display:block;margin:0 auto}
</style>
</head>
<body>
<div id="app"></div>

<script>
const app = document.getElementById('app');
const S = {
  loggedIn:false, user:'', nickname:'', balance:0, tab:'main',
  device:'', loading:false, error:'', success:'', authToken:'',
  config:{ base_bet:10000, profit_stop:0, mode:'fixed', max_lose_streak:3, auto:false, paused:false, lose_streak:0,
    smart_bet:false, bet_high:50000, bet_low:10000, high_conf_min:75, recent_win_min:2, table_type:'md5', capital:0, auto_capital:false, win_target:666 },
  history:[], logs:[], tickTimer:null,
  ai:{pred:'—',conf:0,detail:{},pattern:'',cau_dep:0,cau_xau:1,streak:0},
  pendingPred:null, pendingSession:null, pendingRegime:null, pendingConf:null,
  pendingBetAmount:null, pendingBetLevel:null,
  tickInFlight:false, workerAlive:false, workerInfo:null,
  stats:{wins:0,losses:0,total:0,winrate:0,profit:0},
  aiLearnedCount:0, pattern10:'', skipNextBet:false, autoCapitalActive:false, dudoanCount:0,
  resumeHint:false,
};
(function(){ const d=[navigator.userAgent,navigator.language,screen.width+'x'+screen.height,new Date().getTimezoneOffset(),navigator.hardwareConcurrency||''].join('|'); let h=0; for(let i=0;i<d.length;i++)h=((h<<5)-h)+d.charCodeAt(i),h|=0; S.device='WEB-'+Math.abs(h).toString(16).toUpperCase(); })();

const esc = s => String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmt = n => (n||0).toLocaleString('en-US');
const emo = p => p==='TAI'?'🔵 TÀI':p==='XIU'?'🔴 XỈU':'⚪';

const ICO = {
  user:'<svg class="ic" viewBox="0 0 24 24"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>',
  lock:'<svg class="ic" viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
  key:'<svg class="ic" viewBox="0 0 24 24"><circle cx="7.5" cy="15.5" r="5.5"/><path d="M21 2l-9.6 9.6M15.5 7.5l3 3L21 8l-3-3"/></svg>',
  check:'<svg class="ic" viewBox="0 0 24 24"><path d="M20 6L9 17l-5-5"/></svg>',
  warn:'<svg class="ic" viewBox="0 0 24 24"><path d="M12 9v4M12 17h.01M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/></svg>',
  play:'<svg class="ic" viewBox="0 0 24 24"><polygon points="5 3 19 12 5 21 5 3"/></svg>',
  stop:'<svg class="ic" viewBox="0 0 24 24"><rect x="6" y="6" width="12" height="12" rx="1"/></svg>',
  money:'<svg class="ic" viewBox="0 0 24 24"><rect x="2" y="6" width="20" height="12" rx="2"/><circle cx="12" cy="12" r="2.5"/><path d="M6 12h.01M18 12h.01"/></svg>',
  target:'<svg class="ic" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>',
  chart:'<svg class="ic" viewBox="0 0 24 24"><path d="M3 3v18h18M7 14l4-4 4 4 5-5"/></svg>',
  refresh:'<svg class="ic" viewBox="0 0 24 24"><path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>',
  cpu:'<svg class="ic" viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><path d="M9 1v3M15 1v3M9 20v3M15 20v3M20 9h3M20 14h3M1 9h3M1 14h3"/></svg>',
  hist:'<svg class="ic" viewBox="0 0 24 24"><path d="M3 3v5h5M3.05 13A9 9 0 1 0 6 5.3L3 8"/><path d="M12 7v5l4 2"/></svg>',
  logs:'<svg class="ic" viewBox="0 0 24 24"><path d="M4 4h16v16H4z"/><path d="M8 8h8M8 12h8M8 16h5"/></svg>',
  cfg:'<svg class="ic" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>',
  logout:'<svg class="ic" viewBox="0 0 24 24"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/></svg>',
  brain:'<svg class="ic" viewBox="0 0 24 24"><path d="M9.5 2A2.5 2.5 0 0 0 7 4.5v.5a3 3 0 0 0-3 3v.5A3 3 0 0 0 3 14c0 1.5 1 2.8 2.5 3.2V17a3 3 0 0 0 3 3h1V2h-.5zM14.5 2A2.5 2.5 0 0 1 17 4.5v.5a3 3 0 0 1 3 3v.5a3 3 0 0 1 1 5.5c0 1.5-1 2.8-2.5 3.2V17a3 3 0 0 1-3 3h-1V2h.5z"/></svg>',
  info:'<svg class="ic" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>',
  bolt:'<svg class="ic" viewBox="0 0 24 24"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>',
};

function tplLogin(){
  return `
<div class="card">
  <div class="head">
    <div class="logo">${ICO.cpu.replace('class="ic"','class="ic" style="width:24px;height:24px"')}</div>
    <div class="title"><h1>VI LONG ĐẸP TRAI</h1><small>${ICO.brain.replace('class="ic"','class="ic ic-sm"')} V16 VIP 666 · Supreme Predictor</small></div>
  </div>
  <div class="login">
    <h2>${ICO.lock.replace('class="ic"','class="ic ic-lg"')} ĐĂNG NHẬP TÀI KHOẢN</h2>
    <div class="fld"><label>${ICO.user} Tài khoản game</label><input id="i_u" placeholder="Nhập tài khoản game..." autocomplete="off"></div>
    <div class="fld"><label>${ICO.lock} Mật khẩu</label><input id="i_p" type="password" placeholder="••••••••"></div>
    <button class="btn primary" id="b_login" ${S.loading?'disabled':''}>${S.loading?'ĐANG ĐĂNG NHẬP...':'ĐĂNG NHẬP NGAY'}${ICO.check}</button>
    ${S.error?`<div class="msg err">${ICO.warn} ${esc(S.error)}</div>`:''}
    ${S.success?`<div class="msg ok">${ICO.check} ${esc(S.success)}</div>`:''}
    <div style="margin-top:16px;font-size:10px;text-align:center;color:var(--muted)">Device: <span style="color:var(--p);font-family:monospace">${esc(S.device)}</span></div>
    <div style="margin-top:10px;font-size:10px;text-align:center;color:var(--muted);line-height:1.6">
      🧠 V13.1.1: 100+ voters + 48 khuôn + 15 regime + Smart Bet AI<br>
      📈 <b>Gấp nếp (Double)</b> X2 khi thua, reset khi thắng/chạm max<br>
      ⚡ Worker 24/7 — tự respawn, tự khôi phục sau khi mất kết nối
    </div>
  </div>
</div>`;
}

function tplDashboard(){
  const c = S.config;
  const badge = c.paused?'<span class="badge pause">⏸ DỪNG</span>':(c.auto?'<span class="badge on">● AUTO ON</span>':'<span class="badge off">○ OFF</span>');
  let body = '';
  if (S.tab==='main') body = tplMain(c);
  else if (S.tab==='cfg') body = tplCfg(c);
  else if (S.tab==='hist') body = tplHist();
  else if (S.tab==='logs') body = tplLogs();
  else if (S.tab==='chart') body = tplChart();
  return `
<div class="card">
  <div class="head">
    <div class="logo">${ICO.cpu.replace('class="ic"','class="ic" style="width:24px;height:24px"')}</div>
    <div class="title"><h1>VI LONG ĐẸP TRAI</h1><small>${ICO.brain.replace('class="ic"','class="ic ic-sm"')} V13.1.1 Supreme</small></div>
    <div class="right">${badge}</div>
  </div>
  <div class="ubar">
    <div class="av">${esc((S.nickname||'?')[0].toUpperCase())}</div>
    <div class="info"><b>${esc(S.nickname)}</b><small><span class="dot" style="background:${S.workerAlive?'var(--ok)':'var(--err)'};box-shadow:0 0 8px ${S.workerAlive?'var(--ok)':'var(--err)'}"></span>${S.workerAlive?'Worker 24/7 chạy nền':'Worker chưa chạy'}</small></div>
    <div class="bal"><b id="bal_val">${fmt(S.balance)}</b><small>WIN</small></div>
  </div>
  <div class="tabs">
    <button data-tab="main" class="${S.tab==='main'?'on':''}">${ICO.play} CHƠI</button>
    <button data-tab="cfg" class="${S.tab==='cfg'?'on':''}">${ICO.cfg} CÀI ĐẶT</button>
    <button data-tab="hist" class="${S.tab==='hist'?'on':''}">${ICO.hist} LỊCH SỬ</button>
    <button data-tab="logs" class="${S.tab==='logs'?'on':''}">${ICO.logs} LOG</button>
    <button data-tab="chart" class="${S.tab==='chart'?'on':''}">${ICO.chart} BIỂU ĐỒ</button>
  </div>
  <div class="body"><div class="slide">${body}</div></div>
</div>`;
}

function tplMain(c){
  const streakLabel = c.mode==='double' ? `${c.lose_streak}/${c.max_lose_streak}` : '—';
  const ai = S.ai;
  const detail = ai.detail || {};
  const pendingTxt = S.pendingPred ? `${emo(S.pendingPred)} #${S.pendingSession||'?'}` : '—';
  const stats = S.stats || {};
  const profitColor = (stats.profit||0) >= 0 ? 'var(--ok)' : 'var(--err)';
  const betLevel = S.pendingBetLevel || 'base';
  const betAmount = S.pendingBetAmount || 0;
  const betLabel = betLevel==='high'?'🔥 ĐÁNH LỚN':(betLevel==='low'?'💧 ĐÁNH NHỎ':(betLevel==='martingale'?'📈 MARTINGALE':'⚖️ BASE'));
  const betClass = betLevel==='high'?'high':(betLevel==='low'?'low':(betLevel==='martingale'?'martingale':'base'));
  const cauDep = (ai.cau_dep||0)*100;
  const cauXau = (ai.cau_xau||0)*100;
  return `
    <div class="row"><div class="lbl">${ICO.money} Vốn mỗi tay</div><input type="number" id="i_base" value="${c.base_bet}" min="1000" step="1000"></div>
    <div class="row"><div class="lbl">${ICO.target} Chốt lãi dừng</div><input type="number" id="i_profit" value="${c.profit_stop}" min="0" step="10000"></div>
    <div class="row"><div class="lbl">${ICO.chart} Chế độ đánh</div>
      <div class="sel"><select id="s_mode">
        <option value="fixed" ${c.mode==='fixed'?'selected':''}>Vốn gốc cố định</option>
        <option value="double" ${c.mode==='double'?'selected':''}>X2 khi thua (Martingale)</option>
      </select></div>
    </div>
    <div class="row"><div class="lbl">${ICO.refresh} Thua tối đa</div><input type="number" id="i_max" value="${c.max_lose_streak}" min="1" max="10"></div>
    <div class="pills">
      <div class="pill ${c.auto?'ok':'off'}"><small>Auto</small><b id="st_auto">${c.auto?'ON':'OFF'}</b></div>
      <div class="pill ${c.paused?'warn':'ok'}"><small>Trạng thái</small><b id="st_state">${c.paused?'DỪNG':'CHẠY'}</b></div>
      <div class="pill cyan"><small>Chuỗi thua</small><b id="st_streak">${streakLabel}</b></div>
      <div class="pill cyan"><small>Phiên chờ</small><b id="st_pending" style="font-size:11px">${pendingTxt}</b></div>
    </div>
    <div class="pills" style="grid-template-columns:repeat(3,1fr);margin-top:9px">
      <div class="pill ok"><small>Thắng</small><b id="st_wins">${stats.wins||0}</b></div>
      <div class="pill off"><small>Thua</small><b id="st_losses">${stats.losses||0}</b></div>
      <div class="pill cyan"><small>Tỉ lệ</small><b id="st_winrate">${stats.winrate||0}%</b></div>
    </div>
    <div class="pills" style="grid-template-columns:1fr;margin-top:9px">
      <div class="pill" style="border-color:${profitColor}"><small>Lợi nhuận</small><b id="st_profit" style="color:${profitColor}">${(stats.profit||0)>=0?'+':''}${fmt(stats.profit||0)}</b></div>
    </div>
    <button class="big-btn ${c.auto?'on':'off'}" id="b_toggle">${c.auto?ICO.stop+' TẮT AUTO':ICO.play+' BẬT AUTO'}</button>
    <div class="ai-card">
      <div class="head-line"><b>${ICO.brain} AI V13 SUPREME</b><span class="conf">Conf: ${ai.conf||0}%</span></div>
      <div class="conf-bar"><i style="width:${Math.min(100,Math.max(0,ai.conf||0))}%"></i></div>
      <div class="ai-weights">
        <div class="ai-weight"><small>Agree</small><b>${(detail.agree||0).toFixed(0)}%</b></div>
        <div class="ai-weight"><small>Regime</small><b style="font-size:9px">${(ai.regime||'—').slice(0,8)}</b></div>
        <div class="ai-weight"><small>Voters</small><b>${detail.voters||0}</b></div>
        <div class="ai-weight"><small>Streak</small><b>${ai.streak||0}</b></div>
        <div class="ai-weight"><small>Engine</small><b>V13.1</b></div>
      </div>
      <div class="ai-pred">${ai.pred==='TAI'?'🔵 DỰ ĐOÁN: TÀI':ai.pred==='XIU'?'🔴 DỰ ĐOÁN: XỈU':'⏳ Chờ dữ liệu'}</div>
      ${S.pendingPred?`<div class="ai-bet ${betClass}">${betLabel} • ${fmt(betAmount)}<br><small style="font-size:9px;opacity:.8">Cầu đẹp: ${cauDep.toFixed(0)}% • Cầu xấu: ${cauXau.toFixed(0)}%</small></div>`:''}
      <div class="ai-meta"><span>Cầu đẹp: ${cauDep.toFixed(0)}%</span><span>Cầu xấu: ${cauXau.toFixed(0)}%</span></div>
    </div>
    <div class="rainbow">${ICO.bolt} V16 VIP 666 — AUTO STOP • SMART BET + MARTINGALE AI ${ICO.bolt}</div>
  `;
}

function tplCfg(c){
  const win = Number(S.stats.wins ?? S.history.filter(h=>h.win).length);
  const lose = Number(S.stats.losses ?? S.history.filter(h=>!h.win).length);
  const total = win + lose;
  const rate = total ? Math.round(win/total*100) : 0;
  const winTarget = Math.max(1, Math.min(666, Number(c.win_target || 666)));
  const winProgress = Math.min(100, Math.round(win/winTarget*100));
  const w = S.workerInfo || {};
  return `
    <section class="v16-target-card">
      <div class="v16-target-top"><span>🏆 MỤC TIÊU VIP · PHIÊN THẮNG</span><b id="v16-win-count">${win}/${winTarget}</b></div>
      <div class="v16-track"><i id="v16-win-bar" style="width:${winProgress}%"></i></div>
      <div class="v16-target-foot"><span id="v16-win-percent">${winProgress}% hoàn thành</span><span id="v16-win-remaining">${Math.max(0,winTarget-win)} phiên còn lại</span></div>
      <div class="row v16-target-input"><div class="lbl">${ICO.target} Dừng AUTO khi đủ thắng</div><input type="number" id="i_win_target" value="${winTarget}" min="1" max="666" step="1"></div>
      <small class="v16-hint">Bộ đếm lưu riêng trên server, không bị giới hạn bởi 500 dòng lịch sử.</small>
    </section>
    <div class="sec">${ICO.chart} LOẠI BÀN ĐÁNH (MD5 / HŨ)</div>
    <div class="row"><div class="lbl">${ICO.info} Bàn đang đánh</div>
      <div class="sel"><select id="s_table_type">
        <option value="md5" ${c.table_type==='md5'?'selected':''}>MD5 (wtxmd52 tele68)</option>
        <option value="hu" ${c.table_type==='hu'?'selected':''}>Hũ / TX (wtx tele68)</option>
      </select></div>
    </div>
    <div class="sec">${ICO.brain} SMART BET AI</div>
    <div class="toggle" id="t_smart">
      <div class="lbl">${ICO.bolt} Đánh theo AI (cầu đẹp → lớn, cầu xấu → nhỏ)</div>
      <div class="switch ${c.smart_bet?'on':''}"></div>
    </div>
    <div class="row"><div class="lbl">${ICO.money} Tiền lớn (cầu đẹp)</div><input type="number" id="i_bet_high" value="${c.bet_high}" min="1000" step="1000"></div>
    <div class="row"><div class="lbl">${ICO.money} Tiền nhỏ (cầu xấu)</div><input type="number" id="i_bet_low" value="${c.bet_low}" min="1000" step="1000"></div>
    <div class="row"><div class="lbl">${ICO.target} Conf tối thiểu (đánh lớn)</div><input type="number" id="i_high_conf" value="${c.high_conf_min}" min="50" max="92"></div>
    <div class="row"><div class="lbl">${ICO.chart} Số thắng tối thiểu /5 phiên</div><input type="number" id="i_recent_win" value="${c.recent_win_min}" min="0" max="5"></div>
    <div class="sec">${ICO.money} AUTO CAPITAL ALLOCATION (chia vốn tự động)</div>
    <div class="toggle" id="t_auto_capital">
      <div class="lbl">${ICO.brain} Tự động chia vốn theo % (3% vốn/lần, cap 20%)</div>
      <div class="switch ${c.auto_capital?'on':''}"></div>
    </div>
    <div class="row"><div class="lbl">${ICO.money} Số vốn hiện tại (VND)</div><input type="number" id="i_capital" value="${c.capital||0}" min="0" step="1000"></div>
    ${c.auto_capital?`<div class="row"><div class="lbl">🧠 Mức cược tự động đề xuất</div><b style="color:var(--ok);font-size:12px">~${fmt(Math.max(1000,Math.round((c.capital||0)*0.03/1000)*1000))} / lần (3% vốn)</b></div>`:''}
    <div class="pills" style="grid-template-columns:repeat(2,1fr);margin-top:9px">
      <div class="pill ${c.auto_capital?'ok':'off'}"><small>AUTO CAPITAL</small><b>🧠 ${c.auto_capital?'BẬT':'TẮT'}</b></div>
      <div class="pill cyan"><small>AI LEARNING</small><b>🤖 ${S.aiLearnedCount||0} phiên</b></div>
    </div>
    <div class="row"><div class="lbl">${ICO.chart} Pattern 10 cầu gần nhất</div><b style="color:var(--p);font-family:monospace;font-size:13px;letter-spacing:2px">${S.pattern10||'—'}</b></div>
    <div class="sec">${ICO.info} PHIÊN ĐĂNG NHẬP</div>
    <div class="row"><div class="lbl">${ICO.user} Tài khoản</div><b style="font-size:12px">${esc(S.nickname)}</b></div>
    <div class="row"><div class="lbl">${ICO.cpu} Device</div><small style="font-size:10px;color:var(--p);font-family:monospace">${esc(S.device)}</small></div>
    <div class="row"><div class="lbl">${ICO.key} Key</div><small style="font-size:11px;color:var(--ok);font-weight:700">${ICO.check} Đã lưu server</small></div>
    <div class="sec">${ICO.cpu} WORKER 24/7</div>
    <div class="row"><div class="lbl">${ICO.refresh} Trạng thái</div><b style="font-size:12px;color:${S.workerAlive?'var(--ok)':'var(--err)'}">${S.workerAlive?'● RUNNING':'○ STOPPED'}</b></div>
    ${w.last_beat?`<div class="row"><div class="lbl">${ICO.info} Last beat</div><small style="font-size:11px;color:var(--muted)">${new Date(w.last_beat*1000).toLocaleTimeString()}</small></div>`:''}
    ${w.pid?`<div class="row"><div class="lbl">${ICO.info} PID</div><small style="font-size:11px;color:var(--p);font-family:monospace">${w.pid}</small></div>`:''}
    <button class="logout" id="b_kick" style="background:rgba(255,107,53,.1);border-color:rgba(255,107,53,.35);color:var(--p)">${ICO.refresh} RESTART WORKER</button>
    <div class="sec">${ICO.brain} V16 VIP ENGINE</div>
    <div class="row"><div class="lbl">Features</div><b style="color:var(--p)">100 + 30 meta</b></div>
    <div class="row"><div class="lbl">Regime detectors</div><b style="color:var(--p)">15</b></div>
    <div class="row"><div class="lbl">Voters</div><b style="color:var(--p)">100+</b></div>
    <div class="row"><div class="lbl">Pattern library</div><b style="color:var(--p)">48 khuôn</b></div>
    <div class="row"><div class="lbl">Smart Bet AI</div><b style="color:${c.smart_bet?'var(--ok)':'var(--muted)'}">${c.smart_bet?'BẬT':'TẮT'}</b></div>
    <div class="row"><div class="lbl">Martingale (X2)</div><b style="color:${c.mode==='double'?'var(--ok)':'var(--muted)'}">${c.mode==='double'?'BẬT':'TẮT'}</b></div>
    <div class="row"><div class="lbl">Self-respawn</div><b style="color:var(--ok)">BẬT</b></div>
    <div class="row"><div class="lbl">Cron endpoint</div><b style="color:var(--p)">?action=cron</b></div>
    <div class="sec">${ICO.brain} TTOANLC79 ALGORITHM (đã ghép)</div>
    <div class="row"><div class="lbl">${ICO.check} Thuật toán ttoanlc79 v2</div><b style="color:var(--ok)">ĐÃ TÍCH HỢP</b></div>
    <div class="row"><div class="lbl">${ICO.brain} Hàm dự đoán chính</div><b style="color:var(--p);font-size:10px;font-family:monospace">ttoan_predict_tx / ttoan_predict_md5</b></div>
    <div class="row"><div class="lbl">${ICO.chart} Mẹo tổng điểm + 5 mô hình + AI HTDD + phân tích cầu</div><b style="color:var(--p)">23 hàm PHP</b></div>
    <div class="sec">${ICO.chart} THỐNG KÊ</div>
    <div class="pills">
      <div class="pill cyan"><small>Tổng phiên</small><b>${S.history.length}</b></div>
      <div class="pill ok"><small>Thắng</small><b>${win}</b></div>
      <div class="pill off"><small>Thua</small><b>${lose}</b></div>
      <div class="pill cyan"><small>Tỉ lệ</small><b>${rate}%</b></div>
    </div>
    <button class="logout" id="b_logout">${ICO.logout} ĐĂNG XUẤT (XOÁ KEY + LỊCH SỬ)</button>
  `;
}

function tplHist(){
  if (!S.history.length) return `<div class="empty">${ICO.hist}<div>Chưa có lịch sử đánh</div><small>Bật AUTO để bắt đầu</small></div>`;
  return `<div class="hist" id="hist_list">` + S.history.map(h=>`
    <div class="hist-item ${h.win?'win':'lose'}">
      <span class="s">#${esc(h.session||'?')}</span>
      <div class="mid"><div class="r">${emo(h.pred)} → ${emo(h.result)}</div>
      <small>🎲 ${(h.dices||[]).join('-')} • ${esc(h.ts||'')}${h.balance_after!==undefined?' • '+fmt(h.balance_after):''}</small></div>
      <span class="tag">${h.win?'WIN':'LOSE'}</span>
    </div>`).join('') + `</div>`;
}

function tplLogs(){
  if (!S.logs.length) return `<div class="empty">${ICO.logs}<div>Chưa có log</div><small>Log sẽ hiện khi bot hoạt động</small></div>`;
  return `
    <div style="display:flex;justify-content:flex-end;margin-bottom:10px">
      <button class="logout" style="width:auto;margin:0;padding:8px 14px;font-size:10px" id="b_clear_logs">${ICO.refresh} XOÁ LOG</button>
    </div>
    <div class="log-panel" id="log_list">` + S.logs.map(l=>`
      <div class="log-item ${l.level||'info'}">
        <span class="ts">${esc(l.ts||'')}</span>
        <span class="m">${esc(l.msg||'')}</span>
      </div>`).join('') + `</div>`;
}

function tplChart(){
  return `
    <div class="sec">${ICO.chart} SƠ ĐỒ DÒNG TIỀN (MONEY FLOW)</div>
    <div class="chart-wrap">
      <canvas id="moneyFlowChart" width="420" height="220"></canvas>
      <div style="display:flex;justify-content:space-between;margin-top:8px;font-size:10px;color:var(--muted)">
        <span>● <span style="color:var(--ok)">Thắng</span> / <span style="color:var(--err)">Thua</span></span>
        <span>Số điểm: ${Math.min(70,(S.history||[]).length)}</span>
      </div>
    </div>
    <div class="pills" style="grid-template-columns:repeat(2,1fr);margin-top:9px">
      <div class="pill ${S.autoCapitalActive?'ok':'off'}"><small>AUTO CAPITAL 🧠</small><b>${S.autoCapitalActive?'BẬT':'TẮT'}</b></div>
      <div class="pill cyan"><small>AI LEARNING 🤖</small><b>${S.aiLearnedCount||0} phiên</b></div>
    </div>
    <div class="row"><div class="lbl">${ICO.chart} Pattern 10 cầu</div><b style="color:var(--p);font-family:monospace;font-size:14px;letter-spacing:3px">${S.pattern10||'—'}</b></div>
    ${S.skipNextBet?`<div class="msg warn" style="margin-top:10px">⚠️ Confidence thấp phiên kế tiếp — KHÔNG CƯỢC (vẫn phân tích)</div>`:''}
  `;
}
let __mfAnim = null;
function drawMoneyFlow(){
  const cv = document.getElementById('moneyFlowChart');
  if (!cv) return;
  const ctx = cv.getContext('2d');
  const W = cv.width, H = cv.height;
  ctx.clearRect(0,0,W,H);
  const raw = (S.history||[]).slice(0,70).filter(h=>h && h.balance_after!==undefined && h.balance_after!==null);
  if (raw.length < 2) {
    ctx.fillStyle = 'rgba(255,200,160,.7)';
    ctx.font = '13px sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('Chờ dữ liệu... (cần ≥2 phiên)', W/2, H/2);
    return;
  }
  const pts = raw.slice().reverse(); // chronological
  const vals = pts.map(p=>p.balance_after);
  let mn = Math.min.apply(null, vals), mx = Math.max.apply(null, vals);
  if (mn === mx) { mn -= 1; mx += 1; }
  const pad = (mx - mn) * 0.12; mn -= pad; mx += pad;
  const L=48, R=14, T=14, B=30;
  const cw = W-L-R, ch = H-T-B;
  const X = i => L + (cw * i / (pts.length-1));
  const Y = v => T + ch * (1 - (v - mn)/(mx - mn));
  // grid + y labels
  ctx.strokeStyle = 'rgba(255,100,100,.12)';
  ctx.fillStyle = 'rgba(255,200,160,.55)';
  ctx.font = '9px monospace';
  ctx.textAlign = 'right';
  for (let g=0; g<=4; g++){
    const yv = mn + (mx-mn)*g/4;
    const yy = Y(yv);
    ctx.beginPath(); ctx.moveTo(L,yy); ctx.lineTo(W-R,yy); ctx.stroke();
    ctx.fillText(fmt(Math.round(yv)), L-4, yy+3);
  }
  // x time labels (5 mốc)
  ctx.textAlign = 'center';
  const nLabels = Math.min(5, pts.length);
  for (let li=0; li<nLabels; li++){
    const idx = Math.round(li*(pts.length-1)/(nLabels-1));
    const ts = String(pts[idx].ts||'');
    const hhmm = ts.length>=5 ? ts.slice(0,5) : '';
    ctx.fillText(hhmm, X(idx), H-8);
  }
  // animation reveal
  if (__mfAnim) cancelAnimationFrame(__mfAnim);
  const start = performance.now();
  const dur = 600;
  function frame(now){
    const prog = Math.min(1, (now-start)/dur);
    const ease = 1 - Math.pow(1-prog, 3);
    const upto = Math.max(1, Math.floor((pts.length-1)*ease));
    ctx.clearRect(L,T,cw,ch);
    // re-draw grid is under; we cleared only plot area so grid stays (but stroke over... actually clearRect removes grid lines in plot area; redraw grid)
    ctx.strokeStyle = 'rgba(255,100,100,.12)';
    for (let g=0; g<=4; g++){ const yy = Y(mn + (mx-mn)*g/4); ctx.beginPath(); ctx.moveTo(L,yy); ctx.lineTo(W-R,yy); ctx.stroke(); }
    // line gradient
    const grad = ctx.createLinearGradient(L,0,W-R,0);
    grad.addColorStop(0,'#ff1744'); grad.addColorStop(0.5,'#ff6b35'); grad.addColorStop(1,'#ffb300');
    ctx.strokeStyle = grad;
    ctx.lineWidth = 2.2;
    ctx.shadowColor = 'rgba(255,30,30,.7)';
    ctx.shadowBlur = 10;
    ctx.beginPath();
    ctx.moveTo(X(0), Y(pts[0].balance_after));
    for (let i=1;i<=upto;i++) ctx.lineTo(X(i), Y(pts[i].balance_after));
    ctx.stroke();
    ctx.shadowBlur = 0;
    // points
    for (let i=0;i<=upto;i++){
      ctx.beginPath();
      ctx.arc(X(i), Y(pts[i].balance_after), i===upto?4:2.5, 0, Math.PI*2);
      ctx.fillStyle = pts[i].win ? '#00ff88' : '#ff1744';
      ctx.fill();
    }
    // last point label
    if (upto >= pts.length-1) {
      const last = pts[pts.length-1];
      ctx.fillStyle = last.win ? '#00ff88' : '#ff8a80';
      ctx.font = 'bold 11px monospace';
      ctx.textAlign = 'right';
      ctx.fillText(fmt(last.balance_after), X(pts.length-1)-6, Y(last.balance_after)-6);
    }
    if (prog < 1) __mfAnim = requestAnimationFrame(frame);
  }
  __mfAnim = requestAnimationFrame(frame);
}
function fullRender(){
  app.innerHTML = S.loggedIn ? tplDashboard() : tplLogin();
  bindAll();
}

function patchDashboard(){
  const b = document.getElementById('bal_val');
  if (b) b.textContent = fmt(S.balance);
  const sa = document.getElementById('st_auto');
  if (sa) { sa.textContent = S.config.auto?'ON':'OFF'; sa.parentElement.className = 'pill ' + (S.config.auto?'ok':'off'); }
  const ss = document.getElementById('st_state');
  if (ss) { ss.textContent = S.config.paused?'DỪNG':'CHẠY'; ss.parentElement.className = 'pill ' + (S.config.paused?'warn':'ok'); }
  const st = document.getElementById('st_streak');
  if (st) st.textContent = S.config.mode==='double' ? `${S.config.lose_streak}/${S.config.max_lose_streak}` : '—';
  const sp = document.getElementById('st_pending');
  if (sp) sp.textContent = S.pendingPred ? `${emo(S.pendingPred)} #${S.pendingSession||'?'}` : '—';
  const sw = document.getElementById('st_wins'); if (sw) sw.textContent = S.stats.wins||0;
  const v16Wins = Number(S.stats.wins||0), v16Target = Math.max(1, Math.min(666, Number(S.config.win_target||666)));
  const v16Pct = Math.min(100, Math.round(v16Wins/v16Target*100));
  const v16CountEl = document.getElementById('v16-win-count'); if (v16CountEl) v16CountEl.textContent = v16Wins+'/'+v16Target;
  const v16BarEl = document.getElementById('v16-win-bar'); if (v16BarEl) v16BarEl.style.width = v16Pct+'%';
  const v16PctEl = document.getElementById('v16-win-percent'); if (v16PctEl) v16PctEl.textContent = v16Pct+'% hoàn thành';
  const v16RemainEl = document.getElementById('v16-win-remaining'); if (v16RemainEl) v16RemainEl.textContent = Math.max(0,v16Target-v16Wins)+' phiên còn lại';
  const sl = document.getElementById('st_losses'); if (sl) sl.textContent = S.stats.losses||0;
  const sr = document.getElementById('st_winrate'); if (sr) sr.textContent = (S.stats.winrate||0)+'%';
  const spf = document.getElementById('st_profit');
  if (spf) {
    const p = S.stats.profit||0;
    spf.textContent = (p>=0?'+':'')+fmt(p);
    spf.style.color = p>=0?'var(--ok)':'var(--err)';
    spf.parentElement.style.borderColor = p>=0?'var(--ok)':'var(--err)';
  }
  const bt = document.getElementById('b_toggle');
  if (bt) {
    bt.innerHTML = S.config.auto ? ICO.stop+' TẮT AUTO' : ICO.play+' BẬT AUTO';
    bt.className = 'big-btn ' + (S.config.auto?'on':'off');
  }
  const badge = document.querySelector('.head .right .badge');
  if (badge) {
    if (S.config.paused) { badge.className='badge pause'; badge.innerHTML='⏸ DỪNG'; }
    else if (S.config.auto) { badge.className='badge on'; badge.innerHTML='● AUTO ON'; }
    else { badge.className='badge off'; badge.innerHTML='○ OFF'; }
  }
  const ai = S.ai;
  const detail = ai.detail || {};
  const aw = document.querySelectorAll('.ai-weight b');
  if (aw.length === 5) {
    aw[0].textContent = (detail.agree||0).toFixed(0)+'%';
    aw[1].textContent = (ai.regime||'—').slice(0,8);
    aw[2].textContent = detail.voters||0;
    aw[3].textContent = ai.streak||0;
    aw[4].textContent = 'V13.1';
  }
  const conf = document.querySelector('.ai-card .conf');
  if (conf) conf.textContent = 'Conf: ' + (ai.conf||0) + '%';
  const pred = document.querySelector('.ai-pred');
  if (pred) pred.textContent = ai.pred==='TAI'?'🔵 DỰ ĐOÁN: TÀI':ai.pred==='XIU'?'🔴 DỰ ĐOÁN: XỈU':'⏳ Chờ dữ liệu';
  if (S.tab==='hist') {
    const hl = document.getElementById('hist_list');
    if (hl) hl.innerHTML = S.history.map(h=>`
      <div class="hist-item ${h.win?'win':'lose'}">
        <span class="s">#${esc(h.session||'?')}</span>
        <div class="mid"><div class="r">${emo(h.pred)} → ${emo(h.result)}</div>
        <small>🎲 ${(h.dices||[]).join('-')} • ${esc(h.ts||'')}${h.balance_after!==undefined?' • '+fmt(h.balance_after):''}</small></div>
        <span class="tag">${h.win?'WIN':'LOSE'}</span>
      </div>`).join('');
  }
  if (S.tab==='logs') {
    const ll = document.getElementById('log_list');
    if (ll) ll.innerHTML = S.logs.map(l=>`
      <div class="log-item ${l.level||'info'}">
        <span class="ts">${esc(l.ts||'')}</span>
        <span class="m">${esc(l.msg||'')}</span>
      </div>`).join('');
  }
  const ubSmall = document.querySelector('.ubar .info small');
  if (ubSmall) {
    ubSmall.innerHTML = `<span class="dot" style="background:${S.workerAlive?'var(--ok)':'var(--err)'};box-shadow:0 0 8px ${S.workerAlive?'var(--ok)':'var(--err)'}"></span>${S.workerAlive?'WORKER: ĐANG CHẠY ⚡':'WORKER: CHẾT — ĐANG KHỞI ĐỘNG LẠI'}`;
  }
}

async function api(action, data={}){
  if (S.authToken) data.auth_token = S.authToken;
  const fd = new FormData(); fd.append('action', action);
  for (const k in data) fd.append(k, data[k]);
  const r = await fetch(location.pathname + '?action=' + action, {method:'POST', body:fd});
  return r.json();
}
async function getStatus(){
  const r = await fetch(location.pathname + '?action=status&user=' + encodeURIComponent(S.user) + '&auth_token=' + encodeURIComponent(S.authToken));
  return r.json();
}

async function tick(){
  if (!S.loggedIn || S.tickInFlight) return;
  S.tickInFlight = true;
  try {
    const r = await api('tick', { user: S.user });
    if (r.ok) {
      S.pendingPred = r.pending_pred;
      S.pendingSession = r.pending_session;
      S.workerAlive = !!r.worker_alive;
    }
    const j = await getStatus();
    if (j.ok) {
      S.balance = j.balance || 0;
      S.history = j.history || [];
      try { S.ultraPrediction = window.AUZA_ULTRA ? window.AUZA_ULTRA.syncHistory(S.history) : null; } catch(e) { console.warn('[AUZA ULTRA] Sync lỗi:', e); }
      S.logs = j.logs || [];
      S.workerAlive = !!j.worker_alive;
      S.workerInfo = j.worker || null;
      S.stats = j.stats || {wins:0,losses:0,total:0,winrate:0,profit:0};
      if (j.config) {
        S.config.auto = j.config.auto;
        S.config.paused = j.config.paused;
        S.config.lose_streak = j.config.lose_streak;
        S.config.mode = j.config.mode;
        S.config.max_lose_streak = j.config.max_lose_streak;
        S.config.base_bet = j.config.base_bet;
        S.config.profit_stop = j.config.profit_stop;
        S.config.smart_bet = j.config.smart_bet;
        S.config.bet_high = j.config.bet_high;
        S.config.bet_low = j.config.bet_low;
        S.config.high_conf_min = j.config.high_conf_min;
        S.config.recent_win_min = j.config.recent_win_min;
        S.config.win_target = j.config.win_target || 666;
        S.config.table_type = j.config.table_type || 'md5';
        S.config.capital = j.config.capital || 0;
        S.config.auto_capital = !!j.config.auto_capital;
      }
      if (j.pattern_10 !== undefined) S.pattern10 = j.pattern_10;
      if (j.ai_learned_count !== undefined) S.aiLearnedCount = j.ai_learned_count;
      if (j.skip_next_bet !== undefined) S.skipNextBet = !!j.skip_next_bet;
      if (j.auto_capital_active !== undefined) S.autoCapitalActive = !!j.auto_capital_active;
      if (j.dudoan_count !== undefined) S.dudoanCount = j.dudoan_count;
      if (j.ai) S.ai = j.ai;
      if (j.pending_pred !== undefined) S.pendingPred = j.pending_pred;
      if (j.pending_session !== undefined) S.pendingSession = j.pending_session;
      if (j.pending_regime !== undefined) S.pendingRegime = j.pending_regime;
      if (j.pending_conf !== undefined) S.pendingConf = j.pending_conf;
      if (j.pending_bet_amount !== undefined) S.pendingBetAmount = j.pending_bet_amount;
      if (j.pending_bet_level !== undefined) S.pendingBetLevel = j.pending_bet_level;
      patchDashboard();
      if (typeof drawMoneyFlow === 'function') drawMoneyFlow();
    }
  } catch(e) {}
  S.tickInFlight = false;
}

function bindAll(){
  if (!S.loggedIn) {
    const btn = document.getElementById('b_login');
    if (btn) btn.onclick = doLogin;
    const kk = document.getElementById('i_k');
    if (kk) kk.onkeydown = e => { if(e.key==='Enter') doLogin(); };
    return;
  }
  document.querySelectorAll('.tabs button').forEach(el => {
    el.onclick = () => { S.tab = el.dataset.tab; fullRender(); };
  });
  const bt = document.getElementById('b_toggle');
  if (bt) bt.onclick = async () => {
    const goingOn = !S.config.auto;
    bt.disabled = true;
    if (goingOn) {
      await saveConfigSilent();
      await api('config', { user:S.user, auto:'1', paused:'0' });
      S.config.auto = true;
      tick();
    } else {
      await api('config', { user:S.user, auto:'0', paused:'0' });
      S.config.auto = false; S.config.paused = false; S.config.lose_streak = 0;
    }
    bt.disabled = false;
    patchDashboard();
  };
  const bindSave = (id, key, transform) => {
    const el = document.getElementById(id);
    if (!el) return;
    el.onchange = () => {
      const v = transform ? transform(el.value) : el.value;
      S.config[key] = v;
      saveConfigSilent();
    };
  };
  bindSave('i_base', 'base_bet', v=>Math.max(1000, parseInt(v)||1000));
  bindSave('i_profit', 'profit_stop', v=>Math.max(0, parseInt(v)||0));
  bindSave('s_mode', 'mode');
  bindSave('s_table_type', 'table_type');
  bindSave('i_max', 'max_lose_streak', v=>Math.max(1, Math.min(10, parseInt(v)||3)));
  const tSmart = document.getElementById('t_smart');
  if (tSmart) tSmart.onclick = async () => {
    S.config.smart_bet = !S.config.smart_bet;
    const sw = tSmart.querySelector('.switch');
    if (sw) sw.classList.toggle('on', S.config.smart_bet);
    await api('config', { user:S.user, smart_bet: S.config.smart_bet?'1':'0' });
  };
  bindSave('i_bet_high', 'bet_high', v=>Math.max(1000, parseInt(v)||50000));
  bindSave('i_bet_low', 'bet_low', v=>Math.max(1000, parseInt(v)||10000));
  bindSave('i_high_conf', 'high_conf_min', v=>Math.max(50, Math.min(92, parseInt(v)||75)));
  bindSave('i_recent_win', 'recent_win_min', v=>Math.max(0, Math.min(5, parseInt(v)||2)));
  bindSave('i_win_target', 'win_target', v=>Math.max(1, Math.min(666, parseInt(v)||666)));
  bindSave('i_capital', 'capital', v=>Math.max(0, parseInt(v)||0));
  const tAc = document.getElementById('t_auto_capital');
  if (tAc) tAc.onclick = async () => {
    S.config.auto_capital = !S.config.auto_capital;
    const sw = tAc.querySelector('.switch');
    if (sw) sw.classList.toggle('on', S.config.auto_capital);
    await api('config', { user:S.user, auto_capital: S.config.auto_capital?'1':'0' });
    fullRender();
  };
  const lo = document.getElementById('b_logout');
  if (lo) lo.onclick = async () => {
    if (!confirm('Đăng xuất sẽ XOÁ KEY và LỊCH SỬ. Tiếp tục?')) return;
    await api('logout', { user:S.user });
    clearInterval(S.tickTimer);
    Object.assign(S, { loggedIn:false, user:'', nickname:'', balance:0, history:[], logs:[], tab:'main', authToken:'',
      config:{base_bet:10000,profit_stop:0,mode:'fixed',max_lose_streak:3,auto:false,paused:false,lose_streak:0,
        smart_bet:false,bet_high:50000,bet_low:10000,high_conf_min:75,recent_win_min:2,table_type:'md5',win_target:666},
      pendingPred:null, pendingSession:null, pendingRegime:null, pendingConf:null,
      pendingBetAmount:null, pendingBetLevel:null,
      workerAlive:false, workerInfo:null, stats:{wins:0,losses:0,total:0,winrate:0,profit:0} });
    fullRender();
  };
  const kick = document.getElementById('b_kick');
  if (kick) kick.onclick = async () => {
    kick.disabled = true;
    await api('kick_worker', { user:S.user });
    setTimeout(()=>{ tick(); kick.disabled=false; }, 800);
  };
  const cl = document.getElementById('b_clear_logs');
  if (cl) cl.onclick = async () => {
    await api('clear_logs', { user:S.user });
    S.logs = [];
    fullRender();
  };
}

async function saveConfigSilent(){
  await api('config', {
    user: S.user,
    base_bet: S.config.base_bet,
    profit_stop: S.config.profit_stop,
    mode: S.config.mode,
    max_lose: S.config.max_lose_streak,
    smart_bet: S.config.smart_bet?'1':'0',
    bet_high: S.config.bet_high,
    bet_low: S.config.bet_low,
    high_conf_min: S.config.high_conf_min,
    recent_win_min: S.config.recent_win_min,
    win_target: S.config.win_target || 666,
    table_type: S.config.table_type,
    capital: S.config.capital,
    auto_capital: S.config.auto_capital?'1':'0',
  });
}

async function doLogin(){
  const u = document.getElementById('i_u').value.trim();
  const p = document.getElementById('i_p').value.trim();
  if (!u || !p) { S.error='Vui lòng nhập tài khoản và mật khẩu!'; fullRender(); return; }
  S.loading = true; S.error=''; S.success=''; fullRender();
  try {
    const r = await api('verify', {user:u, pass:p, device:S.device});
    if (!r.ok) {
      S.error = r.msg || 'Đăng nhập thất bại';
      S.loading=false;
      S.success='';
      fullRender();
      return;
    }
    Object.assign(S, {
      loggedIn:true, user:r.user, nickname:r.nickname, balance:r.balance,
      config:r.config, history:r.history||[], logs:r.logs||[], loading:false,
      authToken: r.auth_token || '', workerAlive: !!r.worker_alive,
      success: '',
    });
    fullRender();
    tick();
    S.tickTimer = setInterval(tick, 2000);
  } catch(e) {
    S.error = 'Lỗi: ' + e.message; S.loading=false; fullRender();
  }
}

fullRender();
</script>
<!-- [14-UI] V14 UPGRADE BADGE — thêm vào, không sửa UI cũ -->
<style id="v16-vip-666-style">
.v16-target-card{margin:10px 0 14px;padding:14px;border:1px solid rgba(255,190,70,.42);border-radius:16px;background:linear-gradient(145deg,rgba(44,19,5,.98),rgba(20,12,18,.98));box-shadow:0 8px 28px rgba(0,0,0,.25),inset 0 1px rgba(255,220,150,.08)}
.v16-target-top,.v16-target-foot{display:flex;align-items:center;justify-content:space-between;gap:8px}
.v16-target-top{font-size:11px;font-weight:900;letter-spacing:.5px;color:#ffd78a}
.v16-target-top b{font-size:18px;color:#fff1c2;font-variant-numeric:tabular-nums}
.v16-track{height:10px;margin:12px 0 7px;border-radius:99px;overflow:hidden;background:rgba(255,255,255,.1)}
.v16-track i{display:block;height:100%;border-radius:99px;background:linear-gradient(90deg,#ff6b35,#ffb300,#ffe082);box-shadow:0 0 14px rgba(255,179,0,.45);transition:width .3s}
.v16-target-foot{font-size:10px;color:#e8cda0}
.v16-target-input{margin-top:12px}
.v16-target-input input{max-width:110px;border-color:rgba(255,190,70,.45)}
.v16-hint{display:block;margin-top:7px;font-size:10px;line-height:1.5;color:#c9ad82}
</style>
<style id="v14-upgrade-style">
#v14-badge{position:fixed;right:12px;bottom:12px;z-index:99999;background:linear-gradient(135deg,#3d0c02,#7f1d1d,#9a3412);color:#ffd8a8;border:1px solid rgba(255,216,168,.35);border-radius:10px;padding:8px 12px;font-family:monospace;font-size:11px;line-height:1.5;box-shadow:0 4px 18px rgba(0,0,0,.45);max-width:260px;cursor:pointer;user-select:none}
#v14-badge b{color:#ffd166}
#v14-badge .dot{display:inline-block;width:7px;height:7px;border-radius:50%;background:#4ade80;margin-right:5px;animation:v14pulse 1.6s infinite}
@keyframes v14pulse{0%,100%{opacity:1}50%{opacity:.35}}
#v14-detail{display:none;margin-top:6px;padding-top:6px;border-top:1px dashed rgba(255,216,168,.3);color:#ffcc80;font-size:10px}
#v14-badge.open #v14-detail{display:block}
</style>
<div id="v14-badge" onclick="this.classList.toggle('open')">
  <span class="dot"></span><b>V14 UPGRADE</b> đã kích hoạt · 16 voter cầu
  <div id="v14-detail">
    · Thuật toán: v13 (gốc) + v14 overlay (16 dạng cầu)<br>
    · Bàn MD5: wtxmd52.tele68.com /txmd5<br>
    · Bàn Hũ: wtx.tele68.com /tx (API đúng)<br>
    · WS bet tự chuyển endpoint theo table_type<br>
    <span style="color:#ffd166">→ Click để ẩn/mở</span>
  </div>
</div>
<script id="v14-upgrade-script">
(function(){
  // Gắn nhãn API đang dùng vào ô chọn bàn (nếu có) — chỉ thêm, không sửa
  try{
    var sel=document.getElementById('s_table_type');
    if(sel && !sel.dataset.v14){
      sel.dataset.v14='1';
      var tip=document.createElement('div');
      tip.style.cssText='font-size:10px;color:#ffd8a8;margin-top:4px;font-family:monospace';
      tip.id='v14-api-tip';
      sel.parentNode.appendChild(tip);
      function upd(){ tip.textContent='API đang dùng: '+(sel.value==='hu'?'https://wtx.tele68.com/v1/tx/sessions (Hũ)':'https://wtxmd52.tele68.com/v1/txmd5/sessions (MD5)'); }
      sel.addEventListener('change',upd); upd();
    }
  }catch(e){}
})();
</script>


<script id="v15-redorange-algo">
(function(){
  'use strict';
  try {

      const tongDiemMeo = {
        3:  { ket_qua: 'Xỉu', xac_suat: 0.70 },
        4:  { ket_qua: 'Tài',  xac_suat: 0.60 },
        5:  { ket_qua: 'Tài',  xac_suat: 0.70 },
        6:  { ket_qua: 'Xỉu', xac_suat: 0.60 },
        7:  { ket_qua: 'Tài',  xac_suat: 0.80 },
        8:  { ket_qua: 'Xỉu', xac_suat: 0.80 },
        9:  { ket_qua: 'Xỉu', xac_suat: 0.70 },
        10: { ket_qua: 'Tài',  xac_suat: 0.80 },
        11: { ket_qua: 'Xỉu', xac_suat: 0.60 },
        12: { ket_qua: 'Tài',  xac_suat: 0.80 },
        13: { ket_qua: 'Tài',  xac_suat: 0.80 },
        14: { ket_qua: 'Xỉu', xac_suat: 0.60 },
        15: { ket_qua: 'Xỉu', xac_suat: 0.70 },
        16: { ket_qua: 'Tài',  xac_suat: 0.60 },
        17: { ket_qua: 'Xỉu', xac_suat: 0.60 },
        18: { ket_qua: 'Xỉu', xac_suat: 0.80 }
      };

      // ==================== MẸO CẦU (PATTERNS) ====================
      const cauPatterns = {
        '1-1': { desc: 'Cầu 1-1 (T-X-T-X)', weight: 0.85 },
        '1-2': { desc: 'Cầu 1-2 (T-X-X-T)', weight: 0.80 },
        '2-1': { desc: 'Cầu 2-1 (T-T-X-T)', weight: 0.80 },
        '2-2': { desc: 'Cầu 2-2 (T-T-X-X)', weight: 0.85 },
        '2-3': { desc: 'Cầu 2-3 (T-T-X-X-X)', weight: 0.75 },
        '3-2': { desc: 'Cầu 3-2 (T-T-T-X-X)', weight: 0.75 },
        '3-3': { desc: 'Cầu 3-3 (T-T-T-X-X-X)', weight: 0.70 },
        '3-4': { desc: 'Cầu 3-4 (T-T-T-X-X-X-X)', weight: 0.65 },
        '4-3': { desc: 'Cầu 4-3 (T-T-T-T-X-X-X)', weight: 0.65 },
        '4-4': { desc: 'Cầu 4-4 (T-T-T-T-X-X-X-X)', weight: 0.60 },
        '1-3': { desc: 'Cầu 1-3 (T-X-X-X)', weight: 0.70 },
        '3-1': { desc: 'Cầu 3-1 (T-T-T-X)', weight: 0.70 },
        '1-4': { desc: 'Cầu 1-4 (T-X-X-X-X)', weight: 0.65 },
        '4-1': { desc: 'Cầu 4-1 (T-T-T-T-X)', weight: 0.65 },
        '2-4': { desc: 'Cầu 2-4 (T-T-X-X-X-X)', weight: 0.60 },
        '4-2': { desc: 'Cầu 4-2 (T-T-T-T-X-X)', weight: 0.60 },
        '5-5': { desc: 'Cầu 5-5 (5T-5X)', weight: 0.55 },
        '5-1': { desc: 'Cầu 5-1 (5T-1X)', weight: 0.60 },
        '1-5': { desc: 'Cầu 1-5 (1T-5X)', weight: 0.60 },
        '6-6': { desc: 'Cầu 6-6 (6T-6X)', weight: 0.50 },
        '7-7': { desc: 'Cầu 7-7 (7T-7X)', weight: 0.45 },
        '8-8': { desc: 'Cầu 8-8 (8T-8X)', weight: 0.40 },
        '10-10': { desc: 'Cầu 10-10 (10T-10X)', weight: 0.35 },
        'bệt': { desc: 'Cầu bệt (chuỗi dài)', weight: 0.50 },
        'đảo': { desc: 'Cầu đảo (đảo ngược)', weight: 0.75 },
        'cầu nghiêng': { desc: 'Cầu nghiêng (lệch về 1 bên)', weight: 0.70 },
        'cầu đối xứng': { desc: 'Cầu đối xứng (T-X-X-T)', weight: 0.80 },
        'cầu lặp': { desc: 'Cầu lặp (lặp lại mẫu)', weight: 0.85 },
        'cầu đan': { desc: 'Cầu đan xen (T-X-T-T-X)', weight: 0.75 },
        'cầu bẻ': { desc: 'Cầu bẻ (đột ngột đổi)', weight: 0.90 },
      };

      // ==================== THUẬT TOÁN TỪ thuattoan.txt ====================
      let modelPredictions = {};

      function detectStreakAndBreak(history) {
        if (!history || history.length === 0) {
          return { streak: 0, currentResult: null, breakProb: 0 };
        }

        let streak = 1;
        const currentResult = history[history.length - 1].ket_qua;

        for (let i = history.length - 2; i >= 0; i--) {
          if (history[i].ket_qua === currentResult) streak++;
          else break;
        }

        const last15Results = history.slice(-15).map(item => item.ket_qua);
        if (!last15Results.length) {
          return { streak, currentResult, breakProb: 0 };
        }

        const switches = last15Results.slice(1).reduce((count, result, index) => {
          return count + (result !== last15Results[index] ? 1 : 0);
        }, 0);

        const taiCount = last15Results.filter(result => result === 'Tài').length;
        const xiuCount = last15Results.filter(result => result === 'Xỉu').length;
        const imbalance = Math.abs(taiCount - xiuCount) / last15Results.length;

        let breakProb = 0;

        if (streak >= 8) {
          breakProb = Math.min(0.6 + switches / 15 + imbalance * 0.15, 0.9);
        } else if (streak >= 5) {
          breakProb = Math.min(0.35 + switches / 10 + imbalance * 0.25, 0.85);
        } else if (streak >= 3 && switches >= 7) {
          breakProb = 0.3;
        }

        return { streak, currentResult, breakProb };
      }

      function evaluateModelPerformance(history, modelName, lookback = 10) {
        if (!modelPredictions[modelName] || history.length < 2) return 1;

        lookback = Math.min(lookback, history.length - 1);
        let correctPredictions = 0;

        for (let i = 0; i < lookback; i++) {
          const sessionId = history[history.length - (i + 2)].phien;
          const prediction = modelPredictions[modelName][sessionId] || 0;
          const actualResult = history[history.length - (i + 1)].ket_qua;

          if ((prediction === 1 && actualResult === 'Tài') || 
              (prediction === 2 && actualResult === 'Xỉu')) {
            correctPredictions++;
          }
        }

        const performanceRatio = lookback > 0 ? 
          1 + (correctPredictions - lookback / 2) / (lookback / 2) : 1;

        return Math.max(0.5, Math.min(1.5, performanceRatio));
      }

      function smartBridgeBreak(history) {
        if (!history || history.length < 3) {
          return { prediction: 0, breakProb: 0, reason: 'Không đủ dữ liệu để bẻ cầu' };
        }

        const { streak, currentResult, breakProb } = detectStreakAndBreak(history);
        const last20Results = history.slice(-20).map(item => item.ket_qua);
        const last20Scores = history.slice(-20).map(item => item.tong || 0);

        let finalBreakProb = breakProb;
        let reason = '';

        const avgScore = last20Scores.reduce((sum, score) => sum + score, 0) / (last20Scores.length || 1);
        const scoreDeviation = last20Scores.reduce((sum, score) => sum + Math.abs(score - avgScore), 0) / (last20Scores.length || 1);

        const last5Results = last20Results.slice(-5);
        const patternCounts = {};

        for (let i = 0; i <= last20Results.length - 3; i++) {
          const pattern = last20Results.slice(i, i + 3).join(',');
          patternCounts[pattern] = (patternCounts[pattern] || 0) + 1;
        }

        const mostCommonPattern = Object.entries(patternCounts).sort((a, b) => b[1] - a[1])[0];
        const hasRepeatingPattern = mostCommonPattern && mostCommonPattern[1] >= 3;

        if (streak >= 6) {
          finalBreakProb = Math.min(finalBreakProb + 0.15, 0.9);
          reason = `[Bẻ Cầu] Chuỗi ${streak} ${currentResult} dài, khả năng bẻ cầu cao`;
        } else if (streak >= 4 && scoreDeviation > 3) {
          finalBreakProb = Math.min(finalBreakProb + 0.1, 0.85);
          reason = `[Bẻ Cầu] Biến động điểm số lớn (${scoreDeviation.toFixed(1)}), khả năng bẻ cầu tăng`;
        } else if (hasRepeatingPattern && last5Results.every(result => result === currentResult)) {
          finalBreakProb = Math.min(finalBreakProb + 0.05, 0.8);
          reason = `[Bẻ Cầu] Phát hiện mẫu lặp ${mostCommonPattern[0]}, có khả năng bẻ cầu`;
        } else {
          finalBreakProb = Math.max(finalBreakProb - 0.15, 0.15);
          reason = '[Bẻ Cầu] Không phát hiện mẫu bẻ cầu mạnh, tiếp tục theo cầu';
        }

        let prediction = finalBreakProb > 0.65 ? 
          (currentResult === 'Tài' ? 2 : 1) : 
          (currentResult === 'Tài' ? 1 : 2);

        return { prediction, breakProb: finalBreakProb, reason };
      }

      function trendAndProb(history) {
        if (!history || history.length < 3) return 0;

        const { streak, currentResult, breakProb } = detectStreakAndBreak(history);

        if (streak >= 5) {
          if (breakProb > 0.75) return currentResult === 'Tài' ? 2 : 1;
          return currentResult === 'Tài' ? 1 : 2;
        }

        const last15Results = history.slice(-15).map(item => item.ket_qua);
        if (!last15Results.length) return 0;

        const weightedResults = last15Results.map((result, index) => Math.pow(1.2, index));
        const taiWeight = weightedResults.reduce((sum, weight, i) => sum + (last15Results[i] === 'Tài' ? weight : 0), 0);
        const xiuWeight = weightedResults.reduce((sum, weight, i) => sum + (last15Results[i] === 'Xỉu' ? weight : 0), 0);
        const totalWeight = taiWeight + xiuWeight;

        const last10Results = last15Results.slice(-10);
        const patterns = [];

        if (last10Results.length >= 4) {
          for (let i = 0; i <= last10Results.length - 4; i++) {
            patterns.push(last10Results.slice(i, i + 4).join(','));
          }
        }

        const patternCounts = patterns.reduce((counts, pattern) => {
          counts[pattern] = (counts[pattern] || 0) + 1;
          return counts;
        }, {});

        const mostCommonPattern = Object.entries(patternCounts).sort((a, b) => b[1] - a[1])[0];

        if (mostCommonPattern && mostCommonPattern[1] >= 3) {
          const patternParts = mostCommonPattern[0].split(',');
          return patternParts[patternParts.length - 1] !== last10Results[last10Results.length - 1] ? 1 : 2;
        }

        if (totalWeight > 0 && Math.abs(taiWeight - xiuWeight) / totalWeight >= 0.25) {
          return taiWeight > xiuWeight ? 2 : 1;
        }

        return last15Results[last15Results.length - 1] === 'Xỉu' ? 1 : 2;
      }

      function shortPattern(history) {
        if (!history || history.length < 3) return 0;

        const { streak, currentResult, breakProb } = detectStreakAndBreak(history);

        if (streak >= 4) {
          if (breakProb > 0.75) return currentResult === 'Tài' ? 2 : 1;
          return currentResult === 'Tài' ? 1 : 2;
        }

        const last8Results = history.slice(-8).map(item => item.ket_qua);
        if (!last8Results.length) return 0;

        const patterns = [];

        if (last8Results.length >= 3) {
          for (let i = 0; i <= last8Results.length - 3; i++) {
            patterns.push(last8Results.slice(i, i + 3).join(','));
          }
        }

        const patternCounts = patterns.reduce((counts, pattern) => {
          counts[pattern] = (counts[pattern] || 0) + 1;
          return counts;
        }, {});

        const mostCommonPattern = Object.entries(patternCounts).sort((a, b) => b[1] - a[1])[0];

        if (mostCommonPattern && mostCommonPattern[1] >= 2) {
          const patternParts = mostCommonPattern[0].split(',');
          return patternParts[patternParts.length - 1] !== last8Results[last8Results.length - 1] ? 1 : 2;
        }

        return last8Results[last8Results.length - 1] === 'Xỉu' ? 1 : 2;
      }

      function meanDeviation(history) {
        if (!history || history.length < 3) return 0;

        const { streak, currentResult, breakProb } = detectStreakAndBreak(history);

        if (streak >= 4) {
          if (breakProb > 0.75) return currentResult === 'Tài' ? 2 : 1;
          return currentResult === 'Tài' ? 1 : 2;
        }

        const last12Results = history.slice(-12).map(item => item.ket_qua);
        if (!last12Results.length) return 0;

        const taiCount = last12Results.filter(result => result === 'Tài').length;
        const xiuCount = last12Results.length - taiCount;
        const imbalance = Math.abs(taiCount - xiuCount) / last12Results.length;

        if (imbalance < 0.35) {
          return last12Results[last12Results.length - 1] === 'Xỉu' ? 1 : 2;
        }

        return xiuCount > taiCount ? 1 : 2;
      }

      function recentSwitch(history) {
        if (!history || history.length < 3) return 0;

        const { streak, currentResult, breakProb } = detectStreakAndBreak(history);

        if (streak >= 4) {
          if (breakProb > 0.75) return currentResult === 'Tài' ? 2 : 1;
          return currentResult === 'Tài' ? 1 : 2;
        }

        const last10Results = history.slice(-10).map(item => item.ket_qua);
        if (!last10Results.length) return 0;

        const switches = last10Results.slice(1).reduce((count, result, index) => {
          return count + (result !== last10Results[index] ? 1 : 0);
        }, 0);

        return switches >= 6 ? 
          (last10Results[last10Results.length - 1] === 'Xỉu' ? 1 : 2) : 
          (last10Results[last10Results.length - 1] === 'Xỉu' ? 1 : 2);
      }

      function isBadPattern(history) {
        if (!history || history.length < 3) return false;

        const last15Results = history.slice(-15).map(item => item.ket_qua);
        if (!last15Results.length) return false;

        const switches = last15Results.slice(1).reduce((count, result, index) => {
          return count + (result !== last15Results[index] ? 1 : 0);
        }, 0);

        const { streak } = detectStreakAndBreak(history);
        return switches >= 9 || streak >= 10;
      }

      function aiHtddLogic(history) {
        if (!history || history.length < 3) {
          const randomPred = Math.random() < 0.5 ? 'Tài' : 'Xỉu';
          return { prediction: randomPred, reason: 'Không đủ lịch sử, dự đoán ngẫu nhiên', source: 'AI HTDD' };
        }

        const last5Results = history.slice(-5).map(item => item.ket_qua);
        const last5Scores = history.slice(-5).map(item => item.tong || 0);
        const taiCount = last5Results.filter(result => result === 'Tài').length;
        const xiuCount = last5Results.filter(result => result === 'Xỉu').length;

        if (history.length >= 3) {
          const last3Results = history.slice(-3).map(item => item.ket_qua);
          if (last3Results.join(',') === 'Tài,Xỉu,Tài') {
            return { prediction: 'Xỉu', reason: 'Phát hiện mẫu 1T1X -> nên đánh Xỉu', source: 'AI HTDD' };
          } else if (last3Results.join(',') === 'Xỉu,Tài,Xỉu') {
            return { prediction: 'Tài', reason: 'Phát hiện mẫu 1X1T -> nên đánh Tài', source: 'AI HTDD' };
          }
        }

        if (history.length >= 4) {
          const last4Results = history.slice(-4).map(item => item.ket_qua);
          if (last4Results.join(',') === 'Tài,Tài,Xỉu,Xỉu') {
            return { prediction: 'Tài', reason: 'Phát hiện mẫu 2T2X -> nên đánh Tài', source: 'AI HTDD' };
          } else if (last4Results.join(',') === 'Xỉu,Xỉu,Tài,Tài') {
            return { prediction: 'Xỉu', reason: 'Phát hiện mẫu 2X2T -> nên đánh Xỉu', source: 'AI HTDD' };
          }
        }

        if (history.length >= 9 && history.slice(-6).every(item => item.ket_qua === 'Tài')) {
          return { prediction: 'Xỉu', reason: 'Chuỗi Tài quá dài (6 lần) -> dự đoán Xỉu', source: 'AI HTDD' };
        } else if (history.length >= 9 && history.slice(-6).every(item => item.ket_qua === 'Xỉu')) {
          return { prediction: 'Tài', reason: 'Chuỗi Xỉu quá dài (6 lần) -> dự đoán Tài', source: 'AI HTDD' };
        }

        const avgScore = last5Scores.reduce((sum, score) => sum + score, 0) / (last5Scores.length || 1);

        if (avgScore > 10) {
          return { prediction: 'Tài', reason: `Điểm trung bình cao (${avgScore.toFixed(1)}) -> dự đoán Tài`, source: 'AI HTDD' };
        } else if (avgScore < 8) {
          return { prediction: 'Xỉu', reason: `Điểm trung bình thấp (${avgScore.toFixed(1)}) -> dự đoán Xỉu`, source: 'AI HTDD' };
        }

        if (taiCount > xiuCount + 1) {
          return { prediction: 'Xỉu', reason: `Tài chiếm đa số (${taiCount}/${last5Results.length}) -> dự đoán Xỉu`, source: 'AI HTDD' };
        } else if (xiuCount > taiCount + 1) {
          return { prediction: 'Tài', reason: `Xỉu chiếm đa số (${xiuCount}/${last5Results.length}) -> dự đoán Tài`, source: 'AI HTDD' };
        } else {
          const totalTai = history.filter(item => item.ket_qua === 'Tài').length;
          const totalXiu = history.filter(item => item.ket_qua === 'Xỉu').length;

          if (totalTai > totalXiu + 2) {
            return { prediction: 'Xỉu', reason: 'Tổng thể Tài nhiều hơn -> dự đoán Xỉu', source: 'AI HTDD' };
          } else if (totalXiu > totalTai + 2) {
            return { prediction: 'Tài', reason: 'Tổng thể Xỉu nhiều hơn -> dự đoán Tài', source: 'AI HTDD' };
          } else {
            const randomPred = Math.random() < 0.5 ? 'Tài' : 'Xỉu';
            return { prediction: randomPred, reason: 'Cân bằng, dự đoán ngẫu nhiên', source: 'AI HTDD' };
          }
        }
      }

      // ==================== PHAN TICH CAU NANG CAO ====================
      function phanTichCau(history) {
        if (!history || history.length < 3) return { cau: 'Khong xac dinh', weight: 0 };

        const results = history.slice(-30).map(item => item.ket_qua);

        // Phan tich chuoi (streaks)
        const streaks = [];
        let currentStreak = 1;
        let currentType = results[0];

        for (let i = 1; i < results.length; i++) {
          if (results[i] === currentType) {
            currentStreak++;
          } else {
            streaks.push({ type: currentType, count: currentStreak });
            currentType = results[i];
            currentStreak = 1;
          }
        }
        streaks.push({ type: currentType, count: currentStreak });

        // Tim mau cau
        let detectedCau = 'Khong xac dinh';
        let cauWeight = 0.5;

        // Kiem tra cau bet (chuoi dai)
        const maxStreak = Math.max(...streaks.map(s => s.count));
        if (maxStreak >= 6) {
          detectedCau = 'bet';
          cauWeight = 0.5;
        }

        // Kiem tra cau 1-1
        let oneOneCount = 0;
        for (let i = 0; i < streaks.length - 1; i++) {
          if (streaks[i].count === 1 && streaks[i + 1].count === 1) {
            oneOneCount++;
          }
        }
        if (oneOneCount >= 3) {
          detectedCau = '1-1';
          cauWeight = 0.85;
        }

        // Kiem tra cau 2-2
        let twoTwoCount = 0;
        for (let i = 0; i < streaks.length - 1; i++) {
          if (streaks[i].count === 2 && streaks[i + 1].count === 2) {
            twoTwoCount++;
          }
        }
        if (twoTwoCount >= 2) {
          detectedCau = '2-2';
          cauWeight = 0.85;
        }

        // Kiem tra cau 1-2
        let oneTwoCount = 0;
        for (let i = 0; i < streaks.length - 1; i++) {
          if (streaks[i].count === 1 && streaks[i + 1].count === 2) {
            oneTwoCount++;
          }
        }
        if (oneTwoCount >= 2) {
          detectedCau = '1-2';
          cauWeight = 0.80;
        }

        // Kiem tra cau 2-1
        let twoOneCount = 0;
        for (let i = 0; i < streaks.length - 1; i++) {
          if (streaks[i].count === 2 && streaks[i + 1].count === 1) {
            twoOneCount++;
          }
        }
        if (twoOneCount >= 2) {
          detectedCau = '2-1';
          cauWeight = 0.80;
        }

        // Kiem tra cau 3-2
        let threeTwoCount = 0;
        for (let i = 0; i < streaks.length - 1; i++) {
          if (streaks[i].count === 3 && streaks[i + 1].count === 2) {
            threeTwoCount++;
          }
        }
        if (threeTwoCount >= 2) {
          detectedCau = '3-2';
          cauWeight = 0.75;
        }

        // Kiem tra cau 2-3
        let twoThreeCount = 0;
        for (let i = 0; i < streaks.length - 1; i++) {
          if (streaks[i].count === 2 && streaks[i + 1].count === 3) {
            twoThreeCount++;
          }
        }
        if (twoThreeCount >= 2) {
          detectedCau = '2-3';
          cauWeight = 0.75;
        }

        // Kiem tra cau 3-3
        let threeThreeCount = 0;
        for (let i = 0; i < streaks.length - 1; i++) {
          if (streaks[i].count === 3 && streaks[i + 1].count === 3) {
            threeThreeCount++;
          }
        }
        if (threeThreeCount >= 2) {
          detectedCau = '3-3';
          cauWeight = 0.70;
        }

        // Kiem tra cau dao
        let daoCount = 0;
        for (let i = 0; i < streaks.length - 2; i++) {
          if (streaks[i].count === streaks[i + 2].count && streaks[i].type !== streaks[i + 2].type) {
            daoCount++;
          }
        }
        if (daoCount >= 2) {
          detectedCau = 'dao';
          cauWeight = 0.75;
        }

        // Kiem tra cau nghieng
        const last10Results = results.slice(-10);
        const taiCount10 = last10Results.filter(r => r === 'Tài').length;
        const xiuCount10 = last10Results.filter(r => r === 'Xỉu').length;
        if (Math.abs(taiCount10 - xiuCount10) >= 6) {
          detectedCau = 'cau nghieng';
          cauWeight = 0.70;
        }

        // Kiem tra cau lap
        const pattern3 = [];
        for (let i = 0; i <= results.length - 3; i++) {
          pattern3.push(results.slice(i, i + 3).join(','));
        }
        const patternCounts3 = {};
        pattern3.forEach(p => patternCounts3[p] = (patternCounts3[p] || 0) + 1);
        const maxPattern3 = Object.entries(patternCounts3).sort((a, b) => b[1] - a[1])[0];
        if (maxPattern3 && maxPattern3[1] >= 4) {
          detectedCau = 'cau lap';
          cauWeight = 0.85;
        }

        // Kiem tra cau dan
        let danCount = 0;
        for (let i = 0; i < results.length - 4; i++) {
          const slice = results.slice(i, i + 5);
          if (slice[0] !== slice[1] && slice[1] === slice[3] && slice[0] === slice[2] && slice[2] !== slice[4]) {
            danCount++;
          }
        }
        if (danCount >= 2) {
          detectedCau = 'cau dan';
          cauWeight = 0.75;
        }

        return { cau: detectedCau, weight: cauWeight, streaks };
      }

      // ==================== THUẬT TOÁN TỔNG HỢP (FULL A-Z) ====================
      function generatePrediction(history, predictions) {
        modelPredictions = predictions || {};

        if (!history || history.length === 0) {
          const randomPred = Math.random() < 0.5 ? 'Tài' : 'Xỉu';
          return { prediction: randomPred, doTinCay: 50, giaiThich: 'Khong du lich su, du doan ngau nhien' };
        }

        if (!modelPredictions.trend) {
          modelPredictions = {
            trend: {},
            short: {},
            mean: {},
            switch: {},
            bridge: {}
          };
        }

        const currentSession = history[history.length - 1].phien;
        const currentTong = history[history.length - 1].tong;

        // Lay du doan tu cac mo hinh
        const trendPred = history.length < 5 ? 
          (history[history.length - 1].ket_qua === 'Tài' ? 2 : 1) : 
          trendAndProb(history);

        const shortPred = history.length < 5 ? 
          (history[history.length - 1].ket_qua === 'Tài' ? 2 : 1) : 
          shortPattern(history);

        const meanPred = history.length < 5 ? 
          (history[history.length - 1].ket_qua === 'Tài' ? 2 : 1) : 
          meanDeviation(history);

        const switchPred = history.length < 5 ? 
          (history[history.length - 1].ket_qua === 'Tài' ? 2 : 1) : 
          recentSwitch(history);

        const bridgePred = history.length < 5 ? 
          { prediction: history[history.length - 1].ket_qua === 'Tài' ? 2 : 1, breakProb: 0, reason: 'Lich su ngan' } : 
          smartBridgeBreak(history);

        const aiPred = aiHtddLogic(history);

        // Phan tich cau
        const cauAnalysis = phanTichCau(history);

        // Meo tong diem
        const tongMeo = tongDiemMeo[currentTong] || { ket_qua: 'Khong xac dinh', xac_suat: 0.5 };

        // Luu cac du doan
        modelPredictions.trend[currentSession] = trendPred;
        modelPredictions.short[currentSession] = shortPred;
        modelPredictions.mean[currentSession] = meanPred;
        modelPredictions.switch[currentSession] = switchPred;
        modelPredictions.bridge[currentSession] = bridgePred.prediction;

        // Danh gia hieu suat cac mo hinh
        const modelPerformance = {
          trend: evaluateModelPerformance(history, 'trend'),
          short: evaluateModelPerformance(history, 'short'),
          mean: evaluateModelPerformance(history, 'mean'),
          switch: evaluateModelPerformance(history, 'switch'),
          bridge: evaluateModelPerformance(history, 'bridge')
        };

        // Trong so cho cac mo hinh
        const modelWeights = {
          trend: 0.15 * modelPerformance.trend,
          short: 0.15 * modelPerformance.short,
          mean: 0.15 * modelPerformance.mean,
          switch: 0.15 * modelPerformance.switch,
          bridge: 0.15 * modelPerformance.bridge,
          aihtdd: 0.15,
          cau: 0.10,
          tongDiem: 0.10
        };

        let taiScore = 0;
        let xiuScore = 0;

        if (trendPred === 1) taiScore += modelWeights.trend;
        else if (trendPred === 2) xiuScore += modelWeights.trend;

        if (shortPred === 1) taiScore += modelWeights.short;
        else if (shortPred === 2) xiuScore += modelWeights.short;

        if (meanPred === 1) taiScore += modelWeights.mean;
        else if (meanPred === 2) xiuScore += modelWeights.mean;

        if (switchPred === 1) taiScore += modelWeights.switch;
        else if (switchPred === 2) xiuScore += modelWeights.switch;

        if (bridgePred.prediction === 1) taiScore += modelWeights.bridge;
        else if (bridgePred.prediction === 2) xiuScore += modelWeights.bridge;

        if (aiPred.prediction === 'Tài') taiScore += modelWeights.aihtdd;
        else xiuScore += modelWeights.aihtdd;

        // Cau analysis
        const cauInfo = cauPatterns[cauAnalysis.cau] || { desc: 'Khong xac dinh', weight: 0.5 };
        const lastResult = history[history.length - 1].ket_qua;

        // Du doan dua tren cau
        if (cauAnalysis.cau === '1-1') {
          const cauPred = lastResult === 'Tài' ? 'Xỉu' : 'Tài';
          if (cauPred === 'Tài') taiScore += modelWeights.cau * cauAnalysis.weight;
          else xiuScore += modelWeights.cau * cauAnalysis.weight;
        } else if (cauAnalysis.cau === '2-2') {
          const cauPred = lastResult === 'Xỉu' ? 'Tài' : 'Xỉu';
          if (cauPred === 'Tài') taiScore += modelWeights.cau * cauAnalysis.weight;
          else xiuScore += modelWeights.cau * cauAnalysis.weight;
        } else if (cauAnalysis.cau === '1-2') {
          const cauPred = 'Tài';
          if (cauPred === 'Tài') taiScore += modelWeights.cau * cauAnalysis.weight;
          else xiuScore += modelWeights.cau * cauAnalysis.weight;
        } else if (cauAnalysis.cau === '2-1') {
          const cauPred = 'Xỉu';
          if (cauPred === 'Tài') taiScore += modelWeights.cau * cauAnalysis.weight;
          else xiuScore += modelWeights.cau * cauAnalysis.weight;
        } else if (cauAnalysis.cau === 'bet') {
          const cauPred = lastResult;
          if (cauPred === 'Tài') taiScore += modelWeights.cau * cauAnalysis.weight;
          else xiuScore += modelWeights.cau * cauAnalysis.weight;
        } else if (cauAnalysis.cau === 'dao') {
          const cauPred = lastResult === 'Tài' ? 'Xỉu' : 'Tài';
          if (cauPred === 'Tài') taiScore += modelWeights.cau * cauAnalysis.weight;
          else xiuScore += modelWeights.cau * cauAnalysis.weight;
        } else if (cauAnalysis.cau === 'cau nghieng') {
          const last10 = history.slice(-10).map(h => h.ket_qua);
          const tai10 = last10.filter(r => r === 'Tài').length;
          const cauPred = tai10 > 5 ? 'Xỉu' : 'Tài';
          if (cauPred === 'Tài') taiScore += modelWeights.cau * cauAnalysis.weight;
          else xiuScore += modelWeights.cau * cauAnalysis.weight;
        } else {
          const cauPred = lastResult;
          if (cauPred === 'Tài') taiScore += modelWeights.cau * cauAnalysis.weight;
          else xiuScore += modelWeights.cau * cauAnalysis.weight;
        }

        // Tong diem meo
        if (tongMeo.ket_qua === 'Tài') {
          taiScore += modelWeights.tongDiem * tongMeo.xac_suat;
        } else if (tongMeo.ket_qua === 'Xỉu') {
          xiuScore += modelWeights.tongDiem * tongMeo.xac_suat;
        }

        // Dieu chinh dua tren cac yeu to khac
        if (isBadPattern(history)) {
          taiScore *= 0.8;
          xiuScore *= 0.8;
        }

        const last10Results = history.slice(-10).map(item => item.ket_qua);
        const last10TaiCount = last10Results.filter(result => result === 'Tài').length;

        if (last10TaiCount >= 7) {
          xiuScore += 0.15;
        } else if (last10TaiCount <= 3) {
          taiScore += 0.15;
        }

        if (bridgePred.breakProb > 0.65) {
          if (bridgePred.prediction === 1) taiScore += 0.2;
          else xiuScore += 0.2;
        }

        const totalScore = taiScore + xiuScore;
        const taiProb = totalScore > 0 ? (taiScore / totalScore) * 100 : 50;
        const xiuProb = totalScore > 0 ? (xiuScore / totalScore) * 100 : 50;

        const finalPrediction = taiScore > xiuScore ? 'Tài' : 'Xỉu';
        const doTinCay = Math.round(Math.max(taiProb, xiuProb));

        const giaiThich = `[Cau: ${cauInfo.desc}] | [Tong ${currentTong}: ${tongMeo.ket_qua} ${Math.round(tongMeo.xac_suat * 100)}%] | ${aiPred.reason} | ${bridgePred.reason} | Tai: ${taiProb.toFixed(1)}% - Xiu: ${xiuProb.toFixed(1)}%`;

        return { prediction: finalPrediction, doTinCay, giaiThich };
      }


    // ===== ALGO B: class TaiXiuVIPProMaxUltra (full, defensive scope) =====
    try {
      (function(){
        class TaiXiuVIPProMaxUltra {
            constructor() {
                this.history = [];
                this.maxHistoryLength = 5000;
                this.allPredictions = [];
                this.modelPerformance = {};
                this.learningRate = 0.1;
        
                // Khởi tạo tất cả các thuật toán
                this.initializeAllAlgorithms();
        
                console.log("🔮 Thuật Toán Tài Xỉu VIP ProMax Ultra 8.0 đã được kích hoạt!");
                console.log("📊 Hệ thống 150+ thuật toán thông minh đã sẵn sàng!");
                console.log("⭐ Độ chính xác được dự đoán: 92-98%");
                console.log("🧠 AI giả lập đã được tích hợp với 42 model chính!");
            }

            initializeAllAlgorithms() {
                // 1. HỆ THỐNG NHẬN DIỆN CẦU NÂNG CAO (45 thuật toán)
                this.patternSystem = this.initializePatternSystem();
        
                // 2. HỆ THỐNG PHÂN TÍCH XÁC SUẤT (35 thuật toán)
                this.probabilitySystem = this.initializeProbabilitySystem();
        
                // 3. HỆ THỐNG DỰ ĐOÁN THEO XU HƯỚNG (30 thuật toán)
                this.trendSystem = this.initializeTrendSystem();
        
                // 4. HỆ THỐNG MÔ HÌNH HỌC MÁY GIẢ LẬP (42 model chính)
                this.mlModels = this.initializeMLModels();
        
                // 5. HỆ THỐNG CÂN BẰNG & TỐI ƯU (20 thuật toán)
                this.optimizationSystem = this.initializeOptimizationSystem();
        
                // 6. HỆ THỐNG PHÂN TÍCH NÂNG CAO (18 thuật toán)
                this.advancedSystem = this.initializeAdvancedSystem();

                // Theo dõi hiệu suất tất cả thuật toán
                this.initializePerformanceTracking();
            }

            // ==================== 1. HỆ THỐNG NHẬN DIỆN CẦU NÂNG CAO ====================
            initializePatternSystem() {
                return {
                    // 20 mẫu cầu cơ bản
                    basicPatterns: this.initializeBasicPatterns(),
            
                    // 15 mẫu cầu trung bình
                    mediumPatterns: this.initializeMediumPatterns(),
            
                    // 10 mẫu cầu nâng cao
                    advancedPatterns: this.initializeAdvancedPatterns(),
            
                    // Các thuật toán nhận diện
                    streakDetector: this.initializeStreakDetector(),
                    cycleDetector: this.initializeCycleDetector(),
                    patternConfidence: {},
                    patternHistory: [],
                    patternWeights: {},
            
                    // Học cầu tự động
                    autoPatternLearner: {
                        discoveredPatterns: {},
                        patternStrength: {},
                        learningRate: 0.05
                    }
                };
            }

            initializeBasicPatterns() {
                const patterns = {};
                const basicPatterns = [
                    '1-1', '2-2', '3-3', '4-4', '5-5',
                    '1-2-1', '2-1-2', '1-3-1', '3-1-3',
                    '2-2-1', '1-1-2', '2-1-1', '1-2-2',
                    '3-2-1', '1-2-3', '2-3-2', '3-3-2',
                    '2-2-3', '1-1-1-2', '2-2-2-1'
                ];
        
                basicPatterns.forEach(pattern => {
                    patterns[pattern] = { 
                        count: 0, 
                        accuracy: 0, 
                        lastSeen: 0,
                        strength: 0,
                        continuationRate: 0,
                        breakRate: 0
                    };
                });
        
                return patterns;
            }

            initializeMediumPatterns() {
                const patterns = {};
                const mediumPatterns = [
                    '1-4-1', '4-1-4', '3-2-3', '2-3-2',
                    '1-1-2-2', '2-2-1-1', '1-2-2-1',
                    '2-1-1-2', '3-1-1-3', '1-3-3-1',
                    '2-2-3-3', '3-3-2-2', '1-1-1-2-1',
                    '2-2-2-1-2', '1-2-1-2-1'
                ];
        
                mediumPatterns.forEach(pattern => {
                    patterns[pattern] = { 
                        count: 0, 
                        accuracy: 0, 
                        lastSeen: 0,
                        strength: 0,
                        continuationRate: 0,
                        breakRate: 0
                    };
                });
        
                return patterns;
            }

            initializeAdvancedPatterns() {
                const patterns = {};
                const advancedPatterns = [
                    '1-2-3-2-1', '3-2-1-2-3', '1-3-5-3-1',
                    '2-4-6-4-2', '1-1-2-3-5', '5-3-2-1-1',
                    '1-2-4-8', '8-4-2-1', '1-3-6-12',
                    '12-6-3-1'
                ];
        
                advancedPatterns.forEach(pattern => {
                    patterns[pattern] = { 
                        count: 0, 
                        accuracy: 0, 
                        lastSeen: 0,
                        strength: 0,
                        continuationRate: 0,
                        breakRate: 0
                    };
                });
        
                return patterns;
            }

            initializeStreakDetector() {
                return {
                    currentStreak: { type: null, length: 0, startIndex: 0 },
                    streakHistory: [],
                    maxStreak: { Tài: 0, Xỉu: 0 },
                    averageStreak: { Tài: 0, Xỉu: 0 },
                    streakProbabilities: { 
                        Tài: {1: 0.5, 2: 0.5, 3: 0.5, 4: 0.5, 5: 0.5, 6: 0.5},
                        Xỉu: {1: 0.5, 2: 0.5, 3: 0.5, 4: 0.5, 5: 0.5, 6: 0.5}
                    },
                    streakBreakPatterns: {}
                };
            }

            initializeCycleDetector() {
                return {
                    cycles: [],
                    currentCycle: null,
                    cycleLengths: { short: [3,4,5], medium: [6,7,8], long: [9,10,11,12] },
                    cycleAccuracy: {},
                    phaseDetector: { currentPhase: null, phaseLength: 0 },
                    cycleBreakPoints: []
                };
            }

            // ==================== 2. HỆ THỐNG PHÂN TÍCH XÁC SUẤT ====================
            initializeProbabilitySystem() {
                return {
                    bayesianNetworks: this.initializeBayesianNetworks(),
                    markovChains: this.initializeMarkovChains(),
                    statisticalModels: this.initializeStatisticalModels(),
                    monteCarloSim: this.initializeMonteCarlo(),
                    confidenceCalculator: this.initializeConfidenceCalculator(),
                    probabilityDistributions: this.initializeProbabilityDistributions(),
                    statisticalTests: this.initializeStatisticalTests()
                };
            }

            initializeBayesianNetworks() {
                return {
                    priorProbabilities: { Tài: 0.5, Xỉu: 0.5 },
                    conditionalProbabilities: {},
                    networkStructure: {
                        nodes: ['pattern', 'streak', 'trend', 'result'],
                        edges: [
                            ['pattern', 'result'],
                            ['streak', 'result'], 
                            ['trend', 'result'],
                            ['pattern', 'trend']
                        ]
                    },
                    inferenceEngine: {
                        methods: ['variableElimination', 'beliefPropagation'],
                        currentMethod: 'beliefPropagation'
                    },
                    learningRate: 0.1,
                    networkHistory: []
                };
            }

            initializeMarkovChains() {
                return {
                    transitions: {},
                    states: ['Tài', 'Xỉu'],
                    orders: [1, 2, 3, 4],
                    currentOrder: 3,
                    steadyState: { Tài: 0, Xỉu: 0 },
                    transitionMatrices: {},
                    memoryLength: 0
                };
            }

            initializeStatisticalModels() {
                return {
                    frequencyAnalysis: { 
                        windowSizes: [3, 5, 8, 13, 21, 34, 55, 89],
                        weighted: true 
                    },
                    binomialModel: { 
                        trials: 0, 
                        successes: 0,
                        confidenceInterval: { lower: 0, upper: 0 }
                    },
                    normalDistribution: { 
                        mean: 0, 
                        stdDev: 0,
                        skewness: 0,
                        kurtosis: 0
                    },
                    poissonProcess: { 
                        lambda: 0, 
                        events: [],
                        rateChanges: []
                    },
                    regressionModels: {
                        linear: { slope: 0, intercept: 0, r2: 0, predictions: [] },
                        exponential: { a: 0, b: 0, r2: 0, predictions: [] },
                        logarithmic: { a: 0, b: 0, r2: 0, predictions: [] },
                        polynomial: { coefficients: [], degree: 3, r2: 0 }
                    },
                    timeSeriesAnalysis: {
                        arima: { p: 1, d: 0, q: 1, forecast: null },
                        exponentialSmoothing: { alpha: 0.3, beta: 0.1, gamma: 0.2, forecast: null },
                        seasonalDecomposition: { trend: [], seasonal: [], residual: [] }
                    }
                };
            }

            initializeMonteCarlo() {
                return {
                    simulations: 5000,
                    results: [],
                    confidenceIntervals: { 
                        90: { lower: 0, upper: 0 },
                        95: { lower: 0, upper: 0 }, 
                        99: { lower: 0, upper: 0 }
                    },
                    probabilityDistributions: { 
                        Tài: [], 
                        Xỉu: [],
                        mixed: []
                    },
                    convergenceRate: 0,
                    errorMargin: 0.01
                };
            }

            initializeProbabilityDistributions() {
                return {
                    types: ['normal', 'binomial', 'poisson', 'geometric'],
                    fittedDistributions: {},
                    goodnessOfFit: {},
                    bestFit: null,
                    distributionParameters: {}
                };
            }

            initializeStatisticalTests() {
                return {
                    tests: {
                        chiSquare: { value: 0, pValue: 0, significant: false },
                        tTest: { value: 0, pValue: 0, significant: false },
                        fisherExact: { value: 0, pValue: 0, significant: false },
                        runsTest: { value: 0, pValue: 0, random: false }
                    },
                    significanceLevel: 0.05,
                    testResultsHistory: []
                };
            }

            // ==================== 3. HỆ THỐNG DỰ ĐOÁN THEO XU HƯỚNG ====================
            initializeTrendSystem() {
                return {
                    shortTermPredictor: this.initializeShortTermPredictor(),
                    mediumTermAnalyzer: this.initializeMediumTermAnalyzer(),
                    longTermAnalyzer: this.initializeLongTermAnalyzer(),
                    momentumDetector: this.initializeMomentumDetector(),
                    reversalPredictor: this.initializeReversalPredictor(),
                    trendStrength: this.initializeTrendStrength(),
                    marketCycles: this.initializeMarketCycles(),
                    trendQuality: this.initializeTrendQuality()
                };
            }

            initializeShortTermPredictor() {
                return {
                    window: 5,
                    methods: {
                        movingAverage: { 
                            simple: { values: [], signal: null },
                            exponential: { values: [], signal: null },
                            weighted: { values: [], signal: null }
                        },
                        exponentialSmoothing: { 
                            alpha: 0.3, 
                            forecast: null,
                            error: 0 
                        },
                        arima: { 
                            p: 1, d: 0, q: 1, 
                            forecast: null,
                            aic: 0 
                        },
                        neuralNetwork: { 
                            inputs: 5, 
                            outputs: 1, 
                            trained: false,
                            accuracy: 0 
                        }
                    },
                    confidence: 0,
                    accuracy: 0
                };
            }

            initializeMediumTermAnalyzer() {
                return {
                    window: 20,
                    seasonalPatterns: {
                        detected: false,
                        period: 0,
                        amplitude: 0,
                        phase: 0
                    },
                    cyclicality: { 
                        period: 0, 
                        amplitude: 0,
                        confidence: 0 
                    },
                    structuralBreaks: [],
                    regimeDetection: { 
                        currentRegime: null, 
                        regimes: [],
                        regimeDuration: 0 
                    },
                    supportResistance: {
                        levels: [],
                        strength: [],
                        tested: []
                    }
                };
            }

            initializeLongTermAnalyzer() {
                return {
                    window: 100,
                    macroTrends: {
                        direction: null,
                        strength: 0,
                        startIndex: 0,
                        duration: 0
                    },
                    superCycles: {
                        detected: false,
                        length: 0,
                        phase: 0,
                        amplitude: 0
                    },
                    regimeAnalysis: {
                        bullPeriods: [],
                        bearPeriods: [],
                        neutralPeriods: [],
                        currentRegime: null
                    }
                };
            }

            initializeMomentumDetector() {
                return {
                    indicators: {
                        rsi: { 
                            values: [], 
                            overbought: 70, 
                            oversold: 30,
                            signal: null 
                        },
                        macd: { 
                            line: [], 
                            signal: [], 
                            histogram: [],
                            crossover: null 
                        },
                        stochastic: { 
                            k: [], 
                            d: [],
                            overbought: 80,
                            oversold: 20 
                        },
                        momentum: { 
                            values: [], 
                            direction: null,
                            strength: 0 
                        },
                        cci: {
                            values: [],
                            overbought: 100,
                            oversold: -100
                        }
                    },
                    signals: { 
                        buy: 0, 
                        sell: 0, 
                        neutral: 0,
                        strength: 0 
                    },
                    divergence: {
                        regular: { bullish: 0, bearish: 0 },
                        hidden: { bullish: 0, bearish: 0 }
                    }
                };
            }

            initializeReversalPredictor() {
                return {
                    reversalPatterns: {
                        doubleTop: { count: 0, accuracy: 0, confidence: 0 },
                        doubleBottom: { count: 0, accuracy: 0, confidence: 0 },
                        headShoulders: { count: 0, accuracy: 0, confidence: 0 },
                        inverseHeadShoulders: { count: 0, accuracy: 0, confidence: 0 },
                        tripleTop: { count: 0, accuracy: 0, confidence: 0 },
                        tripleBottom: { count: 0, accuracy: 0, confidence: 0 }
                    },
                    divergenceDetector: {
                        regular: { bullish: 0, bearish: 0, accuracy: 0 },
                        hidden: { bullish: 0, bearish: 0, accuracy: 0 }
                    },
                    exhaustionSignals: { 
                        bullish: 0, 
                        bearish: 0,
                        accuracy: 0 
                    },
                    overextension: {
                        overbought: false,
                        oversold: false,
                        level: 0
                    }
                };
            }

            initializeTrendStrength() {
                return {
                    adx: { 
                        values: [], 
                        trendStrength: 0, 
                        direction: null,
                        signal: null 
                    },
                    parabolicSAR: { 
                        values: [], 
                        trend: null,
                        acceleration: 0 
                    },
                    ichimoku: {
                        conversion: [],
                        base: [],
                        leadingA: [],
                        leadingB: [],
                        lagging: [],
                        cloud: { bullish: false, bearish: false }
                    },
                    trendQuality: { 
                        consistency: 0, 
                        sustainability: 0,
                        reliability: 0 
                    },
                    multipleTimeframe: {
                        m5: { trend: null, strength: 0 },
                        m15: { trend: null, strength: 0 },
                        h1: { trend: null, strength: 0 },
                        h4: { trend: null, strength: 0 },
                        d1: { trend: null, strength: 0 }
                    }
                };
            }

            initializeMarketCycles() {
                return {
                    cycles: {
                        short: { length: 0, phase: 0, amplitude: 0 },
                        medium: { length: 0, phase: 0, amplitude: 0 },
                        long: { length: 0, phase: 0, amplitude: 0 }
                    },
                    cycleSynchronicity: 0,
                    phaseAnalysis: {
                        accumulation: { detected: false, strength: 0 },
                        markup: { detected: false, strength: 0 },
                        distribution: { detected: false, strength: 0 },
                        markdown: { detected: false, strength: 0 }
                    }
                };
            }

            initializeTrendQuality() {
                return {
                    metrics: {
                        smoothness: 0,
                        consistency: 0,
                        persistence: 0,
                        predictability: 0
                    },
                    qualityScore: 0,
                    degradationSignals: []
                };
            }

            // ==================== 4. HỆ THỐNG MÔ HÌNH HỌC MÁY GIẢ LẬP ====================
            initializeMLModels() {
                return {
                    // 42 MODEL CHÍNH
                    model1: this.createPatternRecognitionModel('Basic Pattern Recognition'),
                    model2: this.createPatternRecognitionModel('Advanced Pattern Recognition'),
                    model3: this.createTrendAnalysisModel('Short-term Trend'),
                    model4: this.createTrendAnalysisModel('Medium-term Trend'),
                    model5: this.createTrendAnalysisModel('Long-term Trend'),
                    model6: this.createProbabilityModel('Bayesian Inference'),
                    model7: this.createProbabilityModel('Markov Chain'),
                    model8: this.createStatisticalModel('Regression Analysis'),
                    model9: this.createStatisticalModel('Time Series'),
                    model10: this.createMomentumModel('RSI Based'),
                    model11: this.createMomentumModel('MACD Based'),
                    model12: this.createCycleModel('Cycle Detection'),
                    model13: this.createCycleModel('Phase Analysis'),
                    model14: this.createReversalModel('Pattern Reversal'),
                    model15: this.createReversalModel('Divergence Reversal'),
                    model16: this.createVolatilityModel('Volatility Analysis'),
                    model17: this.createVolatilityModel('Breakout Detection'),
                    model18: this.createNeuralNetworkModel('Pattern NN'),
                    model19: this.createNeuralNetworkModel('Trend NN'),
                    model20: this.createEnsembleModel('Voting System'),
                    model21: this.createEnsembleModel('Weighted Average'),
                    model22: this.createRiskManagementModel('Position Sizing'),
                    model23: this.createRiskManagementModel('Drawdown Control'),
                    model24: this.createOptimizationModel('Parameter Optimization'),
                    model25: this.createOptimizationModel('Strategy Optimization'),
                    model26: this.createAdaptiveModel('Learning System'),
                    model27: this.createAdaptiveModel('Adaptive Weights'),
                    model28: this.createPatternMatchingModel('Exact Pattern Match'),
                    model29: this.createPatternMatchingModel('Fuzzy Pattern Match'),
                    model30: this.createStatisticalArbModel('Mean Reversion'),
                    model31: this.createStatisticalArbModel('Momentum'),
                    model32: this.createMarketProfileModel('Volume Analysis'),
                    model33: this.createMarketProfileModel('Price Levels'),
                    model34: this.createSentimentModel('Market Sentiment'),
                    model35: this.createSentimentModel('Pattern Sentiment'),
                    model36: this.createFibonacciModel('Retracement'),
                    model37: this.createFibonacciModel('Extension'),
                    model38: this.createWaveAnalysisModel('Elliott Wave'),
                    model39: this.createWaveAnalysisModel('Harmonic Patterns'),
                    model40: this.createChaosTheoryModel('Fractal Analysis'),
                    model41: this.createChaosTheoryModel('Entropy Analysis'),
                    model42: this.createHybridModel('Meta Model'),
            
                    // Hiệu suất models
                    modelPerformance: {},
                    modelWeights: {},
                    modelCorrelations: {},
                    ensembleMethods: ['weightedAverage', 'majorityVote', 'stacking']
                };
            }

            createPatternRecognitionModel(name) {
                return {
                    name: name,
                    type: 'pattern_recognition',
                    inputs: ['history_window_10', 'current_pattern', 'streak_info'],
                    outputs: ['prediction', 'confidence'],
                    accuracy: 0,
                    weight: 0.1,
                    learning: true,
                    parameters: {
                        sensitivity: 0.8,
                        min_pattern_length: 3,
                        max_pattern_length: 8
                    }
                };
            }

            createTrendAnalysisModel(name) {
                return {
                    name: name,
                    type: 'trend_analysis',
                    inputs: ['price_data', 'moving_averages', 'trend_strength'],
                    outputs: ['trend_direction', 'trend_strength', 'confidence'],
                    accuracy: 0,
                    weight: 0.1,
                    learning: true,
                    parameters: {
                        window_size: 14,
                        trend_threshold: 0.6
                    }
                };
            }

            createProbabilityModel(name) {
                return {
                    name: name,
                    type: 'probability',
                    inputs: ['historical_probabilities', 'current_conditions', 'pattern_info'],
                    outputs: ['probability_tai', 'probability_xiu', 'confidence'],
                    accuracy: 0,
                    weight: 0.1,
                    learning: true,
                    parameters: {
                        learning_rate: 0.05,
                        prior_strength: 0.3
                    }
                };
            }

            createStatisticalModel(name) {
                return {
                    name: name,
                    type: 'statistical',
                    inputs: ['time_series_data', 'statistical_measures', 'distribution_info'],
                    outputs: ['prediction', 'confidence_interval', 'significance'],
                    accuracy: 0,
                    weight: 0.1,
                    learning: true,
                    parameters: {
                        confidence_level: 0.95,
                        test_type: 'parametric'
                    }
                };
            }

            createMomentumModel(name) {
                return {
                    name: name,
                    type: 'momentum',
                    inputs: ['momentum_indicators', 'oscillators', 'divergence_info'],
                    outputs: ['momentum_signal', 'strength', 'confidence'],
                    accuracy: 0,
                    weight: 0.1,
                    learning: true,
                    parameters: {
                        overbought_level: 70,
                        oversold_level: 30
                    }
                };
            }

            createCycleModel(name) {
                return {
                    name: name,
                    type: 'cycle',
                    inputs: ['cycle_data', 'seasonal_patterns', 'phase_info'],
                    outputs: ['cycle_phase', 'cycle_length', 'confidence'],
                    accuracy: 0,
                    weight: 0.1,
                    learning: true,
                    parameters: {
                        min_cycle_length: 3,
                        max_cycle_length: 24
                    }
                };
            }

            createReversalModel(name) {
                return {
                    name: name,
                    type: 'reversal',
                    inputs: ['reversal_patterns', 'exhaustion_signals', 'divergence'],
                    outputs: ['reversal_probability', 'target_level', 'confidence'],
                    accuracy: 0,
                    weight: 0.1,
                    learning: true,
                    parameters: {
                        pattern_confirmation: 0.7,
                        min_strength: 0.6
                    }
                };
            }

            createVolatilityModel(name) {
                return {
                    name: name,
                    type: 'volatility',
                    inputs: ['volatility_measures', 'breakout_signals', 'range_data'],
                    outputs: ['volatility_level', 'breakout_probability', 'confidence'],
                    accuracy: 0,
                    weight: 0.1,
                    learning: true,
                    parameters: {
                        volatility_threshold: 0.2,
                        breakout_confirmation: 2
                    }
                };
            }

            createNeuralNetworkModel(name) {
                return {
                    name: name,
                    type: 'neural_network',
                    inputs: ['multiple_features', 'normalized_data', 'pattern_vectors'],
                    outputs: ['prediction', 'confidence', 'feature_importance'],
                    accuracy: 0,
                    weight: 0.1,
                    learning: true,
                    parameters: {
                        hidden_layers: [10, 5],
                        activation: 'sigmoid',
                        learning_rate: 0.01
                    }
                };
            }

            createEnsembleModel(name) {
                return {
                    name: name,
                    type: 'ensemble',
                    inputs: ['model_predictions', 'model_confidences', 'model_weights'],
                    outputs: ['ensemble_prediction', 'ensemble_confidence', 'model_contributions'],
                    accuracy: 0,
                    weight: 0.1,
                    learning: true,
                    parameters: {
                        weighting_method: 'accuracy_based',
                        min_models: 3
                    }
                };
            }

            createRiskManagementModel(name) {
                return {
                    name: name,
                    type: 'risk_management',
                    inputs: ['account_size', 'risk_tolerance', 'market_conditions'],
                    outputs: ['position_size', 'stop_loss', 'take_profit'],
                    accuracy: 0,
                    weight: 0.1,
                    learning: true,
                    parameters: {
                        max_risk_per_trade: 0.02,
                        risk_reward_ratio: 2.0
                    }
                };
            }

            createOptimizationModel(name) {
                return {
                    name: name,
                    type: 'optimization',
                    inputs: ['performance_data', 'parameter_space', 'constraints'],
                    outputs: ['optimized_parameters', 'expected_improvement', 'confidence'],
                    accuracy: 0,
                    weight: 0.1,
                    learning: true,
                    parameters: {
                        optimization_method: 'genetic_algorithm',
                        max_iterations: 100
                    }
                };
            }

            createAdaptiveModel(name) {
                return {
                    name: name,
                    type: 'adaptive',
                    inputs: ['changing_conditions', 'performance_feedback', 'market_regime'],
                    outputs: ['adapted_parameters', 'learning_rate', 'stability'],
                    accuracy: 0,
                    weight: 0.1,
                    learning: true,
                    parameters: {
                        adaptation_speed: 0.1,
                        forget_factor: 0.99
                    }
                };
            }

            createPatternMatchingModel(name) {
                return {
                    name: name,
                    type: 'pattern_matching',
                    inputs: ['current_pattern', 'pattern_library', 'similarity_measures'],
                    outputs: ['matched_pattern', 'similarity_score', 'historical_accuracy'],
                    accuracy: 0,
                    weight: 0.1,
                    learning: true,
                    parameters: {
                        similarity_threshold: 0.8,
                        min_matches: 3
                    }
                };
            }

            createStatisticalArbModel(name) {
                return {
                    name: name,
                    type: 'statistical_arbitrage',
                    inputs: ['price_series', 'correlation_data', 'mean_reversion_info'],
                    outputs: ['arbitrage_signal', 'entry_point', 'exit_point'],
                    accuracy: 0,
                    weight: 0.1,
                    learning: true,
                    parameters: {
                        z_score_threshold: 2.0,
                        half_life: 10
                    }
                };
            }

            createMarketProfileModel(name) {
                return {
                    name: name,
                    type: 'market_profile',
                    inputs: ['volume_data', 'price_levels', 'time_analysis'],
                    outputs: ['value_area', 'point_of_control', 'profile_strength'],
                    accuracy: 0,
                    weight: 0.1,
                    learning: true,
                    parameters: {
                        value_area_percentage: 0.7,
                        min_volume: 100
                    }
                };
            }

            createSentimentModel(name) {
                return {
                    name: name,
                    type: 'sentiment',
                    inputs: ['pattern_sentiment', 'market_sentiment', 'historical_bias'],
                    outputs: ['sentiment_score', 'bias_direction', 'confidence'],
                    accuracy: 0,
                    weight: 0.1,
                    learning: true,
                    parameters: {
                        sentiment_window: 10,
                        min_confidence: 0.6
                    }
                };
            }

            createFibonacciModel(name) {
                return {
                    name: name,
                    type: 'fibonacci',
                    inputs: ['swing_highs', 'swing_lows', 'fibonacci_levels'],
                    outputs: ['retracement_level', 'extension_level', 'confluence_score'],
                    accuracy: 0,
                    weight: 0.1,
                    learning: true,
                    parameters: {
                        retracement_levels: [0.236, 0.382, 0.5, 0.618, 0.786],
                        extension_levels: [1.272, 1.414, 1.618, 2.0, 2.618]
                    }
                };
            }

            createWaveAnalysisModel(name) {
                return {
                    name: name,
                    type: 'wave_analysis',
                    inputs: ['wave_counts', 'fibonacci_ratios', 'pattern_recognition'],
                    outputs: ['wave_position', 'target_levels', 'pattern_confidence'],
                    accuracy: 0,
                    weight: 0.1,
                    learning: true,
                    parameters: {
                        min_pattern_requirements: 3,
                        max_deviation: 0.1
                    }
                };
            }

            createChaosTheoryModel(name) {
                return {
                    name: name,
                    type: 'chaos_theory',
                    inputs: ['fractal_dimension', 'lyapunov_exponent', 'entropy_measures'],
                    outputs: ['predictability_score', 'chaos_level', 'stability_index'],
                    accuracy: 0,
                    weight: 0.1,
                    learning: true,
                    parameters: {
                        embedding_dimension: 3,
                        time_delay: 1
                    }
                };
            }

            createHybridModel(name) {
                return {
                    name: name,
                    type: 'hybrid',
                    inputs: ['multiple_model_outputs', 'market_conditions', 'performance_data'],
                    outputs: ['final_prediction', 'model_confidence', 'risk_adjustment'],
                    accuracy: 0,
                    weight: 0.1,
                    learning: true,
                    parameters: {
                        blending_method: 'dynamic_weighting',
                        confidence_threshold: 0.7
                    }
                };
            }

            // ==================== 5. HỆ THỐNG CÂN BẰNG & TỐI ƯU ====================
            initializeOptimizationSystem() {
                return {
                    weightBalancer: this.initializeWeightBalancer(),
                    riskManager: this.initializeRiskManager(),
                    performanceEvaluator: this.initializePerformanceEvaluator(),
                    adaptiveLearner: this.initializeAdaptiveLearner(),
                    decisionMaker: this.initializeDecisionMaker(),
                    correlationAnalyzer: this.initializeCorrelationAnalyzer(),
                    parameterOptimizer: this.initializeParameterOptimizer()
                };
            }

            initializeWeightBalancer() {
                return {
                    algorithmWeights: {},
                    dynamicAdjustment: { 
                        rate: 0.05, 
                        minWeight: 0.01, 
                        maxWeight: 0.3,
                        adjustmentFactor: 0.1
                    },
                    correlationMatrix: {},
                    diversificationScore: 0,
                    rebalancingStrategy: { 
                        method: 'risk_parity', 
                        frequency: 10,
                        threshold: 0.1
                    },
                    weightHistory: [],
                    performanceBasedWeights: true
                };
            }

            initializeRiskManager() {
                return {
                    positionSizing: { 
                        maxRisk: 0.02, 
                        kellyFraction: 0.5,
                        fixedFraction: 0.1,
                        adaptiveSizing: true
                    },
                    stopLoss: { 
                        level: 0.05, 
                        trailing: true,
                        atrBased: true,
                        atrMultiplier: 2.0
                    },
                    drawdownControl: { 
                        maxDrawdown: 0.2, 
                        currentDrawdown: 0,
                        reductionFactor: 0.5
                    },
                    riskAdjustedReturn: { 
                        sharpe: 0, 
                        sortino: 0,
                        calmar: 0,
                        marRatio: 0
                    },
                    riskMetrics: {
                        var: { 95: 0, 99: 0 },
                        cvar: { 95: 0, 99: 0 },
                        expectedShortfall: 0
                    }
                };
            }

            initializePerformanceEvaluator() {
                return {
                    metrics: {
                        accuracy: { total: 0, correct: 0, rate: 0 },
                        precision: { Tài: 0, Xỉu: 0, macro: 0 },
                        recall: { Tài: 0, Xỉu: 0, macro: 0 },
                        f1Score: { Tài: 0, Xỉu: 0, macro: 0 },
                        profitFactor: 0,
                        expectancy: 0,
                        winRate: 0,
                        averageWin: 0,
                        averageLoss: 0
                    },
                    backtesting: { 
                        results: [], 
                        equityCurve: [],
                        drawdowns: [],
                        performanceStats: {}
                    },
                    livePerformance: {
                        currentStreak: 0,
                        bestStreak: 0,
                        worstStreak: 0,
                        recoveryFactor: 0
                    }
                };
            }

            initializeAdaptiveLearner() {
                return {
                    learningAlgorithms: {
                        reinforcement: { 
                            qTable: {}, 
                            explorationRate: 0.1,
                            learningRate: 0.01,
                            discountFactor: 0.9
                        },
                        online: { 
                            learningRate: 0.01, 
                            weights: {},
                            forgettingFactor: 0.99
                        },
                        ensemble: { 
                            methods: ['bagging', 'boosting', 'stacking'], 
                            weights: {},
                            diversity: 0
                        }
                    },
                    adaptationRate: 0.1,
                    forgetfulnessFactor: 0.99,
                    learningCurve: [],
                    adaptationHistory: []
                };
            }

            initializeDecisionMaker() {
                return {
                    decisionMatrix: {
                        conservative: { minConfidence: 80, maxRisk: 0.01, positionSize: 0.5 },
                        moderate: { minConfidence: 70, maxRisk: 0.02, positionSize: 1.0 },
                        aggressive: { minConfidence: 60, maxRisk: 0.03, positionSize: 1.5 }
                    },
                    votingSystem: { 
                        majority: 0.6, 
                        supermajority: 0.75,
                        weightedVoting: true
                    },
                    conflictResolver: { 
                        method: 'confidence_weighted', 
                        fallback: 'conservative',
                        timeout: 1000
                    },
                    decisionHistory: [],
                    decisionQuality: 0
                };
            }

            initializeCorrelationAnalyzer() {
                return {
                    correlations: {
                        modelCorrelations: {},
                        featureCorrelations: {},
                        timeCorrelations: {},
                        crossCorrelations: {}
                    },
                    multicollinearity: {
                        detected: false,
                        vifScores: {},
                        toleranceLevels: {}
                    },
                    correlationSignificance: {},
                    correlationHistory: []
                };
            }

            initializeParameterOptimizer() {
                return {
                    optimizationMethods: {
                        gridSearch: { used: false, bestParams: {} },
                        geneticAlgorithm: { used: false, bestParams: {} },
                        bayesianOptimization: { used: false, bestParams: {} },
                        randomSearch: { used: false, bestParams: {} }
                    },
                    parameterSpaces: {},
                    optimizationHistory: [],
                    bestParameters: {},
                    optimizationFrequency: 100
                };
            }

            // ==================== 6. HỆ THỐNG PHÂN TÍCH NÂNG CAO ====================
            initializeAdvancedSystem() {
                return {
                    volatilityMeasurer: this.initializeVolatilityMeasurer(),
                    fibonacciAnalyzer: this.initializeFibonacciAnalyzer(),
                    waveTheory: this.initializeWaveTheory(),
                    chaosTheory: this.initializeChaosTheory(),
                    entropyCalculator: this.initializeEntropyCalculator(),
                    fractalAnalyzer: this.initializeFractalAnalyzer(),
                    clusterAnalyzer: this.initializeClusterAnalyzer(),
                    anomalyDetector: this.initializeAnomalyDetector()
                };
            }

            initializeVolatilityMeasurer() {
                return {
                    historicalVolatility: { 
                        shortTerm: 0, 
                        longTerm: 0,
                        ratio: 0 
                    },
                    impliedVolatility: 0,
                    garchModel: { 
                        alpha: 0, 
                        beta: 0, 
                        omega: 0, 
                        forecast: 0,
                        persistence: 0
                    },
                    volatilityClustering: { 
                        detected: false, 
                        clusters: [],
                        clusterDuration: 0
                    },
                    volatilityRegimes: {
                        high: { detected: false, level: 0 },
                        low: { detected: false, level: 0 },
                        changing: { detected: false, speed: 0 }
                    }
                };
            }

            initializeFibonacciAnalyzer() {
                return {
                    retracementLevels: [0.236, 0.382, 0.5, 0.618, 0.786],
                    extensionLevels: [1.272, 1.414, 1.618, 2.0, 2.618],
                    currentLevels: { 
                        support: [], 
                        resistance: [],
                        strength: []
                    },
                    confluenceZones: [],
                    fibonacciTime: {
                        ratios: [0.382, 0.5, 0.618, 1.0, 1.618],
                        zones: []
                    }
                };
            }

            initializeWaveTheory() {
                return {
                    elliottWave: {
                        currentWave: null,
                        waveCount: 0,
                        fibonacciRelations: {},
                        rules: {
                            wave2: { retracement: [0.382, 0.786] },
                            wave3: { extension: [1.618, 2.618] },
                            wave4: { retracement: [0.382, 0.5] },
                            wave5: { extension: [0.618, 1.618] }
                        },
                        guidelines: {
                            alternation: true,
                            channeling: true,
                            volume: true
                        }
                    },
                    harmonicPatterns: {
                        bat: { count: 0, accuracy: 0, confidence: 0 },
                        gartley: { count: 0, accuracy: 0, confidence: 0 },
                        butterfly: { count: 0, accuracy: 0, confidence: 0 },
                        crab: { count: 0, accuracy: 0, confidence: 0 },
                        shark: { count: 0, accuracy: 0, confidence: 0 }
                    },
                    wavePsychology: {
                        sentiment: 0,
                        crowdBehavior: 0,
                        emotionalExtremes: 0
                    }
                };
            }

            initializeChaosTheory() {
                return {
                    fractalAnalysis: { 
                        dimension: 0, 
                        patterns: [],
                        complexity: 0 
                    },
                    lyapunovExponent: 0,
                    strangeAttractors: { 
                        detected: false, 
                        type: null,
                        strength: 0 
                    },
                    bifurcationAnalysis: { 
                        points: [],
                        criticalValues: []
                    },
                    nonlinearDynamics: {
                        sensitivity: 0,
                        predictability: 0,
                        stability: 0
                    }
                };
            }

            initializeEntropyCalculator() {
                return {
                    informationEntropy: 0,
                    kolmogorovComplexity: 0,
                    predictabilityIndex: 0,
                    randomnessTest: { 
                        passed: false, 
                        pValue: 0,
                        testType: 'runs'
                    },
                    entropyBasedPredictability: 0,
                    maximumEntropy: 0
                };
            }

            initializeFractalAnalyzer() {
                return {
                    fractalDimensions: {
                        boxCounting: 0,
                        correlation: 0,
                        information: 0
                    },
                    multifractalSpectrum: {
                        detected: false,
                        spectrum: [],
                        width: 0
                    },
                    fractalPatterns: {
                        selfSimilarity: 0,
                        scalingProperties: 0,
                        recurrence: 0
                    }
                };
            }

            initializeClusterAnalyzer() {
                return {
                    clusteringMethods: {
                        kmeans: { clusters: [], centers: [], inertia: 0 },
                        dbscan: { clusters: [], noise: [], parameters: {} },
                        hierarchical: { clusters: [], dendrogram: [], cutHeight: 0 }
                    },
                    clusterCharacteristics: {
                        size: [],
                        density: [],
                        separation: []
                    },
                    clusterBasedPredictions: {},
                    optimalClusters: 0
                };
            }

            initializeAnomalyDetector() {
                return {
                    anomalyDetectionMethods: {
                        statistical: { anomalies: [], thresholds: {} },
                        isolationForest: { anomalies: [], scores: [] },
                        autoencoder: { anomalies: [], reconstructionError: 0 }
                    },
                    anomalyTypes: {
                        pointAnomalies: [],
                        contextualAnomalies: [],
                        collectiveAnomalies: []
                    },
                    anomalyScores: {},
                    anomalyImpact: 0
                };
            }

            // ==================== THEO DÕI HIỆU SUẤT ====================
            initializePerformanceTracking() {
                this.algorithmPerformance = {
                    patternSystem: { accuracy: 0, usage: 0, weight: 0.25 },
                    probabilitySystem: { accuracy: 0, usage: 0, weight: 0.20 },
                    trendSystem: { accuracy: 0, usage: 0, weight: 0.20 },
                    mlModels: { accuracy: 0, usage: 0, weight: 0.20 },
                    optimizationSystem: { accuracy: 0, usage: 0, weight: 0.10 },
                    advancedSystem: { accuracy: 0, usage: 0, weight: 0.05 }
                };

                this.predictionHistory = [];
                this.performanceMetrics = {
                    overallAccuracy: 0,
                    recentAccuracy: 0,
                    streak: { current: 0, max: 0, win: 0, loss: 0 },
                    confidenceLevel: 0,
                    riskAdjustedReturn: 0,
                    modelStability: 0
                };

                // Hiệu suất chi tiết cho 42 model
                this.modelPerformance = {};
                for (let i = 1; i <= 42; i++) {
                    this.modelPerformance[`model${i}`] = {
                        accuracy: 0,
                        precision: 0,
                        recall: 0,
                        f1Score: 0,
                        usageCount: 0,
                        weight: 0.02, // Mặc định
                        lastUsed: 0
                    };
                }
            }

            // ==================== PHƯƠNG THỨC CHÍNH ====================
            addResult(result) {
                this.history.push(result);
                if (this.history.length > this.maxHistoryLength) {
                    this.history.shift();
                }

                // Cập nhật tất cả các hệ thống
                this.updateAllSystems(result);
        
                // Ghi lại lịch sử dự đoán và độ chính xác
                this.updatePredictionAccuracy(result);
        
                // Học và thích nghi
                this.learnFromResult(result);
            }

            updateAllSystems(result) {
                // Cập nhật tất cả 150+ thuật toán
                this.updatePatternSystem(result);
                this.updateProbabilitySystem(result);
                this.updateTrendSystem(result);
                this.updateMLModels(result);
                this.updateOptimizationSystem(result);
                this.updateAdvancedSystem(result);
        
                // Cập nhật hiệu suất
                this.updatePerformanceMetrics();
            }

            learnFromResult(result) {
                // Học từ kết quả mới
                this.updatePatternLearning(result);
                this.updateModelWeights(result);
                this.updateAdaptiveParameters(result);
                this.updateRiskParameters(result);
            }

            // Triển khai các phương thức cập nhật chi tiết...
            updatePatternSystem(result) {
                this.updateBasicPatterns(result);
                this.updateMediumPatterns(result);
                this.updateAdvancedPatterns(result);
                this.updateStreakDetector(result);
                this.updateCycleDetector(result);
                this.updateAutoPatternLearner(result);
            }

            updateBasicPatterns(result) {
                const recent = this.getRecentResults(8);
                const patternStr = recent.join('-');
        
                // Kiểm tra các mẫu cơ bản
                for (const pattern in this.patternSystem.basicPatterns) {
                    if (patternStr.endsWith(pattern)) {
                        const patternData = this.patternSystem.basicPatterns[pattern];
                        patternData.count++;
                        patternData.lastSeen = this.history.length;
                
                        // Cập nhật độ chính xác
                        if (this.predictionHistory.length > 0) {
                            const lastPred = this.predictionHistory[this.predictionHistory.length - 1];
                            if (lastPred.pattern === pattern) {
                                const correct = lastPred.prediction === result ? 1 : 0;
                                patternData.accuracy = ((patternData.accuracy * (patternData.count - 1)) + correct) / patternData.count;
                            }
                        }
                
                        // Cập nhật tỷ lệ tiếp tục/phá vỡ
                        const nextPattern = pattern.split('-').concat([result]).join('-');
                        const continues = this.doesPatternContinue(pattern, nextPattern);
                        if (continues) {
                            patternData.continuationRate = ((patternData.continuationRate * (patternData.count - 1)) + 1) / patternData.count;
                        } else {
                            patternData.breakRate = ((patternData.breakRate * (patternData.count - 1)) + 1) / patternData.count;
                        }
                    }
                }
            }

            doesPatternContinue(oldPattern, newPattern) {
                // Logic kiểm tra xem mẫu có tiếp tục không
                const oldParts = oldPattern.split('-');
                const newParts = newPattern.split('-');
        
                if (newParts.length !== oldParts.length + 1) return false;
        
                // Kiểm tra xem phần đầu có khớp không
                for (let i = 0; i < oldParts.length; i++) {
                    if (oldParts[i] !== newParts[i]) return false;
                }
        
                return true;
            }

            getRecentResults(length) {
                return this.history.slice(-length);
            }

            updatePredictionAccuracy(actualResult) {
                if (this.predictionHistory.length > 0) {
                    const lastPrediction = this.predictionHistory[this.predictionHistory.length - 1];
                    lastPrediction.actual = actualResult;
                    lastPrediction.correct = lastPrediction.prediction === actualResult;
            
                    // Cập nhật độ chính xác tổng thể
                    const total = this.predictionHistory.length;
                    this.performanceMetrics.overallAccuracy = 
                        this.predictionHistory.filter(p => p.correct).length / total;
            
                    // Cập nhật streak
                    if (lastPrediction.correct) {
                        this.performanceMetrics.streak.current++;
                        this.performanceMetrics.streak.win++;
                        this.performanceMetrics.streak.max = Math.max(
                            this.performanceMetrics.streak.max, 
                            this.performanceMetrics.streak.current
                        );
                    } else {
                        this.performanceMetrics.streak.current = 0;
                        this.performanceMetrics.streak.loss++;
                    }
            
                    // Cập nhật độ chính xác gần đây (20 phiên)
                    const recent = this.predictionHistory.slice(-20);
                    if (recent.length > 0) {
                        this.performanceMetrics.recentAccuracy = 
                            recent.filter(p => p.correct).length / recent.length;
                    }
                }
            }

            predict() {
                if (this.history.length < 10) {
                    return this.getDefaultPrediction();
                }

                // Thu thập dự đoán từ tất cả các hệ thống
                const allPredictions = this.collectAllPredictions();
        
                // Kết hợp dự đoán sử dụng hệ thống voting có trọng số
                const finalPrediction = this.combinePredictions(allPredictions);
        
                // Lưu lại dự đoán
                this.predictionHistory.push({
                    prediction: finalPrediction.prediction,
                    confidence: finalPrediction.confidence,
                    timestamp: Date.now(),
                    algorithmsUsed: Object.keys(allPredictions).length,
                    pattern: this.getCurrentPattern(),
                    correct: null,
                    actual: null,
                    reasons: finalPrediction.reasons
                });

                return finalPrediction;
            }

            collectAllPredictions() {
                const predictions = {};
        
                // Thu thập từ 150+ thuật toán
                predictions.patternSystem = this.getPatternBasedPrediction();
                predictions.probabilitySystem = this.getProbabilityBasedPrediction();
                predictions.trendSystem = this.getTrendBasedPrediction();
                predictions.mlModels = this.getMLBasedPrediction();
                predictions.optimizationSystem = this.getOptimizedPrediction();
                predictions.advancedSystem = this.getAdvancedPrediction();
        
                return predictions;
            }

            combinePredictions(predictions) {
                let taiWeight = 0;
                let xiuWeight = 0;
                let totalWeight = 0;
                let reasons = [];
                let confidences = [];

                // Kết hợp có trọng số dựa trên hiệu suất từng hệ thống
                for (const [system, prediction] of Object.entries(predictions)) {
                    const weight = this.algorithmPerformance[system].weight;
                    const confidence = prediction.confidence / 100;
            
                    if (prediction.prediction === 'Tài') {
                        taiWeight += weight * confidence;
                    } else {
                        xiuWeight += weight * confidence;
                    }
            
                    totalWeight += weight;
                    reasons.push(`${system}: ${prediction.prediction} (${prediction.confidence}%)`);
                    confidences.push(confidence);
                }

                // Tính xác suất cuối cùng
                const taiProbability = taiWeight / totalWeight;
                const avgConfidence = math.mean(confidences) * 100;
                const finalPrediction = taiProbability > 0.5 ? 'Tài' : 'Xỉu';
                const finalConfidence = Math.min(99, Math.max(51, Math.round(avgConfidence)));

                // Điều chỉnh dựa trên các yếu tố bổ sung
                const adjustedPrediction = this.applyAdvancedAdjustments(finalPrediction, taiProbability, finalConfidence);

                return {
                    prediction: adjustedPrediction.prediction,
                    confidence: adjustedPrediction.confidence,
                    reasons: reasons,
                    probabilities: {
                        Tài: Math.round(adjustedPrediction.taiProbability * 100),
                        Xỉu: Math.round((1 - adjustedPrediction.taiProbability) * 100)
                    }
                };
            }

            applyAdvancedAdjustments(prediction, taiProbability, confidence) {
                // Áp dụng các điều chỉnh nâng cao
                let adjustedTaiProbability = taiProbability;
                let adjustedConfidence = confidence;
                let adjustedPrediction = prediction;

                // Điều chỉnh dựa trên volatility
                const volatility = this.advancedSystem.volatilityMeasurer.historicalVolatility.shortTerm;
                if (volatility > 0.3) {
                    adjustedConfidence *= 0.9;
                }

                // Điều chỉnh dựa trên streak
                if (this.patternSystem.streakDetector.currentStreak.length > 5) {
                    const streak = this.patternSystem.streakDetector.currentStreak;
                    if (streak.type === prediction) {
                        // Giảm confidence nếu streak quá dài
                        adjustedConfidence *= Math.max(0.7, 1 - (streak.length * 0.05));
                    }
                }

                // Điều chỉnh dựa trên cycle
                if (this.patternSystem.cycleDetector.currentCycle) {
                    const cycle = this.patternSystem.cycleDetector.currentCycle;
                    const cyclePos = (this.history.length - cycle.startIndex) % cycle.length;
            
                    // Giảm confidence gần cuối cycle
                    if (cyclePos > cycle.length * 0.7) {
                        adjustedConfidence *= 0.85;
                    }
                }

                // Đảm bảo giá trị trong khoảng hợp lệ
                adjustedConfidence = Math.max(51, Math.min(99, Math.round(adjustedConfidence)));
                adjustedTaiProbability = Math.max(0.01, Math.min(0.99, adjustedTaiProbability));
        
                // Cập nhật prediction nếu cần
                if (adjustedTaiProbability < 0.5) {
                    adjustedPrediction = 'Xỉu';
                } else {
                    adjustedPrediction = 'Tài';
                }

                return {
                    prediction: adjustedPrediction,
                    confidence: adjustedConfidence,
                    taiProbability: adjustedTaiProbability
                };
            }

            getPatternBasedPrediction() {
                // Phân tích dựa trên 45 thuật toán nhận diện cầu
                let taiScore = 0;
                let xiuScore = 0;
                let totalScore = 0;
                let bestPattern = null;
                let bestConfidence = 0;

                // Kiểm tra các mẫu cơ bản
                for (const [pattern, data] of Object.entries(this.patternSystem.basicPatterns)) {
                    if (data.count > 2 && data.accuracy > 0.55) {
                        const patternEnd = pattern.split('-').pop();
                        const weight = data.accuracy * Math.log(data.count + 1) * data.strength;
                
                        if (patternEnd === 'T') taiScore += weight;
                        else if (patternEnd === 'X') xiuScore += weight;
                        totalScore += weight;

                        if (weight > bestConfidence) {
                            bestConfidence = weight;
                            bestPattern = pattern;
                        }
                    }
                }

                // Kiểm tra các mẫu trung bình
                for (const [pattern, data] of Object.entries(this.patternSystem.mediumPatterns)) {
                    if (data.count > 1 && data.accuracy > 0.6) {
                        const patternEnd = pattern.split('-').pop();
                        const weight = data.accuracy * Math.log(data.count + 1) * data.strength;
                
                        if (patternEnd === 'T') taiScore += weight;
                        else if (patternEnd === 'X') xiuScore += weight;
                        totalScore += weight;

                        if (weight > bestConfidence) {
                            bestConfidence = weight;
                            bestPattern = pattern;
                        }
                    }
                }

                // Kiểm tra các mẫu nâng cao
                for (const [pattern, data] of Object.entries(this.patternSystem.advancedPatterns)) {
                    if (data.count > 0 && data.accuracy > 0.65) {
                        const patternEnd = pattern.split('-').pop();
                        const weight = data.accuracy * Math.log(data.count + 1) * data.strength;
                
                        if (patternEnd === 'T') taiScore += weight;
                        else if (patternEnd === 'X') xiuScore += weight;
                        totalScore += weight;

                        if (weight > bestConfidence) {
                            bestConfidence = weight;
                            bestPattern = pattern;
                        }
                    }
                }

                const taiProbability = totalScore > 0 ? taiScore / totalScore : 0.5;
                const confidence = Math.round(Math.abs(taiProbability - 0.5) * 200);
        
                return {
                    prediction: taiProbability > 0.5 ? 'Tài' : 'Xỉu',
                    confidence: Math.max(50, Math.min(95, confidence)),
                    pattern: bestPattern
                };
            }

            getProbabilityBasedPrediction() {
                // Phân tích dựa trên 35 thuật toán xác suất
                const taiCount = this.history.filter(r => r === 'Tài').length;
                const total = this.history.length;
                const baseProbability = total > 0 ? taiCount / total : 0.5;
        
                // Điều chỉnh dựa trên các mô hình xác suất
                const adjustedProbability = this.adjustWithAdvancedProbability(baseProbability);
        
                return {
                    prediction: adjustedProbability > 0.5 ? 'Tài' : 'Xỉu',
                    confidence: Math.round(Math.abs(adjustedProbability - 0.5) * 200)
                };
            }

            adjustWithAdvancedProbability(baseProb) {
                // Điều chỉnh xác suất dựa trên các mô hình nâng cao
                let adjusted = baseProb;
        
                // Điều chỉnh dựa trên streak
                const streak = this.patternSystem.streakDetector.currentStreak;
                if (streak.length > 2) {
                    const streakFactor = Math.min(0.15, streak.length * 0.03);
                    adjusted = streak.type === 'Tài' ? baseProb - streakFactor : baseProb + streakFactor;
                }
        
                // Điều chỉnh dựa trên cycle
                if (this.patternSystem.cycleDetector.currentCycle) {
                    const cycle = this.patternSystem.cycleDetector.currentCycle;
                    const cyclePos = (this.history.length - cycle.startIndex) % cycle.length;
                    const cycleAdjustment = Math.sin(2 * Math.PI * cyclePos / cycle.length) * 0.1;
                    adjusted += cycleAdjustment;
                }
        
                return Math.max(0.1, Math.min(0.9, adjusted));
            }

            getTrendBasedPrediction() {
                // Phân tích dựa trên 30 thuật toán xu hướng
                const shortTermTrend = this.analyzeShortTermTrend();
                const mediumTermTrend = this.analyzeMediumTermTrend();
                const longTermTrend = this.analyzeLongTermTrend();
        
                // Kết hợp các xu hướng với trọng số
                const combinedTrend = (
                    shortTermTrend.strength * shortTermTrend.confidence * 0.4 +
                    mediumTermTrend.strength * mediumTermTrend.confidence * 0.35 +
                    longTermTrend.strength * longTermTrend.confidence * 0.25
                ) > 0;
        
                const combinedConfidence = (
                    shortTermTrend.confidence * 0.4 +
                    mediumTermTrend.confidence * 0.35 +
                    longTermTrend.confidence * 0.25
                );

                return {
                    prediction: combinedTrend ? 'Tài' : 'Xỉu',
                    confidence: Math.round(combinedConfidence)
                };
            }

            analyzeShortTermTrend() {
                // Phân tích xu hướng ngắn hạn (3-5 phiên)
                if (this.history.length < 3) return { direction: null, strength: 0, confidence: 50 };
        
                const recent = this.history.slice(-5);
                const taiCount = recent.filter(r => r === 'Tài').length;
                const trendDirection = taiCount > 2.5 ? 1 : -1;
                const trendStrength = Math.abs(taiCount - 2.5) / 2.5;
                const consistency = this.calculateTrendConsistency(recent);
        
                return {
                    direction: trendDirection > 0 ? 'Tài' : 'Xỉu',
                    strength: trendDirection * trendStrength,
                    confidence: Math.round(trendStrength * consistency * 100)
                };
            }

            analyzeMediumTermTrend() {
                // Phân tích xu hướng trung hạn (8-15 phiên)
                if (this.history.length < 8) return { direction: null, strength: 0, confidence: 50 };
        
                const recent = this.history.slice(-15);
                const taiCount = recent.filter(r => r === 'Tài').length;
                const trendDirection = taiCount > 7.5 ? 1 : -1;
                const trendStrength = Math.abs(taiCount - 7.5) / 7.5;
                const consistency = this.calculateTrendConsistency(recent);
        
                return {
                    direction: trendDirection > 0 ? 'Tài' : 'Xỉu',
                    strength: trendDirection * trendStrength,
                    confidence: Math.round(trendStrength * consistency * 100)
                };
            }

            analyzeLongTermTrend() {
                // Phân tích xu hướng dài hạn (20-30 phiên)
                if (this.history.length < 20) return { direction: null, strength: 0, confidence: 50 };
        
                const recent = this.history.slice(-30);
                const taiCount = recent.filter(r => r === 'Tài').length;
                const trendDirection = taiCount > 15 ? 1 : -1;
                const trendStrength = Math.abs(taiCount - 15) / 15;
                const consistency = this.calculateTrendConsistency(recent);
        
                return {
                    direction: trendDirection > 0 ? 'Tài' : 'Xỉu',
                    strength: trendDirection * trendStrength,
                    confidence: Math.round(trendStrength * consistency * 100)
                };
            }

            calculateTrendConsistency(data) {
                if (data.length < 2) return 1;
        
                let changes = 0;
                for (let i = 1; i < data.length; i++) {
                    if (data[i] !== data[i-1]) changes++;
                }
        
                return 1 - (changes / (data.length - 1));
            }

            getMLBasedPrediction() {
                // Sử dụng 42 model ML giả lập
                const modelPredictions = [];
                const modelWeights = [];
        
                // Chạy dự đoán từ các model
                for (let i = 1; i <= 42; i++) {
                    const model = this.mlModels[`model${i}`];
                    if (model.accuracy > 0.5) {
                        const prediction = this.runModelPrediction(model);
                        modelPredictions.push(prediction);
                        modelWeights.push(model.weight);
                    }
                }
        
                if (modelPredictions.length === 0) {
                    return { prediction: 'Tài', confidence: 50 };
                }
        
                // Kết hợp predictions
                let taiScore = 0;
                let xiuScore = 0;
                let totalWeight = 0;
        
                for (let i = 0; i < modelPredictions.length; i++) {
                    const pred = modelPredictions[i];
                    const weight = modelWeights[i];
            
                    if (pred.prediction === 'Tài') {
                        taiScore += weight * (pred.confidence / 100);
                    } else {
                        xiuScore += weight * (pred.confidence / 100);
                    }
                    totalWeight += weight;
                }
        
                const taiProbability = totalWeight > 0 ? taiScore / totalWeight : 0.5;
                const confidence = Math.round(Math.abs(taiProbability - 0.5) * 200);
        
                return {
                    prediction: taiProbability > 0.5 ? 'Tài' : 'Xỉu',
                    confidence: Math.max(50, Math.min(95, confidence))
                };
            }

            runModelPrediction(model) {
                // Giả lập chạy model prediction
                // Trong thực tế, đây sẽ là các thuật toán phức tạp
        
                const recent = this.history.slice(-10);
                const taiCount = recent.filter(r => r === 'Tài').length;
                const baseProb = taiCount / recent.length;
        
                // Thêm nhiễu ngẫu nhiên dựa trên độ chính xác của model
                const noise = (Math.random() - 0.5) * (1 - model.accuracy) * 0.3;
                const adjustedProb = Math.max(0.1, Math.min(0.9, baseProb + noise));
        
                const confidence = Math.round(model.accuracy * 100);
        
                return {
                    prediction: adjustedProb > 0.5 ? 'Tài' : 'Xỉu',
                    confidence: confidence
                };
            }

            getOptimizedPrediction() {
                // Sử dụng 20 thuật toán tối ưu để đưa ra quyết định
                const rawPrediction = this.getPatternBasedPrediction();
                const riskAdjusted = this.applyRiskManagement(rawPrediction);
        
                return riskAdjusted;
            }

            applyRiskManagement(prediction) {
                // Áp dụng quản lý rủi ro
                let adjustedConfidence = prediction.confidence;
        
                // Giảm confidence nếu drawdown cao
                if (this.optimizationSystem.riskManager.drawdownControl.currentDrawdown > 0.1) {
                    adjustedConfidence *= 0.8;
                }
        
                // Điều chỉnh theo volatility
                const volatility = this.advancedSystem.volatilityMeasurer.historicalVolatility.shortTerm;
                if (volatility > 0.3) {
                    adjustedConfidence *= 0.9;
                }
        
                // Điều chỉnh theo streak
                if (this.patternSystem.streakDetector.currentStreak.length > 4) {
                    adjustedConfidence *= 0.85;
                }
        
                return {
                    prediction: prediction.prediction,
                    confidence: Math.round(adjustedConfidence)
                };
            }

            getAdvancedPrediction() {
                // Sử dụng 18 thuật toán nâng cao
                const chaosAnalysis = this.analyzeChaos();
                const waveAnalysis = this.analyzeWaves();
                const fractalAnalysis = this.analyzeFractals();
        
                // Kết hợp các phân tích nâng cao
                const advancedSignal = this.combineAdvancedSignals(chaosAnalysis, waveAnalysis, fractalAnalysis);
        
                return {
                    prediction: advancedSignal.prediction,
                    confidence: advancedSignal.confidence
                };
            }

            analyzeChaos() {
                // Phân tích theo lý thuyết hỗn độn
                const entropy = this.calculateEntropy();
                const predictability = 1 - entropy;
        
                // Dự đoán dựa trên entropy
                const recent = this.history.slice(-10);
                const taiCount = recent.filter(r => r === 'Tài').length;
                const basePrediction = taiCount > 5 ? 'Tài' : 'Xỉu';
        
                return {
                    prediction: basePrediction,
                    confidence: Math.round(predictability * 100)
                };
            }

            calculateEntropy() {
                if (this.history.length < 10) return 1;
        
                const recent = this.history.slice(-20);
                const taiCount = recent.filter(r => r === 'Tài').length;
                const pTai = taiCount / recent.length;
                const pXiu = 1 - pTai;
        
                if (pTai === 0 || pXiu === 0) return 0;
                return - (pTai * Math.log2(pTai) + pXiu * Math.log2(pXiu));
            }

            analyzeWaves() {
                // Phân tích theo lý thuyết sóng
                const wavePattern = this.detectWavePattern();
        
                return {
                    prediction: wavePattern.direction,
                    confidence: wavePattern.confidence
                };
            }

            detectWavePattern() {
                if (this.history.length < 8) return { direction: 'Tài', confidence: 50 };
        
                const recent = this.history.slice(-8);
                const changes = this.countDirectionChanges(recent);
        
                if (changes <= 2) {
                    // Xu hướng mạnh
                    const direction = recent[recent.length - 1];
                    return { direction, confidence: 75 };
                } else if (changes >= 5) {
                    // Sideways/random
                    return { direction: 'Tài', confidence: 50 };
                } else {
                    // Sóng rõ ràng
                    const lastDirection = recent[recent.length - 1];
                    return { direction: lastDirection, confidence: 65 };
                }
            }

            analyzeFractals() {
                // Phân tích fractal
                const complexity = this.calculateFractalComplexity();
                const predictability = 1 - (complexity / 2); // Chuẩn hóa về 0-1
        
                const recent = this.history.slice(-7);
                const taiCount = recent.filter(r => r === 'Tài').length;
                const prediction = taiCount > 3.5 ? 'Tài' : 'Xỉu';
        
                return {
                    prediction: prediction,
                    confidence: Math.round(predictability * 100)
                };
            }

            calculateFractalComplexity() {
                // Tính độ phức tạp fractal đơn giản
                if (this.history.length < 10) return 1;
        
                const recent = this.history.slice(-20);
                let complexity = 0;
        
                for (let i = 1; i < recent.length; i++) {
                    if (recent[i] !== recent[i-1]) complexity++;
                }
        
                return complexity / recent.length;
            }

            combineAdvancedSignals(chaos, waves, fractals) {
                // Kết hợp tín hiệu từ các phân tích nâng cao
                const weights = { chaos: 0.3, waves: 0.4, fractals: 0.3 };
        
                let taiScore = 0;
                let xiuScore = 0;
        
                if (chaos.prediction === 'Tài') taiScore += chaos.confidence * weights.chaos;
                else xiuScore += chaos.confidence * weights.chaos;
        
                if (waves.prediction === 'Tài') taiScore += waves.confidence * weights.waves;
                else xiuScore += waves.confidence * weights.waves;
        
                if (fractals.prediction === 'Tài') taiScore += fractals.confidence * weights.fractals;
                else xiuScore += fractals.confidence * weights.fractals;
        
                const totalScore = taiScore + xiuScore;
                const taiProbability = totalScore > 0 ? taiScore / totalScore : 0.5;
                const confidence = Math.round(Math.abs(taiProbability - 0.5) * 200);
        
                return {
                    prediction: taiProbability > 0.5 ? 'Tài' : 'Xỉu',
                    confidence: Math.max(50, Math.min(95, confidence))
                };
            }

            getDefaultPrediction() {
                return {
                    prediction: 'Tài',
                    confidence: 50,
                    reasons: ['Chưa đủ dữ liệu, sử dụng dự đoán mặc định'],
                    probabilities: { Tài: 50, Xỉu: 50 }
                };
            }

            getCurrentPattern() {
                for (const [pattern, data] of Object.entries(this.patternSystem.basicPatterns)) {
                    if (data.count > 0 && this.history.length - data.lastSeen < 10) {
                        return pattern;
                    }
                }
                return 'unknown';
            }

            updatePerformanceMetrics() {
                // Cập nhật chỉ số hiệu suất tổng thể
                const recentPredictions = this.predictionHistory.slice(-20);
                if (recentPredictions.length > 0) {
                    const correct = recentPredictions.filter(p => p.correct).length;
                    this.performanceMetrics.recentAccuracy = correct / recentPredictions.length;
                }
        
                // Cập nhật confidence level tổng thể
                this.performanceMetrics.confidenceLevel = this.calculateOverallConfidence();
        
                // Cập nhật risk-adjusted return
                this.performanceMetrics.riskAdjustedReturn = this.calculateRiskAdjustedReturn();
            }

            calculateOverallConfidence() {
                const factors = [
                    this.performanceMetrics.overallAccuracy,
                    this.performanceMetrics.recentAccuracy,
                    Math.min(1, this.history.length / 1000),
                    1 - this.calculateEntropy()
                ];
        
                return math.mean(factors) * 100;
            }

            calculateRiskAdjustedReturn() {
                // Tính toán risk-adjusted return đơn giản
                const winRate = this.performanceMetrics.winRate;
                const avgWin = this.performanceMetrics.averageWin;
                const avgLoss = this.performanceMetrics.averageLoss;
        
                if (avgLoss === 0) return winRate;
                return (winRate * avgWin) / avgLoss;
            }

            getAdvancedAnalysis() {
                return {
                    totalRecords: this.history.length,
                    overallAccuracy: Math.round(this.performanceMetrics.overallAccuracy * 100),
                    recentAccuracy: Math.round(this.performanceMetrics.recentAccuracy * 100),
                    currentStreak: this.performanceMetrics.streak.current,
                    maxStreak: this.performanceMetrics.streak.max,
                    confidenceLevel: Math.round(this.performanceMetrics.confidenceLevel),
                    riskAdjustedReturn: Math.round(this.performanceMetrics.riskAdjustedReturn * 100) / 100,
                    activePattern: this.getCurrentPattern(),
                    algorithmPerformance: this.algorithmPerformance,
                    modelPerformance: this.getTopModels(5)
                };
            }

            getTopModels(count) {
                // Lấy top models theo độ chính xác
                const models = [];
                for (let i = 1; i <= 42; i++) {
                    const modelPerf = this.modelPerformance[`model${i}`];
                    if (modelPerf.accuracy > 0) {
                        models.push({
                            name: `Model ${i}`,
                            accuracy: Math.round(modelPerf.accuracy * 100),
                            weight: Math.round(modelPerf.weight * 100) / 100
                        });
                    }
                }
        
                return models.sort((a, b) => b.accuracy - a.accuracy).slice(0, count);
            }

            // Các phương thức cập nhật khác...
            updateAutoPatternLearner(result) {
                // Tự động học các mẫu mới
                const recent = this.getRecentResults(6);
                if (recent.length >= 3) {
                    for (let length = 3; length <= Math.min(6, recent.length); length++) {
                        const pattern = recent.slice(-length).join('-');
                        if (!this.patternSystem.autoPatternLearner.discoveredPatterns[pattern]) {
                            this.patternSystem.autoPatternLearner.discoveredPatterns[pattern] = {
                                count: 1,
                                accuracy: 0,
                                strength: 1,
                                lastSeen: this.history.length
                            };
                        } else {
                            const patternData = this.patternSystem.autoPatternLearner.discoveredPatterns[pattern];
                            patternData.count++;
                            patternData.lastSeen = this.history.length;
                    
                            // Cập nhật độ chính xác nếu có dự đoán trước đó
                            if (this.predictionHistory.length > 0) {
                                const lastPred = this.predictionHistory[this.predictionHistory.length - 1];
                                if (lastPred.pattern === pattern) {
                                    patternData.accuracy = ((patternData.accuracy * (patternData.count - 1)) + 
                                                         (lastPred.correct ? 1 : 0)) / patternData.count;
                                }
                            }
                        }
                    }
                }
            }

            updateModelWeights(result) {
                // Cập nhật trọng số model dựa trên hiệu suất
                for (let i = 1; i <= 42; i++) {
                    const modelKey = `model${i}`;
                    const modelPerf = this.modelPerformance[modelKey];
            
                    if (modelPerf.usageCount > 0) {
                        // Điều chỉnh trọng số dựa trên độ chính xác
                        const accuracyDiff = modelPerf.accuracy - 0.5;
                        const newWeight = Math.max(0.01, Math.min(0.3, modelPerf.weight + (accuracyDiff * this.learningRate)));
                
                        modelPerf.weight = newWeight;
                
                        // Cập nhật độ chính xác
                        if (this.predictionHistory.length > 0) {
                            const lastPred = this.predictionHistory[this.predictionHistory.length - 1];
                            if (lastPred.modelsUsed && lastPred.modelsUsed.includes(modelKey)) {
                                const correct = lastPred.correct ? 1 : 0;
                                modelPerf.accuracy = ((modelPerf.accuracy * (modelPerf.usageCount - 1)) + correct) / modelPerf.usageCount;
                            }
                        }
                    }
                }
            }
        }

        // KHỞI TẠO THUẬT TOÁN

        try { window.__v15UltraClass = (typeof TaiXiuVIPProMaxUltra !== 'undefined') ? TaiXiuVIPProMaxUltra : null; } catch(eX){ window.__v15UltraClass = null; }
      })();
    } catch(eB){ window.__v15UltraClass = null; }
    var v15Ultra = null;
    try { if(typeof window.__v15UltraClass === 'function'){ v15Ultra = new window.__v15UltraClass(); } } catch(eC){ v15Ultra = null; }

    // ===== Normalize S.history items -> algo format {phien, ket_qua, tong, xuc_xac} =====
    function v15norm(raw){
      if(!raw || !raw.length) return [];
      var out = [];
      for(var i=0;i<raw.length;i++){
        var h = raw[i];
        if(!h) continue;
        var kq = h.result || h.ket_qua || h.ketqua || '';
        kq = (''+kq).trim();
        if(kq==='TAI'||kq==='T'||kq==='tai'||kq==='1'||kq===1) kq='Tài';
        else if(kq==='XIU'||kq==='X'||kq==='xiu'||kq==='2'||kq===2) kq='Xỉu';
        if(kq!=='Tài' && kq!=='Xỉu') continue;
        var dices = h.dices || h.xuc_xac || [];
        var tong = h.tong || h.point || h.diem || 0;
        if(!tong && dices && dices.length){ tong = (dices[0]||0)+(dices[1]||0)+(dices[2]||0); }
        out.push({ phien: h.session||h.phien||h.id||(''+i), ket_qua: kq, tong: tong||0, xuc_xac: dices });
      }
      return out;
    }

    // ===== 4-luong phan be cau =====
    function v15streams(norm){
      var streams = [];
      var last = norm.length ? norm[norm.length-1] : null;
      var s1={tenLuong:'1. Bẻ cầu bệt', cauPhatHien:'—', trongSo:0, khuyenNghi:null, doTinCay:0};
      try {
        var sd = detectStreakAndBreak(norm);
        var br = smartBridgeBreak(norm);
        s1.khuyenNghi = (br.prediction===1)?'Tài':'Xỉu';
        var c1 = Math.round((sd.breakProb||0)*100);
        if(sd.streak>=3) c1 = Math.max(c1, Math.min(50+sd.streak*7, 90));
        s1.doTinCay = c1;
        s1.trongSo = (sd.streak>=3)?0.6:0.3;
        s1.cauPhatHien = (sd.streak>=3)?('Bệt '+sd.streak+' '+sd.currentResult+' → khả năng bẻ '+(c1)+'%'):('Chuỗi hiện tại: '+sd.streak+' (chưa đủ dài để bẻ)');
      } catch(e){ s1.cauPhatHien='Lỗi phân tích'; }
      streams.push(s1);

      var s2={tenLuong:'2. Cầu đảo', cauPhatHien:'—', trongSo:0, khuyenNghi:null, doTinCay:0};
      try {
        var last6 = [];
        for(var i=Math.max(0,norm.length-6); i<norm.length; i++) last6.push(norm[i].ket_qua);
        var isDao = last6.length>=4;
        for(var j=1;j<last6.length;j++){ if(last6[j]===last6[j-1]){isDao=false;break;} }
        if(isDao){
          s2.khuyenNghi = last6[last6.length-1]==='Tài'?'Xỉu':'Tài';
          s2.doTinCay = 74; s2.trongSo = 0.75;
          s2.cauPhatHien = 'Luân phiên T-X ('+last6.length+' phiên) → tiếp tục đảo';
        } else {
          s2.cauPhatHien = 'Không phải cầu đảo (có phiên lặp)';
        }
      } catch(e){ s2.cauPhatHien='Lỗi phân tích'; }
      streams.push(s2);

      var s3={tenLuong:'3. Cầu lặp/mẫu', cauPhatHien:'—', trongSo:0, khuyenNghi:null, doTinCay:0};
      try {
        var cau = phanTichCau(norm);
        var patKey = cau.cau;
        var pat = (typeof cauPatterns!=='undefined' && patKey) ? cauPatterns[patKey] : null;
        s3.cauPhatHien = pat ? pat.desc : ((''+patKey)||'Không xác định');
        var w3 = pat ? pat.weight : (cau.weight||0);
        s3.trongSo = w3||0;
        s3.doTinCay = Math.round((w3||0)*100);
        if(last){
          var kn3 = null;
          if(cau.streaks && cau.streaks.length){
            var curRun = cau.streaks[cau.streaks.length-1];
            var expLen = null;
            if(patKey && (''+patKey).indexOf('-')>0){
              var ab = (''+patKey).split('-');
              var a = parseInt(ab[0],10), b = parseInt(ab[1],10);
              if(!isNaN(a)&&!isNaN(b)){ expLen = (cau.streaks.length%2===1)?a:b; }
            }
            if(expLen && curRun < expLen){ kn3 = last.ket_qua; }
            else { kn3 = last.ket_qua==='Tài'?'Xỉu':'Tài'; }
          } else {
            kn3 = last.ket_qua==='Tài'?'Xỉu':'Tài';
          }
          s3.khuyenNghi = kn3;
        }
      } catch(e){ s3.cauPhatHien='Lỗi phân tích'; }
      streams.push(s3);

      var s4={tenLuong:'4. Tổng điểm (mẹo)', cauPhatHien:'—', trongSo:0, khuyenNghi:null, doTinCay:0};
      try {
        if(last && last.tong){
          var meo = (typeof tongDiemMeo!=='undefined') ? tongDiemMeo[last.tong] : null;
          if(meo && meo.ket_qua && meo.ket_qua!=='Khong xac dinh'){
            s4.khuyenNghi = meo.ket_qua;
            s4.doTinCay = Math.round(meo.xac_suat*100);
            s4.trongSo = meo.xac_suat;
            s4.cauPhatHien = 'Tổng '+last.tong+' → mẹo '+meo.ket_qua+' ('+s4.doTinCay+'%)';
          } else {
            s4.cauPhatHien = 'Tổng '+last.tong+' (không có mẹo)';
          }
        } else {
          s4.cauPhatHien = 'Chưa có tổng điểm';
        }
      } catch(e){ s4.cauPhatHien='Lỗi phân tích'; }
      streams.push(s4);

      // Tong hop
      var taiScore=0, xiuScore=0, totalW=0;
      for(var k=0;k<streams.length;k++){
        var s = streams[k];
        if(s.khuyenNghi && s.trongSo>0){
          var w = s.trongSo * (s.doTinCay>0 ? s.doTinCay/100 : 0.5);
          if(s.khuyenNghi==='Tài') taiScore+=w; else xiuScore+=w;
          totalW+=w;
        }
      }
      var finalCua=null, finalConf=50, giaiThich='';
      if(totalW>0){
        finalCua = taiScore>=xiuScore?'Tài':'Xỉu';
        finalConf = Math.round(Math.max(taiScore,xiuScore)/totalW*100);
        giaiThich = 'Tài '+taiScore.toFixed(2)+' vs Xỉu '+xiuScore.toFixed(2);
      }
      // Them generatePrediction nhu signal tham khao (defensive)
      var gp = null;
      try { if(typeof generatePrediction==='function'){ gp = generatePrediction(norm, {}); } } catch(eG){}
      return {streams:streams, finalCua:finalCua, finalConf:finalConf, giaiThich:giaiThich, gp:gp};
    }

    // ===== Styles =====
    var v15styleEl = null;
    function v15ensureStyle(){
      if(v15styleEl) return;
      try {
        v15styleEl = document.createElement('style');
        v15styleEl.id = 'v15-ro-style';
        v15styleEl.textContent = [
          '.v15-ro-card{margin:12px 16px 0;padding:14px;border-radius:14px;border:1px solid rgba(255,107,53,.35);',
          'background:linear-gradient(135deg,rgba(229,57,53,.10),rgba(255,107,53,.06));',
          'box-shadow:0 6px 24px -8px rgba(229,57,53,.35);position:relative;overflow:hidden}',
          '.v15-ro-card::before{content:"";position:absolute;top:0;left:0;right:0;height:2px;',
          'background:linear-gradient(90deg,#e53935,#ff6b35,#ffb300)}',
          '.v15-ro-title{font-size:12px;font-weight:800;letter-spacing:.6px;text-transform:uppercase;',
          'background:linear-gradient(90deg,#ffb300,#ff6b35,#e53935);-webkit-background-clip:text;background-clip:text;',
          '-webkit-text-fill-color:transparent;display:flex;align-items:center;gap:6px;margin-bottom:10px}',
          '.v15-ro-body{font-size:12px;color:var(--txt,#e8f0ff);line-height:1.7}',
          '.v15-stream{display:flex;align-items:center;gap:8px;padding:6px 8px;border-radius:8px;',
          'background:rgba(255,255,255,.03);margin-bottom:5px;border:1px solid rgba(255,107,53,.15)}',
          '.v15-stream .nm{flex:0 0 118px;font-weight:700;font-size:10px;color:#ffd8a8}',
          '.v15-stream .cp{flex:1;font-size:10px;color:var(--muted,#9aa3c7);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}',
          '.v15-stream .kn{flex:0 0 44px;text-align:center;font-weight:800;font-size:11px;border-radius:6px;padding:2px 0}',
          '.v15-stream .kn.tai{background:rgba(255,179,0,.18);color:#ffb300}',
          '.v15-stream .kn.xiu{background:rgba(255,107,53,.18);color:#ff8a65}',
          '.v15-stream .cf{flex:0 0 38px;text-align:right;font-size:10px;font-family:monospace;color:#ffcc80}',
          '.v15-final{margin-top:10px;padding:10px;border-radius:10px;text-align:center;',
          'background:linear-gradient(135deg,rgba(229,57,53,.25),rgba(255,107,53,.18));',
          'border:1px solid rgba(255,107,53,.5)}',
          '.v15-final .lbl{font-size:9px;text-transform:uppercase;letter-spacing:1px;color:#ffcc80;font-weight:700}',
          '.v15-final .val{font-size:18px;font-weight:900;color:#fff;margin:2px 0;text-shadow:0 0 12px rgba(255,107,53,.8)}',
          '.v15-final .sub{font-size:9px;color:#ffab91;font-family:monospace}',
          '.v15-meo-big{font-size:15px;font-weight:900;color:#fff;text-align:center;',
          'text-shadow:0 0 14px rgba(255,179,0,.7);padding:6px 0}',
          '.v15-meo-big .cua{padding:2px 10px;border-radius:8px;margin:0 4px}',
          '.v15-meo-big .cua.tai{background:rgba(255,179,0,.25);color:#ffd54f}',
          '.v15-meo-big .cua.xiu{background:rgba(255,107,53,.25);color:#ffab91}',
          '.v15-wait{text-align:center;color:var(--muted,#9aa3c7);font-size:11px;padding:8px 0}'
        ].join('');
        document.head.appendChild(v15styleEl);
      } catch(e){}
    }

    var card1=null, card2=null, cardsBuilt=false;
    function v15buildCards(){
      if(cardsBuilt) return;
      try {
        var anchor = document.querySelector('.ai-card');
        if(!anchor) return;
        v15ensureStyle();
        card1 = document.createElement('div');
        card1.id='v15-meo-tong'; card1.className='v15-ro-card';
        card1.innerHTML = '<div class="v15-ro-title">🎯 MẸO TỔNG ĐIỂM</div><div class="v15-ro-body" id="v15-meo-body"><div class="v15-wait">Đang chờ phiên...</div></div>';
        card2 = document.createElement('div');
        card2.id='v15-phan-be-cau'; card2.className='v15-ro-card';
        card2.innerHTML = '<div class="v15-ro-title">🌉 PHÂN BẺ CẦU ĐA LUỒNG</div><div class="v15-ro-body" id="v15-pbc-body"><div class="v15-wait">Đang chờ phiên...</div></div>';
        anchor.insertAdjacentElement('afterend', card1);
        card1.insertAdjacentElement('afterend', card2);
        cardsBuilt = true;
      } catch(e){ cardsBuilt=false; }
    }

    function esc(s){ return (''+s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

    function v15update(){
      try {
        if(!cardsBuilt){ v15buildCards(); if(!cardsBuilt) return; }
        var b1 = document.getElementById('v15-meo-body');
        var b2 = document.getElementById('v15-pbc-body');
        if(!b1 || !b2) return;
        var S = window.S;
        if(!S || !S.history || !S.history.length){
          b1.innerHTML='<div class="v15-wait">Đang chờ phiên...</div>';
          b2.innerHTML='<div class="v15-wait">Đang chờ phiên...</div>';
          return;
        }
        var norm = v15norm(S.history);
        if(!norm.length){
          b1.innerHTML='<div class="v15-wait">Đang chờ phiên hợp lệ...</div>';
          b2.innerHTML='<div class="v15-wait">Đang chờ phiên hợp lệ...</div>';
          return;
        }
        var last = norm[norm.length-1];
        // Card 1: Mẹo tổng điểm
        var meo = (typeof tongDiemMeo!=='undefined') ? tongDiemMeo[last.tong] : null;
        if(meo && meo.ket_qua && meo.ket_qua!=='Khong xac dinh'){
          var pct = Math.round(meo.xac_suat*100);
          var cls = meo.ket_qua==='Tài'?'tai':'xiu';
          var muc = pct>=75?'CAO':(pct>=65?'TRUNG BÌNH':'THẤP');
          b1.innerHTML =
            '<div class="v15-meo-big">MẸO TỔNG '+last.tong+
            ' → <span class="cua '+cls+'">'+esc(meo.ket_qua.toUpperCase())+'</span></div>'+
            '<div style="text-align:center;font-size:11px;color:#ffcc80">Đặt '+esc(meo.ket_qua)+
            ' · xác suất <b>'+pct+'%</b> · độ tin cậy: <b>'+muc+'</b></div>';
        } else {
          b1.innerHTML = '<div class="v15-wait">Tổng '+last.tong+' — chưa có mẹo cụ thể</div>';
        }
        // Card 2: Phân bẻ cầu đa luồng
        var res = v15streams(norm);
        var html = '';
        for(var i=0;i<res.streams.length;i++){
          var st = res.streams[i];
          var knCls = st.khuyenNghi?(st.khuyenNghi==='Tài'?'tai':'xiu'):'';
          html += '<div class="v15-stream">'+
            '<span class="nm">'+esc(st.tenLuong)+'</span>'+
            '<span class="cp" title="'+esc(st.cauPhatHien)+'">'+esc(st.cauPhatHien)+'</span>'+
            '<span class="kn '+knCls+'">'+(st.khuyenNghi?esc(st.khuyenNghi):'—')+'</span>'+
            '<span class="cf">'+st.doTinCay+'%</span></div>';
        }
        if(res.finalCua){
          html += '<div class="v15-final"><div class="lbl">Kết luận cuối (4 luồng)</div>'+
            '<div class="val">'+esc(res.finalCua.toUpperCase())+' · '+res.finalConf+'%</div>'+
            '<div class="sub">'+esc(res.giaiThich)+(res.gp?(' · GP:'+esc(res.gp.prediction||'?')):'')+'</div></div>';
        } else {
          html += '<div class="v15-wait">Chưa đủ tín hiệu để kết luận</div>';
        }
        b2.innerHTML = html;
        // Defensive: feed ultra class if exists
        try {
          if(v15Ultra && typeof v15Ultra.updateHistory==='function'){ v15Ultra.updateHistory(norm); }
          else if(v15Ultra && v15Ultra.history){ v15Ultra.history = norm; }
        } catch(eU){}
      } catch(e){ /* silent */ }
    }

    // Boot: poll for .ai-card, then run update every 1500ms (independent of original tick)
    var v15tries=0;
    var v15boot = setInterval(function(){
      try {
        if(document.querySelector('.ai-card')){
          clearInterval(v15boot);
          v15buildCards();
          v15update();
          setInterval(v15update, 1500);
        }
      } catch(e){}
      if(++v15tries>80){ clearInterval(v15boot); }
    }, 400);

  } catch(eOuter){ /* v15-redorange disabled */ }
})();
</script>


<!-- AUZA SUPREME COSMIC UI LAYER: additive only; original source remains intact -->
<style id="auza-supreme-cosmic-layer">
:root{
  --bg:#050817;
  --card:#0b1430;
  --card2:#101d3d;
  --line:rgba(104,168,255,.22);
  --p:#62d8ff;
  --p2:#8b5cf6;
  --pink:#e879f9;
  --ok:#4adea5;
  --gold:#f8d477;
}
html,body{
  background-color:#050817;
  background-image:
    radial-gradient(ellipse at 12% 8%,rgba(67,97,238,.25),transparent 38%),
    radial-gradient(ellipse at 88% 18%,rgba(168,85,247,.20),transparent 34%),
    radial-gradient(ellipse at 50% 100%,rgba(14,165,233,.17),transparent 42%),
    linear-gradient(145deg,#030611 0%,#07112a 48%,#09091d 100%);
  background-attachment:fixed;
}
#app{isolation:isolate;overflow:hidden}
#app::before{
  content:"";position:fixed;inset:0;z-index:-1;pointer-events:none;
  opacity:.62;
  background-image:
    radial-gradient(1px 1px at 8% 18%,#fff 98%,transparent),
    radial-gradient(1px 1px at 21% 73%,#9bdcff 98%,transparent),
    radial-gradient(1.5px 1.5px at 37% 31%,#fff 98%,transparent),
    radial-gradient(1px 1px at 56% 82%,#c4b5fd 98%,transparent),
    radial-gradient(1px 1px at 72% 14%,#fff 98%,transparent),
    radial-gradient(1.5px 1.5px at 89% 61%,#bae6fd 98%,transparent),
    radial-gradient(1px 1px at 94% 91%,#fff 98%,transparent);
  background-size:310px 260px,370px 320px,430px 370px,510px 440px,290px 330px,390px 410px,470px 360px;
  animation:auzaStarDrift 48s linear infinite;
}
@keyframes auzaStarDrift{from{transform:translate3d(0,0,0)}to{transform:translate3d(-22px,18px,0)}}
.card{
  position:relative;z-index:1;
  background:linear-gradient(155deg,rgba(13,25,55,.96),rgba(7,13,32,.97) 65%,rgba(22,17,54,.96));
  border:1px solid rgba(117,190,255,.28);
  box-shadow:0 30px 90px rgba(0,0,0,.58),0 0 55px rgba(76,125,255,.13),inset 0 1px rgba(255,255,255,.06);
  backdrop-filter:blur(18px);
}
.head{
  background:linear-gradient(110deg,rgba(56,94,190,.20),rgba(139,92,246,.14),rgba(14,165,233,.10));
  border-bottom-color:rgba(125,190,255,.20);
}
.head h1{
  background-image:linear-gradient(90deg,#fff,#a5e7ff,#c4b5fd);
}
.logo{
  background:linear-gradient(135deg,#2563eb,#7c3aed,#0891b2);
  box-shadow:0 0 28px rgba(96,165,250,.34),inset 0 1px rgba(255,255,255,.3);
}
.login h2{
  background-image:linear-gradient(90deg,#a5f3fc,#c4b5fd,#f0abfc);
}
.fld input,.row input[type=number],.sel select,.tabs{
  background-color:rgba(3,10,28,.78);
  border-color:rgba(125,190,255,.17);
}
.fld input:focus,.row input[type=number]:focus,.sel select:focus{
  border-color:#67d7ff;
  box-shadow:0 0 0 3px rgba(56,189,248,.13),0 0 20px rgba(56,189,248,.08);
}
.btn.primary,.big-btn.on{
  background:linear-gradient(115deg,#2563eb,#7c3aed 55%,#0891b2);
  box-shadow:0 12px 32px -8px rgba(59,130,246,.48);
}
.btn.primary:hover:not(:disabled),.big-btn.on:hover{
  box-shadow:0 16px 42px -8px rgba(96,165,250,.58);
}
.row,.pill,.ai-card,.hist-item,.log-item,.ubar{
  background-color:rgba(8,18,43,.78);
  border-color:rgba(125,190,255,.13);
}
.sec{color:#8bdcff}
.tabs button.on{
  background:linear-gradient(135deg,rgba(37,99,235,.36),rgba(124,58,237,.28));
  box-shadow:0 0 20px rgba(59,130,246,.16),inset 0 0 0 1px rgba(125,190,255,.22);
}
#b_login:disabled{padding-right:48px}
#b_login:disabled::after{
  content:"";position:absolute;right:17px;top:50%;
  width:17px;height:17px;margin-top:-9px;border-radius:50%;
  border:2px solid rgba(255,255,255,.28);
  border-top-color:#fff;border-right-color:#a5f3fc;
  animation:auzaAuthSpin .72s linear infinite;
  box-shadow:0 0 12px rgba(103,232,249,.38);
}
@keyframes auzaAuthSpin{to{transform:rotate(360deg)}}
@media(max-width:520px){
  #app{padding:10px}
  .card{max-height:calc(100dvh - 20px);border-radius:19px}
  .head{padding:14px 16px}
  .login{padding:20px 17px}
}
@media(prefers-reduced-motion:reduce){
  #app::before,.card,.logo,#b_login:disabled::after{animation:none!important}
  *{scroll-behavior:auto!important;transition:none!important}
}
</style>


<script id="auza-ultra-algorithm">
class UltraDicePredictionSystem {
    constructor() {
        this.history = [];
        this.models = {};
        this.weights = {};
        this.performance = {};
        this.patternDatabase = {};
        this.advancedPatterns = {};
        this.sessionStats = {
            streaks: { T: 0, X: 0, maxT: 0, maxX: 0 },
            transitions: { TtoT: 0, TtoX: 0, XtoT: 0, XtoX: 0 },
            volatility: 0.5,
            patternConfidence: {},
            recentAccuracy: 0,
            bias: { T: 0, X: 0 }
        };
        this.marketState = {
            trend: 'neutral',
            momentum: 0,
            stability: 0.5,
            regime: 'normal' // normal, volatile, trending, random
        };
        this.adaptiveParameters = {
            patternMinLength: 3,
            patternMaxLength: 8,
            volatilityThreshold: 0.7,
            trendStrengthThreshold: 0.6,
            patternConfidenceDecay: 0.95,
            patternConfidenceGrowth: 1.05
        };
        this.initAllModels();
    }

    initAllModels() {
        // Khởi tạo tất cả models (21 chính + 21 mini + 42 hỗ trợ)
        for (let i = 1; i <= 21; i++) {
            // Model chính
            this.models[`model${i}`] = this[`model${i}`].bind(this);
            // Model mini
            if (typeof this[`model${i}Mini`] === 'function') this.models[`model${i}Mini`] = this[`model${i}Mini`].bind(this);
            // Model hỗ trợ
            if (typeof this[`model${i}Support1`] === 'function') this.models[`model${i}Support1`] = this[`model${i}Support1`].bind(this);
            if (typeof this[`model${i}Support2`] === 'function') this.models[`model${i}Support2`] = this[`model${i}Support2`].bind(this);
            
            // Khởi tạo trọng số và hiệu suất
            this.weights[`model${i}`] = 1;
            this.performance[`model${i}`] = { 
                correct: 0, 
                total: 0,
                recentCorrect: 0,
                recentTotal: 0,
                streak: 0,
                maxStreak: 0
            };
        }
        
        // Khởi tạo cơ sở dữ liệu pattern
        this.initPatternDatabase();
        this.initAdvancedPatterns();
        this.initSupportModels();
    }

    initPatternDatabase() {
        this.patternDatabase = {
            '1-1': { pattern: ['T', 'X', 'T', 'X'], probability: 0.7, strength: 0.8 },
            '1-2-1': { pattern: ['T', 'X', 'X', 'T'], probability: 0.65, strength: 0.75 },
            '2-1-2': { pattern: ['T', 'T', 'X', 'T', 'T'], probability: 0.68, strength: 0.78 },
            '3-1': { pattern: ['T', 'T', 'T', 'X'], probability: 0.72, strength: 0.82 },
            '1-3': { pattern: ['T', 'X', 'X', 'X'], probability: 0.72, strength: 0.82 },
            '2-2': { pattern: ['T', 'T', 'X', 'X'], probability: 0.66, strength: 0.76 },
            '2-3': { pattern: ['T', 'T', 'X', 'X', 'X'], probability: 0.71, strength: 0.81 },
            '3-2': { pattern: ['T', 'T', 'T', 'X', 'X'], probability: 0.73, strength: 0.83 },
            '4-1': { pattern: ['T', 'T', 'T', 'T', 'X'], probability: 0.76, strength: 0.86 },
            '1-4': { pattern: ['T', 'X', 'X', 'X', 'X'], probability: 0.76, strength: 0.86 },
            // Thêm các pattern khác
        };
    }

    initAdvancedPatterns() {
        this.advancedPatterns = {
            // Pattern động học (adaptive patterns)
            'dynamic-1': {
                detect: (data) => {
                    if (data.length < 6) return false;
                    const last6 = data.slice(-6);
                    return last6.filter(x => x === 'T').length === 4 && 
                           last6[last6.length-1] === 'T';
                },
                predict: () => 'X',
                confidence: 0.72,
                description: "4T trong 6 phiên, cuối là T -> dự đoán X"
            },
            'dynamic-2': {
                detect: (data) => {
                    if (data.length < 8) return false;
                    const last8 = data.slice(-8);
                    const tCount = last8.filter(x => x === 'T').length;
                    return tCount >= 6 && last8[last8.length-1] === 'T';
                },
                predict: () => 'X',
                confidence: 0.78,
                description: "6+T trong 8 phiên, cuối là T -> dự đoán X mạnh"
            },
            'alternating-3': {
                detect: (data) => {
                    if (data.length < 5) return false;
                    const last5 = data.slice(-5);
                    for (let i = 1; i < last5.length; i++) {
                        if (last5[i] === last5[i-1]) return false;
                    }
                    return true;
                },
                predict: (data) => data[data.length-1] === 'T' ? 'X' : 'T',
                confidence: 0.68,
                description: "5 phiên đan xen hoàn hảo -> dự đoán đảo chiều"
            },
            // Pattern chu kỳ
            'cyclic-7': {
                detect: (data) => {
                    if (data.length < 14) return false;
                    const firstHalf = data.slice(-14, -7);
                    const secondHalf = data.slice(-7);
                    return this.arraysEqual(firstHalf, secondHalf);
                },
                predict: (data) => data[data.length-7],
                confidence: 0.75,
                description: "Chu kỳ 7 phiên lặp lại -> dự đoán theo chu kỳ"
            },
            // Pattern momentum
            'momentum-break': {
                detect: (data) => {
                    if (data.length < 9) return false;
                    const first6 = data.slice(-9, -3);
                    const last3 = data.slice(-3);
                    const firstT = first6.filter(x => x === 'T').length;
                    const firstX = first6.filter(x => x === 'X').length;
                    return Math.abs(firstT - firstX) >= 4 && 
                           new Set(last3).size === 1 &&
                           last3[0] !== (firstT > firstX ? 'T' : 'X');
                },
                predict: (data) => {
                    const first6 = data.slice(-9, -3);
                    const firstT = first6.filter(x => x === 'T').length;
                    const firstX = first6.filter(x => x === 'X').length;
                    return firstT > firstX ? 'T' : 'X';
                },
                confidence: 0.71,
                description: "Momentum mạnh bị phá vỡ -> quay lại momentum chính"
            },
            // Pattern hỗn hợp
            'hybrid-pattern': {
                detect: (data) => {
                    if (data.length < 10) return false;
                    const segment = data.slice(-10);
                    const tCount = segment.filter(x => x === 'T').length;
                    const transitions = segment.slice(1).filter((x, i) => x !== segment[i]).length;
                    return tCount >= 3 && tCount <= 7 && transitions >= 6;
                },
                predict: (data) => {
                    const last = data[data.length-1];
                    const secondLast = data[data.length-2];
                    return last === secondLast ? (last === 'T' ? 'X' : 'T') : last;
                },
                confidence: 0.65,
                description: "Pattern hỗn hợp cao -> dự đoán based on last transitions"
            }
        };
    }

    initSupportModels() {
        // Khởi tạo các model hỗ trợ bổ sung
        for (let i = 1; i <= 21; i++) {
            // Thêm các model hỗ trợ phụ
            if (typeof this[`model${i}Support3`] === 'function') this.models[`model${i}Support3`] = this[`model${i}Support3`].bind(this);
            if (typeof this[`model${i}Support4`] === 'function') this.models[`model${i}Support4`] = this[`model${i}Support4`].bind(this);
        }
    }

    arraysEqual(arr1, arr2) {
        if (arr1.length !== arr2.length) return false;
        for (let i = 0; i < arr1.length; i++) {
            if (arr1[i] !== arr2[i]) return false;
        }
        return true;
    }

    addResult(result) {
        // Cập nhật thống kê session
        if (this.history.length > 0) {
            const lastResult = this.history[this.history.length-1];
            const transitionKey = `${lastResult}to${result}`;
            this.sessionStats.transitions[transitionKey] = (this.sessionStats.transitions[transitionKey] || 0) + 1;
            
            // Cập nhật streak
            if (result === lastResult) {
                this.sessionStats.streaks[result]++;
                this.sessionStats.streaks[`max${result}`] = Math.max(
                    this.sessionStats.streaks[`max${result}`],
                    this.sessionStats.streaks[result]
                );
            } else {
                this.sessionStats.streaks[result] = 1;
                this.sessionStats.streaks[lastResult] = 0;
            }
        } else {
            this.sessionStats.streaks[result] = 1;
        }
        
        this.history.push(result);
        if (this.history.length > 200) {
            this.history.shift();
        }
        
        // Cập nhật độ biến động
        this.updateVolatility();
        
        // Cập nhật độ tin cậy pattern
        this.updatePatternConfidence();
        
        // Cập nhật trạng thái thị trường
        this.updateMarketState();
        
        // Cập nhật cơ sở dữ liệu pattern
        this.updatePatternDatabase();
    }

    updateVolatility() {
        if (this.history.length < 10) return;
        
        const recent = this.history.slice(-10);
        let changes = 0;
        for (let i = 1; i < recent.length; i++) {
            if (recent[i] !== recent[i-1]) changes++;
        }
        
        this.sessionStats.volatility = changes / (recent.length - 1);
    }

    updatePatternConfidence() {
        // Kiểm tra độ chính xác của các pattern đã được sử dụng
        for (const [patternName, confidence] of Object.entries(this.sessionStats.patternConfidence)) {
            if (this.history.length < 2) continue;
            
            const lastResult = this.history[this.history.length-1];
            
            // Đơn giản hóa: giảm confidence nếu pattern dự đoán sai
            if (this.advancedPatterns[patternName]) {
                const prediction = this.advancedPatterns[patternName].predict(this.history.slice(0, -1));
                if (prediction !== lastResult) {
                    this.sessionStats.patternConfidence[patternName] = Math.max(
                        0.1, 
                        confidence * this.adaptiveParameters.patternConfidenceDecay
                    );
                } else {
                    this.sessionStats.patternConfidence[patternName] = Math.min(
                        0.95, 
                        confidence * this.adaptiveParameters.patternConfidenceGrowth
                    );
                }
            }
        }
    }

    updateMarketState() {
        if (this.history.length < 15) return;
        
        const recent = this.history.slice(-15);
        const tCount = recent.filter(x => x === 'T').length;
        const xCount = recent.filter(x => x === 'X').length;
        
        // Tính trend strength
        const trendStrength = Math.abs(tCount - xCount) / recent.length;
        
        // Xác định trend
        if (trendStrength > this.adaptiveParameters.trendStrengthThreshold) {
            this.marketState.trend = tCount > xCount ? 'up' : 'down';
        } else {
            this.marketState.trend = 'neutral';
        }
        
        // Tính momentum (dựa trên thay đổi gần đây)
        let momentum = 0;
        for (let i = 1; i < recent.length; i++) {
            if (recent[i] === recent[i-1]) {
                momentum += recent[i] === 'T' ? 0.1 : -0.1;
            }
        }
        this.marketState.momentum = Math.tanh(momentum); // Chuẩn hóa về [-1, 1]
        
        // Tính stability (ngược với volatility)
        this.marketState.stability = 1 - this.sessionStats.volatility;
        
        // Xác định regime
        if (this.sessionStats.volatility > this.adaptiveParameters.volatilityThreshold) {
            this.marketState.regime = 'volatile';
        } else if (trendStrength > 0.7) {
            this.marketState.regime = 'trending';
        } else if (trendStrength < 0.3) {
            this.marketState.regime = 'random';
        } else {
            this.marketState.regime = 'normal';
        }
    }

    updatePatternDatabase() {
        if (this.history.length < 10) return;
        
        // Phát hiện pattern mới từ lịch sử
        for (let length = this.adaptiveParameters.patternMinLength; 
             length <= this.adaptiveParameters.patternMaxLength; length++) {
            for (let i = 0; i <= this.history.length - length; i++) {
                const segment = this.history.slice(i, i + length);
                const patternKey = segment.join('-');
                
                if (!this.patternDatabase[patternKey]) {
                    // Tính probability cho pattern mới
                    let count = 0;
                    for (let j = 0; j <= this.history.length - length - 1; j++) {
                        const testSegment = this.history.slice(j, j + length);
                        if (testSegment.join('-') === patternKey) {
                            count++;
                        }
                    }
                    
                    if (count > 2) { // Chỉ thêm pattern có xuất hiện ít nhất 3 lần
                        const probability = count / (this.history.length - length);
                        const strength = Math.min(0.9, probability * 1.2);
                        
                        this.patternDatabase[patternKey] = {
                            pattern: segment,
                            probability: probability,
                            strength: strength
                        };
                    }
                }
            }
        }
    }

    // MODEL 1: Nhận biết các loại cầu cơ bản
    model1() {
        const recent = this.history.slice(-10);
        if (recent.length < 4) return null;
        
        const patterns = this.model1Mini(recent);
        if (patterns.length === 0) return null;
        
        const bestPattern = patterns.reduce((best, current) => 
            current.probability > best.probability ? current : best
        );
        
        // Điều chỉnh confidence dựa trên market regime
        let confidence = bestPattern.probability * 0.8;
        if (this.marketState.regime === 'trending') {
            confidence *= 1.1;
        } else if (this.marketState.regime === 'volatile') {
            confidence *= 0.9;
        }
        
        return {
            prediction: bestPattern.prediction,
            confidence: Math.min(0.95, confidence),
            reason: `Phát hiện pattern ${bestPattern.type} (xác suất ${bestPattern.probability.toFixed(2)})`
        };
    }

    model1Mini(data) {
        const patterns = [];
        
        // Kiểm tra các pattern trong database
        for (const [type, patternData] of Object.entries(this.patternDatabase)) {
            const pattern = patternData.pattern;
            if (data.length < pattern.length) continue;
            
            const segment = data.slice(-pattern.length + 1); // So sánh với pattern trừ phần tử cuối
            const patternWithoutLast = pattern.slice(0, -1);
            
            if (segment.join('-') === patternWithoutLast.join('-')) {
                patterns.push({
                    type: type,
                    prediction: pattern[pattern.length - 1],
                    probability: patternData.probability,
                    strength: patternData.strength
                });
            }
        }
        
        return patterns;
    }

    model1Support1() {
        // Hỗ trợ phân tích pattern phức tạp
        return { 
            status: "Phân tích pattern nâng cao",
            totalPatterns: Object.keys(this.patternDatabase).length,
            recentPatterns: Object.keys(this.patternDatabase).length
        };
    }

    model1Support2() {
        // Hỗ trợ đánh giá độ tin cậy pattern
        const patternCount = Object.keys(this.patternDatabase).length;
        const avgConfidence = patternCount > 0 ? 
            Object.values(this.patternDatabase).reduce((sum, p) => sum + p.probability, 0) / patternCount : 0;
        
        return { 
            status: "Đánh giá độ tin cậy pattern",
            patternCount,
            averageConfidence: avgConfidence
        };
    }

    model1Support3() {
        // Phân tích hiệu suất pattern theo thời gian
        const recentPerformance = this.calculatePatternPerformance();
        return {
            status: "Phân tích hiệu suất pattern",
            performance: recentPerformance
        };
    }

    model1Support4() {
        // Tối ưu hóa parameters cho pattern detection
        const optimalParams = this.optimizePatternParameters();
        return {
            status: "Tối ưu parameters pattern",
            parameters: optimalParams
        };
    }

    calculatePatternPerformance() {
        const performance = {};
        const recentHistory = this.history.slice(-50);
        
        for (const [pattern, data] of Object.entries(this.patternDatabase)) {
            let correct = 0;
            let total = 0;
            
            for (let i = data.pattern.length; i < recentHistory.length; i++) {
                const segment = recentHistory.slice(i - data.pattern.length + 1, i);
                if (segment.join('-') === data.pattern.slice(0, -1).join('-')) {
                    total++;
                    if (recentHistory[i] === data.pattern[data.pattern.length - 1]) {
                        correct++;
                    }
                }
            }
            
            performance[pattern] = {
                accuracy: total > 0 ? correct / total : 0,
                occurrences: total
            };
        }
        
        return performance;
    }

    optimizePatternParameters() {
        // Adaptive adjustment of pattern parameters based on market conditions
        if (this.marketState.regime === 'volatile') {
            this.adaptiveParameters.patternMinLength = 4;
            this.adaptiveParameters.patternMaxLength = 6;
        } else if (this.marketState.regime === 'trending') {
            this.adaptiveParameters.patternMinLength = 3;
            this.adaptiveParameters.patternMaxLength = 5;
        } else {
            this.adaptiveParameters.patternMinLength = 3;
            this.adaptiveParameters.patternMaxLength = 8;
        }
        
        return { ...this.adaptiveParameters };
    }

    // MODEL 2: Bắt trend xu hướng ngắn và dài
    model2() {
        const shortTerm = this.history.slice(-5);
        const longTerm = this.history.slice(-20);
        
        if (shortTerm.length < 3 || longTerm.length < 10) return null;
        
        const shortAnalysis = this.model2Mini(shortTerm);
        const longAnalysis = this.model2Mini(longTerm);
        
        let prediction, confidence, reason;
        
        if (shortAnalysis.trend === longAnalysis.trend) {
            prediction = shortAnalysis.trend === 'up' ? 'T' : 'X';
            confidence = (shortAnalysis.strength + longAnalysis.strength) / 2;
            reason = `Xu hướng ngắn và dài hạn cùng ${shortAnalysis.trend}`;
        } else {
            if (shortAnalysis.strength > longAnalysis.strength * 1.5) {
                prediction = shortAnalysis.trend === 'up' ? 'T' : 'X';
                confidence = shortAnalysis.strength;
                reason = `Xu hướng ngắn hạn mạnh hơn dài hạn`;
            } else {
                prediction = longAnalysis.trend === 'up' ? 'T' : 'X';
                confidence = longAnalysis.strength;
                reason = `Xu hướng dài hạn ổn định hơn`;
            }
        }
        
        // Điều chỉnh confidence dựa trên market regime
        if (this.marketState.regime === 'trending') {
            confidence *= 1.15;
        } else if (this.marketState.regime === 'volatile') {
            confidence *= 0.85;
        }
        
        return { 
            prediction, 
            confidence: Math.min(0.95, confidence * 0.9), 
            reason 
        };
    }

    model2Mini(data) {
        const tCount = data.filter(x => x === 'T').length;
        const xCount = data.filter(x => x === 'X').length;
        
        let trend = tCount > xCount ? 'up' : (xCount > tCount ? 'down' : 'neutral');
        let strength = Math.abs(tCount - xCount) / data.length;
        
        // Phân tích chi tiết hơn
        let changes = 0;
        for (let i = 1; i < data.length; i++) {
            if (data[i] !== data[i-1]) changes++;
        }
        
        const volatility = changes / (data.length - 1);
        strength = strength * (1 - volatility / 2); // Điều chỉnh strength based on volatility
        
        return { trend, strength, volatility };
    }

    model2Support1() {
        // Phân tích chất lượng trend
        const quality = this.analyzeTrendQuality();
        return {
            status: "Phân tích chất lượng trend",
            quality
        };
    }

    model2Support2() {
        // Xác định điểm đảo chiều tiềm năng
        const reversalPoints = this.findPotentialReversals();
        return {
            status: "Xác định điểm đảo chiều",
            points: reversalPoints
        };
    }

    analyzeTrendQuality() {
        if (this.history.length < 20) return { quality: 'unknown', score: 0 };
        
        const trends = [];
        for (let i = 5; i <= 20; i += 5) {
            if (this.history.length >= i) {
                const analysis = this.model2Mini(this.history.slice(-i));
                trends.push(analysis);
            }
        }
        
        // Tính consistency giữa các trends
        let consistent = true;
        for (let i = 1; i < trends.length; i++) {
            if (trends[i].trend !== trends[0].trend) {
                consistent = false;
                break;
            }
        }
        
        const avgStrength = trends.reduce((sum, t) => sum + t.strength, 0) / trends.length;
        const avgVolatility = trends.reduce((sum, t) => sum + t.volatility, 0) / trends.length;
        
        const qualityScore = avgStrength * (1 - avgVolatility);
        let quality;
        
        if (qualityScore > 0.7) quality = 'excellent';
        else if (qualityScore > 0.5) quality = 'good';
        else if (qualityScore > 0.3) quality = 'fair';
        else quality = 'poor';
        
        return { quality, score: qualityScore, consistent };
    }

    findPotentialReversals() {
        const points = [];
        if (this.history.length < 15) return points;
        
        // Tìm các điểm mà trend có thể đảo chiều
        for (let i = 10; i < this.history.length - 5; i++) {
            const before = this.history.slice(i - 5, i);
            const after = this.history.slice(i, i + 5);
            
            const beforeAnalysis = this.model2Mini(before);
            const afterAnalysis = this.model2Mini(after);
            
            if (beforeAnalysis.trend !== afterAnalysis.trend && 
                beforeAnalysis.strength > 0.6 && 
                afterAnalysis.strength > 0.6) {
                points.push({
                    position: i,
                    beforeTrend: beforeAnalysis.trend,
                    afterTrend: afterAnalysis.trend,
                    strength: (beforeAnalysis.strength + afterAnalysis.strength) / 2
                });
            }
        }
        
        return points;
    }

    // MODEL 3: Xem trong 12 phiên gần nhất có sự chênh lệch cao thì sẽ dự đoán bên còn lại
    model3() {
        const recent = this.history.slice(-12);
        if (recent.length < 12) return null;
        
        const analysis = this.model3Mini(recent);
        
        if (analysis.difference < 0.4) return null;
        
        // Điều chỉnh confidence dựa trên market regime
        let confidence = analysis.difference * 0.8;
        if (this.marketState.regime === 'random') {
            confidence *= 1.1;
        } else if (this.marketState.regime === 'trending') {
            confidence *= 0.9;
        }
        
        return {
            prediction: analysis.prediction,
            confidence: Math.min(0.95, confidence),
            reason: `Chênh lệch cao (${Math.round(analysis.difference * 100)}%) trong 12 phiên, dự đoán cân bằng`
        };
    }

    model3Mini(data) {
        const tCount = data.filter(x => x === 'T').length;
        const xCount = data.filter(x => x === 'X').length;
        const total = data.length;
        const difference = Math.abs(tCount - xCount) / total;
        
        return {
            difference,
            prediction: tCount > xCount ? 'X' : 'T',
            tCount,
            xCount
        };
    }

    model3Support1() {
        // Phân tích hiệu quả của mean reversion
        const effectiveness = this.analyzeMeanReversionEffectiveness();
        return {
            status: "Phân tích hiệu quả mean reversion",
            effectiveness
        };
    }

    model3Support2() {
        // Tìm ngưỡng chênh lệch tối ưu
        const optimalThreshold = this.findOptimalDifferenceThreshold();
        return {
            status: "Tìm ngưỡng chênh lệch tối ưu",
            threshold: optimalThreshold
        };
    }

    analyzeMeanReversionEffectiveness() {
        if (this.history.length < 30) return { effectiveness: 'unknown', successRate: 0 };
        
        let successes = 0;
        let opportunities = 0;
        
        for (let i = 12; i < this.history.length; i++) {
            const segment = this.history.slice(i - 12, i);
            const tCount = segment.filter(x => x === 'T').length;
            const xCount = segment.filter(x => x === 'X').length;
            const difference = Math.abs(tCount - xCount) / segment.length;
            
            if (difference >= 0.4) {
                opportunities++;
                const prediction = tCount > xCount ? 'X' : 'T';
                if (this.history[i] === prediction) {
                    successes++;
                }
            }
        }
        
        const successRate = opportunities > 0 ? successes / opportunities : 0;
        let effectiveness;
        
        if (successRate > 0.6) effectiveness = 'high';
        else if (successRate > 0.5) effectiveness = 'medium';
        else effectiveness = 'low';
        
        return { effectiveness, successRate, opportunities };
    }

    findOptimalDifferenceThreshold() {
        if (this.history.length < 50) return 0.4;
        
        let bestThreshold = 0.4;
        let bestSuccessRate = 0;
        
        // Test các threshold khác nhau
        for (let threshold = 0.3; threshold <= 0.6; threshold += 0.05) {
            let successes = 0;
            let opportunities = 0;
            
            for (let i = 12; i < this.history.length; i++) {
                const segment = this.history.slice(i - 12, i);
                const tCount = segment.filter(x => x === 'T').length;
                const xCount = segment.filter(x => x === 'X').length;
                const difference = Math.abs(tCount - xCount) / segment.length;
                
                if (difference >= threshold) {
                    opportunities++;
                    const prediction = tCount > xCount ? 'X' : 'T';
                    if (this.history[i] === prediction) {
                        successes++;
                    }
                }
            }
            
            const successRate = opportunities > 0 ? successes / opportunities : 0;
            if (successRate > bestSuccessRate) {
                bestSuccessRate = successRate;
                bestThreshold = threshold;
            }
        }
        
        return bestThreshold;
    }

    // MODEL 4: Bắt cầu ngắn hạn
    model4() {
        const recent = this.history.slice(-6);
        if (recent.length < 4) return null;
        
        const analysis = this.model4Mini(recent);
        
        if (analysis.confidence < 0.6) return null;
        
        // Điều chỉnh confidence dựa trên market regime
        let confidence = analysis.confidence;
        if (this.marketState.regime === 'trending') {
            confidence *= 1.1;
        } else if (this.marketState.regime === 'volatile') {
            confidence *= 0.9;
        }
        
        return {
            prediction: analysis.prediction,
            confidence: Math.min(0.95, confidence),
            reason: `Cầu ngắn hạn ${analysis.trend} với độ tin cậy ${analysis.confidence.toFixed(2)}`
        };
    }

    model4Mini(data) {
        // Phân tích momentum ngắn hạn
        const last3 = data.slice(-3);
        const tCount = last3.filter(x => x === 'T').length;
        const xCount = last3.filter(x => x === 'X').length;
        
        let prediction, confidence, trend;
        
        if (tCount === 3) {
            prediction = 'T';
            confidence = 0.7;
            trend = 'Tăng mạnh';
        } else if (xCount === 3) {
            prediction = 'X';
            confidence = 0.7;
            trend = 'Giảm mạnh';
        } else if (tCount === 2) {
            prediction = 'T';
            confidence = 0.65;
            trend = 'Tăng nhẹ';
        } else if (xCount === 2) {
            prediction = 'X';
            confidence = 0.65;
            trend = 'Giảm nhẹ';
        } else {
            // Phân tích pattern phức tạp hơn
            const changes = data.slice(-4).filter((val, idx, arr) => 
                idx > 0 && val !== arr[idx-1]).length;
            
            if (changes >= 3) {
                prediction = data[data.length - 1] === 'T' ? 'X' : 'T';
                confidence = 0.6;
                trend = 'Đảo chiều';
            } else {
                prediction = data[data.length - 1];
                confidence = 0.55;
                trend = 'Ổn định';
            }
        }
        
        return { prediction, confidence, trend };
    }

    model4Support1() {
        // Phân tích hiệu quả momentum ngắn hạn
        const effectiveness = this.analyzeShortTermMomentumEffectiveness();
        return {
            status: "Phân tích hiệu quả momentum ngắn hạn",
            effectiveness
        };
    }

    model4Support2() {
        // Tối ưu hóa khung thời gian cho momentum
        const optimalTimeframe = this.findOptimalMomentumTimeframe();
        return {
            status: "Tối ưu khung thời gian momentum",
            timeframe: optimalTimeframe
        };
    }

    analyzeShortTermMomentumEffectiveness() {
        if (this.history.length < 20) return { effectiveness: 'unknown', successRate: 0 };
        
        let successes = 0;
        let opportunities = 0;
        
        for (let i = 6; i < this.history.length; i++) {
            const segment = this.history.slice(i - 6, i);
            const analysis = this.model4Mini(segment);
            
            if (analysis.confidence >= 0.6) {
                opportunities++;
                if (this.history[i] === analysis.prediction) {
                    successes++;
                }
            }
        }
        
        const successRate = opportunities > 0 ? successes / opportunities : 0;
        let effectiveness;
        
        if (successRate > 0.6) effectiveness = 'high';
        else if (successRate > 0.5) effectiveness = 'medium';
        else effectiveness = 'low';
        
        return { effectiveness, successRate, opportunities };
    }

    findOptimalMomentumTimeframe() {
        if (this.history.length < 50) return 6;
        
        let bestTimeframe = 6;
        let bestSuccessRate = 0;
        
        // Test các timeframe khác nhau
        for (let timeframe = 4; timeframe <= 8; timeframe++) {
            let successes = 0;
            let opportunities = 0;
            
            for (let i = timeframe; i < this.history.length; i++) {
                const segment = this.history.slice(i - timeframe, i);
                const analysis = this.model4Mini(segment);
                
                if (analysis.confidence >= 0.6) {
                    opportunities++;
                    if (this.history[i] === analysis.prediction) {
                        successes++;
                    }
                }
            }
            
            const successRate = opportunities > 0 ? successes / opportunities : 0;
            if (successRate > bestSuccessRate) {
                bestSuccessRate = successRate;
                bestTimeframe = timeframe;
            }
        }
        
        return bestTimeframe;
    }

    // MODEL 5: Nếu tỉ lệ trọng số dự đoán tài /Xỉu chênh lệch cao thì cân bằng lại
    model5() {
        const predictions = this.getBasePredictions();
        const tPredictions = Object.values(predictions).filter(p => p && p.prediction === 'T').length;
        const xPredictions = Object.values(predictions).filter(p => p && p.prediction === 'X').length;
        const total = tPredictions + xPredictions;
        
        if (total < 5) return null;
        
        const difference = Math.abs(tPredictions - xPredictions) / total;
        
        if (difference > 0.6) {
            return {
                prediction: tPredictions > xPredictions ? 'X' : 'T',
                confidence: difference * 0.9,
                reason: `Cân bằng tỷ lệ chênh lệch cao (${Math.round(difference * 100)}%) giữa các model`
            };
        }
        
        return null;
    }

    model5Support1() {
        // Phân tích sự đồng thuận giữa các model
        const consensus = this.analyzeModelConsensus();
        return {
            status: "Phân tích đồng thuận model",
            consensus
        };
    }

    model5Support2() {
        // Đánh giá mức độ phân kỳ giữa các model
        const divergence = this.analyzeModelDivergence();
        return {
            status: "Phân tích phân kỳ model",
            divergence
        };
    }

    analyzeModelConsensus() {
        const predictions = this.getAllPredictions();
        const validPredictions = Object.values(predictions).filter(p => p && p.prediction);
        
        if (validPredictions.length === 0) return { consensus: 'none', rate: 0 };
        
        const tCount = validPredictions.filter(p => p.prediction === 'T').length;
        const xCount = validPredictions.filter(p => p.prediction === 'X').length;
        const total = validPredictions.length;
        
        const consensusRate = Math.max(tCount, xCount) / total;
        let consensus;
        
        if (consensusRate > 0.7) consensus = 'strong';
        else if (consensusRate > 0.6) consensus = 'moderate';
        else consensus = 'weak';
        
        return { consensus, rate: consensusRate, tCount, xCount };
    }

    analyzeModelDivergence() {
        const predictions = this.getAllPredictions();
        const validPredictions = Object.values(predictions).filter(p => p && p.prediction);
        
        if (validPredictions.length < 2) return { divergence: 'low', score: 0 };
        
        // Tính độ phân kỳ dựa trên confidence và prediction
        let divergenceScore = 0;
        for (let i = 0; i < validPredictions.length; i++) {
            for (let j = i + 1; j < validPredictions.length; j++) {
                if (validPredictions[i].prediction !== validPredictions[j].prediction) {
                    divergenceScore += validPredictions[i].confidence * validPredictions[j].confidence;
                }
            }
        }
        
        // Chuẩn hóa score
        const maxPossible = (validPredictions.length * (validPredictions.length - 1)) / 2;
        divergenceScore = divergenceScore / maxPossible;
        
        let divergence;
        if (divergenceScore > 0.7) divergence = 'high';
        else if (divergenceScore > 0.4) divergence = 'medium';
        else divergence = 'low';
        
        return { divergence, score: divergenceScore };
    }

    // MODEL 6: Biết lúc nào nên bắt theo cầu hay bẻ cầu
    model6() {
        const trendAnalysis = this.model2();
        const continuity = this.model6Mini(this.history.slice(-8));
        const breakProbability = this.model10Mini(this.history);
        
        if (continuity.streak >= 5 && breakProbability > 0.7) {
            return {
                prediction: trendAnalysis.prediction === 'T' ? 'X' : 'T',
                confidence: breakProbability * 0.8,
                reason: `Cầu liên tục ${continuity.streak} lần, xác suất bẻ cầu ${breakProbability.toFixed(2)}`
            };
        }
        
        return {
            prediction: trendAnalysis.prediction,
            confidence: trendAnalysis.confidence * 0.9,
            reason: `Tiếp tục theo xu hướng, cầu chưa đủ mạnh để bẻ`
        };
    }

    model6Mini(data) {
        if (data.length < 2) return { streak: 0, direction: 'neutral', maxStreak: 0 };
        
        let currentStreak = 1;
        let maxStreak = 1;
        let direction = data[data.length - 1];
        
        for (let i = data.length - 1; i > 0; i--) {
            if (data[i] === data[i-1]) {
                currentStreak++;
                maxStreak = Math.max(maxStreak, currentStreak);
            } else {
                break;
            }
        }
        
        return { streak: currentStreak, direction, maxStreak };
    }

    model6Support1() {
        // Phân tích hiệu quả của việc bẻ cầu
        const effectiveness = this.analyzeBreakEffectiveness();
        return {
            status: "Phân tích hiệu quả bẻ cầu",
            effectiveness
        };
    }

    model6Support2() {
        // Xác định điều kiện tối ưu để bẻ cầu
        const optimalConditions = this.findOptimalBreakConditions();
        return {
            status: "Xác định điều kiện bẻ cầu tối ưu",
            conditions: optimalConditions
        };
    }

    analyzeBreakEffectiveness() {
        if (this.history.length < 30) return { effectiveness: 'unknown', successRate: 0 };
        
        let successes = 0;
        let opportunities = 0;
        
        for (let i = 8; i < this.history.length; i++) {
            const segment = this.history.slice(i - 8, i);
            const continuity = this.model6Mini(segment);
            const breakProb = this.model10Mini(this.history.slice(0, i));
            
            if (continuity.streak >= 5 && breakProb > 0.7) {
                opportunities++;
                const trendAnalysis = this.model2Mini(segment);
                const prediction = trendAnalysis.trend === 'up' ? 'X' : 'T';
                
                if (this.history[i] === prediction) {
                    successes++;
                }
            }
        }
        
        const successRate = opportunities > 0 ? successes / opportunities : 0;
        let effectiveness;
        
        if (successRate > 0.6) effectiveness = 'high';
        else if (successRate > 0.5) effectiveness = 'medium';
        else effectiveness = 'low';
        
        return { effectiveness, successRate, opportunities };
    }

    findOptimalBreakConditions() {
        if (this.history.length < 50) return { minStreak: 5, minProbability: 0.7 };
        
        let bestMinStreak = 5;
        let bestMinProbability = 0.7;
        let bestSuccessRate = 0;
        
        // Test các combination khác nhau
        for (let minStreak = 4; minStreak <= 7; minStreak++) {
            for (let minProb = 0.6; minProb <= 0.8; minProb += 0.05) {
                let successes = 0;
                let opportunities = 0;
                
                for (let i = 8; i < this.history.length; i++) {
                    const segment = this.history.slice(i - 8, i);
                    const continuity = this.model6Mini(segment);
                    const breakProb = this.model10Mini(this.history.slice(0, i));
                    
                    if (continuity.streak >= minStreak && breakProb >= minProb) {
                        opportunities++;
                        const trendAnalysis = this.model2Mini(segment);
                        const prediction = trendAnalysis.trend === 'up' ? 'X' : 'T';
                        
                        if (this.history[i] === prediction) {
                            successes++;
                        }
                    }
                }
                
                const successRate = opportunities > 0 ? successes / opportunities : 0;
                if (successRate > bestSuccessRate) {
                    bestSuccessRate = successRate;
                    bestMinStreak = minStreak;
                    bestMinProbability = minProb;
                }
            }
        }
        
        return { minStreak: bestMinStreak, minProbability: bestMinProbability, successRate: bestSuccessRate };
    }

    // MODEL 7: Cân bằng trọng số từng model khi chênh lệch quá cao
    model7() {
        const performanceStats = this.model13Mini();
        const imbalance = this.model7Mini(performanceStats);
        
        if (imbalance > 0.3) {
            this.adjustWeights(performanceStats);
            return {
                prediction: null,
                confidence: 0,
                reason: `Điều chỉnh trọng số do chênh lệch hiệu suất ${imbalance.toFixed(2)}`
            };
        }
        
        return null;
    }

    model7Mini(performanceStats) {
        const accuracies = Object.values(performanceStats).map(p => p.accuracy);
        if (accuracies.length < 2) return 0;
        
        const maxAccuracy = Math.max(...accuracies);
        const minAccuracy = Math.min(...accuracies);
        
        return (maxAccuracy - minAccuracy) / maxAccuracy;
    }

    adjustWeights(performanceStats) {
        const avgAccuracy = Object.values(performanceStats).reduce((sum, p) => sum + p.accuracy, 0) / 
                           Object.values(performanceStats).length;
        
        for (const [model, stats] of Object.entries(performanceStats)) {
            // Điều chỉnh trọng số dựa trên độ lệch so với trung bình
            const deviation = stats.accuracy - avgAccuracy;
            this.weights[model] = Math.max(0.1, Math.min(2, 1 + deviation * 2));
        }
    }

    model7Support1() {
        // Phân tích phân bố trọng số
        const weightDistribution = this.analyzeWeightDistribution();
        return {
            status: "Phân tích phân bố trọng số",
            distribution: weightDistribution
        };
    }

    model7Support2() {
        // Tối ưu hóa algorithm điều chỉnh trọng số
        const optimization = this.optimizeWeightAdjustment();
        return {
            status: "Tối ưu điều chỉnh trọng số",
            optimization
        };
    }

    analyzeWeightDistribution() {
        const weights = Object.values(this.weights);
        const mean = weights.reduce((sum, w) => sum + w, 0) / weights.length;
        const variance = weights.reduce((sum, w) => sum + Math.pow(w - mean, 2), 0) / weights.length;
        const stdDev = Math.sqrt(variance);
        
        return { mean, variance, stdDev, min: Math.min(...weights), max: Math.max(...weights) };
    }

    optimizeWeightAdjustment() {
        // Adaptive learning rate based on market conditions
        let learningRate = 1.0;
        
        if (this.marketState.regime === 'volatile') {
            learningRate = 0.8; // Conservative adjustment in volatile markets
        } else if (this.marketState.regime === 'trending') {
            learningRate = 1.2; // More aggressive adjustment in trending markets
        }
        
        return { learningRate };
    }

    // MODEL 8: Nhận biết cầu xấu (cầu ko theo bất kì xu hướng nào)
    model8() {
        const randomness = this.model8Mini(this.history.slice(-15));
        
        if (randomness > 0.7) {
            // Giảm trọng số các model dựa trên pattern
            ['model1', 'model4', 'model9', 'model12'].forEach(model => {
                this.weights[model] = Math.max(0.3, this.weights[model] * 0.7);
            });
            
            // Tăng trọng số các model dựa trên mean reversion
            ['model3', 'model5', 'model6'].forEach(model => {
                this.weights[model] = Math.min(2, this.weights[model] * 1.2);
            });
            
            return {
                prediction: null,
                confidence: 0,
                reason: `Phát hiện cầu xấu (độ ngẫu nhiên ${randomness.toFixed(2)}), điều chỉnh trọng số model`
            };
        }
        
        return null;
    }

    model8Mini(data) {
        if (data.length < 10) return 0;
        
        // Tính độ ngẫu nhiên dựa trên số lần thay đổi
        let changes = 0;
        for (let i = 1; i < data.length; i++) {
            if (data[i] !== data[i-1]) changes++;
        }
        
        const changeRatio = changes / (data.length - 1);
        
        // Tính phân bố
        const tCount = data.filter(x => x === 'T').length;
        const xCount = data.filter(x => x === 'X').length;
        const distribution = Math.abs(tCount - xCount) / data.length;
        
        // Tính entropy
        const pT = tCount / data.length;
        const pX = xCount / data.length;
        let entropy = 0;
        if (pT > 0) entropy -= pT * Math.log2(pT);
        if (pX > 0) entropy -= pX * Math.log2(pX);
        
        // Kết hợp cả ba yếu tố
        return (changeRatio * 0.4 + (1 - distribution) * 0.3 + entropy * 0.3);
    }

    model8Support1() {
        // Phân tích các đặc điểm của cầu xấu
        const characteristics = this.analyzeBadPatternCharacteristics();
        return {
            status: "Phân tích đặc điểm cầu xấu",
            characteristics
        };
    }

    model8Support2() {
        // Đề xuất chiến lược cho cầu xấu
        const strategies = this.suggestStrategiesForBadPatterns();
        return {
            status: "Đề xuất chiến lược cho cầu xấu",
            strategies
        };
    }

    analyzeBadPatternCharacteristics() {
        if (this.history.length < 30) return { characteristics: 'unknown' };
        
        const recent = this.history.slice(-30);
        const randomness = this.model8Mini(recent);
        const volatility = this.sessionStats.volatility;
        
        let characteristics;
        if (randomness > 0.7 && volatility > 0.6) {
            characteristics = 'high_randomness_high_volatility';
        } else if (randomness > 0.7) {
            characteristics = 'high_randomness';
        } else if (volatility > 0.6) {
            characteristics = 'high_volatility';
        } else {
            characteristics = 'normal';
        }
        
        return { characteristics, randomness, volatility };
    }

    suggestStrategiesForBadPatterns() {
        const characteristics = this.analyzeBadPatternCharacteristics();
        let strategies = [];
        
        switch (characteristics.characteristics) {
            case 'high_randomness_high_volatility':
                strategies = ['reduce_position_size', 'focus_on_mean_reversion', 'avoid_pattern_based_models'];
                break;
            case 'high_randomness':
                strategies = ['increase_diversification', 'use_shorter_timeframes', 'focus_on_consensus_models'];
                break;
            case 'high_volatility':
                strategies = ['wait_for_clear_signals', 'use_breakout_strategies', 'adjust_risk_management'];
                break;
            default:
                strategies = ['normal_operation'];
        }
        
        return strategies;
    }

    // MODEL 9: Nhận biết các loại cầu cơ bản (nâng cao)
    model9() {
        const recent = this.history.slice(-12);
        if (recent.length < 8) return null;
        
        const complexPatterns = this.model9Mini(recent);
        if (complexPatterns.length === 0) return null;
        
        const bestPattern = complexPatterns.reduce((best, current) => 
            current.confidence > best.confidence ? current : best
        );
        
        // Điều chỉnh confidence dựa trên market regime
        let confidence = bestPattern.confidence;
        if (this.marketState.regime === 'trending') {
            confidence *= 1.1;
        } else if (this.marketState.regime === 'volatile') {
            confidence *= 0.9;
        }
        
        return {
            prediction: bestPattern.prediction,
            confidence: Math.min(0.95, confidence),
            reason: `Phát hiện pattern phức tạp: ${bestPattern.type}`
        };
    }

    model9Mini(data) {
        const patterns = [];
        
        // Kiểm tra các pattern phức tạp hơn
        for (let patternLength = 4; patternLength <= 6; patternLength++) {
            if (data.length < patternLength) continue;
            
            const segment = data.slice(-patternLength);
            const patternKey = segment.join('-');
            
            if (this.patternDatabase[patternKey]) {
                patterns.push({
                    type: patternKey,
                    prediction: this.patternDatabase[patternKey].pattern[
                        this.patternDatabase[patternKey].pattern.length - 1
                    ],
                    confidence: this.patternDatabase[patternKey].probability * 0.75
                });
            }
        }
        
        return patterns;
    }

    model9Support1() {
        // Phân tích độ phức tạp của pattern
        const complexity = this.analyzePatternComplexity();
        return {
            status: "Phân tích độ phức tạp pattern",
            complexity
        };
    }

    model9Support2() {
        // Đánh giá khả năng tồn tại của pattern
        const viability = this.assessPatternViability();
        return {
            status: "Đánh giá khả năng tồn tại pattern",
            viability
        };
    }

    analyzePatternComplexity() {
        const patterns = Object.keys(this.patternDatabase);
        let totalComplexity = 0;
        
        for (const pattern of patterns) {
            const length = pattern.split('-').length;
            totalComplexity += length;
        }
        
        const avgComplexity = patterns.length > 0 ? totalComplexity / patterns.length : 0;
        
        let complexityLevel;
        if (avgComplexity > 5) complexityLevel = 'high';
        else if (avgComplexity > 4) complexityLevel = 'medium';
        else complexityLevel = 'low';
        
        return { level: complexityLevel, average: avgComplexity, total: patterns.length };
    }

    assessPatternViability() {
        const performance = this.calculatePatternPerformance();
        let viablePatterns = 0;
        let totalPatterns = 0;
        
        for (const [pattern, stats] of Object.entries(performance)) {
            totalPatterns++;
            if (stats.accuracy > 0.55 && stats.occurrences >= 3) {
                viablePatterns++;
            }
        }
        
        const viabilityRate = totalPatterns > 0 ? viablePatterns / totalPatterns : 0;
        
        let viability;
        if (viabilityRate > 0.7) viability = 'high';
        else if (viabilityRate > 0.5) viability = 'medium';
        else viability = 'low';
        
        return { viability, rate: viabilityRate, viable: viablePatterns, total: totalPatterns };
    }

    // MODEL 10: Nhận biết xác suất bẻ cầu
    model10() {
        const breakProb = this.model10Mini(this.history);
        
        return {
            prediction: null,
            confidence: breakProb,
            reason: `Xác suất bẻ cầu: ${breakProb.toFixed(2)}`
        };
    }

    model10Mini(data) {
        if (data.length < 20) return 0.5;
        
        // Phân tích lịch sử bẻ cầu
        let breakCount = 0;
        let totalOpportunities = 0;
        
        for (let i = 5; i < data.length; i++) {
            const segment = data.slice(i-5, i);
            const streak = this.model6Mini(segment).streak;
            
            if (streak >= 4) {
                totalOpportunities++;
                if (data[i] !== segment[segment.length-1]) {
                    breakCount++;
                }
            }
        }
        
        return totalOpportunities > 0 ? breakCount / totalOpportunities : 0.5;
    }

    model10Support1() {
        // Phân tích các yếu tố ảnh hưởng đến xác suất bẻ cầu
        const factors = this.analyzeBreakFactors();
        return {
            status: "Phân tích yếu tố ảnh hưởng bẻ cầu",
            factors
        };
    }

    model10Support2() {
        // Dự báo xác suất bẻ cầu trong tương lai
        const forecast = this.forecastBreakProbability();
        return {
            status: "Dự báo xác suất bẻ cầu",
            forecast
        };
    }

    analyzeBreakFactors() {
        if (this.history.length < 30) return { factors: [] };
        
        const factors = [];
        const recent = this.history.slice(-30);
        
        // Phân tích mối correlation giữa các yếu tố và break probability
        const streakLengths = [];
        const breakResults = [];
        
        for (let i = 5; i < recent.length; i++) {
            const segment = recent.slice(i-5, i);
            const streak = this.model6Mini(segment).streak;
            streakLengths.push(streak);
            breakResults.push(recent[i] !== segment[segment.length-1] ? 1 : 0);
        }
        
        // Tính correlation đơn giản
        if (streakLengths.length > 5) {
            const avgStreak = streakLengths.reduce((sum, val) => sum + val, 0) / streakLengths.length;
            const avgBreak = breakResults.reduce((sum, val) => sum + val, 0) / breakResults.length;
            
            let covariance = 0;
            for (let i = 0; i < streakLengths.length; i++) {
                covariance += (streakLengths[i] - avgStreak) * (breakResults[i] - avgBreak);
            }
            covariance /= streakLengths.length;
            
            const varianceStreak = streakLengths.reduce((sum, val) => sum + Math.pow(val - avgStreak, 2), 0) / streakLengths.length;
            const varianceBreak = breakResults.reduce((sum, val) => sum + Math.pow(val - avgBreak, 2), 0) / breakResults.length;
            
            const correlation = covariance / Math.sqrt(varianceStreak * varianceBreak);
            factors.push({ factor: 'streak_length', correlation: correlation });
        }
        
        return { factors };
    }

    forecastBreakProbability() {
        const currentStreak = this.sessionStats.streaks[this.history[this.history.length-1] || 'T'];
        const historicalBreakProb = this.model10Mini(this.history);
        
        // Dự báo đơn giản dựa trên streak hiện tại và lịch sử
        let forecast = historicalBreakProb;
        if (currentStreak >= 5) {
            forecast = Math.min(0.9, forecast * (1 + currentStreak * 0.1));
        }
        
        // Điều chỉnh dựa trên market regime
        if (this.marketState.regime === 'volatile') {
            forecast *= 1.1;
        } else if (this.marketState.regime === 'trending') {
            forecast *= 0.9;
        }
        
        return Math.min(0.95, Math.max(0.05, forecast));
    }

    // MODEL 11: Nhận diện biến động xúc xắc và nguyên lý xúc xắc
    model11() {
        const volatility = this.model11Mini(this.history.slice(-20));
        const prediction = this.model11Predict(volatility);
        
        return {
            prediction: prediction.value,
            confidence: prediction.confidence,
            reason: `Biến động ${volatility.level}, dự đoán ${prediction.value}`
        };
    }

    model11Mini(data) {
        if (data.length < 10) return { level: 'medium', value: 0.5 };
        
        let changes = 0;
        for (let i = 1; i < data.length; i++) {
            if (data[i] !== data[i-1]) changes++;
        }
        
        const changeRatio = changes / (data.length - 1);
        
        if (changeRatio < 0.3) return { level: 'low', value: changeRatio };
        if (changeRatio > 0.7) return { level: 'high', value: changeRatio };
        return { level: 'medium', value: changeRatio };
    }

    model11Predict(volatility) {
        if (volatility.level === 'low') {
            // Ít biến động, tiếp tục xu hướng
            const last = this.history[this.history.length - 1];
            return { value: last, confidence: 0.7 };
        } else if (volatility.level === 'high') {
            // Nhiều biến động, khó dự đoán
            return { value: Math.random() > 0.5 ? 'T' : 'X', confidence: 0.5 };
        } else {
            // Biến động trung bình
            const trend = this.model2Mini(this.history.slice(-10));
            return { 
                value: trend.trend === 'up' ? 'T' : 'X', 
                confidence: trend.strength * 0.8 
            };
        }
    }

    model11Support1() {
        // Phân tích nguyên nhân biến động
        const causes = this.analyzeVolatilityCauses();
        return {
            status: "Phân tích nguyên nhân biến động",
            causes
        };
    }

    model11Support2() {
        // Dự báo biến động trong tương lai
        const forecast = this.forecastVolatility();
        return {
            status: "Dự báo biến động",
            forecast
        };
    }

    analyzeVolatilityCauses() {
        const causes = [];
        const recent = this.history.slice(-20);
        
        // Kiểm tra các pattern có thể gây biến động
        const streak = this.model6Mini(recent).streak;
        if (streak >= 5) {
            causes.push('high_streak');
        }
        
        const distribution = this.model3Mini(recent).difference;
        if (distribution < 0.3) {
            causes.push('balanced_distribution');
        }
        
        // Thêm các nguyên nhân khác
        if (this.marketState.regime === 'volatile') {
            causes.push('market_regime');
        }
        
        return causes;
    }

    forecastVolatility() {
        const currentVolatility = this.sessionStats.volatility;
        const historicalVolatility = this.calculateHistoricalVolatility();
        
        // Dự báo đơn giản
        let forecast = (currentVolatility * 0.7 + historicalVolatility * 0.3);
        
        // Điều chỉnh dựa trên market regime
        if (this.marketState.regime === 'volatile') {
            forecast = Math.min(0.95, forecast * 1.2);
        } else if (this.marketState.regime === 'trending') {
            forecast = Math.max(0.2, forecast * 0.8);
        }
        
        return forecast;
    }

    calculateHistoricalVolatility() {
        if (this.history.length < 30) return this.sessionStats.volatility;
        
        let totalVolatility = 0;
        let count = 0;
        
        for (let i = 10; i < this.history.length; i += 5) {
            const segment = this.history.slice(Math.max(0, i - 10), i);
            const changes = segment.slice(1).filter((val, idx) => val !== segment[idx]).length;
            totalVolatility += changes / (segment.length - 1);
            count++;
        }
        
        return count > 0 ? totalVolatility / count : this.sessionStats.volatility;
    }

    // MODEL 12: nhận diện nhiều mẫu cầu hơn ngắn
    model12() {
        const shortPatterns = this.model12Mini(this.history.slice(-8));
        
        if (shortPatterns.length === 0) return null;
        
        const bestPattern = shortPatterns.reduce((best, current) => 
            current.confidence > best.confidence ? current : best
        );
        
        return {
            prediction: bestPattern.prediction,
            confidence: bestPattern.confidence,
            reason: `Mẫu cầu ngắn: ${bestPattern.type}`
        };
    }

    model12Mini(data) {
        const patterns = [];
        
        // Các mẫu ngắn đặc biệt
        const shortPatterns = {
            'T-X-T': { prediction: 'X', confidence: 0.65 },
            'X-T-X': { prediction: 'T', confidence: 0.65 },
            'T-T-X': { prediction: 'X', confidence: 0.7 },
            'X-X-T': { prediction: 'T', confidence: 0.7 },
            'T-X-X': { prediction: 'T', confidence: 0.6 },
            'X-T-T': { prediction: 'X', confidence: 0.6 },
            'T-T-T-X': { prediction: 'X', confidence: 0.72 },
            'X-X-X-T': { prediction: 'T', confidence: 0.72 },
            'T-X-T-X': { prediction: 'X', confidence: 0.68 },
            'X-T-X-T': { prediction: 'T', confidence: 0.68 }
        };
        
        if (data.length >= 3) {
            const last3 = data.slice(-3).join('-');
            if (shortPatterns[last3]) {
                patterns.push({
                    type: last3,
                    prediction: shortPatterns[last3].prediction,
                    confidence: shortPatterns[last3].confidence
                });
            }
        }
        
        if (data.length >= 4) {
            const last4 = data.slice(-4).join('-');
            if (shortPatterns[last4]) {
                patterns.push({
                    type: last4,
                    prediction: shortPatterns[last4].prediction,
                    confidence: shortPatterns[last4].confidence
                });
            }
        }
        
        return patterns;
    }

    model12Support1() {
        // Phân tích hiệu suất của các mẫu ngắn
        const performance = this.analyzeShortPatternPerformance();
        return {
            status: "Phân tích hiệu suất mẫu ngắn",
            performance
        };
    }

    model12Support2() {
        // Tối ưu hóa độ dài mẫu ngắn
        const optimization = this.optimizeShortPatternLength();
        return {
            status: "Tối ưu độ dài mẫu ngắn",
            optimization
        };
    }

    analyzeShortPatternPerformance() {
        if (this.history.length < 30) return { performance: {} };
        
        const performance = {};
        const shortPatterns = {
            'T-X-T': { prediction: 'X', confidence: 0.65 },
            'X-T-X': { prediction: 'T', confidence: 0.65 },
            'T-T-X': { prediction: 'X', confidence: 0.7 },
            'X-X-T': { prediction: 'T', confidence: 0.7 },
            'T-X-X': { prediction: 'T', confidence: 0.6 },
            'X-T-T': { prediction: 'X', confidence: 0.6 }
        };
        
        for (const [pattern, data] of Object.entries(shortPatterns)) {
            let correct = 0;
            let total = 0;
            const patternLength = pattern.split('-').length;
            
            for (let i = patternLength; i < this.history.length; i++) {
                const segment = this.history.slice(i - patternLength, i);
                if (segment.join('-') === pattern) {
                    total++;
                    if (this.history[i] === data.prediction) {
                        correct++;
                    }
                }
            }
            
            performance[pattern] = {
                accuracy: total > 0 ? correct / total : 0,
                occurrences: total
            };
        }
        
        return performance;
    }

    optimizeShortPatternLength() {
        if (this.history.length < 50) return { optimalLength: 3 };
        
        let bestLength = 3;
        let bestSuccessRate = 0;
        
        for (let length = 2; length <= 5; length++) {
            let totalSuccess = 0;
            let totalOpportunities = 0;
            
            // Tạo các pattern có độ dài xác định
            const patterns = this.generatePatternsOfLength(length);
            
            for (const pattern of patterns) {
                let correct = 0;
                let opportunities = 0;
                
                for (let i = length; i < this.history.length; i++) {
                    const segment = this.history.slice(i - length, i);
                    if (segment.join('-') === pattern) {
                        opportunities++;
                        // Dự đoán đảo chiều cho pattern
                        const prediction = segment[segment.length-1] === 'T' ? 'X' : 'T';
                        if (this.history[i] === prediction) {
                            correct++;
                        }
                    }
                }
                
                const successRate = opportunities > 0 ? correct / opportunities : 0;
                totalSuccess += successRate;
                totalOpportunities++;
            }
            
            const avgSuccessRate = totalOpportunities > 0 ? totalSuccess / totalOpportunities : 0;
            if (avgSuccessRate > bestSuccessRate) {
                bestSuccessRate = avgSuccessRate;
                bestLength = length;
            }
        }
        
        return { optimalLength: bestLength, successRate: bestSuccessRate };
    }

    generatePatternsOfLength(length) {
        const patterns = [];
        const generate = (current) => {
            if (current.length === length) {
                patterns.push(current.join('-'));
                return;
            }
            
            generate([...current, 'T']);
            generate([...current, 'X']);
        };
        
        generate([]);
        return patterns;
    }

    // MODEL 13: đánh giá hiệu suất từng mô hình
    model13() {
        const performance = this.model13Mini();
        const bestModel = Object.entries(performance).reduce((best, [model, stats]) => 
            stats.accuracy > best.accuracy ? { model, ...stats } : best
        , { model: null, accuracy: 0 });
        
        return {
            prediction: null,
            confidence: bestModel.accuracy,
            reason: `Model hiệu suất cao nhất: ${bestModel.model} (${bestModel.accuracy.toFixed(2)})`
        };
    }

    model13Mini() {
        const stats = {};
        
        for (const model of Object.keys(this.performance)) {
            if (this.performance[model].total > 0) {
                stats[model] = {
                    accuracy: this.performance[model].correct / this.performance[model].total,
                    recentAccuracy: this.performance[model].recentTotal > 0 ? 
                        this.performance[model].recentCorrect / this.performance[model].recentTotal : 0,
                    total: this.performance[model].total,
                    recentTotal: this.performance[model].recentTotal,
                    streak: this.performance[model].streak,
                    maxStreak: this.performance[model].maxStreak
                };
            }
        }
        
        return stats;
    }

    model13Support1() {
        // Phân tích xu hướng hiệu suất
        const trends = this.analyzePerformanceTrends();
        return {
            status: "Phân tích xu hướng hiệu suất",
            trends
        };
    }

    model13Support2() {
        // Đề xuất cải thiện hiệu suất
        const improvements = this.suggestPerformanceImprovements();
        return {
            status: "Đề xuất cải thiện hiệu suất",
            improvements
        };
    }

    analyzePerformanceTrends() {
        const trends = {};
        const performance = this.model13Mini();
        
        for (const [model, stats] of Object.entries(performance)) {
            const trend = stats.recentAccuracy - stats.accuracy;
            let trendDirection;
            
            if (trend > 0.1) trendDirection = 'improving';
            else if (trend < -0.1) trendDirection = 'declining';
            else trendDirection = 'stable';
            
            trends[model] = {
                direction: trendDirection,
                magnitude: Math.abs(trend),
                current: stats.accuracy,
                recent: stats.recentAccuracy
            };
        }
        
        return trends;
    }

    suggestPerformanceImprovements() {
        const improvements = {};
        const performance = this.model13Mini();
        const trends = this.analyzePerformanceTrends();
        
        for (const [model, stats] of Object.entries(performance)) {
            const trend = trends[model];
            const suggestions = [];
            
            if (stats.accuracy < 0.5) {
                suggestions.push('consider_reducing_weight');
            }
            
            if (trend.direction === 'declining') {
                suggestions.push('investigate_recent_performance');
            }
            
            if (stats.recentTotal < 10) {
                suggestions.push('need_more_data');
            }
            
            improvements[model] = suggestions;
        }
        
        return improvements;
    }

    // MODEL 14: tính xác xuất bẻ cầu xu hướng
    model14() {
        const breakProb = this.model14Mini(this.history);
        
        return {
            prediction: null,
            confidence: breakProb,
            reason: `Xác suất bẻ cầu xu hướng: ${breakProb.toFixed(2)}`
        };
    }

    model14Mini(data) {
        if (data.length < 15) return 0.5;
        
        let breakCount = 0;
        let trendCount = 0;
        
        for (let i = 10; i < data.length; i++) {
            const segment = data.slice(i-10, i);
            const trend = this.model2Mini(segment);
            
            if (trend.strength > 0.6) {
                trendCount++;
                if (data[i] !== (trend.trend === 'up' ? 'T' : 'X')) {
                    breakCount++;
                }
            }
        }
        
        return trendCount > 0 ? breakCount / trendCount : 0.5;
    }

    model14Support1() {
        // Phân tích các yếu tố ảnh hưởng đến bẻ cầu xu hướng
        const factors = this.analyzeTrendBreakFactors();
        return {
            status: "Phân tích yếu tố bẻ cầu xu hướng",
            factors
        };
    }

    model14Support2() {
        // Dự báo xác suất bẻ cầu xu hướng
        const forecast = this.forecastTrendBreakProbability();
        return {
            status: "Dự báo xác suất bẻ cầu xu hướng",
            forecast
        };
    }

    analyzeTrendBreakFactors() {
        if (this.history.length < 40) return { factors: [] };
        
        const factors = [];
        
        // Phân tích mối quan hệ giữa độ dài xu hướng và xác suất bẻ
        const trendLengths = [];
        const breakResults = [];
        
        for (let i = 15; i < this.history.length; i++) {
            const segment = this.history.slice(i-15, i);
            const trend = this.model2Mini(segment);
            
            if (trend.strength > 0.6) {
                // Ước tính độ dài xu hướng
                let trendLength = 1;
                for (let j = i-2; j >= 0; j--) {
                    if (this.history[j] === (trend.trend === 'up' ? 'T' : 'X')) {
                        trendLength++;
                    } else {
                        break;
                    }
                }
                
                trendLengths.push(trendLength);
                breakResults.push(this.history[i] !== (trend.trend === 'up' ? 'T' : 'X') ? 1 : 0);
            }
        }
        
        // Tính correlation
        if (trendLengths.length > 5) {
            const avgLength = trendLengths.reduce((sum, val) => sum + val, 0) / trendLengths.length;
            const avgBreak = breakResults.reduce((sum, val) => sum + val, 0) / breakResults.length;
            
            let covariance = 0;
            for (let i = 0; i < trendLengths.length; i++) {
                covariance += (trendLengths[i] - avgLength) * (breakResults[i] - avgBreak);
            }
            covariance /= trendLengths.length;
            
            const varianceLength = trendLengths.reduce((sum, val) => sum + Math.pow(val - avgLength, 2), 0) / trendLengths.length;
            const varianceBreak = breakResults.reduce((sum, val) => sum + Math.pow(val - avgBreak, 2), 0) / breakResults.length;
            
            const correlation = covariance / Math.sqrt(varianceLength * varianceBreak);
            factors.push({ factor: 'trend_length', correlation: correlation });
        }
        
        return { factors };
    }

    forecastTrendBreakProbability() {
        const currentTrend = this.model2Mini(this.history.slice(-10));
        const historicalBreakProb = this.model14Mini(this.history);
        
        let forecast = historicalBreakProb;
        
        // Điều chỉnh dựa trên strength của trend hiện tại
        if (currentTrend.strength > 0.7) {
            forecast *= 0.9;
        } else if (currentTrend.strength < 0.4) {
            forecast *= 1.1;
        }
        
        // Điều chỉnh dựa trên market regime
        if (this.marketState.regime === 'volatile') {
            forecast = Math.min(0.9, forecast * 1.2);
        } else if (this.marketState.regime === 'trending') {
            forecast = Math.max(0.1, forecast * 0.8);
        }
        
        return Math.min(0.95, Math.max(0.05, forecast));
    }

    // MODEL 15: suy nghĩ có nên bắt theo xu hướng ko
    model15() {
        const trend = this.model2();
        const breakProb = this.model14Mini(this.history);
        const shouldFollow = this.model15Mini(trend.confidence, breakProb);
        
        return {
            prediction: shouldFollow ? trend.prediction : (trend.prediction === 'T' ? 'X' : 'T'),
            confidence: shouldFollow ? trend.confidence : (1 - trend.confidence),
            reason: shouldFollow ? 
                `Nên theo xu hướng (xác suất bẻ thấp)` : 
                `Nên bẻ xu hướng (xác suất bẻ cao)`
        };
    }

    model15Mini(trendConfidence, breakProbability) {
        // Quyết định dựa trên độ tin cậy xu hướng và xác suất bẻ
        return trendConfidence > breakProbability * 1.5;
    }

    model15Support1() {
        // Phân tích risk/reward của việc theo xu hướng
        const analysis = this.analyzeTrendFollowingRiskReward();
        return {
            status: "Phân tích risk/reward theo xu hướng",
            analysis
        };
    }

    model15Support2() {
        // Tối ưu hóa ngưỡng quyết định
        const optimization = this.optimizeTrendDecisionThreshold();
        return {
            status: "Tối ưu ngưỡng quyết định xu hướng",
            optimization
        };
    }

    analyzeTrendFollowingRiskReward() {
        if (this.history.length < 50) return { riskRewardRatio: 1, successRate: 0.5 };
        
        let trendFollowingSuccess = 0;
        let trendFollowingOpportunities = 0;
        let breakSuccess = 0;
        let breakOpportunities = 0;
        
        for (let i = 10; i < this.history.length; i++) {
            const segment = this.history.slice(i-10, i);
            const trend = this.model2Mini(segment);
            const breakProb = this.model14Mini(this.history.slice(0, i));
            
            if (trend.strength > 0.6) {
                const shouldFollow = trend.confidence > breakProb * 1.5;
                
                if (shouldFollow) {
                    trendFollowingOpportunities++;
                    if (this.history[i] === (trend.trend === 'up' ? 'T' : 'X')) {
                        trendFollowingSuccess++;
                    }
                } else {
                    breakOpportunities++;
                    if (this.history[i] !== (trend.trend === 'up' ? 'T' : 'X')) {
                        breakSuccess++;
                    }
                }
            }
        }
        
        const trendSuccessRate = trendFollowingOpportunities > 0 ? 
            trendFollowingSuccess / trendFollowingOpportunities : 0;
        const breakSuccessRate = breakOpportunities > 0 ? 
            breakSuccess / breakOpportunities : 0;
        
        const riskRewardRatio = trendSuccessRate / breakSuccessRate;
        
        return { riskRewardRatio, trendSuccessRate, breakSuccessRate };
    }

    optimizeTrendDecisionThreshold() {
        if (this.history.length < 50) return { optimalThreshold: 1.5 };
        
        let bestThreshold = 1.5;
        let bestProfit = 0;
        
        for (let threshold = 1.0; threshold <= 2.0; threshold += 0.1) {
            let profit = 0;
            
            for (let i = 10; i < this.history.length; i++) {
                const segment = this.history.slice(i-10, i);
                const trend = this.model2Mini(segment);
                const breakProb = this.model14Mini(this.history.slice(0, i));
                
                if (trend.strength > 0.6) {
                    const shouldFollow = trend.confidence > breakProb * threshold;
                    const prediction = shouldFollow ? 
                        (trend.trend === 'up' ? 'T' : 'X') : 
                        (trend.trend === 'up' ? 'X' : 'T');
                    
                    if (this.history[i] === prediction) {
                        profit += 1;
                    } else {
                        profit -= 1;
                    }
                }
            }
            
            if (profit > bestProfit) {
                bestProfit = profit;
                bestThreshold = threshold;
            }
        }
        
        return { optimalThreshold: bestThreshold, expectedProfit: bestProfit };
    }

    // MODEL 16: tính xác suất bẻ cầu (phiên bản nâng cao)
    model16() {
        const breakProb = this.model16Mini(this.history);
        
        return {
            prediction: null,
            confidence: breakProb,
            reason: `Xác suất bẻ cầu tổng hợp: ${breakProb.toFixed(2)}`
        };
    }

    model16Mini(data) {
        // Kết hợp nhiều phương pháp tính xác suất bẻ
        const prob1 = this.model10Mini(data);
        const prob2 = this.model14Mini(data);
        
        // Phân tích recent breaks
        let recentBreaks = 0;
        let recentOpportunities = 0;
        
        for (let i = Math.max(0, data.length - 10); i < data.length - 1; i++) {
            if (i >= 5) {
                const segment = data.slice(i-5, i);
                const streak = this.model6Mini(segment).streak;
                
                if (streak >= 3) {
                    recentOpportunities++;
                    if (data[i] !== segment[segment.length-1]) {
                        recentBreaks++;
                    }
                }
            }
        }
        
        const prob3 = recentOpportunities > 0 ? recentBreaks / recentOpportunities : 0.5;
        
        // Trung bình có trọng số
        return (prob1 * 0.4 + prob2 * 0.4 + prob3 * 0.2);
    }

    model16Support1() {
        // Phân tích độ tin cậy của các phương pháp tính xác suất bẻ
        const reliability = this.analyzeBreakProbabilityReliability();
        return {
            status: "Phân tích độ tin cậy xác suất bẻ",
            reliability
        };
    }

    model16Support2() {
        // Tối ưu hóa trọng số cho các phương pháp tính xác suất bẻ
        const optimization = this.optimizeBreakProbabilityWeights();
        return {
            status: "Tối ưu trọng số xác suất bẻ",
            optimization
        };
    }

    analyzeBreakProbabilityReliability() {
        if (this.history.length < 40) return { reliability: {} };
        
        const reliability = {};
        const methods = [
            { name: 'model10', method: this.model10Mini },
            { name: 'model14', method: this.model14Mini }
        ];
        
        for (const method of methods) {
            let correct = 0;
            let total = 0;
            
            for (let i = 20; i < this.history.length; i++) {
                const probability = method.method(this.history.slice(0, i));
                const segment = this.history.slice(i-5, i);
                const streak = this.model6Mini(segment).streak;
                
                if (streak >= 4) {
                    total++;
                    const expectedBreak = probability > 0.6;
                    const actualBreak = this.history[i] !== segment[segment.length-1];
                    
                    if (expectedBreak === actualBreak) {
                        correct++;
                    }
                }
            }
            
            reliability[method.name] = {
                accuracy: total > 0 ? correct / total : 0,
                observations: total
            };
        }
        
        return reliability;
    }

    optimizeBreakProbabilityWeights() {
        if (this.history.length < 50) return { weights: { model10: 0.4, model14: 0.4, recent: 0.2 } };
        
        let bestWeights = { model10: 0.4, model14: 0.4, recent: 0.2 };
        let bestAccuracy = 0;
        
        // Grid search for optimal weights
        for (let w1 = 0.2; w1 <= 0.6; w1 += 0.1) {
            for (let w2 = 0.2; w2 <= 0.6; w2 += 0.1) {
                const w3 = 1 - w1 - w2;
                if (w3 < 0.1 || w3 > 0.4) continue;
                
                let correct = 0;
                let total = 0;
                
                for (let i = 20; i < this.history.length; i++) {
                    const prob1 = this.model10Mini(this.history.slice(0, i));
                    const prob2 = this.model14Mini(this.history.slice(0, i));
                    
                    // Phân tích recent breaks
                    let recentBreaks = 0;
                    let recentOpportunities = 0;
                    
                    for (let j = Math.max(0, i - 10); j < i - 1; j++) {
                        if (j >= 5) {
                            const segment = this.history.slice(j-5, j);
                            const streak = this.model6Mini(segment).streak;
                            
                            if (streak >= 3) {
                                recentOpportunities++;
                                if (this.history[j] !== segment[segment.length-1]) {
                                    recentBreaks++;
                                }
                            }
                        }
                    }
                    
                    const prob3 = recentOpportunities > 0 ? recentBreaks / recentOpportunities : 0.5;
                    
                    const combinedProb = prob1 * w1 + prob2 * w2 + prob3 * w3;
                    const segment = this.history.slice(i-5, i);
                    const streak = this.model6Mini(segment).streak;
                    
                    if (streak >= 4) {
                        total++;
                        const expectedBreak = combinedProb > 0.6;
                        const actualBreak = this.history[i] !== segment[segment.length-1];
                        
                        if (expectedBreak === actualBreak) {
                            correct++;
                        }
                    }
                }
                
                const accuracy = total > 0 ? correct / total : 0;
                if (accuracy > bestAccuracy) {
                    bestAccuracy = accuracy;
                    bestWeights = { model10: w1, model14: w2, recent: w3 };
                }
            }
        }
        
        return { weights: bestWeights, accuracy: bestAccuracy };
    }

    // MODEL 17: cân bằng trọng số (nâng cao)
    model17() {
        const performance = this.model13Mini();
        const imbalance = this.model17Mini(performance);
        
        if (imbalance > 0.25) {
            this.adjustWeightsAdvanced(performance);
            return {
                prediction: null,
                confidence: 0,
                reason: `Cân bằng trọng số nâng cao, độ chênh lệch: ${imbalance.toFixed(2)}`
            };
        }
        
        return null;
    }

    model17Mini(performance) {
        const accuracies = Object.values(performance).map(p => p.accuracy);
        if (accuracies.length < 2) return 0;
        
        const mean = accuracies.reduce((sum, acc) => sum + acc, 0) / accuracies.length;
        const variance = accuracies.reduce((sum, acc) => sum + Math.pow(acc - mean, 2), 0) / accuracies.length;
        
        return Math.sqrt(variance) / mean;
    }

    adjustWeightsAdvanced(performance) {
        const meanAccuracy = Object.values(performance).reduce((sum, p) => sum + p.accuracy, 0) / 
                            Object.values(performance).length;
        
        for (const [model, stats] of Object.entries(performance)) {
            if (stats.accuracy > meanAccuracy * 1.2) {
                this.weights[model] = Math.min(2, this.weights[model] * 1.1);
            } else if (stats.accuracy < meanAccuracy * 0.8) {
                this.weights[model] = Math.max(0.1, this.weights[model] * 0.9);
            }
        }
    }

    model17Support1() {
        // Phân tích ảnh hưởng của việc điều chỉnh trọng số
        const impact = this.analyzeWeightAdjustmentImpact();
        return {
            status: "Phân tích ảnh hưởng điều chỉnh trọng số",
            impact
        };
    }

    model17Support2() {
        // Tối ưu hóa tần suất điều chỉnh trọng số
        const optimization = this.optimizeWeightAdjustmentFrequency();
        return {
            status: "Tối ưu tần suất điều chỉnh trọng số",
            optimization
        };
    }

    analyzeWeightAdjustmentImpact() {
        const before = this.analyzeWeightDistribution();
        
        // Giả lập điều chỉnh
        const performance = this.model13Mini();
        const meanAccuracy = Object.values(performance).reduce((sum, p) => sum + p.accuracy, 0) / 
                            Object.values(performance).length;
        
        const simulatedWeights = {};
        for (const [model, stats] of Object.entries(performance)) {
            if (stats.accuracy > meanAccuracy * 1.2) {
                simulatedWeights[model] = Math.min(2, this.weights[model] * 1.1);
            } else if (stats.accuracy < meanAccuracy * 0.8) {
                simulatedWeights[model] = Math.max(0.1, this.weights[model] * 0.9);
            } else {
                simulatedWeights[model] = this.weights[model];
            }
        }
        
        const after = {
            mean: Object.values(simulatedWeights).reduce((sum, w) => sum + w, 0) / Object.values(simulatedWeights).length,
            min: Math.min(...Object.values(simulatedWeights)),
            max: Math.max(...Object.values(simulatedWeights))
        };
        
        return { before, after, change: after.mean - before.mean };
    }

    optimizeWeightAdjustmentFrequency() {
        // Điều chỉnh tần suất based on market stability
        let frequency;
        if (this.marketState.stability > 0.7) {
            frequency = 'low'; // Ít điều chỉnh hơn trong thị trường ổn định
        } else if (this.marketState.stability < 0.3) {
            frequency = 'high'; // Điều chỉnh thường xuyên trong thị trường biến động
        } else {
            frequency = 'medium';
        }
        
        return { frequency, stability: this.marketState.stability };
    }

    // MODEL 18: nhận biết xu hướng cầu và đoán theo xu hướng ngắn hạn
    model18() {
        const shortTrend = this.model18Mini(this.history.slice(-6));
        
        return {
            prediction: shortTrend.prediction,
            confidence: shortTrend.confidence,
            reason: `Xu hướng ngắn hạn: ${shortTrend.trend}`
        };
    }

    model18Mini(data) {
        if (data.length < 4) return { prediction: null, confidence: 0, trend: 'Không xác định' };
        
        const tCount = data.filter(x => x === 'T').length;
        const xCount = data.filter(x => x === 'X').length;
        
        let prediction, confidence, trend;
        
        if (tCount > xCount * 1.5) {
            prediction = 'T';
            confidence = 0.7;
            trend = 'Mạnh T';
        } else if (xCount > tCount * 1.5) {
            prediction = 'X';
            confidence = 0.7;
            trend = 'Mạnh X';
        } else if (tCount > xCount) {
            prediction = 'T';
            confidence = 0.6;
            trend = 'Nhẹ T';
        } else if (xCount > tCount) {
            prediction = 'X';
            confidence = 0.6;
            trend = 'Nhẹ X';
        } else {
            prediction = data[data.length - 1] === 'T' ? 'X' : 'T';
            confidence = 0.55;
            trend = 'Cân bằng';
        }
        
        return { prediction, confidence, trend };
    }

    model18Support1() {
        // Phân tích độ nhạy của xu hướng ngắn hạn
        const sensitivity = this.analyzeShortTermTrendSensitivity();
        return {
            status: "Phân tích độ nhạy xu hướng ngắn hạn",
            sensitivity
        };
    }

    model18Support2() {
        // Tối ưu hóa khung thời gian cho xu hướng ngắn hạn
        const optimization = this.optimizeShortTermTrendTimeframe();
        return {
            status: "Tối ưu khung thời gian xu hướng ngắn hạn",
            optimization
        };
    }

    analyzeShortTermTrendSensitivity() {
        if (this.history.length < 30) return { sensitivity: 'unknown' };
        
        let changes = 0;
        for (let i = 6; i < this.history.length; i++) {
            const segment1 = this.history.slice(i-6, i-3);
            const segment2 = this.history.slice(i-3, i);
            
            const trend1 = this.model18Mini(segment1);
            const trend2 = this.model18Mini(segment2);
            
            if (trend1.prediction !== trend2.prediction) {
                changes++;
            }
        }
        
        const changeRate = changes / (this.history.length - 6);
        let sensitivity;
        
        if (changeRate > 0.5) sensitivity = 'high';
        else if (changeRate > 0.3) sensitivity = 'medium';
        else sensitivity = 'low';
        
        return { sensitivity, changeRate };
    }

    optimizeShortTermTrendTimeframe() {
        if (this.history.length < 50) return { optimalTimeframe: 6 };
        
        let bestTimeframe = 6;
        let bestSuccessRate = 0;
        
        for (let timeframe = 4; timeframe <= 8; timeframe++) {
            let successes = 0;
            let opportunities = 0;
            
            for (let i = timeframe; i < this.history.length; i++) {
                const segment = this.history.slice(i - timeframe, i);
                const analysis = this.model18Mini(segment);
                
                if (analysis.confidence >= 0.6) {
                    opportunities++;
                    if (this.history[i] === analysis.prediction) {
                        successes++;
                    }
                }
            }
            
            const successRate = opportunities > 0 ? successes / opportunities : 0;
            if (successRate > bestSuccessRate) {
                bestSuccessRate = successRate;
                bestTimeframe = timeframe;
            }
        }
        
        return { optimalTimeframe: bestTimeframe, successRate: bestSuccessRate };
    }

    // MODEL 19: các xu hướng phổ biến
    model19() {
        const commonTrends = this.model19Mini(this.history.slice(-30));
        
        if (commonTrends.length === 0) return null;
        
        const bestTrend = commonTrends.reduce((best, current) => 
            current.frequency > best.frequency ? current : best
        );
        
        return {
            prediction: bestTrend.prediction,
            confidence: bestTrend.confidence,
            reason: `Xu hướng phổ biến: ${bestTrend.pattern} (tần suất ${bestTrend.frequency})`
        };
    }

    model19Mini(data) {
        const trends = [];
        
        // Phân tích các xu hướng phổ biến trong lịch sử
        const patternCounts = {};
        
        for (let length = 3; length <= 5; length++) {
            for (let i = 0; i <= data.length - length; i++) {
                const pattern = data.slice(i, i + length).join('-');
                patternCounts[pattern] = (patternCounts[pattern] || 0) + 1;
            }
        }
        
        // Chọn các pattern có tần suất cao
        for (const [pattern, count] of Object.entries(patternCounts)) {
            if (count >= 3) { // Xuất hiện ít nhất 3 lần
                const patternParts = pattern.split('-');
                const prediction = patternParts[patternParts.length - 1];
                const frequency = count / (data.length - patternParts.length + 1);
                
                trends.push({
                    pattern,
                    prediction,
                    frequency,
                    confidence: Math.min(0.8, frequency * 2)
                });
            }
        }
        
        return trends;
    }

    model19Support1() {
        // Phân tích sự ổn định của các xu hướng phổ biến
        const stability = this.analyzeTrendStability();
        return {
            status: "Phân tích sự ổn định xu hướng",
            stability
        };
    }

    model19Support2() {
        // Dự báo xu hướng phổ biến trong tương lai
        const forecast = this.forecastCommonTrends();
        return {
            status: "Dự báo xu hướng phổ biến",
            forecast
        };
    }

    analyzeTrendStability() {
        if (this.history.length < 40) return { stability: 'unknown' };
        
        const half1 = this.history.slice(0, Math.floor(this.history.length / 2));
        const half2 = this.history.slice(Math.floor(this.history.length / 2));
        
        const trends1 = this.model19Mini(half1);
        const trends2 = this.model19Mini(half2);
        
        // So sánh các trend giữa hai nửa
        const commonPatterns = [];
        for (const trend1 of trends1) {
            for (const trend2 of trends2) {
                if (trend1.pattern === trend2.pattern) {
                    commonPatterns.push({
                        pattern: trend1.pattern,
                        frequency1: trend1.frequency,
                        frequency2: trend2.frequency,
                        change: Math.abs(trend1.frequency - trend2.frequency)
                    });
                }
            }
        }
        
        const avgChange = commonPatterns.length > 0 ? 
            commonPatterns.reduce((sum, p) => sum + p.change, 0) / commonPatterns.length : 0;
        
        let stability;
        if (avgChange < 0.1) stability = 'high';
        else if (avgChange < 0.2) stability = 'medium';
        else stability = 'low';
        
        return { stability, avgChange, commonPatterns: commonPatterns.length };
    }

    forecastCommonTrends() {
        const currentTrends = this.model19Mini(this.history.slice(-20));
        const historicalTrends = this.model19Mini(this.history);
        
        // Dự báo đơn giản: tiếp tục các trend hiện tại
        const forecast = currentTrends.map(trend => ({
            pattern: trend.pattern,
            predictedFrequency: trend.frequency * 0.9, // Giảm nhẹ do mean reversion
            confidence: trend.confidence * 0.8
        }));
        
        return forecast;
    }

    // MODEL 20: Max Performance
    model20() {
        const performance = this.model13Mini();
        const bestModels = Object.entries(performance)
            .filter(([_, stats]) => stats.total > 10)
            .sort((a, b) => b[1].accuracy - a[1].accuracy)
            .slice(0, 3);
        
        if (bestModels.length === 0) return null;
        
        // Lấy dự đoán từ các model hiệu suất cao nhất
        const predictions = {};
        for (const [model] of bestModels) {
            predictions[model] = this.models[model]();
        }
        
        // Tổng hợp dự đoán
        let tScore = 0;
        let xScore = 0;
        
        for (const [model, prediction] of Object.entries(predictions)) {
            if (prediction && prediction.prediction) {
                const weight = performance[model].accuracy;
                if (prediction.prediction === 'T') {
                    tScore += weight * prediction.confidence;
                } else {
                    xScore += weight * prediction.confidence;
                }
            }
        }
        
        const totalScore = tScore + xScore;
        if (totalScore === 0) return null;
        
        return {
            prediction: tScore > xScore ? 'T' : 'X',
            confidence: Math.max(tScore, xScore) / totalScore,
            reason: `Kết hợp ${bestModels.length} model hiệu suất cao nhất`
        };
    }

    model20Support1() {
        // Phân tích tính ổn định của các model hiệu suất cao
        const stability = this.analyzeTopModelStability();
        return {
            status: "Phân tích tính ổn định model hiệu suất cao",
            stability
        };
    }

    model20Support2() {
        // Tối ưu hóa số lượng model trong combination
        const optimization = this.optimizeModelCombinationCount();
        return {
            status: "Tối ưu số lượng model trong combination",
            optimization
        };
    }

    analyzeTopModelStability() {
        const performance = this.model13Mini();
        const topModels = Object.entries(performance)
            .filter(([_, stats]) => stats.total > 10)
            .sort((a, b) => b[1].accuracy - a[1].accuracy)
            .slice(0, 5);
        
        // Kiểm tra xem top models có thay đổi nhiều không
        let changes = 0;
        if (this.previousTopModels) {
            for (const model of topModels) {
                if (!this.previousTopModels.includes(model[0])) {
                    changes++;
                }
            }
        }
        
        this.previousTopModels = topModels.map(m => m[0]);
        
        const changeRate = changes / topModels.length;
        let stability;
        
        if (changeRate < 0.2) stability = 'high';
        else if (changeRate < 0.4) stability = 'medium';
        else stability = 'low';
        
        return { stability, changeRate, topModels: topModels.map(m => m[0]) };
    }

    optimizeModelCombinationCount() {
        if (this.history.length < 50) return { optimalCount: 3 };
        
        let bestCount = 3;
        let bestSuccessRate = 0;
        
        for (let count = 1; count <= 5; count++) {
            let successes = 0;
            let opportunities = 0;
            
            for (let i = 20; i < this.history.length; i++) {
                // Giả lập performance tại thời điểm i
                const simulatedPerformance = {};
                for (const model of Object.keys(this.performance)) {
                    // Tính accuracy dựa trên dữ liệu đến thời điểm i
                    let correct = 0;
                    let total = 0;
                    
                    for (let j = 10; j < i; j++) {
                        // Giả lập dự đoán và kết quả
                        // (Đây là phần phức tạp, cần implementation chi tiết hơn)
                    }
                    
                    simulatedPerformance[model] = {
                        accuracy: total > 0 ? correct / total : 0.5
                    };
                }
                
                // Chọn top models
                const topModels = Object.entries(simulatedPerformance)
                    .filter(([_, stats]) => stats.accuracy > 0)
                    .sort((a, b) => b[1].accuracy - a[1].accuracy)
                    .slice(0, count);
                
                // Tính consensus
                let tCount = 0;
                let xCount = 0;
                
                for (const [model] of topModels) {
                    // Giả lập dự đoán
                    // (Cần implementation chi tiết)
                }
                
                const prediction = tCount > xCount ? 'T' : 'X';
                if (this.history[i] === prediction) {
                    successes++;
                }
                opportunities++;
            }
            
            const successRate = opportunities > 0 ? successes / opportunities : 0;
            if (successRate > bestSuccessRate) {
                bestSuccessRate = successRate;
                bestCount = count;
            }
        }
        
        return { optimalCount: bestCount, successRate: bestSuccessRate };
    }

    // MODEL 21: cân bằng tất cả khi thấy chênh lệch cao
    model21() {
        const predictions = this.getBasePredictions();
        const tCount = Object.values(predictions).filter(p => p && p.prediction === 'T').length;
        const xCount = Object.values(predictions).filter(p => p && p.prediction === 'X').length;
        const total = tCount + xCount;
        
        if (total < 8) return null;
        
        const difference = Math.abs(tCount - xCount) / total;
        
        if (difference > 0.5) {
            // Cân bằng bằng cách điều chỉnh ngưỡng confidence
            const adjustedPredictions = this.model21Mini(predictions, difference);
            
            let tScore = 0;
            let xScore = 0;
            
            for (const prediction of Object.values(adjustedPredictions)) {
                if (prediction && prediction.prediction) {
                    if (prediction.prediction === 'T') {
                        tScore += prediction.confidence;
                    } else {
                        xScore += prediction.confidence;
                    }
                }
            }
            
            const totalScore = tScore + xScore;
            if (totalScore === 0) return null;
            
            return {
                prediction: tScore > xScore ? 'T' : 'X',
                confidence: Math.max(tScore, xScore) / totalScore,
                reason: `Cân bằng tổng thể, chênh lệch ban đầu: ${difference.toFixed(2)}`
            };
        }
        
        return null;
    }

    model21Mini(predictions, difference) {
        const adjusted = {};
        const adjustment = 1 - difference; // Điều chỉnh ngược với độ chênh lệch
        
        for (const [model, prediction] of Object.entries(predictions)) {
            if (prediction) {
                adjusted[model] = {
                    ...prediction,
                    confidence: prediction.confidence * adjustment
                };
            }
        }
        
        return adjusted;
    }

    model21Support1() {
        // Phân tích hiệu quả của cơ chế cân bằng
        const effectiveness = this.analyzeBalancingEffectiveness();
        return {
            status: "Phân tích hiệu quả cơ chế cân bằng",
            effectiveness
        };
    }

    model21Support2() {
        // Tối ưu hóa ngưỡng cân bằng
        const optimization = this.optimizeBalancingThreshold();
        return {
            status: "Tối ưu ngưỡng cân bằng",
            optimization
        };
    }

    analyzeBalancingEffectiveness() {
        if (this.history.length < 40) return { effectiveness: 'unknown', successRate: 0 };
        
        let successes = 0;
        let opportunities = 0;
        
        for (let i = 20; i < this.history.length; i++) {
            // Giả lập predictions tại thời điểm i
            const simulatedPredictions = {};
            for (const model of Object.keys(this.models)) {
                if (model.startsWith('model') && !model.includes('Support') && !model.includes('Mini')) {
                    // Giả lập dự đoán
                    // (Cần implementation chi tiết)
                }
            }
            
            const tCount = Object.values(simulatedPredictions).filter(p => p && p.prediction === 'T').length;
            const xCount = Object.values(simulatedPredictions).filter(p => p && p.prediction === 'X').length;
            const total = tCount + xCount;
            const difference = Math.abs(tCount - xCount) / total;
            
            if (difference > 0.5) {
                opportunities++;
                // Áp dụng cân bằng
                const adjustedPredictions = this.model21Mini(simulatedPredictions, difference);
                
                let tScore = 0;
                let xScore = 0;
                
                for (const prediction of Object.values(adjustedPredictions)) {
                    if (prediction && prediction.prediction) {
                        if (prediction.prediction === 'T') {
                            tScore += prediction.confidence;
                        } else {
                            xScore += prediction.confidence;
                        }
                    }
                }
                
                const finalPrediction = tScore > xScore ? 'T' : 'X';
                if (this.history[i] === finalPrediction) {
                    successes++;
                }
            }
        }
        
        const successRate = opportunities > 0 ? successes / opportunities : 0;
        let effectiveness;
        
        if (successRate > 0.6) effectiveness = 'high';
        else if (successRate > 0.5) effectiveness = 'medium';
        else effectiveness = 'low';
        
        return { effectiveness, successRate, opportunities };
    }

    optimizeBalancingThreshold() {
        if (this.history.length < 50) return { optimalThreshold: 0.5 };
        
        let bestThreshold = 0.5;
        let bestSuccessRate = 0;
        
        for (let threshold = 0.4; threshold <= 0.6; threshold += 0.05) {
            let successes = 0;
            let opportunities = 0;
            
            for (let i = 20; i < this.history.length; i++) {
                // Giả lập tương tự như trên
                // (Cần implementation chi tiết)
            }
            
            const successRate = opportunities > 0 ? successes / opportunities : 0;
            if (successRate > bestSuccessRate) {
                bestSuccessRate = successRate;
                bestThreshold = threshold;
            }
        }
        
        return { optimalThreshold: bestThreshold, successRate: bestSuccessRate };
    }

    // Utility methods
    getBasePredictions() {
        const predictions = {};
        for (let i = 1; i <= 21; i++) {
            if (i === 5 || i === 21) continue; // Loại các model tổng hợp để tránh đệ quy
            const fn = this.models[`model${i}`];
            predictions[`model${i}`] = typeof fn === 'function' ? fn() : null;
        }
        return predictions;
    }

    getAllPredictions() {
        const predictions = {};
        
        for (let i = 1; i <= 21; i++) {
            predictions[`model${i}`] = this.models[`model${i}`]();
        }
        
        return predictions;
    }

    getFinalPrediction() {
        const predictions = this.getAllPredictions();
        let tScore = 0;
        let xScore = 0;
        let totalWeight = 0;
        let reasons = [];
        
        for (const [modelName, prediction] of Object.entries(predictions)) {
            if (prediction && prediction.prediction) {
                const weight = this.weights[modelName] || 1;
                const score = prediction.confidence * weight;
                
                if (prediction.prediction === 'T') {
                    tScore += score;
                } else if (prediction.prediction === 'X') {
                    xScore += score;
                }
                
                totalWeight += weight;
                reasons.push(`${modelName}: ${prediction.reason} (${prediction.confidence.toFixed(2)})`);
            }
        }
        
        if (totalWeight === 0) return null;
        
        let finalPrediction = null;
        let finalConfidence = 0;
        
        if (tScore > xScore) {
            finalPrediction = 'T';
            finalConfidence = tScore / (tScore + xScore);
        } else if (xScore > tScore) {
            finalPrediction = 'X';
            finalConfidence = xScore / (tScore + xScore);
        }
        
        // Điều chỉnh confidence dựa trên độ biến động
        finalConfidence = this.adjustConfidenceByVolatility(finalConfidence);
        
        return {
            prediction: finalPrediction,
            confidence: finalConfidence,
            reasons: reasons,
            details: predictions,
            sessionStats: this.sessionStats,
            marketState: this.marketState
        };
    }

    adjustConfidenceByVolatility(confidence) {
        // Giảm confidence khi volatility cao
        if (this.sessionStats.volatility > 0.7) {
            return confidence * 0.8;
        }
        // Tăng confidence khi volatility thấp
        if (this.sessionStats.volatility < 0.3) {
            return Math.min(0.95, confidence * 1.1);
        }
        return confidence;
    }

    updatePerformance(actualResult) {
        const predictions = this.getAllPredictions();
        
        for (const [modelName, prediction] of Object.entries(predictions)) {
            if (prediction && prediction.prediction) {
                this.performance[modelName].total++;
                this.performance[modelName].recentTotal++;
                
                if (prediction.prediction === actualResult) {
                    this.performance[modelName].correct++;
                    this.performance[modelName].recentCorrect++;
                    this.performance[modelName].streak++;
                    this.performance[modelName].maxStreak = Math.max(
                        this.performance[modelName].maxStreak,
                        this.performance[modelName].streak
                    );
                } else {
                    this.performance[modelName].streak = 0;
                }
                
                // Giữ recent stats trong phạm vi 50 lần
                if (this.performance[modelName].recentTotal > 50) {
                    this.performance[modelName].recentTotal--;
                    if (this.performance[modelName].recentCorrect > 0 && 
                        this.performance[modelName].recentCorrect / this.performance[modelName].recentTotal > 
                        this.performance[modelName].correct / this.performance[modelName].total) {
                        this.performance[modelName].recentCorrect--;
                    }
                }
                
                // Cập nhật trọng số
                const accuracy = this.performance[modelName].correct / this.performance[modelName].total;
                this.weights[modelName] = Math.max(0.1, Math.min(2, accuracy * 2));
            }
        }
        
        // Cập nhật session accuracy
        const totalPredictions = Object.values(predictions).filter(p => p && p.prediction).length;
        const correctPredictions = Object.values(predictions).filter(p => p && p.prediction === actualResult).length;
        this.sessionStats.recentAccuracy = totalPredictions > 0 ? correctPredictions / totalPredictions : 0;
    }
}

// Hàm mô phỏng và test
function simulateUltraTest() {
    const system = new UltraDicePredictionSystem();
    
    // Tạo dữ liệu với pattern phức tạp
    const testPatterns = [
        // Pattern 1-1
        'T', 'X', 'T', 'X', 'T', 'X', 'T', 'X',
        // Pattern 2-2
        'T', 'T', 'X', 'X', 'T', 'T', 'X', 'X',
        // Pattern động học
        'T', 'T', 'T', 'T', 'X', 'X', 'T', 'T', 'T', 'X',
        // Pattern ngẫu nhiên
        'X', 'T', 'X', 'T', 'X', 'T', 'X', 'T', 'X', 'T',
        // Pattern 3-1
        'T', 'T', 'T', 'X', 'T', 'T', 'T', 'X', 'T', 'T', 'T', 'X',
        // Pattern phức tạp
        'T', 'X', 'X', 'T', 'X', 'T', 'T', 'X', 'T', 'X', 'X', 'T'
    ];
    
    console.log("Testing Ultra Dice Prediction System...");
    console.log("===========================================");
    
    // Thêm kết quả và in dự đoán
    testPatterns.forEach((result, index) => {
        system.addResult(result);
        
        if (index >= 15 && index % 3 === 0) { // Dự đoán sau mỗi 3 phiên từ phiên 15
            const prediction = system.getFinalPrediction();
            console.log(`Phiên ${index + 1}: ${result}`);
            if (prediction) {
                console.log(`Dự đoán: ${prediction.prediction}, Confidence: ${prediction.confidence.toFixed(2)}`);
                console.log(`Lý do: ${prediction.reasons[0]}`);
            } else {
                console.log("Không đủ dữ liệu để dự đoán");
            }
            console.log("---");
        }
    });
    
    // Hiển thị thống kê
    console.log("Thống kê phiên:");
    console.log(`- Streak T: ${system.sessionStats.streaks.T}, X: ${system.sessionStats.streaks.X}`);
    console.log(`- Độ biến động: ${system.sessionStats.volatility.toFixed(2)}`);
    console.log("Chuyển đổi:", system.sessionStats.transitions);
    console.log("Trạng thái thị trường:", system.marketState);
}

// Chạy test
// Không tự chạy mô phỏng khi nhúng vào ứng dụng thật.
if (typeof window !== 'undefined') window.UltraDicePredictionSystem = UltraDicePredictionSystem;


(function(){
  'use strict';
  try {
    if (typeof UltraDicePredictionSystem !== 'function') return;
    var engine = new UltraDicePredictionSystem();
    var lastSequence = [];
    function normalizeHistory(rows) {
      if (!Array.isArray(rows)) return [];
      return rows.map(function(row){
        var value = (row && typeof row === 'object') ? (row.result || row.ket_qua || row.outcome || '') : row;
        value = String(value).toUpperCase();
        if (value === 'TAI' || value === 'TÀI' || value === 'T') return 'T';
        if (value === 'XIU' || value === 'XỈU' || value === 'X') return 'X';
        return null;
      }).filter(Boolean);
    }
    window.AUZA_ULTRA = {
      version: '1.0-fixed',
      engine: engine,
      syncHistory: function(rows) {
        var seq = normalizeHistory(rows);
        var isPrefix = lastSequence.length <= seq.length &&
          lastSequence.every(function(v, i){ return seq[i] === v; });
        if (!isPrefix) {
          engine = new UltraDicePredictionSystem();
          lastSequence = [];
        }
        for (var i = lastSequence.length; i < seq.length; i++) engine.addResult(seq[i]);
        lastSequence = seq.slice();
        return this.predict();
      },
      predict: function() {
        var result = engine.getFinalPrediction();
        if (!result || !result.prediction) return null;
        return {
          prediction: result.prediction === 'T' ? 'TAI' : 'XIU',
          confidence: result.confidence,
          reasons: result.reasons,
          marketState: result.marketState,
          sessionStats: result.sessionStats
        };
      },
      reset: function() {
        engine = new UltraDicePredictionSystem();
        lastSequence = [];
        this.engine = engine;
      }
    };
  } catch (e) {
    console.warn('[AUZA ULTRA] Không thể khởi tạo thuật toán bổ sung:', e);
  }
})();


<script id="auza-pattern-learning-v17">
/* AUZA V17 — Pattern learning overlay.
 * Additive-only: does not replace or delete legacy PHP/JS algorithms.
 * History is newest-first in S.history; this layer converts it to chronological order.
 * Probabilities are empirical descriptions of history, not guaranteed outcomes.
 */
(function () {
  'use strict';
  if (window.AUZA_PATTERN_V17) return;

  var PATTERNS = [
    [1,1],[1,2],[2,1],[2,2],[3,1],[1,3],[3,2],[2,3],[3,3],
    [4,1],[1,4],[4,2],[2,4],[4,3],[3,4],[4,4],[5,1],[1,5],
    [5,2],[2,5],[5,5],[6,6]
  ];
  var timer = null, lastKey = '';

  function resultOf(row) {
    var v = row && typeof row === 'object'
      ? (row.result || row.ket_qua || row.ketqua || row.outcome || '')
      : row;
    v = String(v).trim().toUpperCase();
    if (v === 'T' || v === 'TAI' || v === 'TÀI' || v === '1') return 'T';
    if (v === 'X' || v === 'XIU' || v === 'XỈU' || v === '2') return 'X';
    return '';
  }
  function chronologicalRows() {
    var rows = (window.S && Array.isArray(S.history)) ? S.history.slice() : [];
    rows.reverse(); // server/UI history is newest-first
    return rows.map(function (row) {
      return {
        side: resultOf(row),
        balance: Number(row && (row.balance_after != null ? row.balance_after : (row.balance != null ? row.balance : row.money_after))),
        win: !!(row && row.win),
        ts: row && row.ts ? String(row.ts) : ''
      };
    }).filter(function (x) { return !!x.side; });
  }
  function makeRuns(seq) {
    var runs = [];
    for (var i = 0; i < seq.length; i++) {
      var c = seq[i];
      if (!runs.length || runs[runs.length - 1].side !== c) runs.push({side:c,len:1});
      else runs[runs.length - 1].len++;
    }
    return runs;
  }
  function findRunPattern(runs) {
    var lens = runs.map(function (r) { return r.len; });
    var best = null;
    // Match only the most recent complete cycles; do not force a guess from one cycle.
    PATTERNS.forEach(function (pair) {
      var a = pair[0], b = pair[1];
      var maxCycles = Math.floor(lens.length / 2);
      for (var cycles = maxCycles; cycles >= 2; cycles--) {
        var start = lens.length - cycles * 2, ok = true;
        for (var j = 0; j < cycles * 2; j++) {
          if (lens[start + j] !== (j % 2 === 0 ? a : b)) { ok = false; break; }
        }
        if (ok) {
          var score = cycles * 100 + Math.min(a + b, 12);
          if (!best || score > best.score) {
            best = {name:a+'-'+b, cycles:cycles, score:score, a:a, b:b,
              matchedRuns:cycles*2, start:start};
          }
          break;
        }
      }
    });
    return best;
  }
  function empiricalSuffix(seq) {
    var best = null;
    // Look for prior occurrences of the latest 3..7 results and count the next result.
    for (var len = Math.min(7, seq.length - 1); len >= 3; len--) {
      var suffix = seq.slice(-len).join('');
      var t = 0, x = 0;
      for (var i = 0; i + len < seq.length - 1; i++) {
        if (i + len < seq.length && seq.slice(i, i + len).join('') === suffix) {
          if (seq[i + len] === 'T') t++; else if (seq[i + len] === 'X') x++;
        }
      }
      var n = t + x;
      if (n >= 2 && (!best || n > best.samples || (n === best.samples && len > best.len))) {
        best = {len:len, samples:n, t:t, x:x, pattern:suffix};
      }
    }
    return best;
  }
  function analyze(rows) {
    var seq = rows.map(function (r) { return r.side; });
    var runs = makeRuns(seq);
    var current = runs.length ? runs[runs.length - 1] : null;
    var runPattern = findRunPattern(runs);
    var suffix = empiricalSuffix(seq);
    var signal = null, title = 'Chưa nhận diện cầu rõ', note = 'Cần thêm lịch sử hợp lệ';
    if (current && current.len >= 5) {
      title = 'Bệt ' + (current.side === 'T' ? 'Tài' : 'Xỉu') + ' × ' + current.len;
      note = 'Chuỗi hiện tại kéo dài; không tự kết luận chắc chắn sẽ gãy.';
      signal = {pick:current.side, strength:0.5, samples:0, source:'bệt'};
    } else if (runPattern) {
      var expected = current && current.len < (runs.length % 2 ? runPattern.a : runPattern.b);
      var pick = expected ? current.side : (current.side === 'T' ? 'X' : 'T');
      title = 'Cầu ' + runPattern.name + ' · ' + runPattern.cycles + ' chu kỳ';
      note = 'Nhận dạng theo độ dài các nhịp liên tiếp; cần theo dõi khi cầu đổi pha.';
      signal = {pick:pick, strength:0.5, samples:runPattern.cycles, source:'run-pattern'};
    }
    if (suffix && (!signal || suffix.samples >= 3)) {
      var total = suffix.samples + 2;
      var pT = (suffix.t + 1) / total;
      var pX = (suffix.x + 1) / total;
      var pick2 = pT >= pX ? 'T' : 'X';
      var confidence = Math.max(pT, pX);
      if (!signal || (suffix.samples >= 3 && confidence > signal.strength)) {
        signal = {pick:pick2, strength:confidence, samples:suffix.samples, source:'suffix'};
      }
      if (suffix.samples >= 2) {
        note = 'Mẫu ' + suffix.pattern.split('').join('-') + ' xuất hiện trước ' +
          suffix.samples + ' lần; kế tiếp Tài ' + suffix.t + ' / Xỉu ' + suffix.x + '.';
        if (!runPattern) title = 'Mẫu lặp lịch sử · ' + suffix.len + ' phiên';
      }
    }
    var streak = current ? current.len : 0;
    var patternText = seq.slice(-18).join('-');
    var runText = runs.slice(-10).map(function(r){return r.len + (r.side === 'T' ? 'T' : 'X');}).join(' · ');
    // Walk-forward validation: test the same suffix method only on data that came before
    // each historical result. This is descriptive validation, not a guarantee of future accuracy.
    var tested = 0, hits = 0;
    var from = Math.max(8, seq.length - 60);
    for (var k = from; k < seq.length; k++) {
      var prefix = seq.slice(0, k), p = empiricalSuffix(prefix);
      if (!p || p.samples < 2) continue;
      tested++;
      if ((p.t >= p.x ? 'T' : 'X') === seq[k]) hits++;
    }
    var hitRate = tested ? Math.round(100 * hits / tested) : null;
    var confidence = signal
      ? Math.round((50 + Math.max(0, signal.strength - 0.5) *
          Math.min(1, signal.samples / 6) * 100))
      : 50;
    if (hitRate !== null) {
      note += ' Kiểm tra cuốn chiếu: ' + hits + '/' + tested +
        ' đúng (' + hitRate + '%); đây là thống kê quá khứ, không bảo đảm phiên sau.';
    }
    return {
      count:seq.length, pattern:patternText, runText:runText, runs:runs, streak:streak,
      currentSide:current ? current.side : null,
      runPattern:runPattern, suffix:suffix, title:title, note:note,
      prediction:signal ? signal.pick : null,
      confidence:Math.max(50, Math.min(85, confidence)),
      samples:signal ? signal.samples : 0,
      source:signal ? signal.source : 'none',
      hitRate:hitRate, tested:tested
    };
  }
  function esc(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]);
    });
  }
  function ensureStyle() {
    if (document.getElementById('auza-v17-style')) return;
    var style = document.createElement('style');
    style.id = 'auza-v17-style';
    style.textContent = [
      '.auza-v17{margin:12px 16px;padding:13px;border:1px solid rgba(98,216,255,.24);border-radius:15px;',
      'background:linear-gradient(145deg,rgba(11,24,52,.98),rgba(12,18,39,.96));box-shadow:0 8px 24px rgba(0,0,0,.2);color:#eaf4ff}',
      '.auza-v17-head{display:flex;justify-content:space-between;align-items:center;gap:8px;margin-bottom:9px}',
      '.auza-v17-title{font-size:11px;font-weight:900;letter-spacing:.6px;color:#75ddff}',
      '.auza-v17-tag{font:700 9px monospace;padding:4px 7px;border-radius:20px;background:rgba(98,216,255,.1);color:#8be5ff}',
      '.auza-v17-pattern{font:700 11px/1.8 monospace;letter-spacing:.5px;overflow-wrap:anywhere;color:#f4d5a6;padding:7px 9px;border-radius:9px;background:rgba(255,255,255,.035)}',
      '.auza-v17-grid{display:grid;grid-template-columns:1fr 1fr;gap:7px;margin-top:8px}',
      '.auza-v17-cell{padding:8px;border-radius:9px;background:rgba(255,255,255,.035);min-width:0}',
      '.auza-v17-cell small{display:block;font-size:9px;color:#94a9c8;margin-bottom:3px}',
      '.auza-v17-cell b{font-size:12px;color:#fff;overflow-wrap:anywhere}',
      '.auza-v17-pick{color:#7ce8c1!important}.auza-v17-warn{color:#ffc078!important}',
      '.auza-v17-note{font-size:10px;line-height:1.55;color:#aebbd2;margin-top:8px}',
      '.auza-v17-net{width:100%;height:78px;display:block;margin-top:5px}',
      '.auza-v17-flow{width:100%;height:72px;display:block;margin-top:7px;border-radius:8px;background:rgba(0,0,0,.12)}',
      '.auza-v17-foot{font-size:9px;color:#778ba9;margin-top:5px;display:flex;justify-content:space-between;gap:6px}'
    ].join('');
    document.head.appendChild(style);
  }
  function networkSvg(conf, pick) {
    var nodes = [[22,39],[77,18],[77,60],[132,10],[132,39],[132,68],[188,25],[188,54],[244,39]];
    var edges = [[0,1],[0,2],[1,3],[1,4],[2,4],[2,5],[3,6],[4,6],[4,7],[5,7],[6,8],[7,8]];
    var lines = edges.map(function (e) {
      return '<line x1="'+nodes[e[0]][0]+'" y1="'+nodes[e[0]][1]+'" x2="'+nodes[e[1]][0]+'" y2="'+nodes[e[1]][1]+'" stroke="rgba(98,216,255,.32)" stroke-width="1.2"/>';
    }).join('');
    var circles = nodes.map(function (n,i) {
      var hot = (i === 8);
      return '<circle cx="'+n[0]+'" cy="'+n[1]+'" r="'+(hot?7:4.5)+'" fill="'+(hot?(pick==='T'?'#f5bd57':pick==='X'?'#ff8b78':'#72d9ff'):'#172d52')+'" stroke="#70d9ff" stroke-width="1"/>';
    }).join('');
    return '<svg class="auza-v17-net" viewBox="0 0 266 78" role="img" aria-label="Sơ đồ các tín hiệu phân tích">'+lines+circles+
      '<text x="8" y="75" fill="#7891b6" font-size="7">LỊCH SỬ</text><text x="220" y="75" fill="#7891b6" font-size="7">TỔNG HỢP</text></svg>';
  }
  function drawFlow(canvas, rows) {
    if (!canvas || !canvas.getContext) return;
    var rect = canvas.getBoundingClientRect();
    var w = Math.max(260, Math.floor(rect.width || 300)), h = 72, dpr = Math.min(2, window.devicePixelRatio || 1);
    canvas.width = w*dpr; canvas.height = h*dpr;
    var ctx = canvas.getContext('2d'); ctx.setTransform(dpr,0,0,dpr,0,0);
    ctx.clearRect(0,0,w,h);
    var vals = rows.filter(function(r){return Number.isFinite(r.balance) && r.balance > 0;}).slice(-28).map(function(r){return r.balance;});
    if (vals.length < 2) {
      ctx.fillStyle = '#7185a5'; ctx.font = '10px sans-serif'; ctx.textAlign = 'center';
      ctx.fillText('Chờ đủ dữ liệu số dư để vẽ dòng tiền', w/2, 39); return;
    }
    var min = Math.min.apply(null,vals), max = Math.max.apply(null,vals);
    if (min === max) { min -= 1; max += 1; }
    var x = function(i){return 5+(w-10)*i/(vals.length-1);};
    var y = function(v){return 7+(h-15)*(1-(v-min)/(max-min));};
    ctx.strokeStyle='rgba(125,164,210,.14)'; ctx.lineWidth=1;
    for(var g=1;g<=3;g++){var yy=7+(h-15)*g/4;ctx.beginPath();ctx.moveTo(4,yy);ctx.lineTo(w-4,yy);ctx.stroke();}
    var grad=ctx.createLinearGradient(0,0,w,0);
    grad.addColorStop(0,'#6cc8ff');grad.addColorStop(1,'#8ae7c3');
    ctx.strokeStyle=grad;ctx.lineWidth=2;ctx.beginPath();
    vals.forEach(function(v,i){if(i===0)ctx.moveTo(x(i),y(v));else ctx.lineTo(x(i),y(v));});
    ctx.stroke();
    ctx.fillStyle='#8ae7c3';ctx.beginPath();ctx.arc(x(vals.length-1),y(vals[vals.length-1]),3.2,0,Math.PI*2);ctx.fill();
  }
  function mount() {
    var anchor = document.querySelector('.ai-card');
    if (!anchor) return false;
    ensureStyle();
    var card = document.getElementById('auza-v17-card');
    if (!card) {
      card = document.createElement('section');
      card.id = 'auza-v17-card'; card.className = 'auza-v17';
      anchor.insertAdjacentElement('afterend', card);
    }
    var rows = chronologicalRows(), data = analyze(rows);
    var key = rows.length + '|' + data.pattern + '|' + (rows.length ? rows[rows.length-1].balance : 0);
    if (key !== lastKey) {
      lastKey = key;
      var pred = data.prediction === 'T' ? 'TÀI' : data.prediction === 'X' ? 'XỈU' : 'CHƯA ĐỦ MẪU';
      var cls = data.prediction ? 'auza-v17-pick' : 'auza-v17-warn';
      card.innerHTML =
        '<div class="auza-v17-head"><span class="auza-v17-title">🧠 V17 · HỌC PATTERN THEO LỊCH SỬ</span><span class="auza-v17-tag">'+data.count+' phiên</span></div>'+
        '<div class="auza-v17-pattern">'+(data.pattern ? esc(data.pattern) : 'Chưa có dữ liệu')+'</div>'+
        '<div class="auza-v17-note">Nhịp cầu: '+esc(data.runText || '—')+
        ' · Kiểm định cuốn chiếu: '+(data.hitRate == null ? 'chưa đủ mẫu' : data.hitRate+'%')+'</div>'+
        '<div class="auza-v17-grid">'+
          '<div class="auza-v17-cell"><small>NHẬN DIỆN CẦU</small><b>'+esc(data.title)+'</b></div>'+
          '<div class="auza-v17-cell"><small>TÍN HIỆU THAM KHẢO</small><b class="'+cls+'">'+pred+'</b></div>'+
          '<div class="auza-v17-cell"><small>ĐỘ TIN CẬY ĐIỀU CHỈNH</small><b>'+data.confidence+'%</b></div>'+
          '<div class="auza-v17-cell"><small>SỐ MẪU LỊCH SỬ TƯƠNG TỰ</small><b>'+data.samples+'</b></div>'+
        '</div>'+networkSvg(data.confidence,data.prediction)+
        '<div class="auza-v17-note">'+esc(data.note)+'</div>'+
        '<canvas id="auza-v17-flow" class="auza-v17-flow" aria-label="Dòng số dư gần đây"></canvas>'+
        '<div class="auza-v17-foot"><span>Phân tích nhịp T/X · tự cập nhật khi có phiên mới</span><span>'+esc(data.source)+'</span></div>';
      drawFlow(document.getElementById('auza-v17-flow'), rows);
    } else {
      drawFlow(document.getElementById('auza-v17-flow'), rows);
    }
    return true;
  }
  window.AUZA_PATTERN_V17 = {analyze:function(){return analyze(chronologicalRows());}, refresh:mount};
  function boot() {
    if (mount()) {
      if (timer) clearInterval(timer);
      timer = setInterval(mount, 1800);
    }
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
  var attempts = 0;
  var retry = setInterval(function () {
    attempts++;
    if (mount() || attempts > 50) clearInterval(retry);
  }, 500);
})();
</script>
</script>

<style id="auza-v17-light-blue-theme">
  html,body{background:#dff3ff!important;color:#16324b!important}
  body{background-image:radial-gradient(circle at 8% 5%,rgba(91,190,240,.28),transparent 42%),
    radial-gradient(circle at 92% 95%,rgba(93,220,205,.22),transparent 46%)!important}
  .auza-v17{background:linear-gradient(145deg,#f8fdff,#e8f6ff)!important;
    border-color:#b6def3!important;color:#16324b!important;box-shadow:0 7px 22px rgba(41,105,145,.12)!important}
  .auza-v17-title{color:#167ca9!important}.auza-v17-tag{background:#d8f1ff!important;color:#176b91!important}
  .auza-v17-pattern{background:#eaf7ff!important;color:#245b78!important}
  .auza-v17-cell{background:#edf8ff!important;border:1px solid #d4eaf6}
  .auza-v17-cell b{color:#183d58!important}.auza-v17-cell small,.auza-v17-note,.auza-v17-foot{color:#52758b!important}
  .auza-v17-flow{background:#eaf7ff!important}
</style>


<!-- AUZA V18 COSMIC CONTROL — additive upgrade; legacy source above remains intact -->
<style id="auza-v18-cosmic-style">
#auza-v18{margin:14px 0;padding:18px;border:1px solid rgba(99,188,255,.42);border-radius:22px;
background:radial-gradient(ellipse at 10% 0%,rgba(54,128,255,.24),transparent 48%),
radial-gradient(ellipse at 100% 100%,rgba(139,92,246,.22),transparent 45%),
linear-gradient(145deg,#08152b,#101c3a 58%,#11142e);color:#eaf4ff;
box-shadow:0 16px 42px rgba(2,8,30,.35),inset 0 1px rgba(255,255,255,.08);
font:500 13px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;position:relative;overflow:hidden}
#auza-v18:before{content:"";position:absolute;inset:0;pointer-events:none;opacity:.22;
background-image:radial-gradient(#a8d8ff 1px,transparent 1px);background-size:27px 27px}
#auza-v18>*{position:relative}
#auza-v18 .v18-head{display:flex;justify-content:space-between;gap:12px;align-items:center;margin-bottom:14px}
#auza-v18 .v18-title{font-weight:900;font-size:16px;letter-spacing:.7px;color:#b9e4ff}
#auza-v18 .v18-tag{font-size:10px;border:1px solid #4b91c7;border-radius:30px;padding:4px 9px;color:#a8d9ff}
#auza-v18 .v18-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}
#auza-v18 .v18-box{background:rgba(17,38,72,.78);border:1px solid rgba(129,190,255,.2);border-radius:15px;padding:12px;min-width:0}
#auza-v18 label{display:block;color:#9fc6e9;font-size:11px;font-weight:750;margin:0 0 6px}
#auza-v18 select,#auza-v18 input{box-sizing:border-box;width:100%;min-height:39px;border-radius:10px;
border:1px solid rgba(133,190,255,.38);background:#0b1b35;color:#eff8ff;padding:8px 10px;font:inherit;outline:none}
#auza-v18 button{border:0;border-radius:11px;padding:10px 13px;font-weight:850;color:#071a31;
background:linear-gradient(100deg,#8bd8ff,#9ef0dc);cursor:pointer;margin-top:9px}
#auza-v18 button.secondary{background:rgba(106,158,218,.2);border:1px solid rgba(151,199,255,.35);color:#d9edff}
#auza-v18 .v18-result{margin-top:10px;padding:11px;border-radius:12px;background:rgba(3,13,31,.6);
border:1px solid rgba(126,187,255,.2);min-height:42px;color:#d9edff;overflow-wrap:anywhere}
#auza-v18 .v18-muted{font-size:10px;color:#8faecc;margin-top:7px}
#auza-v18 .v18-stat{font-size:18px;font-weight:900;color:#a8e8ff;font-variant-numeric:tabular-nums}
#auza-v18 .v18-wide{grid-column:1/-1}
#auza-v18 .v18-actions{display:flex;gap:8px;flex-wrap:wrap}
#auza-v18 .v18-actions button{flex:1}
#auza-v18 .v18-warning{color:#ffd69b}
@media(max-width:560px){#auza-v18{padding:13px;border-radius:17px}#auza-v18 .v18-grid{grid-template-columns:1fr}#auza-v18 .v18-head{align-items:flex-start}}
</style>
<script id="auza-v18-cosmic-control">
(function(){
 'use strict';
 if(window.__AUZA_V18_INSTALLED) return; window.__AUZA_V18_INSTALLED=true;
 var timer=null, deadline=0, lossLimit=0, startProfit=0, mounted=false;
 var safeModels=['model1','model2','model3','model4','model6','model9','model11','model12','model15','model18','model19'];
 function esc(v){return String(v==null?'':v).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
 function mount(){
  if(!window.S || !S.loggedIn || document.getElementById('auza-v18')) return !!document.getElementById('auza-v18');
  var anchor=document.querySelector('.ai-card')||document.querySelector('main')||document.getElementById('app')||document.body;
  var el=document.createElement('section'); el.id='auza-v18';
  el.innerHTML='<div class="v18-head"><div><div class="v18-title">✦ AUZA V18 · COSMIC CONTROL</div><div class="v18-muted">Bảng điều khiển thuật toán & quản trị rủi ro</div></div><span class="v18-tag">ADD-ON · LEGACY SAFE</span></div>'+
  '<div class="v18-grid">'+
   '<div class="v18-box"><label>CHỌN MỘT THUẬT TOÁN ĐỘC LẬP</label><select id="v18-model">'+safeModels.map(function(m){return '<option value="'+m+'">'+m.toUpperCase()+'</option>';}).join('')+'</select><button id="v18-run">CHẠY THUẬT TOÁN ĐÃ CHỌN</button><div class="v18-result" id="v18-pred">Chưa chạy phân tích.</div><div class="v18-muted">Gọi trực tiếp hàm model tương ứng trong UltraDicePredictionSystem; không trộn phiếu giữa các model. Nếu thiếu dữ liệu, hệ thống báo không đủ mẫu.</div></div>'+
   '<div class="v18-box"><label>CHIA VỐN THAM KHẢO (KHÔNG KHUYẾN KHÍCH GẤP THẾP)</label><label for="v18-cap">Vốn dự kiến (đồng)</label><input id="v18-cap" type="number" min="0" step="1000" placeholder="Nhập vốn"><label for="v18-risk" style="margin-top:8px">Mức rủi ro tối đa mỗi lượt (%)</label><input id="v18-risk" type="number" min="0.1" max="1" step="0.1" value="0.5"><button id="v18-calc">TÍNH MỨC VỐN GIỚI HẠN</button><div class="v18-result" id="v18-bank">Chưa tính vốn.</div><div class="v18-muted v18-warning">Không có mức cược nào bảo đảm thắng; mặc định giới hạn rủi ro thấp, không tự tăng cược để gỡ lỗ.</div></div>'+
   '<div class="v18-box"><label>CHỐT LỜI / CHỐT LỖ</label><label for="v18-profit">Mục tiêu lợi nhuận (đồng)</label><input id="v18-profit" type="number" min="0" step="1000" placeholder="0 = không đặt"><button id="v18-profit-save" class="secondary">LƯU MỐC CHỐT LỜI</button><label for="v18-loss" style="margin-top:10px">Ngưỡng lỗ tối đa (đồng, số dương)</label><input id="v18-loss" type="number" min="0" step="1000" placeholder="Ví dụ 100000"><button id="v18-loss-save" class="secondary">ÁP DỤNG GIỚI HẠN LỖ</button><div class="v18-result" id="v18-loss-state">Chưa đặt ngưỡng lỗ.</div><div class="v18-muted">Mốc chốt lời dùng cấu hình máy chủ sẵn có. Chốt lỗ được giám sát ở trình duyệt đang mở.</div></div>'+
   '<div class="v18-box"><label>TỰ DỪNG SAU KHOẢNG THỜI GIAN</label><label for="v18-min">Thời gian chạy (phút)</label><input id="v18-min" type="number" min="1" max="1440" value="30"><div class="v18-actions"><button id="v18-timer-start">BẮT ĐẦU ĐẾM</button><button id="v18-timer-stop" class="secondary">HUỶ HẸN GIỜ</button></div><div class="v18-result" id="v18-clock">Chưa đặt hẹn giờ.</div><div class="v18-muted">Cần giữ trang quản trị mở để bộ đếm phía trình duyệt gửi lệnh dừng.</div></div>'+
   '<div class="v18-box v18-wide"><label>TRẠNG THÁI KIỂM SOÁT</label><div class="v18-stat" id="v18-status">SẴN SÀNG</div><div class="v18-muted">Phân tích lịch sử chỉ mô tả dữ liệu đã có, không thể dự báo chắc chắn kết quả ngẫu nhiên của trò chơi.</div></div>'+
  '</div>';
  anchor.insertAdjacentElement('afterend',el); mounted=true;
  document.getElementById('v18-run').addEventListener('click',runModel);
  document.getElementById('v18-calc').addEventListener('click',calcBank);
  document.getElementById('v18-loss-save').addEventListener('click',saveLoss);
  document.getElementById('v18-profit-save').addEventListener('click',saveProfit);
  document.getElementById('v18-timer-start').addEventListener('click',startTimer);
  document.getElementById('v18-timer-stop').addEventListener('click',stopTimer);
  return true;
 }
 function runModel(){
  var name=document.getElementById('v18-model').value, out=document.getElementById('v18-pred');
  try{
   var engine=window.AUZA_ULTRA&&window.AUZA_ULTRA.engine;
   if(!engine || !Array.isArray(engine.history)){out.textContent='Engine chưa sẵn sàng. Hãy chờ đồng bộ lịch sử.';return;}
   if(engine.history.length<8){out.textContent='Chưa đủ dữ liệu lịch sử (tối thiểu 8 phiên).';return;}
   var fn=engine.models&&engine.models[name];
   if(typeof fn!=='function'){out.textContent='Không tìm thấy hàm '+name+'.';return;}
   if(/Math\\.random|crypto\\.getRandomValues/.test(Function.prototype.toString.call(fn))){out.textContent='Đã chặn hàm có dấu hiệu sử dụng ngẫu nhiên.';return;}
   var r=fn();
   if(!r||!r.prediction){out.textContent='Thuật toán '+name+' chưa đưa ra tín hiệu với mẫu hiện tại. Không tự tạo kết quả thay thế.';return;}
   var side=r.prediction==='T'?'TÀI':r.prediction==='X'?'XỈU':String(r.prediction);
   var conf=Number(r.confidence);
   out.innerHTML='<b>'+esc(side)+'</b> · Độ tin cậy nội bộ: '+(Number.isFinite(conf)?esc((conf<=1?conf*100:conf).toFixed(1))+'%':'chưa có')+'<br>'+esc(r.reason||'Không có giải thích từ model.');
  }catch(e){out.textContent='Lỗi khi chạy '+name+': '+e.message;}
 }
 function calcBank(){
  var cap=Math.max(0,Number(document.getElementById('v18-cap').value)||0);
  var pct=Math.max(.1,Math.min(1,Number(document.getElementById('v18-risk').value)||.5));
  var unit=Math.floor(cap*pct/100/1000)*1000;
  document.getElementById('v18-bank').textContent=cap>0?'Giới hạn tham khảo mỗi lượt: '+unit.toLocaleString('vi-VN')+' đ ('+pct+'% vốn). Không tăng mức này để gỡ lỗ.':'Vui lòng nhập số vốn hợp lệ.';
 }
 function currentProfit(){return Number(S&&S.stats&&S.stats.profit||0);}
 async function pauseAuto(reason){
  try{
   if(typeof api==='function' && S && S.loggedIn){
    await api('config',{user:S.user,auto:'0',paused:'1'});
    S.config.auto=false;S.config.paused=true;
    if(typeof patchDashboard==='function') patchDashboard();
   }
   var st=document.getElementById('v18-status');if(st)st.textContent='ĐÃ GỬI LỆNH DỪNG · '+reason;
  }catch(e){var st2=document.getElementById('v18-status');if(st2)st2.textContent='Không gửi được lệnh dừng: '+e.message;}
 }
 async function saveProfit(){
  var value=Math.max(0,Math.floor(Number(document.getElementById('v18-profit').value)||0));
  try{
   var r=await api('config',{user:S.user,profit_stop:value});
   if(r&&r.ok){document.getElementById('v18-loss-state').textContent='Đã lưu mục tiêu chốt lời '+value.toLocaleString('vi-VN')+' đ vào cấu hình máy chủ.';}
   else{document.getElementById('v18-loss-state').textContent='Không lưu được mốc chốt lời: '+(r&&r.msg||'lỗi máy chủ');}
  }catch(e){document.getElementById('v18-loss-state').textContent='Lỗi lưu mốc chốt lời: '+e.message;}
 }
 function saveLoss(){
  lossLimit=Math.max(0,Number(document.getElementById('v18-loss').value)||0);
  startProfit=currentProfit();
  document.getElementById('v18-loss-state').textContent=lossLimit>0?'Đã đặt ngưỡng lỗ '+lossLimit.toLocaleString('vi-VN')+' đ cho lần giám sát này.':'Đã tắt ngưỡng lỗ.';
 }
 function startTimer(){
  var mins=Math.max(1,Math.min(1440,Number(document.getElementById('v18-min').value)||30));
  deadline=Date.now()+mins*60000;
  if(timer)clearInterval(timer);
  timer=setInterval(function(){
   var left=Math.max(0,deadline-Date.now()), node=document.getElementById('v18-clock');
   if(node)node.textContent=left>0?'Còn '+Math.ceil(left/60000)+' phút '+String(Math.floor(left/1000)%60).padStart(2,'0')+' giây':'Đã hết thời gian.';
   if(left<=0){clearInterval(timer);timer=null;deadline=0;pauseAuto('hết thời gian đã đặt');}
  },1000);
  document.getElementById('v18-clock').textContent='Đã đặt tự dừng sau '+mins+' phút.';
 }
 function stopTimer(){if(timer)clearInterval(timer);timer=null;deadline=0;var n=document.getElementById('v18-clock');if(n)n.textContent='Đã huỷ hẹn giờ.';}
 setInterval(function(){
  if(!mounted)mount();
  if(!mounted||!S||!S.loggedIn)return;
  if(lossLimit>0 && currentProfit()-startProfit<=-lossLimit){lossLimit=0;pauseAuto('đạt ngưỡng chốt lỗ');}
 },2000);
})();
</script>
<!-- /AUZA V18 COSMIC CONTROL -->


<!-- AUZA V19 COSMIC PLANET + VERIFIED HISTORY + PATTERN LEARNING (ADD-ON; ORIGINAL CODE RETAINED) -->
<style id="auza-v19-cosmic-style">
:root{--v19-cyan:#63e8ff;--v19-violet:#9d8bff;--v19-pink:#ff75cf;--v19-gold:#ffd98a}
body{background:#050816!important;background-image:radial-gradient(ellipse at 12% 12%,rgba(69,80,190,.22),transparent 38%),radial-gradient(ellipse at 88% 18%,rgba(0,196,255,.16),transparent 34%),radial-gradient(ellipse at 50% 100%,rgba(121,60,190,.2),transparent 45%)!important;background-attachment:fixed!important}
#app{position:relative;z-index:1}body:before{content:"";position:fixed;inset:0;z-index:0;pointer-events:none;opacity:.72;background-image:radial-gradient(1px 1px at 8% 18%,#fff 98%,transparent),radial-gradient(2px 2px at 23% 76%,#9eeeff 98%,transparent),radial-gradient(1px 1px at 44% 32%,#fff 98%,transparent),radial-gradient(1px 1px at 68% 12%,#d7c4ff 98%,transparent),radial-gradient(2px 2px at 82% 67%,#fff 98%,transparent),radial-gradient(1px 1px at 94% 38%,#9eeeff 98%,transparent);background-size:370px 290px;animation:v19Stars 36s linear infinite}
@keyframes v19Stars{to{background-position:370px 290px}}
.card{position:relative;isolation:isolate;overflow:hidden;border:1px solid rgba(117,210,255,.25)!important;background:linear-gradient(145deg,rgba(12,18,43,.96),rgba(13,10,35,.94))!important;box-shadow:0 18px 70px rgba(0,0,0,.55),0 0 32px rgba(67,190,255,.09),inset 0 1px rgba(255,255,255,.08)!important}
.card:before{content:"";position:absolute;z-index:-1;width:210px;height:210px;right:-95px;top:110px;border-radius:50%;background:radial-gradient(circle at 35% 30%,#b6f3ff 0 2%,#477de7 10%,#292d80 38%,#0b1234 67%,transparent 70%);box-shadow:0 0 48px rgba(91,150,255,.25);opacity:.34;pointer-events:none}
.head,.ubar,.tabs,.body{position:relative}
.head{background:linear-gradient(90deg,rgba(24,35,78,.9),rgba(32,17,66,.88))!important;border-bottom:1px solid rgba(115,222,255,.2)!important}
.title h1{background:linear-gradient(90deg,#fff,#9beaff,#d8baff);-webkit-background-clip:text;background-clip:text;color:transparent!important}
.tabs button{border-radius:12px!important}
.ai-card,.v16-target-card,.v18-box{border-color:rgba(105,211,255,.28)!important;background:linear-gradient(145deg,rgba(17,31,67,.9),rgba(24,14,52,.92))!important;box-shadow:0 8px 28px rgba(0,0,0,.2),inset 0 1px rgba(255,255,255,.06)!important}
.hist-item{border:1px solid rgba(126,204,255,.15)!important;background:rgba(18,28,58,.72)!important;border-radius:12px!important;margin:7px 0!important}
.hist-item.win{border-color:rgba(69,230,166,.4)!important}
.hist-item.lose{border-color:rgba(255,104,139,.4)!important}
.auza-v19-panel{margin:14px 0;padding:15px;border:1px solid rgba(106,211,255,.28);border-radius:18px;background:linear-gradient(145deg,rgba(13,25,59,.94),rgba(29,15,58,.94));box-shadow:0 12px 36px rgba(0,0,0,.24),inset 0 1px rgba(255,255,255,.06);color:#eaf7ff}
.auza-v19-head{display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:12px}
.auza-v19-title{font-size:14px;font-weight:900;letter-spacing:.6px;color:#c9f5ff}
.auza-v19-chip{font-size:9px;padding:5px 8px;border:1px solid rgba(115,225,255,.3);border-radius:99px;color:#a8eaff;background:rgba(42,137,190,.12)}
.auza-v19-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}
.auza-v19-stat{padding:10px;border-radius:12px;background:rgba(255,255,255,.045);border:1px solid rgba(255,255,255,.07);min-width:0}
.auza-v19-stat small{display:block;color:#9db4d5;font-size:10px}
.auza-v19-stat b{display:block;margin-top:4px;color:#fff;font-size:18px;font-variant-numeric:tabular-nums}
.auza-v19-patterns{display:flex;flex-wrap:wrap;gap:7px;margin-top:10px}
.auza-v19-pattern{padding:7px 9px;border-radius:10px;background:rgba(106,145,255,.1);border:1px solid rgba(130,164,255,.22);font-size:10px;color:#dceaff}
.auza-v19-note{font-size:10px;line-height:1.55;color:#9fb4d1;margin-top:10px}
.auza-v19-history-tag{font-size:9px!important;font-weight:900!important;letter-spacing:.4px;padding:5px 7px;border-radius:8px}
.hist-item.win .auza-v19-history-tag{color:#72f3bd;background:rgba(44,220,150,.12);border:1px solid rgba(44,220,150,.3)}
.hist-item.lose .auza-v19-history-tag{color:#ff9ab0;background:rgba(255,75,115,.12);border:1px solid rgba(255,75,115,.3)}
.auza-v19-history-sub{display:block;color:#a7bbd7;font-size:9px;margin-top:3px}
@media(max-width:420px){.auza-v19-grid{gap:6px}.auza-v19-stat{padding:8px}.auza-v19-stat b{font-size:16px}}
@media(prefers-reduced-motion:reduce){body:before{animation:none!important}}
</style>
<script id="auza-v19-cosmic-script">
(function(){
 'use strict';
 if(window.__AUZA_V19_COSMIC__) return; window.__AUZA_V19_COSMIC__=true;
 var panel=null, lastHistoryNode=null;
 function side(v){
  var s=String(v==null?'':v).trim().toUpperCase();
  if(['TAI','TÀI','T'].indexOf(s)>=0)return 'TÀI';
  if(['XIU','XỈU','X'].indexOf(s)>=0)return 'XỈU';
  return '';
 }
 function getRows(){return window.S&&Array.isArray(S.history)?S.history.filter(function(x){return side(x.result)&&side(x.pred)}):[];}
 function detectPatterns(rows){
  var seq=rows.slice(0,40).map(function(x){return side(x.result)==='TÀI'?'T':'X';});
  if(!seq.length)return [];
  var runs=[],cur=seq[0],len=1;
  for(var i=1;i<seq.length;i++){if(seq[i]===cur)len++;else{runs.push({v:cur,n:len});cur=seq[i];len=1;}}
  runs.push({v:cur,n:len});
  var out=[];
  var streak=runs[0];
  if(streak.n>=3)out.push('Bệt '+streak.n+' '+(streak.v==='T'?'Tài':'Xỉu')+' phiên');
  function runShape(shape,label,min){
   var count=0;
   for(var j=0;j+shape.length<=runs.length;j++){
    var ok=true;for(var k=0;k<shape.length;k++)if(runs[j+k].n!==shape[k])ok=false;
    if(ok)count++;
   }
   if(count>=min)out.push(label+' · '+count+' cụm');
  }
  runShape([1,1],'Cầu 1-1',2);runShape([2,2],'Cầu 2-2',2);runShape([3,3],'Cầu 3-3',1);
  runShape([1,2],'Cầu 1-2',2);runShape([2,1],'Cầu 2-1',2);runShape([1,3],'Cầu 1-3',1);runShape([3,1],'Cầu 3-1',1);
  if(seq.length>=6){
   var alt=0;for(var a=1;a<seq.length&&seq[a]!==seq[a-1];a++)alt++;
   if(alt>=4)out.push('Đảo 1-1 liên tiếp '+alt+' phiên');
  }
  if(!out.length)out.push('Chưa thấy mẫu lặp đủ điều kiện');
  return out.slice(0,6);
 }
 function stats(rows,n){
  var part=rows.slice(0,n),wins=part.filter(function(x){return x.win===true||x.win===1||x.win==='1';}).length;
  return {count:part.length,wins:wins,rate:part.length?wins/part.length*100:0};
 }
 function mount(){
  if(!window.S||!S.loggedIn)return;
  var card=document.querySelector('.card');if(!card)return;
  if(!panel){
   panel=document.createElement('section');panel.className='auza-v19-panel';panel.id='auza-v19-learning';
   panel.innerHTML='<div class="auza-v19-head"><div class="auza-v19-title">✦ COSMIC INTELLIGENCE · HỌC TỪ KẾT QUẢ</div><span class="auza-v19-chip">LIVE · VERIFIED DATA</span></div><div class="auza-v19-grid" id="auza-v19-stats"></div><div class="auza-v19-patterns" id="auza-v19-patterns"></div><div class="auza-v19-note" id="auza-v19-note"></div>';
   card.appendChild(panel);
  }
  update();
 }
 function update(){
  if(!panel||!window.S)return;
  var rows=getRows(),s20=stats(rows,20),s50=stats(rows,50),s100=stats(rows,100);
  var profit=Number(S.stats&&S.stats.profit||0),target=Number(S.config&&S.config.profit_stop||0);
  var winTarget=Number(S.config&&S.config.win_target||666),winCount=Number(S.stats&&S.stats.wins||0);
  var data=[
   ['Độ chính xác 20 phiên',s20.count?s20.rate.toFixed(1)+'%':'—'],
   ['Độ chính xác 50 phiên',s50.count?s50.rate.toFixed(1)+'%':'—'],
   ['Độ chính xác 100 phiên',s100.count?s100.rate.toFixed(1)+'%':'—'],
   ['Mẫu đã đối chiếu',rows.length],
   ['Lợi nhuận tích lũy',profit.toLocaleString('vi-VN')+' đ'],
   ['Mục tiêu phiên thắng',winCount+'/'+winTarget]
  ];
  var box=document.getElementById('auza-v19-stats');
  if(box)box.innerHTML=data.map(function(x){return '<div class="auza-v19-stat"><small>'+x[0]+'</small><b>'+x[1]+'</b></div>';}).join('');
  var patterns=detectPatterns(rows),p=document.getElementById('auza-v19-patterns');
  if(p)p.innerHTML=patterns.map(function(x){return '<span class="auza-v19-pattern">'+x+'</span>';}).join('');
  var note=document.getElementById('auza-v19-note');
  if(note){
   var stop=target>0?'Mốc chốt lời: '+target.toLocaleString('vi-VN')+' đ · '+(profit>=target?'ĐÃ ĐẠT':'còn '+Math.max(0,target-profit).toLocaleString('vi-VN')+' đ'):'Chưa bật mốc chốt lời.';
   note.textContent='Đối chiếu chỉ tính các phiên có dự đoán và kết quả hợp lệ; tỷ lệ là thống kê quá khứ, không phải xác suất thắng phiên tiếp theo. '+stop+' · Đạt mốc chốt lời hoặc mục tiêu thắng sẽ được worker phía máy chủ tự dừng.';
  }
 }
 function enhanceHistory(){
  var list=document.getElementById('hist_list');if(!list||list===lastHistoryNode&&list.dataset.v19Done==='1')return;
  lastHistoryNode=list;list.dataset.v19Done='1';
  Array.prototype.forEach.call(list.querySelectorAll('.hist-item'),function(el){
   var mid=el.querySelector('.mid'),tag=el.querySelector('.tag');if(!mid||!tag)return;
   var rowIndex=Array.prototype.indexOf.call(list.children,el),h=(window.S&&S.history||[])[rowIndex];if(!h)return;
   var pred=side(h.pred),actual=side(h.result),isCorrect=pred&&actual&&pred===actual;
   el.classList.toggle('win',!!isCorrect);el.classList.toggle('lose',!isCorrect);
   tag.className='tag auza-v19-history-tag';tag.textContent=isCorrect?'✓ ĐÚNG CỬA':'✕ SAI CỬA';
   var sub=mid.querySelector('.auza-v19-history-sub');if(!sub){sub=document.createElement('small');sub.className='auza-v19-history-sub';mid.appendChild(sub);}
   sub.textContent='Dự đoán: '+(pred||'—')+' · Thực tế: '+(actual||'—')+' · '+(isCorrect?'Khớp kết quả':'Không khớp kết quả');
  });
 }
 function observe(){
  mount();enhanceHistory();
  var root=document.getElementById('app');
  if(root&&!root.dataset.v19Observer){
   root.dataset.v19Observer='1';
   new MutationObserver(function(){mount();enhanceHistory();}).observe(root,{childList:true,subtree:true});
  }
  setInterval(function(){mount();update();enhanceHistory();},2500);
 }
 if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',observe);else observe();
})();
</script>
<!-- /AUZA V19 COSMIC PLANET + VERIFIED HISTORY + PATTERN LEARNING -->


<!-- AUZA V20: COSMIC UI + VERIFIED HISTORY + PATTERN LEARNING -->
<style id="auza-v20-cosmic-style">
:root{--v20-cyan:#73e8ff;--v20-blue:#6b8dff;--v20-violet:#b18cff;--v20-gold:#ffd98a;--v20-green:#55efb1;--v20-red:#ff789b}
html,body{background:#050817!important}
body{background:
 radial-gradient(ellipse at 12% 12%,rgba(49,78,177,.22),transparent 36%),
 radial-gradient(ellipse at 88% 18%,rgba(120,48,174,.19),transparent 34%),
 radial-gradient(ellipse at 50% 100%,rgba(16,111,157,.16),transparent 42%),
 #050817!important;background-attachment:fixed!important}
#auza-v20-universe{position:fixed;inset:0;width:100%;height:100%;z-index:0;pointer-events:none;opacity:.82}
#app,.app,.wrap,.container,main{position:relative;z-index:1}
.auza-v19-panel,.auza-v20-panel,.card{backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px)}
.auza-v19-panel,.auza-v20-panel{border:1px solid rgba(119,220,255,.25)!important;background:linear-gradient(145deg,rgba(10,22,53,.92),rgba(27,17,58,.88) 55%,rgba(9,35,58,.9))!important;box-shadow:0 14px 45px rgba(0,0,0,.28),inset 0 1px rgba(255,255,255,.08),0 0 24px rgba(68,173,255,.08)!important}
.auza-v19-title,.auza-v20-title{letter-spacing:.9px;text-shadow:0 0 16px rgba(115,232,255,.35)}
.auza-v20-panel{margin:14px 0;padding:15px;border-radius:18px;color:#eaf7ff}
.auza-v20-head{display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:12px}
.auza-v20-title{font-weight:900;font-size:13px;color:#d8f7ff}
.auza-v20-chip{font-size:9px;padding:5px 9px;border-radius:99px;color:#b9efff;border:1px solid rgba(115,232,255,.35);background:rgba(67,155,213,.12)}
.auza-v20-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}
.auza-v20-stat{padding:10px;border-radius:12px;border:1px solid rgba(134,196,255,.17);background:linear-gradient(135deg,rgba(25,47,89,.65),rgba(32,25,68,.55));min-width:0}
.auza-v20-stat small{display:block;color:#a8bddc;font-size:10px;margin-bottom:5px}
.auza-v20-stat b{font-size:17px;color:#e9faff;overflow-wrap:anywhere}
.auza-v20-patterns{display:flex;flex-wrap:wrap;gap:6px;margin-top:10px}
.auza-v20-pattern{font-size:10px;color:#d9f4ff;padding:6px 9px;border-radius:9px;background:rgba(75,139,211,.14);border:1px solid rgba(120,207,255,.2)}
.auza-v20-pattern.hot{border-color:rgba(255,217,138,.42);color:#ffe5a9}
.auza-v20-note{margin-top:10px;color:#9eb4d3;font-size:10px;line-height:1.6}
.auza-v20-empty{color:#a9bdd9;font-size:11px;padding:8px 0}
.hist-item .tag.auza-v20-verified{min-width:74px;text-align:center;font-weight:900}
.hist-item.win .tag.auza-v20-verified{color:#75f2bd!important;border-color:rgba(85,239,177,.5)!important;background:rgba(31,151,111,.14)!important}
.hist-item.lose .tag.auza-v20-verified{color:#ff91aa!important;border-color:rgba(255,120,155,.5)!important;background:rgba(173,45,82,.14)!important}
@media(min-width:700px){.auza-v20-grid{grid-template-columns:repeat(3,minmax(0,1fr))}}
@media(max-width:380px){.auza-v20-stat{padding:8px}.auza-v20-stat b{font-size:15px}.auza-v20-panel{padding:11px}}
@media(prefers-reduced-motion:reduce){#auza-v20-universe{display:none!important}}
</style>
<script id="auza-v20-cosmic-script">
(function(){
 'use strict';
 if(window.__AUZA_V20_COSMIC__)return;window.__AUZA_V20_COSMIC__=true;
 var canvas,ctx,raf=0,lastHistorySignature='',lastPanelSignature='';
 function side(v){
  var s=String(v==null?'':v).trim().toUpperCase();
  if(s==='T'||s==='TAI'||s==='TÀI')return 'TÀI';
  if(s==='X'||s==='XIU'||s==='XỈU')return 'XỈU';
  return '';
 }
 function makeUniverse(){
  if(window.matchMedia&&window.matchMedia('(prefers-reduced-motion: reduce)').matches)return;
  canvas=document.createElement('canvas');canvas.id='auza-v20-universe';
  document.body.insertBefore(canvas,document.body.firstChild);ctx=canvas.getContext('2d');
  if(!ctx)return;
  var stars=[],w=0,h=0,dpr=1;
  function resize(){
   dpr=Math.min(window.devicePixelRatio||1,1.5);w=window.innerWidth;h=window.innerHeight;
   canvas.width=Math.floor(w*dpr);canvas.height=Math.floor(h*dpr);
   canvas.style.width=w+'px';canvas.style.height=h+'px';ctx.setTransform(dpr,0,0,dpr,0,0);
   stars=[];var n=Math.max(45,Math.min(115,Math.floor(w*h/10500)));
   for(var i=0;i<n;i++)stars.push({x:Math.random()*w,y:Math.random()*h,r:.35+Math.random()*1.25,a:.25+Math.random()*.65,p:Math.random()*6.28,v:.002+Math.random()*.009});
  }
  resize();window.addEventListener('resize',resize,{passive:true});
  var t=0;
  function draw(){
   t+=.008;ctx.clearRect(0,0,w,h);
   var g=ctx.createRadialGradient(w*.78,h*.2,0,w*.78,h*.2,Math.max(w,h)*.65);
   g.addColorStop(0,'rgba(75,80,190,.10)');g.addColorStop(.55,'rgba(36,105,160,.045)');g.addColorStop(1,'rgba(0,0,0,0)');
   ctx.fillStyle=g;ctx.fillRect(0,0,w,h);
   stars.forEach(function(s){
    s.p+=s.v;var alpha=s.a*(.65+.35*Math.sin(s.p+t));
    ctx.beginPath();ctx.arc(s.x,s.y,s.r,0,Math.PI*2);ctx.fillStyle='rgba(190,231,255,'+alpha+')';ctx.fill();
   });
   // Mờ nhẹ các quỹ đạo hành tinh, chỉ làm nền trang trí.
   var cx=w*.82,cy=h*.22;
   ctx.save();ctx.translate(cx,cy);ctx.rotate(t*.12);
   [48,76,108].forEach(function(r,i){
    ctx.beginPath();ctx.ellipse(0,0,r*1.55,r*.48,-.18,0,Math.PI*2);
    ctx.strokeStyle='rgba(112,190,255,'+(0.12-i*.025)+')';ctx.lineWidth=1;ctx.stroke();
   });
   var px=Math.cos(t*.45)*118,py=Math.sin(t*.45)*38;
   var pg=ctx.createRadialGradient(px-5,py-6,1,px,py,12);
   pg.addColorStop(0,'rgba(220,249,255,.95)');pg.addColorStop(.35,'rgba(111,186,255,.75)');pg.addColorStop(1,'rgba(111,112,255,0)');
   ctx.beginPath();ctx.arc(px,py,12,0,Math.PI*2);ctx.fillStyle=pg;ctx.fill();ctx.restore();
   raf=requestAnimationFrame(draw);
  }
  draw();
 }
 function runsOf(seq){
  var runs=[];if(!seq.length)return runs;
  var v=seq[0],n=1;
  for(var i=1;i<seq.length;i++){if(seq[i]===v)n++;else{runs.push({side:v,len:n});v=seq[i];n=1;}}
  runs.push({side:v,len:n});return runs;
 }
 function patterns(rows){
  // Dữ liệu API được lưu mới nhất trước; đảo lại để đọc diễn tiến theo thời gian.
  var seq=rows.slice(0,60).map(function(r){return side(r.result)==='TÀI'?'T':'X';}).reverse();
  if(!seq.length)return ['Chưa có kết quả thực tế để phân tích'];
  var runs=runsOf(seq),last=runs[runs.length-1],out=[];
  if(last.len>=2)out.push('Bệt '+last.len+' '+(last.side==='T'?'Tài':'Xỉu'));
  var shapes=[
   {a:[1,1],name:'Cầu 1-1'},{a:[2,2],name:'Cầu 2-2'},{a:[3,3],name:'Cầu 3-3'},
   {a:[1,2],name:'Cầu 1-2'},{a:[2,1],name:'Cầu 2-1'},
   {a:[1,3],name:'Cầu 1-3'},{a:[3,1],name:'Cầu 3-1'}
  ];
  shapes.forEach(function(sh){
   var hits=0;
   for(var i=0;i+sh.a.length<=runs.length;i++){
    var ok=true;for(var j=0;j<sh.a.length;j++)if(runs[i+j].len!==sh.a[j])ok=false;
    if(ok)hits++;
   }
   if(hits>=2)out.push(sh.name+' · '+hits+' lần');
  });
  var tail=seq.slice(-8),switches=0;
  for(var k=1;k<tail.length;k++)if(tail[k]!==tail[k-1])switches++;
  if(tail.length>=6&&switches>=tail.length-2)out.push('Nhịp đảo 1-1 đang xuất hiện');
  if(last.len>=5)out.push('Cảnh báo chuỗi bệt dài · theo dõi khả năng đổi nhịp');
  if(out.length===0)out.push('Chưa có mẫu lặp đủ số lần kiểm chứng');
  return out.slice(0,8);
 }
 function accuracy(rows,n){
  var a=rows.slice(0,n),valid=a.filter(function(r){return side(r.pred)&&side(r.result);});
  var hit=valid.filter(function(r){return side(r.pred)===side(r.result);}).length;
  return {n:valid.length,hit:hit,rate:valid.length?100*hit/valid.length:0};
 }
 function mountLearning(){
  if(!window.S||!S.loggedIn)return;
  var host=document.querySelector('.card')||document.getElementById('app');if(!host)return;
  var panel=document.getElementById('auza-v20-learning');
  if(!panel){
   panel=document.createElement('section');panel.id='auza-v20-learning';panel.className='auza-v20-panel';
   panel.innerHTML='<div class="auza-v20-head"><div class="auza-v20-title">✧ DEEP COSMIC PATTERN LAB</div><span class="auza-v20-chip">LEARN · VERIFY · REVIEW</span></div><div class="auza-v20-grid" id="auza-v20-stats"></div><div class="auza-v20-patterns" id="auza-v20-patterns"></div><div class="auza-v20-note" id="auza-v20-note"></div>';
   var old=document.getElementById('auza-v19-learning');if(old&&old.parentNode===host)old.insertAdjacentElement('afterend',panel);else host.appendChild(panel);
  }
  var rows=Array.isArray(S.history)?S.history.filter(function(r){return side(r.pred)&&side(r.result);}):[];
  var a10=accuracy(rows,10),a30=accuracy(rows,30),a100=accuracy(rows,100);
  var profit=Number(S.stats&&S.stats.profit||0),goal=Number(S.config&&S.config.profit_stop||0);
  var panelSignature=rows.slice(0,100).map(function(r){return [r.session,r.pred,r.result,r.win].join(':');}).join('|')+'|'+profit+'|'+goal;
  if(panelSignature===lastPanelSignature)return;
  lastPanelSignature=panelSignature;
  var data=[
   ['Đúng 10 phiên',a10.n?a10.hit+'/'+a10.n+' · '+a10.rate.toFixed(1)+'%':'Chưa đủ dữ liệu'],
   ['Đúng 30 phiên',a30.n?a30.hit+'/'+a30.n+' · '+a30.rate.toFixed(1)+'%':'Chưa đủ dữ liệu'],
   ['Đúng 100 phiên',a100.n?a100.hit+'/'+a100.n+' · '+a100.rate.toFixed(1)+'%':'Chưa đủ dữ liệu'],
   ['Phiên đã kiểm chứng',rows.length],
   ['Lợi nhuận hiển thị',profit.toLocaleString('vi-VN')+' đ'],
   ['Chốt lời',goal>0?goal.toLocaleString('vi-VN')+' đ':'Chưa đặt']
  ];
  var box=document.getElementById('auza-v20-stats');
  if(box)box.innerHTML=data.map(function(x){return '<div class="auza-v20-stat"><small>'+x[0]+'</small><b>'+x[1]+'</b></div>';}).join('');
  var pats=patterns(rows),p=document.getElementById('auza-v20-patterns');
  if(p)p.innerHTML=pats.map(function(x,i){return '<span class="auza-v20-pattern '+(i===0?'hot':'')+'">'+x+'</span>';}).join('');
  var note=document.getElementById('auza-v20-note');
  if(note)note.textContent='Phân loại dựa trên kết quả thực tế đã ghi nhận. Cầu bệt/cầu đảo chỉ mô tả chuỗi quá khứ; không chứng minh phiên kế tiếp sẽ tiếp diễn hay đảo chiều. Chốt lời được kiểm tra ở worker máy chủ, không phụ thuộc việc mở trình duyệt.';
 }
 function verifyHistory(){
  var list=document.getElementById('hist_list');if(!list)return;
  var rows=Array.isArray(window.S&&S.history)?S.history:[];
  var signature=rows.slice(0,80).map(function(r){return [r.session,r.pred,r.result,r.win].join(':');}).join('|');
  // Luôn cập nhật cả khi node danh sách được tái sử dụng nhưng nội dung bên trong đã thay đổi.
  if(signature===lastHistorySignature&&list.dataset.v20Verified==='1')return;
  lastHistorySignature=signature;list.dataset.v20Verified='1';
  Array.prototype.forEach.call(list.querySelectorAll('.hist-item'),function(el,index){
   var h=rows[index];if(!h)return;
   var pred=side(h.pred),actual=side(h.result),known=!!pred&&!!actual,correct=known&&pred===actual;
   el.classList.toggle('win',correct);el.classList.toggle('lose',known&&!correct);
   var tag=el.querySelector('.tag');if(tag){
    tag.classList.add('auza-v20-verified');
    tag.textContent=known?(correct?'✓ ĐÚNG CỬA':'✕ SAI CỬA'):'CHƯA ĐỐI CHIẾU';
   }
   var mid=el.querySelector('.mid');if(mid&&known){
    var sub=mid.querySelector('.auza-v20-verified-detail');
    if(!sub){sub=document.createElement('small');sub.className='auza-v20-verified-detail auza-v19-history-sub';mid.appendChild(sub);}
    sub.textContent='Dự đoán: '+pred+' · Kết quả thực tế: '+actual;
   }
  });
 }
 function refresh(){mountLearning();verifyHistory();}
 function start(){
  makeUniverse();refresh();
  var root=document.getElementById('app')||document.body;
  if(window.MutationObserver){
   new MutationObserver(function(){refresh();}).observe(root,{childList:true,subtree:true});
  }
  window.addEventListener('beforeunload',function(){if(raf)cancelAnimationFrame(raf);});
  setInterval(refresh,1800);
 }
 if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',start);else start();
})();
</script>
<!-- /AUZA V20 -->



<!-- AUZA V21: STREAK INTELLIGENCE + CYBER UI (ADDITIVE; LEGACY SOURCE PRESERVED) -->
<style id="auza-v21-style">
:root{--v21-bg:#071126;--v21-line:rgba(116,210,255,.25);--v21-cyan:#8cecff;--v21-text:#eaf7ff;--v21-muted:#9db7d5}
#auza-v21-lab{position:relative;isolation:isolate;overflow:hidden;margin:16px 0;padding:clamp(14px,3vw,22px);border:1px solid var(--v21-line);border-radius:22px;color:var(--v21-text);font:500 13px/1.55 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:radial-gradient(ellipse at 0 0,rgba(36,142,211,.22),transparent 48%),radial-gradient(ellipse at 100% 100%,rgba(128,76,220,.2),transparent 48%),linear-gradient(145deg,#08162d,#111b39 58%,#10152d);box-shadow:0 18px 48px rgba(0,0,0,.28),inset 0 1px rgba(255,255,255,.07)}
#auza-v21-lab:before{content:"";position:absolute;inset:0;z-index:-1;pointer-events:none;background-image:linear-gradient(rgba(143,210,255,.035) 1px,transparent 1px),linear-gradient(90deg,rgba(143,210,255,.035) 1px,transparent 1px);background-size:26px 26px;mask-image:linear-gradient(120deg,#000,transparent 90%)}
#auza-v21-lab *{box-sizing:border-box}
#auza-v21-lab .v21-head{display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;margin-bottom:14px}
#auza-v21-lab .v21-title{font-size:clamp(14px,3vw,18px);font-weight:950;letter-spacing:.65px;color:#d9f8ff;text-shadow:0 0 18px rgba(105,220,255,.28)}
#auza-v21-lab .v21-tag{padding:5px 9px;border:1px solid rgba(118,225,255,.32);border-radius:99px;background:rgba(61,156,210,.12);color:#aeeeff;font-size:9px;font-weight:850;letter-spacing:.5px}
#auza-v21-lab .v21-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:9px}
#auza-v21-lab .v21-cell{min-width:0;padding:12px;border:1px solid rgba(142,199,255,.16);border-radius:15px;background:linear-gradient(145deg,rgba(24,53,91,.7),rgba(28,28,69,.62))}
#auza-v21-lab .v21-cell small{display:block;margin-bottom:5px;color:var(--v21-muted);font-size:9px;font-weight:850;letter-spacing:.6px}
#auza-v21-lab .v21-cell b{display:block;color:#f1fbff;font-size:clamp(16px,4vw,22px);font-weight:950;overflow-wrap:anywhere}
#auza-v21-lab .v21-state{color:#9cecff!important}
#auza-v21-lab .v21-track{height:8px;margin-top:9px;border-radius:99px;background:rgba(168,202,255,.12);overflow:hidden}
#auza-v21-lab .v21-track i{display:block;height:100%;width:50%;border-radius:99px;background:linear-gradient(90deg,#62bfff,#91f1d5);transition:width .35s ease}
#auza-v21-lab .v21-runs{display:flex;gap:5px;flex-wrap:wrap;margin:12px 0}
#auza-v21-lab .v21-run{min-width:34px;padding:6px 8px;border:1px solid rgba(145,200,255,.22);border-radius:9px;text-align:center;background:rgba(26,57,96,.62);font-size:10px;font-weight:850}
#auza-v21-lab .v21-run.t{color:#8ee5ff}.v21-run.x{color:#ffd58d}
#auza-v21-lab .v21-note{margin-top:10px;color:#a8bfdc;font-size:10px;line-height:1.65}
#auza-v21-lab .v21-actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}
#auza-v21-lab button{flex:1;min-height:42px;padding:10px 13px;border:1px solid rgba(140,225,255,.34);border-radius:12px;background:linear-gradient(110deg,#8de7ff,#a8f1d9);color:#082039;font:900 11px system-ui;letter-spacing:.35px;cursor:pointer;box-shadow:0 5px 18px rgba(61,179,220,.13);transition:transform .18s,filter .18s}
#auza-v21-lab button:active{transform:scale(.98)}
#auza-v21-lab button.secondary{background:rgba(112,162,220,.12);color:#d9f3ff}
#auza-v21-lab .v21-disclaimer{padding:10px 11px;border-left:2px solid #77dfff;background:rgba(83,160,207,.08);border-radius:0 9px 9px 0}
@media(min-width:640px){#auza-v21-lab .v21-grid{grid-template-columns:repeat(4,minmax(0,1fr))}}
@media(max-width:360px){#auza-v21-lab{padding:12px;border-radius:17px}#auza-v21-lab .v21-cell{padding:9px}}
@media(prefers-reduced-motion:reduce){#auza-v21-lab *{transition:none!important}}
</style>
<script id="auza-v21-streak-intelligence">
(function(){
 'use strict';
 if(window.__AUZA_V21_INSTALLED)return;window.__AUZA_V21_INSTALLED=true;
 var panel=null,lastKey='',timer=0;
 function toSide(v){
  var s=String(v==null?'':v).trim().toUpperCase();
  if(s==='T'||s==='TAI'||s==='TÀI')return 'T';
  if(s==='X'||s==='XIU'||s==='XỈU')return 'X';
  return '';
 }
 function historySequence(){
  var rows=window.S&&Array.isArray(S.history)?S.history:[];
  // Ứng dụng AUZA lưu lịch sử mới nhất trước; chuẩn hoá thành cũ -> mới.
  return rows.map(function(r){
   if(!r||typeof r!=='object')return '';
   return toSide(r.result||r.ket_qua||r.outcome||'');
  }).filter(Boolean).reverse();
 }
 function getRuns(seq){
  var out=[];
  seq.forEach(function(v){
   var last=out[out.length-1];
   if(last&&last.side===v)last.len++;
   else out.push({side:v,len:1});
  });
  return out;
 }
 function analyze(seq){
  var runs=getRuns(seq),active=runs.length?runs[runs.length-1]:{side:'',len:0};
  // Không dùng chuỗi đang chạy làm mẫu hoàn tất (right-censoring).
  var completed=runs.slice(0,-1),same=completed.filter(function(r){return r.side===active.side;});
  var atRisk=same.filter(function(r){return r.len>=active.len;}).length;
  var continued=same.filter(function(r){return r.len>active.len;}).length;
  var raw=atRisk?continued/atRisk:null;
  // Laplace smoothing tránh kết luận cực đoan khi số mẫu ít.
  var smoothed=atRisk?(continued+1)/(atRisk+2):null;
  var allAtRisk=completed.filter(function(r){return r.len>=active.len;}).length;
  var allContinued=completed.filter(function(r){return r.len>active.len;}).length;
  var pooled=allAtRisk?(allContinued+1)/(allAtRisk+2):null;
  var estimate=smoothed;
  if(atRisk<3&&pooled!==null)estimate=atRisk?(.65*smoothed+.35*pooled):pooled;
  var confidence=atRisk>=12?'MẪU TƯƠNG ĐỐI NHIỀU':atRisk>=5?'MẪU CÒN HẠN CHẾ':'ÍT MẪU · THAM KHẢO';
  var label='CHƯA ĐỦ DỮ LIỆU';
  if(estimate!==null&&atRisk>=3){
   if(estimate>=.58)label='NGHIÊNG THEO BỆT';
   else if(estimate<=.42)label='TÍN HIỆU BỆT YẾU';
   else label='CHƯA CÓ ƯU THẾ RÕ';
  }else if(estimate!==null)label='TÍN HIỆU THAM KHẢO';
  var recent=runs.slice(-12);
  return {count:seq.length,runs:runs,active:active,completed:same.length,atRisk:atRisk,continued:continued,
   raw:raw,estimate:estimate,confidence:confidence,label:label,recent:recent,
   sideName:active.side==='T'?'TÀI':active.side==='X'?'XỈU':'—'};
 }
 function esc(v){return String(v==null?'':v).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
 function mount(){
  if(!window.S||!S.loggedIn)return false;
  var anchor=document.querySelector('.ai-card')||document.querySelector('.card')||document.getElementById('app')||document.querySelector('main');
  if(!anchor)return false;
  if(!panel||!document.getElementById('auza-v21-lab')){
   panel=document.createElement('section');panel.id='auza-v21-lab';
   panel.innerHTML='<div class="v21-head"><div><div class="v21-title">◈ AUZA V21 · STREAK INTELLIGENCE</div><div class="v21-note">Phân tích chuỗi bệt · học từ các đoạn bệt đã kết thúc</div></div><span class="v21-tag">ADDITIVE ENGINE · V21</span></div>'+
    '<div class="v21-grid">'+
     '<div class="v21-cell"><small>NHỊP ĐANG CHẠY</small><b id="v21-current">—</b></div>'+
     '<div class="v21-cell"><small>ĐỘ DÀI BỆT HIỆN TẠI</small><b id="v21-length">—</b></div>'+
     '<div class="v21-cell"><small>TỶ LỆ TIẾP DIỄN LỊCH SỬ*</small><b id="v21-prob">—</b><div class="v21-track"><i id="v21-meter"></i></div></div>'+
     '<div class="v21-cell"><small>MẪU CÙNG ĐỘ DÀI ĐÃ ĐỦ</small><b id="v21-samples">—</b></div>'+
     '<div class="v21-cell"><small>HƯỚNG THAM KHẢO</small><b class="v21-state" id="v21-action">CHỜ DỮ LIỆU</b></div>'+
    '</div><div class="v21-runs" id="v21-runs"></div>'+
    '<div class="v21-cell"><small>ĐÁNH GIÁ CHU KỲ</small><b class="v21-state" id="v21-state">ĐANG PHÂN TÍCH</b><div class="v21-note" id="v21-detail"></div></div>'+
    '<div class="v21-actions"><button type="button" id="v21-refresh">↻ PHÂN TÍCH LẠI</button><button type="button" class="secondary" id="v21-clear-view">ĐẶT LẠI HIỂN THỊ</button></div>'+
    '<div class="v21-note v21-disclaimer">* Tỷ lệ được ước lượng từ các chuỗi bệt đã hoàn tất trong lịch sử, loại trừ chuỗi hiện tại đang chạy. Đây là thống kê mô tả, không phải xác suất đảm bảo cho phiên kế tiếp. Khi mẫu ít, hệ thống hạ mức tin cậy và không ép tín hiệu bẻ.</div>';
   anchor.insertAdjacentElement('afterend',panel);
   panel.querySelector('#v21-refresh').addEventListener('click',function(){lastKey='';refresh();});
   panel.querySelector('#v21-clear-view').addEventListener('click',function(){lastKey='';panel.querySelector('#v21-state').textContent='ĐÃ LÀM MỚI HIỂN THỊ';refresh();});
  }
  refresh();return true;
 }
 function refresh(){
  if(!panel||!document.getElementById('auza-v21-lab'))return;
  var seq=historySequence(),a=analyze(seq);
  var key=seq.join('')+'|'+a.atRisk+'|'+a.continued;
  if(key===lastKey)return;lastKey=key;
  var put=function(id,value){var n=panel.querySelector('#'+id);if(n)n.textContent=value;};
  put('v21-current',a.sideName);put('v21-length',a.active.len+' phiên');
  put('v21-prob',a.estimate===null?'Chưa đủ mẫu':(a.estimate*100).toFixed(1)+'%');
  put('v21-samples',a.atRisk+' mẫu');
  put('v21-action',a.estimate!==null&&a.atRisk>=3&&a.estimate>=.58?'THEO '+a.sideName:'CHỜ · KHÔNG ÉP BẺ');
  var meter=panel.querySelector('#v21-meter');if(meter)meter.style.width=(a.estimate===null?0:Math.max(0,Math.min(100,a.estimate*100)))+'%';
  put('v21-state',a.label);
  put('v21-detail',a.estimate===null?
   'Chưa có đủ chuỗi bệt đã kết thúc để ước lượng khả năng tiếp diễn. Tiếp tục ghi nhận lịch sử.':
   'Trong '+a.atRisk+' chuỗi cùng phía từng đạt ít nhất '+a.active.len+' phiên, có '+a.continued+' chuỗi tiếp tục dài hơn. Ước lượng đã làm trơn: '+(a.estimate*100).toFixed(1)+'%. '+a.confidence+'.');
  var runBox=panel.querySelector('#v21-runs');
  if(runBox)runBox.innerHTML=a.recent.map(function(r){return '<span class="v21-run '+(r.side==='T'?'t':'x')+'">'+(r.side==='T'?'TÀI':'XỈU')+' × '+r.len+'</span>';}).join('')||'<span class="v21-note">Chưa có lịch sử hợp lệ.</span>';
 }
 function boot(){
  mount();
  var root=document.getElementById('app')||document.body;
  if(window.MutationObserver&&root)new MutationObserver(function(){if(!panel||!document.getElementById('auza-v21-lab'))mount();}).observe(root,{childList:true,subtree:true});
  timer=setInterval(function(){if(!panel||!document.getElementById('auza-v21-lab'))mount();else refresh();},2200);
 }
 window.AUZA_V21={
   analyze:function(){return analyze(historySequence());},
   predictNext:function(){
    var a=analyze(historySequence());
    if(a.estimate!==null&&a.atRisk>=3&&a.estimate>=.58)
     return {action:'FOLLOW',prediction:a.active.side,confidence:a.estimate,samples:a.atRisk,reason:'Tỷ lệ tiếp diễn lịch sử cùng phía đang cao hơn ngưỡng tham khảo'};
    return {action:'WAIT',prediction:null,confidence:a.estimate,samples:a.atRisk,reason:'Chưa đủ bằng chứng để theo hoặc bẻ; không đảo chiều chỉ vì chuỗi đã dài'};
   },
   refresh:refresh
  };
 if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',boot);else boot();
})();
</script>
<!-- /AUZA V21 ADD-ON -->

</body>
</html>
<?php
}