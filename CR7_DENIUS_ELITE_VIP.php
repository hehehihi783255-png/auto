<?php
/**
 * CR7 DENIUS — 35-Core Adaptive Prediction Engine
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
        'hmac_secret' => 'CR7_DENIUS_AUTH_HMAC_v3',
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

const LEARNING_DIR = DATA_DIR . '/learning';
if (!is_dir(LEARNING_DIR)) @mkdir(LEARNING_DIR, 0700, true);
@file_put_contents(LEARNING_DIR . '/.htaccess', "Require all denied\nDeny from all\n");

function learning_paths(string $key): array {
    $id = hash('sha256', strtolower(trim($key)));
    return [LEARNING_DIR . '/' . $id . '.jsonl', LEARNING_DIR . '/' . $id . '.stats.json'];
}

/** Append-only, per-key training store. Each session is recorded once. */
function learning_record_session(string $key, int $sid, string $actual, array $sessions): void {
    if ($sid <= 0 || !in_array($actual, ['T','X'], true)) return;
    [$rawPath, $statsPath] = learning_paths($key);
    $lockPath = $rawPath . '.lock';
    $lock = @fopen($lockPath, 'c+');
    if (!$lock) return;
    if (!@flock($lock, LOCK_EX)) { fclose($lock); return; }
    $stats = is_file($statsPath) ? (json_decode((string)@file_get_contents($statsPath), true) ?: []) : [];
    $lastSid = (int)($stats['last_session_id'] ?? 0);
    if ($sid <= $lastSid) { @flock($lock, LOCK_UN); fclose($lock); return; }

    // API trả danh sách mới nhất trước; chỉ lấy các phiên đứng trước phiên đang học.
    $prior = [];
    foreach ($sessions as $row) {
        $rid = (int)($row['id'] ?? 0);
        if ($rid >= $sid) continue;
        $mapped = map_result((string)($row['resultTruyenThong'] ?? ''));
        if ($mapped !== null) $prior[$rid] = $mapped === 'TAI' ? 'T' : 'X';
    }
    ksort($prior, SORT_NUMERIC);
    $sequence = array_values($prior);
    $patterns = $stats['patterns'] ?? [];
    $maxN = min(8, count($sequence));
    for ($n = 2; $n <= $maxN; $n++) {
        $context = implode('', array_slice($sequence, -$n));
        if (!isset($patterns[$n][$context])) $patterns[$n][$context] = ['T'=>0,'X'=>0];
        $patterns[$n][$context][$actual] = (int)($patterns[$n][$context][$actual] ?? 0) + 1;
    }
    $row = ['session'=>$sid, 'result'=>$actual, 'context'=>implode('', array_slice($sequence, -8)), 'ts'=>time()];
    @file_put_contents($rawPath, json_encode($row, JSON_UNESCAPED_UNICODE) . "\n", FILE_APPEND | LOCK_EX);
    $stats['version'] = 2;
    $stats['last_session_id'] = $sid;
    $stats['total_sessions'] = (int)($stats['total_sessions'] ?? 0) + 1;
    $stats['patterns'] = $patterns;
    $tmp = $statsPath . '.tmp';
    if (@file_put_contents($tmp, json_encode($stats, JSON_UNESCAPED_UNICODE), LOCK_EX) !== false) { @rename($tmp, $statsPath); @chmod($statsPath, 0600); }
    @chmod($rawPath, 0600);
    @flock($lock, LOCK_UN); fclose($lock);
}

function learning_vote(string $key, array $hist): ?array {
    [, $statsPath] = learning_paths($key);
    if (!is_file($statsPath)) return null;
    $stats = json_decode((string)@file_get_contents($statsPath), true);
    if (!is_array($stats) || empty($stats['patterns'])) return null;
    $patterns = $stats['patterns'];
    $votes = ['T'=>0.0, 'X'=>0.0]; $evidence = 0;
    // hist newest-first; reverse the recent segment to form chronological context.
    for ($n = 2; $n <= min(8, count($hist)); $n++) {
        $context = implode('', array_reverse(array_slice($hist, 0, $n)));
        $counts = $patterns[$n][$context] ?? null;
        if (!is_array($counts)) continue;
        $t = (int)($counts['T'] ?? 0); $x = (int)($counts['X'] ?? 0); $total = $t + $x;
        if ($total < 3) continue;
        $weight = log(1 + $total) * (1 + ($n * 0.08));
        $votes['T'] += (($t + 1) / ($total + 2)) * $weight;
        $votes['X'] += (($x + 1) / ($total + 2)) * $weight;
        $evidence += $total;
    }
    $sum = $votes['T'] + $votes['X'];
    if ($sum <= 0) return null;
    $side = $votes['T'] >= $votes['X'] ? 'T' : 'X';
    $edge = abs($votes['T'] - $votes['X']) / $sum;
    return ['side'=>$side, 'strength'=>$edge, 'evidence'=>$evidence, 'total'=>(int)($stats['total_sessions'] ?? 0)];
}

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
    $s=key_load_by_user($u); if(!$s) return false;
    return !empty(license_check((string)($s['license_key']??''),(string)($s['device']??''))['ok']);
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
// DENIUS CR7 ENGINE — port 35-core logic from lc.py
// No reverse/anti-rig rules. Per-account weights adapt after each settled session.
function ai_default_weights(): array {
    return [
      'trend'=>1,'pattern'=>1,'frequency'=>1,'momentum'=>1,'symmetry'=>1,'alternating'=>1,'fibonacci'=>1,'chaos'=>1,'shadow'=>1,
      'markov1'=>1,'markov2'=>1,'markov3'=>1,'rsi_indicator'=>1,'macd_cross'=>1,'pivot_reversal'=>1,'cluster_3'=>1,
      'parity'=>1,'golden_ratio'=>1,'quantum'=>1,'anti_bait'=>2,'smart_breaker'=>2,'ngram_4'=>1.5,'ngram_5'=>1.5,
      'elliott_wave'=>1.5,'contrarian'=>2,'bollinger_bands'=>1.5,'mean_reversion'=>1,'mirror_reflection'=>1,
      'martingale_trap'=>1.5,'poisson_prob'=>1,'harmonic_cycle'=>1,'breakout_hunter'=>1.5,'volume_fakeout'=>1.5,
      'time_decay'=>1,'neural_bias'=>1,'twin_peaks'=>1
    ];
}
function ai_predict_core(array $hist, array $weights): array {
    // hist newest-first, symbols T/X
    $n=count($hist); $last=$hist[0]; $opp=$last==='T'?'X':'T';
    $seq=implode('',array_reverse($hist)); $recent=substr($seq,-50);
    $streak=1; for($i=$n-2;$i>=0 && $hist[$i]===$last;$i--) $streak++;
    $m=[];
    $m['trend']=count(array_filter(array_slice($hist,0,5),fn($v)=>$v===$last))>=3?$last:$opp;
    $m['pattern']=(str_ends_with($seq,'TXTX')||str_ends_with($seq,'TTXX'))?$opp:$last;
    $trans=['T'=>['T'=>0,'X'=>0],'X'=>['T'=>0,'X'=>0]];
    for($i=0;$i<$n-1;$i++) $trans[$hist[$i+1]][$hist[$i]]++;
    $m['markov1']=$trans[$last]['T']>$trans[$last]['X']?'T':'X';
    $m['markov2']=array_slice($hist,0,2)===['T','T']?'T':'X';
    $m['markov3']=array_slice($hist,0,3)===[$last,$last,$last]?$opp:$m['markov2'];
    $last20=array_slice($hist,0,20);
    $m['frequency']=count(array_filter($last20,fn($v)=>$v==='T'))>10?'X':'T';
    $moment=0; foreach(array_slice($hist,0,5) as $i=>$v) $moment+=($v==='T'?1:-1)*(5-$i);
    $m['momentum']=$moment>0?'T':'X';
    $m['symmetry']=(strlen($seq)>=6 && substr($seq,-6,3)===strrev(substr($seq,-3)))?$opp:$last;
    $m['alternating']=$opp;
    $m['fibonacci']=in_array($streak,[3,5,8,13],true)?$opp:$last;
    $tail10=substr($seq,-10); $changes=0;
    for($i=1;$i<strlen($tail10);$i++) if($tail10[$i]!==$tail10[$i-1]) $changes++;
    $m['chaos']=$changes>=7?$opp:$last;
    $m['shadow']=count(array_filter(array_slice($hist,0,50),fn($v)=>$v==='T'))<25?'T':'X';
    $t10=substr_count(substr($seq,-10),'T');
    $m['rsi_indicator']=$t10>=7?'X':($t10<=3?'T':$last);
    $m['macd_cross']=substr_count(substr($seq,-3),'T')>(substr_count(substr($seq,-9),'T')/3)?'T':'X';
    $m['pivot_reversal']=($n>=3 && $hist[2]===$hist[1] && $hist[1]!==$hist[0])?$last:$last;
    $m['cluster_3']=in_array(substr($seq,-3),['TTT','TXX','XTX','XXT'],true)?'T':'X';
    $m['parity']=$streak%2===0?$opp:$last;
    $m['golden_ratio']=(count(array_filter(array_slice($hist,0,30),fn($v)=>$v==='T'))/min(30,$n))<0.618?'T':'X';
    // Deterministic replacement for random "quantum" vote in source.
    $m['quantum']=(hexdec(substr(hash('sha256',$seq),0,2))%2===0)?'T':'X';
    $m['anti_bait']=($streak>=5||str_ends_with($seq,'TXTXT'))?$opp:$last;
    $maxStreak=1;$cur=1;
    for($i=1;$i<$n;$i++){if($hist[$i]===$hist[$i-1])$cur++;else{$maxStreak=max($maxStreak,$cur);$cur=1;}}
    $maxStreak=max($maxStreak,$cur);
    $m['smart_breaker']=($streak>=$maxStreak-1&&$streak>=3)?$opp:$last;
    foreach([4,5] as $len){
      $ctx=substr($seq,-$len);$t=0;$x=0;
      for($i=0;$i<strlen($seq)-$len;$i++) if(substr($seq,$i,$len)===$ctx){
        $next=$seq[$i+$len]??''; if($next==='T')$t++;elseif($next==='X')$x++;
      }
      $m['ngram_'.$len]=$t>$x?'T':($x>$t?'X':$opp);
    }
    $m['elliott_wave']=str_ends_with($seq,'TXTXT')?$last:(str_ends_with($seq,'TTXXTT')?'X':$opp);
    $m['contrarian']=($streak===4||$streak===6)?$opp:(str_ends_with($seq,'TXTXTX')?'X':$last);
    $rate=$t10/10;
    $m['bollinger_bands']=$rate>=0.8?'X':($rate<=0.2?'T':$last);
    $base=array_slice($hist,0,100);$tcount=count(array_filter($base,fn($v)=>$v==='T'));
    $m['mean_reversion']=$tcount<(count($base)*0.45)?'T':'X';
    $m['mirror_reflection']=strlen($seq)>=8?(substr($seq,-8,1)==='T'?'T':'X'):$opp;
    $m['martingale_trap']=in_array($streak,[3,7],true)?$opp:$last;
    $m['poisson_prob']=(count(array_filter(array_slice($hist,0,5),fn($v)=>$v==='T'))%2===1)?'T':'X';
    $m['harmonic_cycle']=$n>=4?$hist[3]:$opp;
    $m['breakout_hunter']=($streak===1&&$n>=3&&$hist[1]===$hist[2])?$last:$opp;
    $m['volume_fakeout']=(in_array(substr($seq,-5),['TTTXT','XXXTX'],true))?$last:$opp;
    $m['time_decay']=$opp;
    $m['neural_bias']=count(array_filter(array_slice($hist,0,7),fn($v)=>$v==='T'))>3?'T':'X';
    $m['twin_peaks']=(str_ends_with($seq,'TTXTT')||str_ends_with($seq,'XXTXX'))?$opp:$last;
    $scores=['T'=>0.0,'X'=>0.0];
    foreach($m as $name=>$side){$w=max(0.1,(float)($weights[$name]??1));$scores[$side]+=pow($w,1.5);}
    $side=$scores['T']>$scores['X']?'T':'X';
    $total=$scores['T']+$scores['X'];$confidence=$total>0?round(50+abs($scores['T']-$scores['X'])/$total*45):50;
    return ['side'=>$side,'confidence'=>(int)max(50,min(95,$confidence)),'models'=>$m,'scores'=>$scores];
}
function engine_predict(string $key, array $sessions): ?array {
    $hist=[];
    foreach($sessions as $row){
      $r=map_result((string)($row['resultTruyenThong']??''));
      if($r!==null)$hist[]=$r==='TAI'?'T':'X';
    }
    // Use whatever verified API history exists immediately; no artificial 10-session gate.
    if(!$hist)return null;
    $state=key_load($key);
    $weights=array_merge(ai_default_weights(),$state['ai_weights']??[]);
    $r=ai_predict_core($hist,$weights);
    // Add a separate long-term n-gram memory vote from the append-only BigData archive.
    $memory=learning_vote($key,$hist);
    if($memory!==null && $memory['evidence']>=6){
      $boost=min(3.0,log(1+$memory['evidence'])*0.55);
      $r['scores'][$memory['side']]+=$boost;
      $r['side']=$r['scores']['T']>$r['scores']['X']?'T':'X';
      $sum=$r['scores']['T']+$r['scores']['X'];
      $r['confidence']=(int)max(50,min(95,round(50+abs($r['scores']['T']-$r['scores']['X'])/max(0.001,$sum)*45)));
    }
    // Bind the model snapshot to the exact next session so delayed API results cannot train the wrong round.
    $latestId=0; foreach($sessions as $row){if(map_result((string)($row['resultTruyenThong']??''))!==null){$latestId=(int)($row['id']??0);break;}}
    key_update($key,function($d)use($r,$hist,$latestId){$d['ai_pending_models']=$r['models'];$d['ai_pending_context']=implode('',array_reverse(array_slice($hist,0,8)));$d['ai_pending_for_session']=$latestId+1;return $d;});
    return ['prediction'=>$r['side']==='T'?'TAI':'XIU','base'=>$r['side'],'final_sym'=>$r['side'],
      'confidence'=>$r['confidence'],'history_count'=>count($hist),
      'models'=>$r['models'],'scores'=>$r['scores']];
}

function ai_backfill_history(string $key, array $sessions): void {
    $state=key_load($key);
    if(!empty($state['ai_backfilled'])) return;
    $ordered=[];
    foreach($sessions as $row){
      $sid=(int)($row['id']??0);$r=map_result((string)($row['resultTruyenThong']??''));
      if($sid>0&&$r!==null)$ordered[$sid]=$r==='TAI'?'T':'X';
    }
    ksort($ordered,SORT_NUMERIC);
    $weights=array_merge(ai_default_weights(),$state['ai_weights']??[]);
    $streaks=$state['ai_model_streaks']??[];$trained=0;$prefix=[];
    foreach($ordered as $actual){
      if(count($prefix)>=1){
        $pred=ai_predict_core(array_reverse($prefix),$weights);
        foreach($pred['models'] as $name=>$guess){
          if($guess===$actual){$streaks[$name]=(int)($streaks[$name]??0)+1;$weights[$name]=min(20.0,$weights[$name]+0.5+0.2*$streaks[$name]);}
          else{$streaks[$name]=0;$weights[$name]=max(0.1,$weights[$name]-2.5);}
        }
        $trained++;
      }
      $prefix[]=$actual;
    }
    key_update($key,function($d)use($weights,$streaks,$trained,$ordered){
      $d['ai_weights']=$weights;$d['ai_model_streaks']=$streaks;
      $d['ai_training_count']=(int)($d['ai_training_count']??0)+$trained;
      $d['ai_backfilled']=true;
      $d['ai_backfill_sessions']=count($ordered);
      return $d;
    });
}
function ai_learn_result(string $key, string $actual, int $sessionId): void {
    $s=key_load($key);$models=$s['ai_pending_models']??[];
    if(!$models || (int)($s['ai_pending_for_session']??0)!==$sessionId)return;
    $weights=array_merge(ai_default_weights(),$s['ai_weights']??[]);
    $streaks=$s['ai_model_streaks']??[];
    foreach($models as $name=>$guess){
      if($guess===$actual){
        $streaks[$name]=(int)($streaks[$name]??0)+1;
        $weights[$name]=min(20.0,(float)$weights[$name]+0.5+0.2*$streaks[$name]);
      }else{
        $streaks[$name]=0;
        $weights[$name]=max(0.1,(float)$weights[$name]-2.5);
      }
    }
    key_update($key,function($d)use($weights,$streaks,$actual){
      $d['ai_weights']=$weights;$d['ai_model_streaks']=$streaks;
      $d['ai_training_count']=(int)($d['ai_training_count']??0)+1;
      $d['ai_last_actual']=$actual;$d['ai_pending_models']=[];
      $d['ai_pending_for_session']=0;
      return $d;
    });
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
    ai_backfill_history($key, $sessions);

    // Backfill the available API history once, including accounts upgraded from older builds.
    [, $learningStatsPath] = learning_paths($key);
    if (!is_file($learningStatsPath)) {
        $bootstrap = [];
        foreach ($sessions as $row) {
            $sid = (int)($row['id'] ?? 0);
            $mapped = map_result((string)($row['resultTruyenThong'] ?? ''));
            if ($sid > 0 && $mapped !== null) $bootstrap[$sid] = $mapped === 'TAI' ? 'T' : 'X';
        }
        ksort($bootstrap, SORT_NUMERIC);
        foreach ($bootstrap as $sid => $sym) learning_record_session($key, (int)$sid, $sym, $sessions);
    }

    if ($lastId === 0) {
        // First run: import all completed sessions currently supplied by the API
        // into the permanent per-key learning archive, oldest to newest.
        $bootstrap = [];
        foreach ($sessions as $row) {
            $sid = (int)($row['id'] ?? 0);
            $mapped = map_result((string)($row['resultTruyenThong'] ?? ''));
            if ($sid > 0 && $mapped !== null) $bootstrap[$sid] = $mapped === 'TAI' ? 'T' : 'X';
        }
        ksort($bootstrap, SORT_NUMERIC);
        foreach ($bootstrap as $sid => $sym) learning_record_session($key, (int)$sid, $sym, $sessions);
        key_update($key, fn($d) => array_merge($d, ['last_session_id'=>$latestId]));
        key_log($key, 'info', '📡 Baseline #'.$latestId.' | Learning archive: '.count($bootstrap).' sessions');
        return $actions;
    }

    if ($latestId > $lastId) {
        for ($sid = $lastId + 1; $sid <= $latestId; $sid++) {
            $found = find_session($sessions, $sid);
            if (!$found) continue;
            $result = map_result((string)($found['resultTruyenThong'] ?? ''));
            if ($result === null) continue;
            learning_record_session($key, $sid, $result === 'TAI' ? 'T' : 'X', $sessions);
            ai_learn_result($key, $result === 'TAI' ? 'T' : 'X', $sid);
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

                    // Record prediction accuracy only; never activate a reverse-direction mode.
                    $predLog = $d['pred_log'] ?? [];
                    array_unshift($predLog, ['base'=>$baseSym, 'final'=>$finalSym, 'actual'=>$actualSym, 'ts'=>time()]);
                    $d['pred_log'] = array_slice($predLog, 0, 500);

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
        $licOk = license_worker_valid((string)($s['license_key'] ?? ''));
        if (!$licOk) { key_update($key, function($d){ $d['config']['auto']=false; $d['config']['paused']=true; return $d; }); break; }
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

// ═══════ CR7 LICENSE / ADMIN / ORDERS ═══════
const LICENSE_FILE = DATA_DIR . '/license_vault.json';
const ORDER_FILE = DATA_DIR . '/payment_orders.json';
const ADMIN_ACCESS_KEY = '0912212@@';
const ADMIN_CREATE_PIN = '246810';
const QR_IMAGE_URL = 'https://raw.githubusercontent.com/nguyenha783255-wq/QR-DENIUS/refs/heads/main/IMG_8347.png';
function json_store_read(string $path): array {
    if (!is_file($path)) return [];
    $v = json_decode((string)@file_get_contents($path), true);
    return is_array($v) ? $v : [];
}
function json_store_write(string $path, array $data): void {
    $tmp=$path.'.tmp';
    @file_put_contents($tmp, json_encode($data, JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT), LOCK_EX);
    @rename($tmp,$path); @chmod($path,0600);
}
function client_ip_addr(): string {
    // Không tin X-Forwarded-For nếu server chưa cấu hình proxy tin cậy.
    return substr((string)($_SERVER['REMOTE_ADDR'] ?? 'unknown'),0,64);
}
function license_device_fingerprint(string $device): string {
    return hash('sha256',substr($device,0,180).'|'.substr((string)($_SERVER['HTTP_USER_AGENT']??''),0,300));
}
function license_cleanup_expired(): void {
    $all=json_store_read(LICENSE_FILE); $changed=false;
    foreach($all as $k=>$v) if(!empty($v['expires_at']) && (int)$v['expires_at']<=time()) { unset($all[$k]); $changed=true; }
    if($changed) json_store_write(LICENSE_FILE,$all);
}
function license_worker_valid(string $license): bool {
    if(trim($license)==='') return false; license_cleanup_expired();
    $all=json_store_read(LICENSE_FILE); $id=hash('sha256',strtoupper(trim($license)));
    if(!isset($all[$id])) return false; $v=$all[$id];
    return empty($v['revoked']) && !empty($v['activated_at']) && (int)($v['expires_at']??0)>time();
}
function license_check(string $license, string $device=''): array {
    license_cleanup_expired(); $all=json_store_read(LICENSE_FILE); $id=hash('sha256',strtoupper(trim($license)));
    if(!isset($all[$id])) return ['ok'=>false,'msg'=>'KEY KHÔNG HỢP LỆ HOẶC ĐÃ HẾT HẠN'];
    $v=$all[$id]; if(!empty($v['revoked'])) return ['ok'=>false,'msg'=>'KEY ĐÃ BỊ THU HỒI'];
    $fp=license_device_fingerprint($device);
    if(empty($v['device_fp'])) { $v['device_fp']=$fp; $v['device_id']=substr($device,0,80); $v['ip_first']=client_ip_addr(); $v['activated_at']=time(); $v['expires_at']=time()+(int)$v['duration_seconds']; $all[$id]=$v; json_store_write(LICENSE_FILE,$all); }
    elseif(!hash_equals((string)$v['device_fp'],$fp)) return ['ok'=>false,'msg'=>'KEY ĐÃ ĐƯỢC GẮN VỚI THIẾT BỊ KHÁC'];
    if((int)($v['expires_at']??0)<=time()) { unset($all[$id]); json_store_write(LICENSE_FILE,$all); return ['ok'=>false,'msg'=>'KEY ĐÃ HẾT HẠN']; }
    return ['ok'=>true,'license'=>$v,'remaining'=>(int)$v['expires_at']-time()];
}
function admin_token_valid(string $token): bool {
    if(!$token) return false; $d=base64_decode($token,true); if($d===false) return false;
    $p=explode('|',$d); if(count($p)!==2) return false;
    return (int)$p[0]>=time() && hash_equals(hash_hmac('sha256',$p[0],'CR7_ADMIN_SESSION_v1'),$p[1]);
}
const ADMIN_DEVICE_FILE = DATA_DIR . '/admin_device_lock.json';
function admin_device_fingerprint(string $device): string {
    return hash('sha256', substr($device,0,180).'|'.substr((string)($_SERVER['HTTP_USER_AGENT']??''),0,300));
}
/** Bind the admin account once to the first device that successfully logs in. */
function admin_device_allowed(string $device, bool $bindFirst=false): bool {
    if (trim($device)==='') return false;
    $fp=admin_device_fingerprint($device);
    $fh=@fopen(ADMIN_DEVICE_FILE.'.lock','c+');
    if(!$fh) return false;
    if(!@flock($fh,LOCK_EX)){fclose($fh);return false;}
    $saved=json_store_read(ADMIN_DEVICE_FILE);
    if(empty($saved['device_fp']) && $bindFirst) {
        $saved=['device_fp'=>$fp,'device_id'=>substr($device,0,80),'ip_first'=>client_ip_addr(),'bound_at'=>time()];
        json_store_write(ADMIN_DEVICE_FILE,$saved);
    }
    $ok=!empty($saved['device_fp']) && hash_equals((string)$saved['device_fp'],$fp);
    @flock($fh,LOCK_UN); fclose($fh);
    return $ok;
}
function make_admin_token(): string { $exp=(string)(time()+7200); return base64_encode($exp.'|'.hash_hmac('sha256',$exp,'CR7_ADMIN_SESSION_v1')); }
function license_make_key(): string { return 'CR7-'.strtoupper(bin2hex(random_bytes(3))).'-'.strtoupper(bin2hex(random_bytes(3))).'-'.strtoupper(bin2hex(random_bytes(2))); }
function license_duration_map(): array { return ['1 ngày'=>['seconds'=>86400,'price'=>15000],'3 ngày'=>['seconds'=>259200,'price'=>35000],'1 tuần'=>['seconds'=>604800,'price'=>60000],'1 tháng'=>['seconds'=>2592000,'price'=>100000]]; }
function license_issue(string $duration, string $source='admin'): array {
    $map=license_duration_map(); if(!isset($map[$duration])) throw new RuntimeException('Thời hạn không hợp lệ');
    $key=license_make_key(); $all=json_store_read(LICENSE_FILE); $id=hash('sha256',strtoupper($key));
    $all[$id]=['key'=>$key,'name'=>$duration,'duration'=>$duration,'duration_seconds'=>$map[$duration]['seconds'],'price'=>$map[$duration]['price'],'created_at'=>time(),'activated_at'=>null,'expires_at'=>null,'device_fp'=>null,'device_id'=>null,'ip_first'=>null,'source'=>$source,'revoked'=>false];
    json_store_write(LICENSE_FILE,$all); return $all[$id];
}
function order_cleanup(): void {
    $orders=json_store_read(ORDER_FILE); $changed=false;
    foreach($orders as $id=>$o) if(($o['status']??'')==='pending' && (int)($o['expires_at']??0)<=time()) { $orders[$id]['status']='expired'; $orders[$id]['updated_at']=time(); $changed=true; }
    if($changed) json_store_write(ORDER_FILE,$orders);
}
function admin_required(): bool {
    return admin_token_valid((string)($_POST['admin_token']??$_GET['admin_token']??''))
        && admin_device_allowed((string)($_POST['admin_device']??$_GET['admin_device']??''));
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
        case 'license_check':
            $r=license_check((string)($_POST['license_key']??''),(string)($_POST['device']??''));
            echo json_encode($r); exit;
        case 'license_activate':
            $lk=trim((string)($_POST['license_key']??'')); $dev=(string)($_POST['device']??'');
            $r=license_check($lk,$dev); echo json_encode($r); exit;
        case 'admin_login':
            $k=(string)($_POST['admin_key']??''); $dev=(string)($_POST['device']??'');
            if(!hash_equals(ADMIN_ACCESS_KEY,$k)) { http_response_code(403); echo json_encode(['ok'=>false,'msg'=>'Mã admin không đúng']); exit; }
            if(!admin_device_allowed((string)($_POST['admin_device']??''),true)) { http_response_code(403); echo json_encode(['ok'=>false,'msg'=>'ADMIN PANEL ĐÃ KHÓA VỚI THIẾT BỊ ĐẦU TIÊN']); exit; }
            echo json_encode(['ok'=>true,'admin_token'=>make_admin_token()]); exit;
        case 'admin_list':
            if(!admin_required()){http_response_code(403);echo json_encode(['ok'=>false,'msg'=>'Admin unauthorized']);exit;}
            license_cleanup_expired(); order_cleanup(); $all=json_store_read(LICENSE_FILE); $orders=json_store_read(ORDER_FILE);
            $today=date('Y-m-d'); $earned=0; foreach($orders as $o) if(($o['status']??'')==='approved' && date('Y-m-d',(int)($o['approved_at']??0))===$today) $earned+=(int)($o['amount']??0);
            $list=[]; foreach($all as $id=>$v){$v['remaining']=!empty($v['expires_at'])?max(0,(int)$v['expires_at']-time()):null;$v['id']=$id;$list[]=$v;}
            echo json_encode(['ok'=>true,'keys'=>$list,'orders'=>array_values($orders),'earned_today'=>$earned,'qr_image'=>QR_IMAGE_URL]); exit;
        case 'admin_create_key':
            if(!admin_required() || !hash_equals(ADMIN_CREATE_PIN,(string)($_POST['pin']??''))){http_response_code(403);echo json_encode(['ok'=>false,'msg'=>'Không được phép']);exit;}
            $v=license_issue((string)($_POST['duration']??'')); echo json_encode(['ok'=>true,'key'=>$v['key'],'license'=>$v]); exit;
        case 'admin_delete_key':
            if(!admin_required()){http_response_code(403);echo json_encode(['ok'=>false]);exit;}
            $all=json_store_read(LICENSE_FILE); $id=(string)($_POST['id']??''); unset($all[$id]); json_store_write(LICENSE_FILE,$all); echo json_encode(['ok'=>true]); exit;
        case 'payment_create':
            order_cleanup(); $duration=(string)($_POST['duration']??''); $map=license_duration_map(); if(!isset($map[$duration])){echo json_encode(['ok'=>false,'msg'=>'Gói không hợp lệ']);exit;}
            $orders=json_store_read(ORDER_FILE); $oid=strtoupper(bin2hex(random_bytes(5))); $code='DENIUS'.strtoupper(substr(bin2hex(random_bytes(3)),0,6)).'-'.str_replace(' ','',$duration);
            $orders[$oid]=['id'=>$oid,'duration'=>$duration,'amount'=>$map[$duration]['price'],'content'=>$code,'status'=>'pending','created_at'=>time(),'expires_at'=>time()+900,'approved_at'=>null,'license_key'=>null,'buyer_device'=>substr((string)($_POST['device']??''),0,80),'buyer_ip'=>client_ip_addr()];
            json_store_write(ORDER_FILE,$orders); echo json_encode(['ok'=>true,'order'=>$orders[$oid],'qr_image'=>QR_IMAGE_URL]); exit;
        case 'payment_list':
            order_cleanup(); $orders=json_store_read(ORDER_FILE); $ids=json_decode((string)($_POST['ids']??'[]'),true); if(!is_array($ids))$ids=[]; $out=[];
            foreach($ids as $id) if(isset($orders[$id])) $out[]=$orders[$id]; echo json_encode(['ok'=>true,'orders'=>$out]); exit;
        case 'payment_mark_sent':
            order_cleanup(); $orders=json_store_read(ORDER_FILE); $id=(string)($_POST['id']??''); if(!isset($orders[$id])||($orders[$id]['status']??'')!=='pending'){echo json_encode(['ok'=>false,'msg'=>'Đơn không còn hiệu lực']);exit;}
            $orders[$id]['status']='waiting_review';$orders[$id]['sent_at']=time();json_store_write(ORDER_FILE,$orders);echo json_encode(['ok'=>true]);exit;
        case 'admin_review_order':
            if(!admin_required()){http_response_code(403);echo json_encode(['ok'=>false]);exit;}
            $orders=json_store_read(ORDER_FILE);$id=(string)($_POST['id']??'');$decision=(string)($_POST['decision']??'');if(!isset($orders[$id])||!in_array($decision,['approve','reject'],true)||!in_array(($orders[$id]['status']??''),['pending','waiting_review'],true)){echo json_encode(['ok'=>false,'msg'=>'Đơn không hợp lệ hoặc đã xử lý']);exit;}
            if($decision==='approve'){$lic=license_issue((string)$orders[$id]['duration'],'payment');$orders[$id]['license_key']=$lic['key'];$orders[$id]['status']='approved';$orders[$id]['approved_at']=time();}else{$orders[$id]['status']='rejected';$orders[$id]['rejected_at']=time();}
            json_store_write(ORDER_FILE,$orders);echo json_encode(['ok'=>true,'order'=>$orders[$id]]);exit;
        case 'verify':
            $u = trim($_POST['user'] ?? ''); $p = trim($_POST['pass'] ?? '');
            $dev = trim($_POST['device'] ?? 'WEB');
            $lic = license_check((string)($_POST['license_key'] ?? ''), $dev);
            if (empty($lic['ok'])) { echo json_encode(['ok'=>false,'msg'=>$lic['msg'] ?? 'License invalid']); exit; }
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
            $s['user']=$u; $s['key']=$key; $s['device']=$dev; $s['license_key']=trim((string)($_POST['license_key']??''));
            $s['nickname']=$gl['nickname']??$u; $s['token']=$gl['token']??'';
            $s['balance']=$gl['money']??($s['balance']??0);
            if (!isset($s['history'])) $s['history']=[];
            if (!isset($s['logs'])) $s['logs']=[];
            if (!isset($s['pred_log'])) $s['pred_log']=[];
            
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
            if (!require_auth($u, $tk)) { echo json_encode(['ok'=>false,'msg'=>'Token hoặc key không hợp lệ']); exit; }
            $key = key_resolve($u); $s = key_load($key);
            if (!$s || empty($s['token'])) { echo json_encode(['ok'=>false,'msg'=>'Session lost']); exit; }
            $lic=license_check((string)($s['license_key']??''),(string)($s['device']??''));
            if(empty($lic['ok'])) { echo json_encode(['ok'=>false,'msg'=>$lic['msg']??'Key hết hạn']); exit; }
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
                $d['ai_weights'] = ai_default_weights(); $d['ai_model_streaks'] = [];
                $d['pred_log'] = [];
                return $d;
            });
            key_log($key, 'info', '🔄 Reset adaptive learning');
            echo json_encode(['ok'=>true]);
            exit;

        case 'status':
            $u = trim($_GET['user'] ?? ''); $tk = trim($_GET['auth_token'] ?? '');
            if (!require_auth($u, $tk)) { echo json_encode(['ok'=>false,'msg'=>'Unauthorized hoặc key hết hạn']); exit; }
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
            if (!require_auth($u, $tk)) { echo json_encode(['ok'=>false,'msg'=>'Unauthorized hoặc key hết hạn']); exit; }
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
                'last_ws_error'=>$s2['last_ws_error']??null]);
            exit;

        case 'logout':
            $u = trim($_POST['user'] ?? ''); $tk = trim($_POST['auth_token'] ?? '');
            if (!require_auth($u, $tk)) { echo json_encode(['ok'=>false,'msg'=>'Unauthorized hoặc key hết hạn']); exit; }
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
            if (!require_auth($u, $tk)) { echo json_encode(['ok'=>false,'msg'=>'Unauthorized hoặc key hết hạn']); exit; }
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
<title>CR7 DENIUS · ELITE AI</title>
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

/* CR7 ELITE — stadium-night black / championship gold */
:root{
 --bg-1:#05070c;--bg-2:#090d16;--bg-3:#111827;
 --pink-1:#f4c75e;--pink-2:#e7b83f;--pink-3:#fff0ad;
 --rose:#d8a52d;--rose-deep:#f4ca63;--text:#f7f4e9;--text-dim:#c6b98f;--muted:#7f7868;
 --mint:#71e6b4;
}
body{background:radial-gradient(ellipse at 50% -10%,#34301d 0%,#10131c 38%,#05070c 78%)!important;color:#f7f4e9}
.bg-layer{background:radial-gradient(circle at 15% 18%,rgba(255,207,91,.12),transparent 30%),radial-gradient(circle at 85% 70%,rgba(35,91,150,.12),transparent 32%)!important}
.aurora{background:linear-gradient(120deg,transparent,rgba(240,190,65,.08),transparent,rgba(57,120,190,.08),transparent)!important;animation:cr7Aurora 12s ease-in-out infinite alternate}
@keyframes cr7Aurora{from{transform:translateX(-8%) rotate(-4deg)}to{transform:translateX(8%) rotate(4deg)}}
.card,.glass{background:linear-gradient(145deg,rgba(25,29,38,.91),rgba(8,11,17,.94))!important;border:1px solid rgba(235,190,78,.25)!important;box-shadow:0 18px 55px rgba(0,0,0,.48),inset 0 1px rgba(255,255,255,.05)!important;backdrop-filter:blur(18px)}
.brand,.hbrand h1{background:linear-gradient(90deg,#fff0ad,#e4b63f,#fff8d8,#b88925)!important;background-size:250% 100%!important;-webkit-background-clip:text!important;background-clip:text!important;animation:cr7Gold 5s linear infinite!important;filter:drop-shadow(0 0 12px rgba(239,190,66,.32))}
@keyframes cr7Gold{to{background-position:250% 0}}
.brand{letter-spacing:3px!important;text-shadow:0 0 25px rgba(231,184,63,.22)}
.brand-sub b,.greet,.step,.hbrand small{color:#e8bf56!important}
.logo,.hlogo{border:2px solid #e8bf56!important;box-shadow:0 0 0 3px rgba(232,191,86,.16),0 0 28px rgba(232,191,86,.24)!important}
.field input{background:rgba(5,8,13,.86)!important;color:#fff!important;border:1px solid rgba(232,191,86,.3)!important}
.field input:focus{border-color:#f0c85d!important;box-shadow:0 0 0 3px rgba(232,191,86,.14)!important}
.btn{background:linear-gradient(110deg,#9a6c17,#e4b63f,#fff0ad,#bd8b25)!important;color:#17130a!important;box-shadow:0 10px 30px rgba(220,171,53,.22)!important}
.stat,.hint,.act{background:rgba(255,255,255,.045)!important;border-color:rgba(232,191,86,.18)!important;color:#e9dfc5!important}
.stat .val,.bal-val,.name,.title{color:#f2d27b!important}
.res-val.tai{filter:drop-shadow(0 0 18px rgba(75,174,255,.45))}
.res-val.xiu{filter:drop-shadow(0 0 18px rgba(239,88,88,.45))}
.res-card:after{content:"CR7  •  SIUUU";position:absolute;bottom:13px;right:18px;font-size:9px;letter-spacing:3px;font-weight:900;color:rgba(236,194,83,.26);pointer-events:none}
.screen:before{content:"";position:fixed;inset:0;pointer-events:none;opacity:.16;background:repeating-linear-gradient(115deg,transparent 0 70px,rgba(255,220,130,.035) 71px 72px);z-index:0}
.act{color:#e8bf56!important}
.petal{background:radial-gradient(ellipse at 30% 30%,#fff7d8,#e8bf56 60%,#9b711c 90%)!important;filter:drop-shadow(0 0 7px rgba(232,191,86,.65))!important}
.orb-1{background:radial-gradient(circle,rgba(201,151,42,.48),transparent 70%)!important}
.orb-2{background:radial-gradient(circle,rgba(40,87,137,.35),transparent 70%)!important}
.orb-3{background:radial-gradient(circle,rgba(255,226,140,.35),transparent 70%)!important}
.orb-4{background:radial-gradient(circle,rgba(161,119,36,.25),transparent 70%)!important}



/* ═══ CR7 DENIUS SIGNATURE UI · LIGHT CHAMPIONSHIP EDITION ═══ */
:root{--bg-1:#f4f7fc;--bg-2:#e9eff8;--bg-3:#dce6f3;--pink-1:#d5a43a;--pink-2:#b98722;--pink-3:#ffe8a3;--rose:#c28b28;--rose-deep:#a97519;--text:#18263b;--text-dim:#63748c;--muted:#8796aa;--mint:#159b73;--glass-border:rgba(190,151,69,.28)}
html,body{background:#edf2f9!important;color:#18263b!important}
body{background:radial-gradient(ellipse at 50% 0%,#fff 0%,#edf3fb 50%,#dce6f2 100%)!important}
.bg-layer{background:radial-gradient(circle at 12% 18%,rgba(221,180,91,.22),transparent 30%),radial-gradient(circle at 88% 68%,rgba(91,142,207,.18),transparent 34%)!important}
.aurora{background:linear-gradient(120deg,transparent,rgba(225,185,94,.18),transparent,rgba(89,143,211,.14),transparent)!important}
.card,.glass{background:linear-gradient(145deg,rgba(255,255,255,.96),rgba(245,248,253,.94))!important;border:1px solid rgba(190,151,69,.28)!important;box-shadow:0 20px 60px rgba(48,73,111,.13),inset 0 1px 0 #fff!important;color:#1d2c43!important}
.brand{background:linear-gradient(100deg,#9b6b17,#e0b74e,#876018,#d8aa3c)!important;background-size:220% 100%!important;-webkit-background-clip:text!important;background-clip:text!important;filter:drop-shadow(0 5px 14px rgba(189,143,47,.18))!important}
.brand-sub{color:#71819a!important}
.logo,.hlogo{border:2px solid #d6ad54!important;box-shadow:0 0 0 5px rgba(217,177,89,.12),0 12px 30px rgba(74,98,135,.16)!important}
.field input,.adminSelect{background:#fff!important;color:#1b2a40!important;border:1px solid #d8e1ed!important;box-shadow:inset 0 1px 3px rgba(28,52,84,.04)!important}
.field input:focus{border-color:#c99b3d!important;box-shadow:0 0 0 4px rgba(201,155,61,.13)!important}
.field label,.lbl{color:#63748c!important}
.btn{background:linear-gradient(110deg,#b78428,#e2bd63,#f5dda0,#c18d2d)!important;color:#273044!important;box-shadow:0 9px 24px rgba(185,137,43,.2)!important;border:1px solid rgba(255,255,255,.72)!important}
.btn-soft,.back-btn{background:rgba(255,255,255,.88)!important;color:#344760!important;border:1px solid #d9e2ed!important}
.stat,.hint,.act{background:rgba(255,255,255,.82)!important;border:1px solid #e0e7f0!important;color:#35465e!important;box-shadow:0 8px 24px rgba(55,78,111,.055)!important}
.stat .val,.bal-val,.name,.title{color:#9b711f!important}
.h-row{background:rgba(255,255,255,.9)!important;border-color:#e1e8f1!important}
.h-mid .r1{color:#24344c!important}.h-mid .r2{color:#7b8ba1!important}
.nav{background:rgba(248,250,254,.92)!important;border-color:#e0e7f0!important}
.nav-btn{background:#fff!important;color:#687991!important;border-color:#dce4ef!important}
.nav-btn.on{background:linear-gradient(120deg,#b9852d,#e4c16f)!important;color:#fff!important}
.screen:before{opacity:.22;background:repeating-linear-gradient(115deg,transparent 0 90px,rgba(182,143,56,.035) 91px 92px)!important}
#particles{opacity:.45!important}
.petal{background:radial-gradient(ellipse at 30% 30%,#fff8df,#dcb65c 60%,#b98b2d 90%)!important;filter:drop-shadow(0 0 4px rgba(206,167,82,.28))!important}
.toast{background:#fff!important;color:#263750!important;border-color:#e1e8f0!important}
.admin-screen .wrap{width:min(1120px,100%);padding:18px}
.admin-shell{width:100%;max-height:94vh;overflow:auto;padding:clamp(18px,3vw,34px);border-radius:30px;background:linear-gradient(145deg,rgba(255,255,255,.98),rgba(239,244,251,.97));border:1px solid rgba(197,157,69,.35);box-shadow:0 26px 80px rgba(40,65,104,.16),inset 0 1px #fff;position:relative}
.admin-shell:before{content:"";position:absolute;inset:0 0 auto;height:5px;border-radius:30px 30px 0 0;background:linear-gradient(90deg,#9e741e,#f1d78e,#8faed7,#c79a3c)}
.admin-top{display:flex;justify-content:space-between;align-items:center;gap:18px;padding:10px 4px 22px;border-bottom:1px solid #e5eaf1}
.admin-kicker{font-size:10px;letter-spacing:2.8px;font-weight:900;color:#9a762d}
.admin-brand{font-size:clamp(25px,5vw,40px);cursor:pointer;user-select:none;margin:7px 0}
.admin-mark{width:62px;height:62px;display:grid;place-items:center;border-radius:20px;background:linear-gradient(145deg,#f7e5ad,#c18e2e);color:white;font-size:38px;font-weight:1000;font-style:italic;box-shadow:0 12px 28px rgba(182,134,39,.22);transform:skew(-5deg)}
.admin-actions{display:flex;gap:10px;flex-wrap:wrap;padding:18px 0}
.admin-actions .btn{min-width:145px}
.admin-revenue{padding:22px 24px;border-radius:22px;background:linear-gradient(115deg,#263d60,#41638d 58%,#c39a4a);color:#fff;display:flex;flex-direction:column;gap:5px;box-shadow:0 14px 34px rgba(46,74,113,.18);position:relative;overflow:hidden}
.admin-revenue:after{content:"CR7";position:absolute;right:20px;top:-25px;font-size:105px;font-weight:1000;font-style:italic;color:rgba(255,255,255,.1)}
.admin-revenue span{font-size:10px;letter-spacing:2px;font-weight:900;color:#f4e7c4}
.admin-revenue strong{font-size:clamp(26px,5vw,38px);font-weight:1000;color:#fff}
.admin-revenue small{font-size:11px;color:rgba(255,255,255,.72)}
.admin-create-lock{margin:18px 0;padding:14px 17px;border-radius:15px;background:#fff9e9;border:1px dashed #d6b66b;color:#8d6820;font-size:11px;font-weight:900;letter-spacing:.5px;text-align:center}
.admin-create{padding:18px;border-radius:20px;background:#fff;border:1px solid #e6dfca;margin:15px 0}
.admin-create-row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.adminSelect{flex:1;min-width:150px;padding:13px;border-radius:13px}
.admin-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-top:20px}
.admin-section{min-width:0;padding:18px;border-radius:21px;background:rgba(255,255,255,.78);border:1px solid #e3e9f1}
.admin-section-title{font-size:12px;font-weight:1000;letter-spacing:1.2px;color:#9a762d;margin-bottom:14px}
.admin-list{display:flex;flex-direction:column;gap:11px}
.admin-item{padding:15px;border-radius:16px;background:linear-gradient(145deg,#fff,#f7f9fc);border:1px solid #e3e9f1;box-shadow:0 5px 18px rgba(47,70,105,.05);min-width:0}
.admin-item-head{display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap}
.admin-item-head>b{font:900 12px ui-monospace,monospace;color:#243a5b;overflow-wrap:anywhere}
.admin-status{font-size:9px;font-weight:1000;letter-spacing:.7px;padding:6px 9px;border-radius:20px;background:#edf2f8;color:#66758b}
.admin-status.active{background:#e4f7ef;color:#13845d}.admin-status.unused{background:#fff4d9;color:#98701e}.admin-status.inactive{background:#fce9e9;color:#b64b4b}
.admin-meta{display:grid;gap:6px;margin:12px 0;color:#687991;font-size:11px;overflow-wrap:anywhere}
.admin-delete,.admin-approve{padding:9px 13px;border-radius:10px;border:1px solid #f0caca;background:#fff1f1;color:#b94a4a;font-weight:900;font-size:10px}
.admin-approve{border-color:#bde5d2;background:#e9f8f0;color:#13845d}
.admin-order-actions{display:flex;gap:8px;flex-wrap:wrap}
.admin-issued{margin-top:10px;padding:10px;border-radius:10px;background:#edf7f2;color:#267052;font-size:11px;overflow-wrap:anywhere}
.admin-empty{padding:28px 10px;text-align:center;color:#8a98aa;font-size:12px}
.admin-foot{text-align:center;padding:20px 0 2px;color:#9aa6b7;font-size:9px;letter-spacing:2px;font-weight:900}
.admin-quick-return{position:fixed;right:14px;bottom:calc(18px + env(safe-area-inset-bottom));z-index:9990;border:1px solid rgba(194,148,52,.35);border-radius:999px;padding:12px 16px;background:linear-gradient(110deg,#b9852d,#e8c977);color:#fff;font-weight:1000;font-size:10px;letter-spacing:1px;box-shadow:0 9px 25px rgba(119,91,36,.22)}
@media(max-width:760px){.admin-grid{grid-template-columns:1fr}.admin-shell{border-radius:22px;padding:17px}.admin-screen .wrap{padding:9px}.admin-mark{width:48px;height:48px;font-size:30px}.admin-section{padding:13px}}

/* CR7 PURCHASE EXPERIENCE · responsive, fixed-scale mobile layout */
.purchase-screen{position:relative;isolation:isolate}
.purchase-screen:before{content:"";position:absolute;inset:0;pointer-events:none;z-index:-1;
 background:radial-gradient(ellipse at 12% 12%,rgba(255,219,128,.42),transparent 42%),
 radial-gradient(ellipse at 88% 20%,rgba(103,166,255,.28),transparent 40%),
 radial-gradient(ellipse at 50% 100%,rgba(255,255,255,.78),transparent 58%)}
.purchase-wrap{width:100%;max-width:760px;margin:0 auto;min-height:0;align-items:stretch;justify-content:flex-start;padding:clamp(10px,3vw,24px);overflow-y:auto;overscroll-behavior:contain}
.purchase-card{width:100%;max-width:620px;margin:auto;padding:clamp(17px,4vw,30px);border-radius:28px;
 background:linear-gradient(145deg,rgba(255,255,255,.94),rgba(246,249,255,.91) 48%,rgba(255,248,229,.94));
 border:1px solid rgba(203,164,82,.46);box-shadow:0 24px 70px rgba(34,55,91,.16),0 0 34px rgba(226,187,98,.15),inset 0 1px 0 #fff;
 backdrop-filter:blur(24px) saturate(160%);-webkit-backdrop-filter:blur(24px) saturate(160%);
 animation:purchaseEnter .42s ease both}
@keyframes purchaseEnter{from{opacity:0;transform:translateY(12px) scale(.99)}to{opacity:1;transform:none}}
.purchase-head{display:flex;align-items:center;gap:14px;margin:8px 0 20px}
.purchase-emblem{width:56px;height:56px;flex:0 0 56px;display:grid;place-items:center;border-radius:18px;
 background:linear-gradient(145deg,#fff0bd,#d6aa4d 58%,#8e6727);color:#fff;font-size:27px;font-weight:1000;font-style:italic;
 box-shadow:0 10px 24px rgba(168,123,39,.26),inset 0 1px 0 rgba(255,255,255,.8)}
.purchase-title{font-size:clamp(19px,5vw,27px);font-weight:1000;letter-spacing:1.3px;color:#233958;line-height:1.15}
.purchase-sub{margin-top:5px;font-size:10px;font-weight:900;letter-spacing:1.5px;color:#9b7939}
.purchase-back{display:inline-flex;align-items:center;gap:8px;border:1px solid #dce4ef;border-radius:14px;padding:10px 14px;
 background:linear-gradient(180deg,#fff,#f1f5fb);color:#425875;font-size:11px;font-weight:1000;letter-spacing:.6px;
 box-shadow:0 5px 14px rgba(38,62,98,.08);transition:transform .2s,box-shadow .2s}
.purchase-back:active{transform:scale(.97)}
.purchase-plans{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}
.purchase-plan{position:relative;min-width:0;padding:18px 15px 15px;border-radius:20px;text-align:left;overflow:hidden;font:inherit;cursor:pointer;
 border:1px solid rgba(191,159,95,.36);background:linear-gradient(145deg,#fff,#f5f8fd);
 box-shadow:0 9px 22px rgba(45,67,100,.075);transition:transform .22s,box-shadow .22s,border-color .22s}
.purchase-plan:before{content:"";position:absolute;inset:0 auto 0 0;width:3px;background:linear-gradient(#e9ce88,#a6c2e9)}
.purchase-plan:after{content:"";position:absolute;width:110px;height:110px;right:-55px;top:-60px;border-radius:50%;background:rgba(238,205,131,.18);filter:blur(2px)}
.purchase-plan:active{transform:scale(.975)}
.purchase-plan:disabled{opacity:.58;cursor:wait;transform:none}
.purchase-plan.featured{background:linear-gradient(145deg,#fff9e9,#edf4ff);border-color:rgba(190,145,53,.72);box-shadow:0 12px 30px rgba(172,132,54,.15),0 0 0 1px rgba(255,255,255,.9) inset}
.plan-duration{display:block;color:#526681;font-size:12px;font-weight:900;letter-spacing:.7px}
.plan-price{display:block;margin:9px 0 12px;color:#203858;font-size:clamp(20px,5vw,26px);font-weight:1000;letter-spacing:-.5px}
.plan-buy{display:flex;align-items:center;justify-content:center;gap:7px;width:100%;padding:11px 8px;border-radius:12px;
 background:linear-gradient(115deg,#263f64,#426b9c 56%,#b68b3d);color:#fff;font-size:10px;font-weight:1000;letter-spacing:1px;
 box-shadow:0 8px 18px rgba(40,65,101,.2),inset 0 1px 0 rgba(255,255,255,.32)}
.purchase-note{margin-top:16px;padding:13px 14px;border-radius:15px;background:rgba(234,241,250,.75);border:1px solid #e1e8f1;color:#718198;font-size:10px;line-height:1.65;text-align:center}
.payment-summary{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:14px 16px;margin:14px 0;border-radius:17px;
 background:linear-gradient(110deg,#243d61,#42658e 62%,#b78c43);color:#fff;box-shadow:0 12px 26px rgba(37,61,96,.2)}
.payment-summary span{font-size:10px;font-weight:900;letter-spacing:1px;color:#f8e9bf}
.payment-summary strong{font-size:clamp(20px,5vw,27px);font-weight:1000;white-space:nowrap}
.payment-details{display:grid;gap:9px;margin:14px 0}
.payment-line{display:flex;align-items:center;justify-content:space-between;gap:9px;min-width:0;padding:12px 13px;border-radius:14px;background:#fff;border:1px solid #e3e9f1}
.payment-line>div{min-width:0}
.payment-label{display:block;margin-bottom:4px;color:#8a98aa;font-size:9px;font-weight:900;letter-spacing:1px}
.payment-value{display:block;color:#263e60;font-size:12px;font-weight:900;overflow-wrap:anywhere}
.payment-copy{flex:0 0 auto;border:1px solid #d9e3f0;border-radius:10px;padding:8px 10px;background:linear-gradient(#fff,#edf3fa);color:#3f5d83;font-size:9px;font-weight:1000}
.payment-qr{display:grid;place-items:center;margin:13px auto;padding:12px;width:min(100%,260px);border-radius:20px;background:#fff;border:1px solid #e4e9f1;box-shadow:0 10px 28px rgba(39,61,94,.09)}
.payment-qr img{display:block;width:100%;max-width:230px;height:auto;object-fit:contain;border-radius:10px}
.payment-instruction{padding:13px 14px;border-radius:15px;background:linear-gradient(145deg,#fff9e9,#f0f5fc);border:1px solid #ead9b0;color:#6d624b;font-size:10px;line-height:1.7}
.payment-timer{margin:12px 0;text-align:center;color:#9b742e;font-size:12px;font-weight:1000;letter-spacing:.5px}
.purchase-primary{width:100%;padding:15px 16px;border:0;border-radius:15px;background:linear-gradient(110deg,#20395d,#416a9d 55%,#bd9349);
 color:#fff;font-size:12px;font-weight:1000;letter-spacing:1.3px;box-shadow:0 12px 26px rgba(38,63,99,.24),inset 0 1px 0 rgba(255,255,255,.3);transition:transform .2s,filter .2s}
.purchase-primary:active{transform:scale(.98);filter:brightness(1.08)}
.purchase-primary:disabled{opacity:.48;box-shadow:none}
.purchase-alt{width:100%;margin-top:9px;padding:12px;border:1px solid #dce4ef;border-radius:14px;background:#fff;color:#506681;font-size:10px;font-weight:1000;letter-spacing:.8px}
#adminSecretLogo{cursor:pointer;touch-action:manipulation}
@media(max-width:480px){
 .purchase-wrap{padding:9px;padding-bottom:calc(12px + env(safe-area-inset-bottom))}
 .purchase-card{padding:16px 13px;border-radius:23px}
 .purchase-head{gap:11px;margin:8px 0 16px}
 .purchase-emblem{width:48px;height:48px;flex-basis:48px;border-radius:15px;font-size:23px}
 .purchase-plans{gap:9px}
 .purchase-plan{padding:15px 11px 12px;border-radius:17px}
 .plan-price{font-size:21px}
 .payment-line{padding:11px 10px}
}
@media(prefers-reduced-motion:reduce){.purchase-card{animation:none!important}.purchase-plan,.purchase-primary{transition:none!important}}
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
const LS_KEY = 'cr7_denius_elite_v3';
const app = document.getElementById('app');
const toastBox = document.getElementById('toast');

const S = {
  step: 'license', tab: 'main', user: '', nickname: '', balance: 0, authToken: '', device: '', adminDevice:'', licenseKey:'', adminToken:'', adminClicks:0, adminCreatePin:'', currentOrder:null,
  loading: false, error: '',
  config: {base_bet:0,profit_stop:0,auto:false,paused:false,lose_streak:0,bet_streak:0},
  history: [], stats: {wins:0,losses:0,total:0,winrate:0,profit:0},
  pendingPred: null, pendingSession: null, pendingBetAmount: null, pendingConf: null,
  workerAlive: false, lastWsError: null,
  setupBaseBet: 0, setupTarget: 0, lastBalance: 0,
};

(function initAdminDevice() {
  const k='cr7_admin_device_v1';
  try {
    let id=localStorage.getItem(k);
    if(!id){
      const bytes=new Uint8Array(18);
      if(window.crypto && crypto.getRandomValues) crypto.getRandomValues(bytes);
      else for(let i=0;i<bytes.length;i++) bytes[i]=(Date.now()+i*37)&255;
      id=Array.from(bytes,x=>x.toString(16).padStart(2,'0')).join('');
      localStorage.setItem(k,id);
    }
    S.adminDevice=id;
  } catch(e) { S.adminDevice='volatile-'+String(Date.now()); }
})();
(function() {
  const d = [navigator.userAgent, navigator.language, screen.width+'x'+screen.height].join('|');
  let h = 0; for (let i = 0; i < d.length; i++) h = ((h << 5) - h) + d.charCodeAt(i), h |= 0;
  S.device = 'ONI-' + Math.abs(h).toString(16).toUpperCase().slice(0, 8);
})();

(function initPetals() {
  const count = window.innerWidth < 600 ? 5 : 9;
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
  const colors = ['#d9ad48', '#f5d98b', '#7ca8df', '#a9c7ed'];
  function resize() {
    canvas.width = window.innerWidth; canvas.height = window.innerHeight;
    particles = [];
    const count = window.innerWidth < 600 ? 12 : 22;
    for (let i = 0; i < count; i++) {
      particles.push({
        x: Math.random() * canvas.width, y: Math.random() * canvas.height,
        vx: (Math.random() - 0.5) * 0.4, vy: (Math.random() - 0.5) * 0.4,
        r: Math.random() * 3 + 1, color: colors[Math.floor(Math.random() * colors.length)],
        alpha: Math.random() * 0.5 + 0.3,
      });
    }
  }
  let lastFrame = 0;
  function animate(now) {
    if (document.hidden) { requestAnimationFrame(animate); return; }
    if (now - lastFrame < 33) { requestAnimationFrame(animate); return; }
    lastFrame = now;
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    for (const p of particles) {
      p.x += p.vx; p.y += p.vy;
      if (p.x < 0 || p.x > canvas.width) p.vx *= -1;
      if (p.y < 0 || p.y > canvas.height) p.vy *= -1;
      ctx.globalAlpha = p.alpha; ctx.fillStyle = p.color;
      ctx.shadowBlur = 0;
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
  if (S.step === 'license') renderLicense();
  else if (S.step === 'login') renderLogin();
  else if (S.step === 'admin') renderAdmin();
  else if (S.step === 'buy') renderBuy();
  else if (S.step === 'payment') renderPayment();
  else if (S.step === 'notifications') renderNotifications();
  else if (S.step === 'info') renderInfo();
  else if (S.step === 'base_bet') renderBaseBet();
  else if (S.step === 'target') renderTarget();
  else if (S.step === 'main') { if (S.tab === 'history') renderHistory(); else renderMain(); }
  if (S.adminToken && ['main','history','info','base_bet','target','login'].includes(S.step)) {
    const old=document.getElementById('adminQuickReturn'); if(old) old.remove();
    const b=document.createElement('button'); b.id='adminQuickReturn'; b.className='admin-quick-return'; b.textContent='ADMIN PANEL';
    b.onclick=()=>{S.step='admin';renderAdmin();}; document.body.appendChild(b);
  } else { const old=document.getElementById('adminQuickReturn'); if(old) old.remove(); }
}

function saveLicense(k){try{localStorage.setItem('cr7_license_v1',k)}catch(e){}}
function loadLicense(){try{return localStorage.getItem('cr7_license_v1')||''}catch(e){return ''}}
function clearLicense(){try{localStorage.removeItem('cr7_license_v1')}catch(e){}}
function renderLicense(){
  app.innerHTML='<div class="screen"><div class="wrap"><div class="card glass neon"><img src="'+LOGO_URL+'" class="logo" id="adminSecretLogo" alt="LC79 logo"><div class="brand" id="adminSecretTitle">CR7 DENIUS</div><div class="brand-sub">⚽ CRISTIANO RONALDO · LICENSE CENTER</div><div class="field"><label>🔑 NHẬP KEY KÍCH HOẠT</label><input id="licenseInput" autocomplete="off" placeholder="CR7-XXXXXX-XXXXXX-XXXX"></div><button class="btn" id="licenseEnter">KÍCH HOẠT / TIẾP TỤC</button><button class="btn btn-soft" id="buyOpen">💎 MUA KEY</button><button class="btn btn-soft" id="noticeOpen">🔔 HÒM THÔNG BÁO <span id="noticeCount"></span></button><div class="foot">CR7 ELITE · SIUUU</div><div class="msg" id="licenseMsg"></div></div></div></div>';
  // Cách 1: chạm tên CR7 để nhập mã admin trực tiếp.
  document.getElementById('adminSecretTitle').onclick=()=>{adminLoginPrompt(prompt('NHẬP KEY ADMIN')||'')};
  // Cách 2: chạm logo LC79 đủ 10 lần để mở hộp nhập mã admin.
  let logoTaps=0,logoTapReset=null;
  document.getElementById('adminSecretLogo').addEventListener('click',()=>{
    logoTaps++;
    clearTimeout(logoTapReset);
    logoTapReset=setTimeout(()=>{logoTaps=0},2600);
    if(logoTaps>=10){logoTaps=0;adminLoginPrompt(prompt('LC79 ADMIN ACCESS · NHẬP KEY ADMIN')||'');}
  });
  document.getElementById('licenseEnter').onclick=async()=>{const k=document.getElementById('licenseInput').value.trim();if(!k){toast('Vui lòng nhập key','err');return;}const r=await api('license_activate',{license_key:k,device:S.device});if(!r.ok){document.getElementById('licenseMsg').textContent=r.msg||'Key không hợp lệ';return;}S.licenseKey=k;saveLicense(k);S.step='login';render();};
  document.getElementById('buyOpen').onclick=()=>{S.step='buy';render()};
  document.getElementById('noticeOpen').onclick=()=>{S.step='notifications';renderNotifications()};
  const saved=loadLicense(); if(saved){document.getElementById('licenseInput').value=saved; api('license_check',{license_key:saved,device:S.device}).then(r=>{if(r.ok){S.licenseKey=saved;S.step='login';render();}else clearLicense()}).catch(()=>{});}
  refreshNoticeCount();
}
async function adminLoginPrompt(adminKey){const r=await api('admin_login',{admin_key:adminKey||'',admin_device:S.adminDevice});if(!r.ok){toast(r.msg||'Admin denied','err');return;}S.adminToken=r.admin_token;S.step='admin';renderAdmin();}
function adminApi(action,data={}){data.admin_token=S.adminToken;data.admin_device=S.adminDevice;return api(action,data)}
async function renderAdmin(){
  app.innerHTML='<div class="screen admin-screen"><div class="wrap admin-wrap"><section class="admin-shell"><header class="admin-top"><div><div class="admin-kicker">CR7 · DENIUS CONTROL CENTER</div><div class="brand admin-brand" id="adminSecretTitleAdmin">ADMIN PANEL</div><div class="brand-sub">LICENSE COMMAND · SECURE DEVICE LOCK</div></div><div class="admin-mark">7</div></header><div class="admin-actions"><button class="btn btn-soft" id="adminToTool">⚽ MỞ TOOL</button><button class="btn btn-soft" id="adminExit">ĐĂNG XUẤT</button></div><div class="admin-revenue"><span>DOANH THU HÔM NAY</span><strong id="adminEarn">Đang tải...</strong><small>Đơn đã được admin duyệt</small></div><div class="admin-create-lock" id="createAccessHint">🔒 KHU VỰC TẠO KEY ĐANG ẨN · NHẤN 10 LẦN VÀO ADMIN PANEL</div><section class="admin-create" id="createPanel" style="display:none"><div class="admin-section-title">TẠO LICENSE MỚI</div><div class="admin-create-row"><select id="newDuration" class="adminSelect"><option>1 ngày</option><option>3 ngày</option><option>1 tuần</option><option>1 tháng</option></select><button class="btn" id="createKeyBtn">＋ TẠO KEY</button></div><div id="createdKey" class="msg"></div></section><div class="admin-grid"><section class="admin-section"><div class="admin-section-title">01 / DANH SÁCH LICENSE</div><div id="adminKeys" class="admin-list">Đang tải...</div></section><section class="admin-section"><div class="admin-section-title">02 / DUYỆT THANH TOÁN</div><div id="adminOrders" class="admin-list">Đang tải...</div></section></div><footer class="admin-foot">CR7 DENIUS ELITE · AUTHORIZED DEVICE ONLY</footer></section></div></div>';
  document.getElementById('adminToTool').onclick=()=>{S.step=(S.user&&S.authToken)?'main':(S.licenseKey?'login':'license');S.tab='main';render();};
  document.getElementById('adminExit').onclick=()=>{S.adminToken='';S.step='license';render();};
  S.adminClicks=0;
  document.getElementById('adminSecretTitleAdmin').onclick=()=>{S.adminClicks++;if(S.adminClicks>=10){S.adminClicks=0;const pin=prompt('NHẬP MẬT KHẨU TẠO KEY');if(pin==='246810'){S.adminCreatePin=pin;document.getElementById('createPanel').style.display='block';document.getElementById('createAccessHint').textContent='🔓 HỆ THỐNG TẠO KEY ĐÃ MỞ';}else toast('Mật khẩu không đúng','error')}};
  document.getElementById('createKeyBtn').onclick=async()=>{const r=await adminApi('admin_create_key',{duration:document.getElementById('newDuration').value,pin:S.adminCreatePin});if(r.ok){document.getElementById('createdKey').innerHTML='KEY MỚI: <b>'+esc(r.key)+'</b> <button data-copy="'+esc(r.key)+'">SAO CHÉP</button>';document.querySelector('#createdKey [data-copy]').onclick=()=>copyText(r.key);loadAdminData();}else toast(r.msg||'Lỗi tạo key','error')};
  loadAdminData();
}
async function loadAdminData(){const r=await adminApi('admin_list');if(!r.ok){toast('Phiên admin hết hạn','err');S.step='license';render();return;}document.getElementById('adminEarn').textContent=fmt(r.earned_today)+'đ';
  document.getElementById('adminKeys').innerHTML=(r.keys||[]).map(k=>'<article class="admin-item"><div class="admin-item-head"><b>'+esc(k.key)+'</b><span class="admin-status '+(k.activated_at?'active':'unused')+'">'+(k.activated_at?'ĐÃ KÍCH HOẠT':'CHƯA KÍCH HOẠT')+'</span></div><div class="admin-meta"><span>Gói: '+esc(k.name)+'</span><span>Thời hạn: '+esc(k.duration||k.name)+'</span><span>Còn lại: '+(k.remaining===null?'Chưa kích hoạt':fmtTime(k.remaining))+'</span><span>Thiết bị: '+esc(k.device_id||'Chưa gắn')+'</span><span>IP: '+esc(k.ip_first||'—')+'</span></div><button class="admin-delete" data-del="'+k.id+'">XÓA KEY</button></article>').join('')||'<div class="admin-empty">Chưa có key nào</div>';
  document.querySelectorAll('[data-del]').forEach(b=>b.onclick=async()=>{if(confirm('Xóa key này?')){await adminApi('admin_delete_key',{id:b.dataset.del});loadAdminData()}});
  document.getElementById('adminOrders').innerHTML=(r.orders||[]).map(o=>'<article class="admin-item"><div class="admin-item-head"><b>ĐƠN '+esc(o.id)+'</b><span class="admin-status '+(o.status==='approved'?'active':(o.status==='rejected'||o.status==='expired'?'inactive':'unused'))+'">'+esc(o.status)+'</span></div><div class="admin-meta"><span>Gói: '+esc(o.duration)+'</span><span>Thanh toán: '+fmt(o.amount)+'đ</span><span>Nội dung: '+esc(o.content)+'</span><span>IP: '+esc(o.buyer_ip||'—')+'</span></div>'+((o.status==='waiting_review'||o.status==='pending')?'<div class="admin-order-actions"><button class="admin-approve" data-approve="'+o.id+'">DUYỆT ĐƠN</button><button class="admin-delete" data-reject="'+o.id+'">TỪ CHỐI</button></div>':'')+(o.license_key?'<div class="admin-issued">KEY ĐÃ CẤP: <b>'+esc(o.license_key)+'</b></div>':'')+'</article>').join('')||'<div class="admin-empty">Chưa có đơn thanh toán</div>';
  document.querySelectorAll('[data-approve]').forEach(b=>b.onclick=async()=>{await adminApi('admin_review_order',{id:b.dataset.approve,decision:'approve'});loadAdminData()});document.querySelectorAll('[data-reject]').forEach(b=>b.onclick=async()=>{await adminApi('admin_review_order',{id:b.dataset.reject,decision:'reject'});loadAdminData()});
}
function fmtTime(sec){sec=Math.max(0,sec|0);const d=Math.floor(sec/86400),h=Math.floor(sec%86400/3600),m=Math.floor(sec%3600/60);return (d?d+' ngày ':'')+h+' giờ '+m+' phút';}
function copyText(t){if(navigator.clipboard)navigator.clipboard.writeText(t).then(()=>toast('Đã copy','success'));else{const x=document.createElement('textarea');x.value=t;document.body.appendChild(x);x.select();document.execCommand('copy');x.remove();toast('Đã copy','success')}}
async function renderBuy(){
  const plans=[['1 ngày',15000],['3 ngày',35000],['1 tuần',60000],['1 tháng',100000]];
  app.innerHTML='<div class="screen purchase-screen"><div class="wrap purchase-wrap"><section class="purchase-card"><button class="purchase-back" id="buyBack">← QUAY LẠI</button><header class="purchase-head"><div class="purchase-emblem">7</div><div><div class="purchase-title">CR7 ELITE ACCESS</div><div class="purchase-sub">BẢNG GIÁ LICENSE · SIUUU EDITION</div></div></header><div class="purchase-plans">'+plans.map((p,i)=>'<button class="purchase-plan '+(i===2?'featured':'')+'" data-plan="'+p[0]+'"><span class="plan-duration">'+(i===2?'✦ GÓI ĐƯỢC ƯA CHUỘNG':p[0].toUpperCase())+'</span><strong class="plan-price">'+fmt(p[1])+'đ</strong><span class="plan-buy">CHỌN GÓI <b>→</b></span></button>').join('')+'</div><div class="purchase-note">🔐 KEY gắn với thiết bị đầu tiên khi kích hoạt · Thời hạn chỉ bắt đầu tính từ lần kích hoạt đầu tiên.<br>Đơn thanh toán có hiệu lực trong 15 phút.</div></section></div></div>';
  document.getElementById('buyBack').onclick=()=>{S.step='license';render()};
  document.querySelectorAll('[data-plan]').forEach(b=>b.onclick=()=>createPaymentOrder(b.dataset.plan));
}
async function createPaymentOrder(duration){
  const buttons=[...document.querySelectorAll('[data-plan]')];buttons.forEach(b=>b.disabled=true);
  try{
    const r=await api('payment_create',{duration,device:S.device});
    if(!r.ok){toast(r.msg||'Không tạo được đơn','err');buttons.forEach(b=>b.disabled=false);return;}
    S.currentOrder=r.order;
    let ids=[];try{ids=JSON.parse(localStorage.getItem('cr7_order_ids')||'[]')}catch(e){}
    ids.push(r.order.id);localStorage.setItem('cr7_order_ids',JSON.stringify([...new Set(ids)]));
    S.step='payment';renderPayment();
  }catch(e){toast('Không thể kết nối máy chủ thanh toán','err');buttons.forEach(b=>b.disabled=false);}
}
function renderPayment(){
  const o=S.currentOrder;
  if(!o){S.step='buy';renderBuy();return;}
  const qr='https://raw.githubusercontent.com/nguyenha783255-wq/QR-DENIUS/refs/heads/main/IMG_8347.png';
  app.innerHTML='<div class="screen purchase-screen"><div class="wrap purchase-wrap"><section class="purchase-card"><button class="purchase-back" id="paymentBack">← VỀ BẢNG GIÁ</button><header class="purchase-head"><div class="purchase-emblem">₫</div><div><div class="purchase-title">THANH TOÁN AN TOÀN</div><div class="purchase-sub">CR7 DENIUS · BANK TRANSFER</div></div></header><div class="payment-summary"><div><span>GÓI ĐÃ CHỌN</span><div style="font-size:13px;font-weight:900;margin-top:5px">'+esc(o.duration)+'</div></div><strong>'+fmt(o.amount)+'đ</strong></div><div class="payment-qr"><img src="'+esc(qr)+'" alt="Mã QR thanh toán"></div><div class="payment-details"><div class="payment-line"><div><span class="payment-label">NGÂN HÀNG / CHỦ TÀI KHOẢN</span><strong class="payment-value">NGUYEN THI HA</strong></div><button class="payment-copy" data-copy="NGUYEN THI HA">COPY</button></div><div class="payment-line"><div><span class="payment-label">SỐ TÀI KHOẢN</span><strong class="payment-value">0354783255</strong></div><button class="payment-copy" data-copy="0354783255">COPY</button></div><div class="payment-line"><div><span class="payment-label">SỐ TIỀN CHUYỂN</span><strong class="payment-value">'+fmt(o.amount)+'đ</strong></div><button class="payment-copy" data-copy="'+o.amount+'">COPY</button></div><div class="payment-line"><div><span class="payment-label">NỘI DUNG CHUYỂN KHOẢN · BẮT BUỘC ĐÚNG</span><strong class="payment-value">'+esc(o.content)+'</strong></div><button class="payment-copy" data-copy="'+esc(o.content)+'">COPY</button></div></div><div class="payment-instruction">1. Quét mã QR hoặc nhập thông tin chuyển khoản ở trên.<br>2. Giữ nguyên chính xác nội dung chuyển khoản để hệ thống đối soát.<br>3. Sau khi chuyển khoản, nhấn nút xác nhận bên dưới. Admin sẽ kiểm tra và duyệt đơn.</div><div class="payment-timer" id="orderCountdown">Đơn thanh toán còn 15:00</div><button class="purchase-primary" id="sentBtn">✓ TÔI ĐÃ CHUYỂN KHOẢN</button><button class="purchase-alt" id="paymentNotice">XEM TRẠNG THÁI ĐƠN / THÔNG BÁO</button></section></div></div>';
  const qrImg=document.querySelector('.payment-qr img');if(qrImg)qrImg.addEventListener('error',()=>{const box=qrImg.parentElement;box.innerHTML='<div style="padding:18px;color:#9a6e24;font-size:11px;text-align:center">KHÔNG TẢI ĐƯỢC MÃ QR · VUI LÒNG DÙNG THÔNG TIN CHUYỂN KHOẢN</div>'},{once:true});
  document.getElementById('paymentBack').onclick=()=>{S.step='buy';renderBuy()};
  document.getElementById('paymentNotice').onclick=()=>{S.step='notifications';renderNotifications()};
  document.querySelectorAll('[data-copy]').forEach(b=>b.onclick=()=>copyText(b.dataset.copy));
  const end=Number(o.expires_at)||Math.floor(Date.now()/1000)+900;
  const timer=setInterval(()=>{
    const left=end-Math.floor(Date.now()/1000),el=document.getElementById('orderCountdown'),btn=document.getElementById('sentBtn');
    if(!el){clearInterval(timer);return;}
    if(left<=0){el.textContent='ĐƠN ĐÃ HẾT HẠN';if(btn)btn.disabled=true;clearInterval(timer);}
    else{const m=Math.floor(left/60),sec=left%60;el.textContent='ĐƠN THANH TOÁN CÒN '+String(m).padStart(2,'0')+':'+String(sec).padStart(2,'0');}
  },1000);
  document.getElementById('sentBtn').onclick=async()=>{
    const btn=document.getElementById('sentBtn');btn.disabled=true;btn.textContent='ĐANG GỬI XÁC NHẬN...';
    try{const x=await api('payment_mark_sent',{id:o.id});if(x.ok){toast('Đã gửi yêu cầu. Admin sẽ duyệt đơn','success');btn.textContent='ĐÃ GỬI · CHỜ ADMIN DUYỆT';}
    else{toast(x.msg||'Không gửi được xác nhận','err');btn.disabled=false;btn.textContent='✓ TÔI ĐÃ CHUYỂN KHOẢN';}}
    catch(e){toast('Lỗi kết nối, vui lòng thử lại','err');btn.disabled=false;btn.textContent='✓ TÔI ĐÃ CHUYỂN KHOẢN';}
  };
}
async function refreshNoticeCount(){let ids=[];try{ids=JSON.parse(localStorage.getItem('cr7_order_ids')||'[]')}catch(e){}if(!ids.length)return;const r=await api('payment_list',{ids:JSON.stringify(ids)});const n=(r.orders||[]).filter(o=>o.status==='approved'||o.status==='rejected').length;const el=document.getElementById('noticeCount');if(el)el.textContent=n?'('+n+')':'';}
async function renderNotifications(){let ids=[];try{ids=JSON.parse(localStorage.getItem('cr7_order_ids')||'[]')}catch(e){}const r=await api('payment_list',{ids:JSON.stringify(ids)});app.innerHTML='<div class="screen"><div class="wrap"><div class="card glass neon" style="max-height:90vh;overflow:auto"><button class="back-btn" id="noticeBack">← Quay lại</button><div class="brand">🔔 HÒM THÔNG BÁO</div><div id="noticeItems">'+((r.orders||[]).map(o=>'<div class="stat" style="display:block"><b>'+esc(o.duration)+' · '+esc(o.status)+'</b><p>'+esc(o.id)+'</p>'+(o.status==='approved'?'<p>KEY CỦA BẠN: <b>'+esc(o.license_key)+'</b> <button data-copy="'+esc(o.license_key)+'">COPY KEY</button></p>':'')+(o.status==='waiting_review'?'<p>Đơn đang chờ admin duyệt trong 5–15 phút</p>':'')+'</div>').join('')||'Chưa có thông báo')+'</div></div></div></div>';document.getElementById('noticeBack').onclick=()=>{S.step='license';render()};document.querySelectorAll('[data-copy]').forEach(b=>b.onclick=()=>copyText(b.dataset.copy));}

function renderLogin() {
  app.innerHTML =
    '<div class="screen"><div class="wrap"><div class="card glass neon">' +
    '<img src="' + LOGO_URL + '" class="logo" onerror="this.style.display=\'none\'">' +
    '<div class="brand">CR7 DENIUS</div>' +
    '<div class="brand-sub">⚽ CRISTIANO RONALDO · ELITE ENGINE</div>' +
    '<div class="field"><label>👤 TÀI KHOẢN</label><input id="in_u" type="text" placeholder="Nhập tài khoản..." value="' + esc(S.user) + '"></div>' +
    '<div class="field"><label>🔒 MẬT KHẨU</label><input id="in_p" type="password" placeholder="••••••••"></div>' +
    '<button class="btn" id="btn_login"' + (S.loading?' disabled':'') + '>' + (S.loading?'ĐANG XÁC THỰC':'ĐĂNG NHẬP') + '</button>' +
    (S.error ? '<div class="msg err">⚠️ ' + esc(S.error) + '</div>' : '') +
    '<div class="foot"><b>CR7 ELITE</b> · CRISTIANO RONALDO · SIUUU</div>' +
    '</div></div></div>';
  const loginLogo=document.querySelector('.card .logo');
  if(loginLogo){let logoTaps=0,logoReset=null;loginLogo.style.cursor='pointer';loginLogo.addEventListener('click',()=>{logoTaps++;clearTimeout(logoReset);logoReset=setTimeout(()=>{logoTaps=0},2600);if(logoTaps>=10){logoTaps=0;adminLoginPrompt(prompt('LC79 ADMIN ACCESS · NHẬP KEY ADMIN')||'');}});}
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
    const r = await api('verify', {user:u, pass:p, device:S.device, license_key:S.licenseKey});
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
      lastWsError:r.last_ws_error});
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
    '<div class="hbrand"><h1>CR7 DENIUS</h1><small>⚽ ' + esc(S.nickname) + '</small></div>' +
    '<div class="hact">' + aliveDot +
    '<button class="act kill" id="btn_kill" title="Dừng">⏹</button>' +
    '<button class="act logout" id="btn_logout" title="Đăng xuất">⏏</button>' +
    '</div></div>' +
    '<div class="scroll">' +
    '<div class="bal-card glass"><div class="bal-lbl">SỐ DƯ HIỆN TẠI</div>' +
    '<span class="bal-val" id="bal_val">' + fmt(S.balance) + '</span><span class="bal-suf">đ</span></div>' +
    '<div class="res-card glass">' +
    cheatBadge +
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
    if (S.licenseKey && tickCounter % 5 === 0) {
      try { const lr=await api('license_check',{license_key:S.licenseKey,device:S.device}); if(!lr.ok){clearLicense();clearAuth();S.authToken='';S.step='license';if(tickTimer)clearInterval(tickTimer);renderLicense();toast('Key đã hết hạn hoặc không còn hợp lệ','err');return;} } catch(e) {}
    }
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
          
          S.lastWsError = j.last_ws_error;
        }
      }
    } catch (e) {}
  }, 1000);
}

// boot
S.licenseKey=loadLicense();
if(S.licenseKey){api('license_check',{license_key:S.licenseKey,device:S.device}).then(r=>{if(r.ok)tryResume();else{clearLicense();renderLicense();}}).catch(()=>renderLicense());}else renderLicense();
setInterval(async()=>{if(!S.licenseKey||['license','admin','buy','notifications'].includes(S.step))return;try{const lr=await api('license_check',{license_key:S.licenseKey,device:S.device});if(!lr.ok){clearLicense();clearAuth();S.authToken='';S.user='';S.step='license';if(tickTimer)clearInterval(tickTimer);renderLicense();toast('KEY HẾT HẠN — VUI LÒNG NHẬP KEY MỚI','err');}}catch(e){}},5000);
setInterval(refreshNoticeCount,10000);
</script>
</body>
</html>
<?php }