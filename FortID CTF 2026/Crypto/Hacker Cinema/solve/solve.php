<?php
// ---- replicate server crypto + canonical_json exactly ----
function canonicalize_value(mixed $value): mixed {
    if (is_array($value)) {
        $isList = array_keys($value) === range(0, count($value) - 1);
        if ($isList) return array_map('canonicalize_value', $value);
        ksort($value, SORT_STRING);
        foreach ($value as $k => $v) $value[$k] = canonicalize_value($v);
    }
    return $value;
}
function canonical_json(mixed $value): string {
    return json_encode(canonicalize_value($value),
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION);
}
function N(): GMP { return gmp_init('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141'); }
function P(): GMP { return gmp_init('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F'); }
function Gx(): GMP { return gmp_init('0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798'); }
function Gy(): GMP { return gmp_init('0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8'); }
function G(): array { return [Gx(), Gy()]; }
function mod_g($x,$m){ $r=gmp_mod($x,$m); return gmp_cmp($r,0)<0?gmp_add($r,$m):$r; }
function inv_mod($x,$m){ return gmp_invert(mod_g($x,$m),$m); }
function point_add(?array $p, ?array $q): ?array {
    if($p===null)return $q; if($q===null)return $p;
    [$x1,$y1]=$p; [$x2,$y2]=$q; $pr=P();
    if(gmp_cmp($x1,$x2)===0 && gmp_cmp(mod_g(gmp_add($y1,$y2),$pr),0)===0) return null;
    if(gmp_cmp($x1,$x2)===0 && gmp_cmp($y1,$y2)===0)
        $l=mod_g(gmp_mul(gmp_mul(3,gmp_mul($x1,$x1)),inv_mod(gmp_mul(2,$y1),$pr)),$pr);
    else $l=mod_g(gmp_mul(gmp_sub($y2,$y1),inv_mod(gmp_sub($x2,$x1),$pr)),$pr);
    $x3=mod_g(gmp_sub(gmp_sub(gmp_mul($l,$l),$x1),$x2),$pr);
    $y3=mod_g(gmp_sub(gmp_mul($l,gmp_sub($x1,$x3)),$y1),$pr);
    return [$x3,$y3];
}
function scalar_mul($k,?array $pt=null): ?array {
    $k=mod_g($k,N()); $res=null; $add=$pt??G();
    while(gmp_cmp($k,0)>0){ if(gmp_testbit($k,0))$res=point_add($res,$add); $add=point_add($add,$add); $k=gmp_div_q($k,2);} 
    return $res;
}
function gmp_from_bytes($b){ $v=gmp_import($b,1,GMP_MSW_FIRST|GMP_BIG_ENDIAN); return $v===false?gmp_init(0):$v; }
function sha256_int($d){ return mod_g(gmp_from_bytes(hash('sha256',$d,true)),N()); }
function hex64($x){ return str_pad(gmp_strval($x,16),64,'0',STR_PAD_LEFT); }

$n=N();
// ---- two reused-nonce signatures from the server ----
$ta=["date"=>"0000-01-29","movie"=>"Hackers","screen"=>"mainframe-1","seat"=>"A01","winner"=>false];
$tb=["date"=>"0000-01-30","movie"=>"Hackers","screen"=>"mainframe-1","seat"=>"A01","winner"=>false];
$r = gmp_init('0x8847bc49b8dcdb8c730a9bc65998814edb34584371441290757001196ef4c037');
$sa= gmp_init('0xf3f9d385d2e662e5624be92de1505ec95259f4195b6710fa58ae59146aaebb0f');
$sb= gmp_init('0x4f022dc731aac43ab2c82742772c3c8339c15c0592580f4f5c21b7780786189a');
$za= sha256_int(canonical_json($ta));
$zb= sha256_int(canonical_json($tb));
echo "msg_a=".canonical_json($ta)."\nmsg_b=".canonical_json($tb)."\n";
// k = (za - zb)/(sa - sb)
$k = mod_g(gmp_mul(mod_g(gmp_sub($za,$zb),$n), inv_mod(gmp_sub($sa,$sb),$n)), $n);
// d = (sa*k - za)/r
$d = mod_g(gmp_mul(mod_g(gmp_sub(gmp_mul($sa,$k),$za),$n), inv_mod($r,$n)), $n);
echo "recovered k=".hex64($k)."\nrecovered d=".hex64($d)."\n";
// verify: pub = d*G, and re-sign msg_a with k, check r
$pub=scalar_mul($d);
echo "pubkey=(".hex64($pub[0]).",".hex64($pub[1]).")\n";
// sanity: s_a' = k^-1 (za + r d)
$sa2 = mod_g(gmp_mul(inv_mod($k,$n), gmp_add($za, gmp_mul($r,$d))), $n);
echo "check sa matches: ".(gmp_cmp($sa2,$sa)===0?"YES":"NO")."\n";

// ---- forge a winner:true ticket ----
$win=["date"=>"2026-10-11","movie"=>"Hackers","screen"=>"mainframe-1","seat"=>"C07","winner"=>true];
$msg=canonical_json($win);
$z=sha256_int($msg);
// deterministic k2 (any nonzero); use fixed
$k2=gmp_init('0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef');
$R=scalar_mul($k2); $rr=mod_g($R[0],$n);
$ss=mod_g(gmp_mul(inv_mod($k2,$n), gmp_add($z, gmp_mul($rr,$d))),$n);
$env=["ticket"=>$win,"signature"=>["alg"=>"ECDSA-secp256k1-SHA256","r"=>hex64($rr),"s"=>hex64($ss)]];
echo "FORGED_ENVELOPE=".canonical_json($env)."\n";
