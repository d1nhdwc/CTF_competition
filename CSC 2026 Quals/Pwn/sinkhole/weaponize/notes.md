# candidate / "sinkhole" — weaponization notes (agent: downstream + smi-check)

## Target
- Chromium, V8 **15.3.71.0**, x64 Linux. Prebuilt unstripped `chrome` shipped in the handout.
- Bot runs: `chrome --headless=new --no-sandbox --disable-gpu --js-flags="--no-memory-protection-keys --expose-cage-base" <url>`.
- Flag at `/flag` (mode 600, owner ctf). `--no-sandbox` ⇒ renderer can read it directly.
- Submission: public http/https URL pasted into `nc 113.20.103.216 31337` (prompts "URL to visit").

## Established facts (each MEASURED on the shipped binary, not assumed)
- **V8 sandbox is NOT compiled in.** No `Sandbox::`/`TrustedPointerTable`/`CodePointerTable` symbols; no 1 TB PROT_NONE reservation in `/proc/<renderer>/maps`. ⇒ `JSArrayBuffer::backing_store` and `JSTypedArray::external_pointer` are **raw 64-bit pointers**; corrupting one gives whole-process R/W.
- **Pointer compression ON** (4 GB cage; `cageBase()` gives the base, fresh per process).
- **Leaptiering ON** (`JSDispatchTable` present).
- **JIT/WASM code pages are plain `rwx`** because `--no-memory-protection-keys` disables ThreadIsolation (`src/common/code-memory-access.cc`). Confirmed in the live map: one 512 MB `rwxp` region outside the cage.

## Object layouts (ground-truth from /proc, this build)
- JSArrayBuffer (size 0x38): byte_length **+0x14**, max_byte_length +0x1c, backing_store **+0x24**, extension +0x2c, bit_field +0x34.
- JSTypedArray (size 0x3c): buffer +0x10, bit_field +0x14, byte_offset +0x18, **byte_length +0x20**, (raw_length +0x28 — NOT the element-count field used by the bounds check for a Uint8Array; observed 0x1100000011), **external_pointer +0x30**, base_pointer +0x38 (Smi 0, off-heap).
  - Element bounds use **byte_length @ +0x20**; element j of an off-heap Uint8Array is at `external_pointer + j` (base_pointer 0).
- Uint8Array map (RO space, stable): compressed **0x01033295**. Float64Array map: 0x0103b781.
- WasmInstanceObject +0x0c = trusted_data (plain tagged ptr, no TPT); WasmTrustedInstanceData +0x28 = jump_table_start = base of the module's rwx region; jump-table slot 0 = `jmp rel32` → exported fn entry.

## The two bugs (whole patch = exactly these two Maglev passes + maglev_licm default→true)
- **maglev-smi-check-elimination** → **addrof** (leak only). `OverwriteWith<UnsafeSmiUntag>` over the value's *definition* while only one *use* (input(0) of a `CheckInt32Condition(kUnsignedLessThan,kOutOfBounds)`) was inspected ⇒ every other use of that value is unchecked ⇒ passing a HeapObject yields `compressed_ptr >> 1`. `addrof(o) = (big(o,arr,0) - 1) * 2`. Provably not an OOB (each keyed access re-checks its own converted index against its own length).
- **maglev-store-sink** → the **OOB double read + write** (attacker-chosen index, 8-byte, 8-aligned). Owned/characterised by the other agent (storesink/notes.md §7b).
- Both gated on `graph_->num_blocks() > 1024` (`kSmallFunctionMaxBlocks`), which no test builds.

## Tier-up protocol (correctness requirement, baked into the page)
- Both bugs fire under NATURAL tier-up with the bot's flags only (no natives). Verified.
- smi-check addrof: ~640 if-arms, warm ~1200 Smi-only calls, idle ~1.5 s (concurrent Maglev finalise+install), ~400 nudge calls, then probe. Fires from ≥550 arms; deterministic address across runs.
- store-sink: ~400 arms, arrays built with `TEMPLATE.slice()` (literals/`new Array` mature to PACKED_DOUBLE and delete the transition node), inner nested loop `for(i<n){for(j<2){}}` to defeat loop-peeling, a TAGGED store after the double store. Fires at call ~651.
- Keep total invocations per victim **< 3000** (`invocation_count_for_turbofan`); TurboFan installing cancels the pending Maglev job. Victim bytecode **< 60 KB** (~400 arms ≈ 8 KB).
- Never cache a compressed address across an allocation (BigInt math allocates → scavenge moves young objects). Re-derive from addrof each use.

## Downstream chain — PROVEN end to end
1. Retarget a Uint8Array's external_pointer → whole-process sliding window (read64c/write64c).
2. WasmInstance +0x0c → trusted +0x28 → rwx code base → jump-table slot0 → fn entry; scan for the marker instruction.
3. Overwrite the wasm body with 73-byte shellcode; call the export.
4. Shellcode: open("/flag"), read into a JS-visible ArrayBuffer backing store, close; returns via the Liftoff epilogue `mov rsp,rbp;pop rbp;ret`.
5. Exfil four ways (Image/sendBeacon/fetch/XHR POST) + document.title to a public collector.
- Proven with: (a) `sctest.c` — shellcode run in a harness reproducing the Liftoff frame, callee-saved preserved, flag read; (b) `lab3.py` — the full JS chain (`exploit.js`) driven with a stand-in primitive injected via /proc/mem: `boom() → open()/read() → flag → exfil`, reproduced 4/4 runs. Against a non-existent `/flag` the syscall returned ENOENT (-2), itself proof of execution.

## Files
- `exploit.html` — shipping page (targets `/flag`, four-way exfil, per-victim invocation budget, retry loop).
- `sce.js` — smi-check addrof (stage 1a, verified natural).
- `storesink.js` — drop-in point for the store-sink primitive (stage 1 primary).
- `primitive.js` — selects storesink (primary) vs smi-check+write (fallback) behind {addrof, read64c, write64c}.
- `exploit.js` — stages 2–5 (arbitrary R/W → wasm rwx → shellcode → exfil). Production.
- `sc.asm` / `sctest.c` — shellcode + its standalone proof harness.
- `collector.py` — hosts the page + collects exfil; highlights CSCV2026{...}/SVATTT{...}.
- `wtest.html` / `lab3.py` — /proc-injected stand-in primitive harness (used to prove stages 2–5).
- `rwtest.html` — combined real-addrof + store-sink-write two-typed-array steer (in progress: read64c/write64c).
- `groom.html` — grooming experiment for a single-bug store-sink R/W.

## Status — COMPLETE
- addrof (smi-check): DONE — natural tier-up, bot flags only, deterministic.
- store-sink OOB double read+write: DONE — reproduced, reads bit-exact, writes land.
- read64c/write64c (two-typed-array steer): DONE — corrupt a groomed Uint8Array U's
  external_pointer (+0x30, at byte_length_slot+2 on the 8-byte confused-read grid) to
  &U2.external_pointer (= cageBase + addrof(U2) + 0x30, addrof read AFTER warmup so U2 is
  promoted). U then aliases U2's window: write U to steer, read/write U2. Verified: same-shape
  objects share a map word; a property write flips a JS-visible value.
- Full chain (exploit.js): DONE — arbitrary R/W -> wasm rwx -> shellcode -> open("/flag")/read
  -> 4-way exfil. Proven end to end with the bot's EXACT flags and NO natives syntax.

## Verification numbers
- 5/5 reliable local runs (bot flags, no natives).
- End-to-end through a public localhost.run tunnel with a fresh cold-profile Chrome using the
  bot's exact flags: flag exfiltrated to the collector in ~9 s (bot budget 45 s).
- Chain uses two victim functions (~1600 addrof warmup + ~750 store-sink), each under the
  3000-invocation TurboFan-cancel budget; both fire under natural tier-up.

## Deploy
- collector.py on 0.0.0.0:8000 serves the page and collects exfil; flags -> flag.txt.
- Public URL submitted to `nc 113.20.103.216 31337`: https://<sub>.lhr.life/exploit.html
  (no query params: defaults to reading /flag and exfil to its own origin).
