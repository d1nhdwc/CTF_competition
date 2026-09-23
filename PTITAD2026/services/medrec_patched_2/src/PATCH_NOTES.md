# MedRec patched source

Applied patches:

1. `front.c` / `dump_staff_card()`
   - Keeps `STAFF/ROSTER` response shape up to `DATA 128`.
   - Zero-pads bytes after `doctor.remark[64]` to avoid leaking adjacent `password[64]`.

2. `front.c` / `chart_page()`
   - Clamps `CHART/EXPORT` reads to `patient.body_len - off`.
   - Prevents heap out-of-bounds reads at and past EOF.

3. `rend.c` / `cmd_field_add()`
   - Uses `calloc()` for field data.
   - Prevents `FIELD GET` from leaking uninitialized heap memory.

4. `rend.c` / `cmd_stamp()`
   - Keeps the previous overflow check and adds an explicit `off > canvas_sz` hardening guard.

Existing patches kept from the uploaded `(2)` version:

- `rend.c` / `cmd_sheet()` validates and allocates replacement sheet/canvas before freeing old state.
- `rend.c` / `cmd_stamp()` rejects overlong stamps instead of writing past canvas.
- `db.c` empty-doctor eviction code is preserved as uploaded.

Sanity tests performed locally:

- Build with `gcc -Wall -Wextra -O2 -o medrecd main.c front.c rend.c db.c util.c` succeeded.
- `STAFF 0 128` returns `DATA 128` with zero padding after the 64-byte remark.
- `CHART <pid> <body_len> 160` returns `DATA 0` instead of reading past EOF.
- `FIELD ADD` then `FIELD GET` returns zero-filled data.
- `STAMP 7 31` with two bytes returns `ERR RANGE` and does not overflow.

Not changed because checker behavior is uncertain:

- `PATIENTS <doctor_id>` still lists another doctor's patients.
- `NORM` patient charts are still readable cross-doctor.
- `hex2bin()` still truncates oversized hex instead of rejecting it.
- Unix renderer socket is still `0666`.
