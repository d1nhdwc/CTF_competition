enc = bytes.fromhex('16a4d3f41898a347bf31dbb26fe04ecf9340bc3bc2827dc871236ec208e1ee7483')
print("enc len", len(enc))
def asc(x): return ''.join(chr(c) if 32<=c<127 else '.' for c in x)
MUL=0x6c62272e; ADD=0x07354a6b; M=0xffffffff

def hit(a): return a[:4].lower()=='v1t{' or 'v1t{' in a.lower()

# password hash variants
pw=b'VaultPass v1.3'
def h_mul(buf,init): 
    s=init
    for b in buf: s=((s*MUL)+b)&M
    return s
def h_chain(buf):
    p=buf[0]
    for i in range(1,len(buf)): p=((p^buf[i])+i)&0xff
    return p

seeds={}
seeds['dbeef']=0xdeadbeef
seeds['hmul_pw_dbeef']=h_mul(pw,0xdeadbeef)
seeds['hmul_pw16_dbeef']=h_mul((pw+b'\0'*16)[:16],0xdeadbeef)
seeds['hmul_pw0']=h_mul(pw,0)
seeds['chain_pw']=h_chain(pw)
seeds['chain_pw16']=h_chain((pw+b'\0'*16)[:16])
for lit in [0x6c62272e,0x07354a6b,0x80000057,0x9456fdd0,0xfdd09456]:
    seeds[hex(lit)]=lit

def stream(seed,n,shift):
    s=seed&M;o=[]
    for _ in range(n):
        s=(s*MUL+ADD)&M
        o.append((s>>shift)&0xff)
    return o

found=[]
for sn,sv in seeds.items():
    for shift in (24,16,8,0):
        ks=stream(sv,len(enc),shift)
        for op,f in [('xor',lambda e,k,i:e^k),('xor_i',lambda e,k,i:e^k^i),
                     ('add',lambda e,k,i:(e+k)&0xff),('sub',lambda e,k,i:(e-k)&0xff),
                     ('rsub',lambda e,k,i:(k-e)&0xff)]:
            out=bytes(f(enc[i],ks[i],i)&0xff for i in range(len(enc)))
            a=asc(out)
            if hit(a): found.append((sn,shift,op,a))
for x in found: print(x)
print("found:",len(found))
# show best dbeef>>24 xor
ks=stream(0xdeadbeef,len(enc),24)
print("dbeef>>24 xor:", asc(bytes(enc[i]^ks[i] for i in range(len(enc)))))
