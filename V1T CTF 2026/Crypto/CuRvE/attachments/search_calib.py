import cypari2, time, sys
pari = cypari2.Pari()
pari.allocatemem(1<<30)

p = 97982165658893843609584817170666566922413747910860465693496474781541838583617
B = 1 << 42           # DLP-able prime bound
BIGMIN = 1 << 60      # mandatory big prime > 2^60

def smooth_profile(n):
    # factor out primes up to B, return (smooth_part, list of (prime,exp) with prime<=B, cofactor)
    f = pari.factor(n, B)
    primes = [int(f[0][i]) for i in range(len(f[0]))]
    exps   = [int(f[1][i]) for i in range(len(f[0]))]
    smooth = 1
    small = []
    cof = 1
    for pr, e in zip(primes, exps):
        if pr <= B:
            smooth *= pr**e
            small.append((pr, e))
        else:
            cof *= pr**e
    return smooth, small, cof

a = 0x1000000000000000000000000000000000000abcdef  # >2^100
t0 = time.time()
tried = 0
best = 0
results = []
import random
while time.time() - t0 < 60:
    b = random.randrange(1<<101, 1<<150)
    try:
        E = pari.ellinit([a, b], p)
    except Exception:
        continue
    if E == 0 or (isinstance(E, (list,)) and len(E)==0):
        continue
    try:
        n = int(pari.ellcard(E))
    except Exception:
        continue
    tried += 1
    smooth, small, cof = smooth_profile(n)
    # require big prime cofactor > 2^60 and prime (fast server factor)
    if cof > BIGMIN and pari.ispseudoprime(cof):
        if smooth > best:
            best = smooth
            results.append((smooth.bit_length(), b, cof.bit_length(), small[-5:]))
            print(f"tried={tried} smoothbits={smooth.bit_length()} cofbits={cof.bit_length()} maxsmallprime={max(pr for pr,_ in small) if small else 0}")

print("=== done ===")
print("tried", tried, "best smoothbits", best.bit_length())
