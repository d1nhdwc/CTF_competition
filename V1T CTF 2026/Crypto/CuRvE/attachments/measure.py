import cypari2, time, random, signal
pari = cypari2.Pari(); pari.allocatemem(1<<31)

p = 97982165658893843609584817170666566922413747910860465693496474781541838583617
a = 0x1000000000000000000000000000000000000abcdef

def trial_factor(n, lim):
    f = pari.factor(n, lim)
    fac = [(int(f[0][i]), int(f[1][i])) for i in range(len(f[0]))]
    smooth=1; cof=1; small=[]
    for pr,e in fac:
        if pr < lim:
            smooth*=pr**e; small.append((pr,e))
        else:
            cof*=pr**e
    return smooth, small, cof

t0=time.time()
tested=0
good=[]
while time.time()-t0 < 80:
    b=random.randrange(1<<101,1<<150)
    try:
        E=pari.ellinit([a,b],p)
        n=int(pari.ellcard(E))
    except Exception:
        continue
    tested+=1
    # strip small primes up to 2^24
    tf=time.time()
    smooth, small, cof = trial_factor(n, 1<<24)
    cof_prime = bool(pari.ispseudoprime(cof)) if cof>1 else True
    print(f"[{tested}] n_bits={n.bit_length()} smooth_bits={smooth.bit_length()} cof_bits={cof.bit_length()} cof_prime={cof_prime} factor_t={time.time()-tf:.2f}s maxp={max((pr for pr,_ in small),default=0)}", flush=True)
    if cof_prime and cof> (1<<60) and smooth>1:
        good.append((smooth.bit_length(), [pr for pr,_ in small]))

print("=== SUMMARY ===", flush=True)
print("tested", tested, "good(smooth*prime)", len(good), flush=True)
for g in good:
    print(g, flush=True)
