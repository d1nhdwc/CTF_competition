import subprocess, json, re, sys

B="https://hacker-cinema-296dee9a43fd.inst5.ctf.fortid.com"

def days_from_civil(y,m,d):
    y -= m<=2
    era=(y if y>=0 else y-399)//400
    yoe=y-era*400
    doy=(153*(m+(-3 if m>2 else 9))+2)//5 + d-1
    doe=yoe*365+yoe//4-yoe//100+doy
    return era*146097+doe-719468

def civil_from_days(z):
    z+=719468
    era=(z if z>=0 else z-146096)//146097
    doe=z-era*146097
    yoe=(doe-doe//1460+doe//36524-doe//146096)//365
    y=yoe+era*400
    doy=doe-(365*yoe+yoe//4-yoe//100)
    mp=(5*doy+2)//153
    d=doy-(153*mp+2)//5+1
    m=mp+3 if mp<10 else mp-9
    return y+(m<=2),m,d

def buy(ts, seat="A01"):
    loc=subprocess.run(["curl","-s","-i","-X","POST",f"{B}/buy","--data",f"seat={seat}&screening={ts}"],
                       capture_output=True,text=True).stdout
    m=re.search(r'id=([A-Za-z0-9_-]+)', loc)
    if not m: return None
    tid=m.group(1)
    subprocess.run(["curl","-s",f"{B}/ticket.png?id={tid}","-o","d.png"],capture_output=True)
    raw=subprocess.run(["zbarimg","--raw","-q","d.png"],capture_output=True,text=True).stdout.strip()
    try: return json.loads(raw)
    except: return None

def parse_date(s):
    # handles '-0249-10-15' and '1653-02-10'
    m=re.match(r'^(-?\d+)-(\d{2})-(\d{2})$', s)
    y,mo,d=int(m.group(1)),int(m.group(2)),int(m.group(3))
    return y,mo,d

if __name__=="__main__":
    # scan BC region: offset = kiosk_day - ticket_day
    YEAR1 = -62135596800
    lo, hi = -70000000000, YEAR1
    N=40
    results=[]
    for i in range(N+1):
        ts = lo + (hi-lo)*i//N
        env=buy(ts)
        if not env: print(f"ts={ts} FAIL"); continue
        td=env['ticket']['date']
        y,mo,d=parse_date(td)
        tday=days_from_civil(y,mo,d)
        kday=ts//86400
        off=kday-tday
        results.append((ts,td,off))
        print(f"ts={ts:>14}  ticket={td:>12}  kiosk_day_date={'%05d-%02d-%02d'%civil_from_days(kday)}  offset={off}")

def scan_day(day_start_ts, label, n=25):
    print(f"\n=== {label}: kiosk day starting ts={day_start_ts} ({'%05d-%02d-%02d'%civil_from_days(day_start_ts//86400)}) ===")
    seen={}
    for i in range(n):
        ts=day_start_ts + (86400*i)//n
        env=buy(ts)
        if not env: print(f"  ts={ts} FAIL"); continue
        td=env['ticket']['date']; r=env['signature']['r']
        seen.setdefault((td,r[:12]),[]).append(ts)
        print(f"  ts={ts:>14}  ticket={td:>12}  r={r[:16]}..")
    print("  distinct (ticketdate, r-prefix):", list(seen.keys()))

def offset_at(ts):
    env=buy(ts)
    if not env: return None, None, None
    td=env['ticket']['date']
    y,mo,d=parse_date(td)
    tday=days_from_civil(y,mo,d)
    kday=ts//86400
    return kday-tday, td, env['signature']['r']
