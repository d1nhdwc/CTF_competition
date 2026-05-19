import re,time,sys
flag='tjctf{m1n3rv4_h34rd_th3_n0nc3_tick}'
pat=sys.argv[1]
st=time.perf_counter(); re.match(pat,flag,flags=re.DOTALL); print(time.perf_counter()-st)
