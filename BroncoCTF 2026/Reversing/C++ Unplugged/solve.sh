bash -lc python3 - << 'PY'
from math import pow

def updateNum(start):
    if start < 5:
        start = 5
    elif start < 10:
        start = 8
    else:
        start = int(start/5)
    counter=3
    while counter < 6:
        counter += 1
        if counter == 5:
            continue
        start += 1
    return start

def secretMath(idx):
    if idx==0: return 100-5
    elif idx==1: return 32*2
    else: return 19*5

def part1():
    something=''; flag_selector_1=0; var1=True; var2=22; var3=13; var4=5; var5=1
    if var1 and var2 > var3:
        var1=False
        flag_selector_1 = -4
        if var1 or (var2-var3 == 9 and var4 < var3):
            flag_selector_1 += 7
        else:
            flag_selector_1=(3+2)*3
        flag_selector_1 -= 1
    else:
        flag_selector_1=0
    if flag_selector_1 == 0: something='hello'
    elif flag_selector_1 == 1: something='world'
    elif flag_selector_1 == 2:
        var5=updateNum(var5)
        if var5 == 7: something='bron'
    elif flag_selector_1 == 3: something='pop'
    elif flag_selector_1 == 4: something='country'
    elif flag_selector_1 == 5: something='rap'
    else: something='who???'
    return something

def part2():
    ans=''
    chars=['b','#','c','i','u','&','e','@','d','o','p','t','*','3','{','}']
    ans += chars[5%3]
    if chars[6] == chars[3]: ans += chars[2]
    elif chars[6] != chars[2]: ans += chars[6+3]
    else: ans += chars[0+1]
    numbers=[92,23,10,32,74,90,89,23,100,53,7,11,92,6]
    if numbers[1] <= numbers[7] and numbers[3] <= numbers[5] - numbers[3]:
        ans += chars[14]
    return ans

def part3():
    parts=list('abcdefghijklmnopqrstuvwxyz0123456789')+['@','!','_']
    var1=37; var2=5; var3=52; res=''
    for i in range(6):
        if i==0: res += parts[7+1]
        elif i==1:
            var1 += 1
            res += parts[var1]
        elif i==2:
            var3 = updateNum(var3)
            res += parts[(var1-1)%var2]
        elif i==3: res += parts[36]
        elif i==4: res += parts[var3]
        else: res += parts[5*5+4]
    return res

def part4():
    more=''; i=21; test=True
    while i < 5*7:
        if i % 4 == 0:
            i += 1
            continue
        if i == 3*7 or i == pow(5,2):
            more += '_'
        elif i >= 7 + 4*5:
            if 149 % 30 == i:
                more += 'k'
            elif i <= pow(3,2)*3:
                more += 'i'
            else:
                more += '3'
        elif i % 2 == 0:
            if test:
                more += '1'; test=False
            else:
                if i <= 26: more += 'l'
                elif i > pow(10,2) or i % 2 == 5: more += 'h'
                else: more += 'k'
        elif i > 28//4*3 + 1:
            more += 'n'
        i += 1
        if i == 31: break
    return more

def part5():
    res=''; i=0; limiter=3
    while i < limiter:
        if ((i*7+3)%5 == 4): res += chr(120)
        else: res += chr(secretMath(i))
        i += 1
    return res

def part6():
    out=''; guard=1337
    if ((guard*3+1)%2 == 1): out += chr(65)
    else: out += chr(100+15)
    if ((guard//7)%5 == 4): out += chr(120)
    else: out += chr(50+1)
    out += chr(110-7)
    out += chr(102*1)
    if guard < 0: return out
    out += chr(60 + 12%7)
    out += chr(130-13)
    while True:
        out += chr(54*2)
        guard += 1
        if not (guard == 0): break
    out += chr(122-6)
    out += chr(25*5)
    return out
for f in [part1,part2,part3,part4,part5,part6]: print(f.__name__, repr(f()))
print('flag', ''.join(f() for f in [part1,part2,part3,part4,part5,part6]))
PY
