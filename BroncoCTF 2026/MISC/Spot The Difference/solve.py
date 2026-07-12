a = open("file1.txt").read().splitlines()
b = open("file2.txt").read().splitlines()

flag = ""
for x, y in zip(a, b):
    if x != y and x.lower() != y.lower():
        flag += y

print(flag)
