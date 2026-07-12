import random
from datetime import datetime

with open("flag.txt", "r") as f:
    flag = f.read().strip()

keystring = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"

N = 15


def encrypt_flag(n):
    for _ in range(n):
        key = random.choices(keystring, k=len(flag))
        enc = bytes([ord(f) ^ ord(k) for f, k in zip(flag, key)])
        print(enc.hex())


def scramble_list(n):
    l = list(x for x in range(N))
    for _ in range(n):
        random.shuffle(l)
        print(l)


def pick_random_letters(n):
    for _ in range(n):
        print("".join(random.choices(keystring, k=N)))


def greet_user():
    print(f"Access time: {datetime.now()}")
    print("Hello there, user!")
    print("Welcome to the Randomness Exhibit!")
    print(
        "To show it off, I'll scramble some lists, pick some random letters, and then give you a couple encrypted flags as a treat."
    )
    print("You even get to pick the quantities!")

    a = input("How many list-scrambles do you want?")
    b = input("How many random-letter-pickings do you want?")
    c = input("How many flag encryptions do you want?")

    try:
        a = int(a)
        b = int(b)
        c = int(c)
    except:
        print("One of those doesn't look quite right...")
        return

    if a < 0 or b < 0 or c < 0:
        print("I think you know I can't do that!")
        return

    if a + b + c > 20_000:
        print("Hey! I don't want to give TOO much away. Take it slow...")
        return

    scramble_list(a)
    pick_random_letters(b)
    encrypt_flag(c)

    print("Well, I think I've helped enough. Good luck!")


greet_user()
