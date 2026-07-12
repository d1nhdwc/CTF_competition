import hashlib

FLAG = [REDACTED]
TARGET = 468
MAX_EDITS = 3
blorgs = 1
edits = 0

valid = {
    "11198b294adbcf089f9d27990258fd22",
    "b0fe2606af48e49fd3746844798eb6a0",
    "334c4a4c42fdb79d7ebc3e73b517e6f8",
    "dbd73c2b545209688ed794c0d5413d5a",
    "a9c449d4fa44e9e5a41c574ae55ce4d9",
    "A7DD12B1DAB17D25467B0B0A4C8D4A92",
}

program = None
program_cmd = ""


def handle_input(bytes_in: bytes):
    global blorgs, edits, program, program_cmd
    select = hashlib.md5(bytes_in).hexdigest()
    if select not in valid:
        print("That is not a real command!")
        return

    user_in = bytes_in.decode("latin-1")
    if user_in == "increase":
        blorgs += 1
        blorgs *= 2
        edits += 1
    elif user_in == "decrease":
        blorgs -= 1
        blorgs *= 2
        edits += 1
    elif user_in == "none":
        blorgs *= 2
    elif user_in == "program":
        if program is not None:
            valid.remove(hashlib.md5(program.encode("latin-1")).hexdigest())
        program = input("What is the name of the new command? ")
        program_cmd = input(
            "Which (space separated) commands would you like it to run:"
        )
        valid.add(hashlib.md5(program.encode("latin-1")).hexdigest())
    elif user_in == program:
        for cmd in program_cmd.split(" "):
            print(f"Running: {cmd}")
            handle_input(cmd.encode("latin-1"))
    elif user_in == "quit":
        print("Bye!")
        exit()
    else:
        if blorgs == TARGET:
            print(f"Wow! You earned the flag: {FLAG}")
        else:
            print(f"Maybe get your blorgs in line first...")


def run():
    global blorgs, edits
    print(
        "Hello! I have in my possession many blorgs. So many that I will double the number you have after each response."
    )
    print(f"I will let you make {MAX_EDITS} requests.")
    print(f"You need to get EXACTLY {TARGET} blorgs before I'll show you the flag...")
    print("Here are the valid commands:")
    print("increase: increase the amount of blorgs by 1 before doubling")
    print("decrease: decrease the amount of blorgs by 1 before doubling")
    print("none: don't mess with the blorgs right now")
    print("show: show the flag")
    print("program: set a command to let you run a series of other commands")
    while blorgs <= TARGET and edits <= MAX_EDITS:
        print(f"You have {blorgs} blorgs and {MAX_EDITS - edits} edits remaining.")
        print("What would you like to do? ")
        user_in = input("> ")
        if len(user_in) == 0:
            print("Nothing to say? Fine by me!")
            break
        handle_input(user_in.encode("latin-1"))

    print("You have FAILED.")


if __name__ == "__main__":
    run()
