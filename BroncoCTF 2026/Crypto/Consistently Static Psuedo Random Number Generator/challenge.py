import random


# Advanced birthday prediction algorithm
class RNG:
    def __init__(self, entropy: bytes):
        self.nextrep = 0

        shift = random.randint(0, len(entropy))
        self.schedule = list(range(len(entropy)))
        self.schedule = self.schedule[shift:] + self.schedule[:shift]
        if random.random() > 0.5:
            self.schedule.reverse()

        self.state = list(entropy)

    def next(self):
        a = sum(self.state) % 256
        self.state[self.schedule[self.nextrep % len(self.schedule)]] = a
        self.nextrep += 1
        return a


flag = b""
with open("flag.txt", "rb") as f:
    flag = f.read()

rand = RNG(flag)

months = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
]

# Yeah, I start with Monday. Open a ticket if you wish to discuss.
days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]

areas = ["Asia", "Africa", "the Americas", "Europe", "Australia"]

print("I will guess your birth day, month and region.")
while True:
    guess = rand.next()

    month = months[guess % len(months)]
    day = days[guess % len(days)]
    area = areas[guess % len(areas)]

    print(f"I see it now: you were born in {month}... on a {day}, in {area}")

    response = input("Did I get it right? ")
    if response.lower().startswith("y"):
        print("Yay!")
        exit()
    print("It seems that I've gotten something wrong, let me listen again...")
