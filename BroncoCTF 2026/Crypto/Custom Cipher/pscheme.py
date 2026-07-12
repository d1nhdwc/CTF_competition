import cmath
import itertools
import random


class Poly:
    def __init__(self, coeff: list):
        self.coeff = coeff
        self.coeff.reverse()
        self.coeff = list(itertools.dropwhile(lambda x: x == 0, self.coeff))
        self.coeff.reverse()

        if len(self.coeff) == 0:
            self.coeff = [0]

    def get_degree(self):
        return len(self.coeff) - 1

    def copy(self):
        return Poly(self.coeff[:])

    def is_zero(self):
        return self.get_degree() == 1 and self.coeff[0] == 0

    def __mul__(self, other):
        if other.get_degree() == 1 and other.coeff[0] == 0:
            return Poly([0])

        newdeg = self.get_degree() + other.get_degree()
        newcoeff = [0 for _ in range(newdeg + 1)]
        for i1, c1 in enumerate(self.coeff):
            for i2, c2 in enumerate(other.coeff):
                newcoeff[i1 + i2] += c1 * c2

        return Poly(newcoeff)

    def __add__(self, other):
        return Poly(
            [
                a + b
                for a, b in itertools.zip_longest(self.coeff, other.coeff, fillvalue=0)
            ]
        )

    def to_distrib_form(self, delim: str = " "):
        return delim.join(map(str, self.coeff[:-1]))

    def __str__(self):
        return "+".join([f"{c}x^{i}" for i, c in enumerate(self.coeff)][::-1])

    def __repr__(self):
        return f"[Poly: {str(self)}]"


def keygen(root_bits: int, key_degree: int):
    private = sorted([random.randint(1, 2**root_bits - 1) for _ in range(key_degree)])
    public = Poly([1])
    for root in private:
        root_poly = Poly([-root, 1])
        public = public * root_poly

    return (private, public)


def encrypt(public: Poly, message: list[int]):
    for root in message:
        root_poly = Poly([-root, 1])
        public = public * root_poly

    order = sorted(message)
    for i, e in enumerate(order):
        ind = message.index(e)
        order[i] = ind
        message[ind] = -1
    order = sum([x << (2 * i) for i, x in enumerate(order)])

    return (public, order)


def encrypt_string(enc: str, pub: Poly):
    send_list = []
    for substr in itertools.batched(enc, 4):
        message = list(map(ord, substr))
        message += [0 for _ in range(4 - len(message))]

        to_send, order = encrypt(pub, message)
        send_list.append(to_send.to_distrib_form() + " " + str(order))

    return "/".join(send_list)


if __name__ == "__main__":
    N = 64
    B = 8
    FLAG = [REDACTED]

    priv, pub = keygen(8, 64)
    print("====PUBLIC KEY====")
    print(pub.to_distrib_form())
    print("====MESSAGE====")
    print(encrypt_string(FLAG, pub))
