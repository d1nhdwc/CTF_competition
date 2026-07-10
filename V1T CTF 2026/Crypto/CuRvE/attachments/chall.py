from sage.all import *
from Crypto.Util.number import * 
from hashlib import sha256
import random
M = set() # Message Space 
h = set() # Hash Space
R = set() # R Space
S = set() # S Space




def Key_Generation():

    p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
    K = GF(p)
    a = K(0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc)
    b = K(0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b)
    E = EllipticCurve(K, (a, b))
    G = E(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
    E.set_order(0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551 * 0x1)
    n = E.order()
    
    # priv and pub key
    Alphabet = "abcdefghijklmnopqrstuvwxyz"
    Alphabet = [c for c in Alphabet]
    priv_key =  random.choices(Alphabet, k=21)
    priv_key = bytes_to_long(''.join(priv_key).encode())
    pub_key = priv_key * G
    return E, G, priv_key, pub_key, n


def ECDSA_Sign(E, G, d, m):
    h = int(sha256(m).hexdigest(), 16)
    k = randint(1, E.order() - 1)
    k = next_prime(k)
    R = k * G
    R = R.xy()[0]
    r = R % E.order()
    s = (inverse_mod(k, E.order()) * (h + r * d)) % E.order()

    S.add(s)
    R.add(r)
    h.add(h)
    M.add(m)

    return (r, s)

def ECDSA_Verify(E, G, Q, r, s, m):
    N = int(E.order())
    
    if not (0 < r < N) or not (0 < s < N):
        return False
        
    h = int(sha256(m).hexdigest(), 16)
    
    Right_Hand_Side = (h % N) * G + (int(r) % N) * Q
    
    if Right_Hand_Side.is_zero():
        return False
    try:
        p = int(E.base_field().order())
        R_candidate = E.lift_x(Integer(r % p))
        
        if int(s) * R_candidate == Right_Hand_Side or int(s) * (-R_candidate) == Right_Hand_Side:
            return True
    except ValueError:
        return False
        
    return False


def sign_message(message):
    signature = ECDSA_Sign(E, G, priv_key, message)
    return signature

def verify_signature(message, signature):
    r, s = signature
    return ECDSA_Verify(E, G, pub_key, r, s, message)

def change_parameters(priv_key):

    p = getPrime(256)
    K = GF(p)
   
    print("Here is Your new ECDSA parameters:")
    print(f"Prime p = {p}")
    
    a = input("Enter the coefficient a (hex): ")
    b = input("Enter the coefficient b (hex): ")
    a = (int(a, 16))
    b = (int(b, 16))
    
    assert a.bit_length() > 100 and b.bit_length() > 100, print(a.bit_length(), b.bit_length())
    E = EllipticCurve(K, [a, b])
    n = E.order()
    factors = factor(n)
    B = 2**60

    assert any(f[0] > B for f in factors), "OOPS, You've cheated!"
    G = E.random_element()
    pub_key = priv_key * G
    

    return E, G, priv_key, pub_key, n


def get_flag(E, G, pub_key):
    with open('flag.txt', 'r') as f:
        flag = f.read()

    message = bytes.fromhex(input("Enter the message you want to verify (hex): "))
    r = int(input("Enter r (hex): "), 16)
    s = int(input("Enter s (hex): "), 16)

    assert message not in M, "This message has already been signed!"
    assert r not in R, "This r value has already been used!"
    assert s not in S, "This s value has already been used!"

    assert ECDSA_Verify(E, G, pub_key, r, s, message), "Invalid signature!"
    
    print(f"Congratulations! Here is your flag: {flag}")
    exit(0)

def menu(is_Changed = False):
    menus = [
        ". Sign a message",
        ". Verify a signature",
        ". Change ECDSA parameters",
        ". Get flag",
        ". Exit"
    ]
    if is_Changed:
        menus[2] = ". Change ECDSA parameters (Currently: Changed)"

    for i,m in enumerate(menus):
        print(f"{i+1}. {m}")
    
    choice = int(input("Your choice: "))
    if choice ==3 and is_Changed:
        print("OOPS! You've already changed the ECDSA parameters, Please choose another option.")
        return -1,-1
    is_Changed = 1 if choice == 3 else 0 

    return choice, is_Changed




def banner():
    print("""
     _       __     __                             __                          
| |     / /__  / /________  ____ ___  ___     / /_____     ____ ___  __  __
| | /| / / _ \/ / ___/ __ \/ __ `__ \/ _ \   / __/ __ \   / __ `__ \/ / / /
| |/ |/ /  __/ / /__/ /_/ / / / / / /  __/  / /_/ /_/ /  / / / / / / /_/ / 
|__/|__/\___/_/\___/\____/_/ /_/ /_/\___/   \__/\____/  /_/ /_/ /_/\__, /  
                                                                  /____/   
    ________________  _____ ___                 __                         __
   / ____/ ____/ __ \/ ___//   |     __________/ /_  ___  ____ ___  ____ _/ /
  / __/ / /   / / / /\__ \/ /| |    / ___/ ___/ __ \/ _ \/ __ `__ \/ __ `/ / 
 / /___/ /___/ /_/ /___/ / ___ |   (__  ) /__/ / / /  __/ / / / / / /_/ /_/  
/_____/\____/_____//____/_/  |_|  /____/\___/_/ /_/\___/_/ /_/ /_/\__,_(_)
    """)
    print("You can sign messages, verify signatures, and even change the ECDSA parameters (but be careful!).")
    print("Try to get the flag by signing a message that contains it!")
    
def challenge():
    banner()
    
    print("\n Here is my gift for you: ")
    
    E, G, priv_key, pub_key, n = Key_Generation()
    
    print(f"Public key: {(hex(pub_key.xy()[0]), hex(pub_key.xy()[1]))}")
    print(f"Base point G: {hex(G.xy()[0]), hex(G.xy()[1])}")
    print(f"Order of the curve: {n}")
    print(f"Elliptic curve: {E}")
    print("\n Now, it's your turn to play with the ECDSA scheme! ")
    
    is_Changed = False
    
    while True:
        
        choice, is_Changed = menu(is_Changed)
        
        if choice == 1:
        
            message = bytes.fromhex(input("Enter the message you want to sign (hex): "))
            signature = sign_message(message)
            print(f"Signature: {signature}")
        
        elif choice == 2:
            
            message = bytes.fromhex(input("Enter the message you want to verify (hex): "))
            r = int(input("Enter r (hex): "), 16)
            s = int(input("Enter s (hex): "), 16)
            signature = (r, s)
            if verify_signature(message, signature):
                print("Signature is valid!")
            else:
                print("Signature is invalid!")
        
        elif choice == 3:
            
            E, G, priv_key, pub_key, n = change_parameters(priv_key)
            print(f"New Public key: {(hex(pub_key.xy()[0]), hex(pub_key.xy()[1]))}")
            print(f"New Base point G: {(hex(G.xy()[0]), hex(G.xy()[1]))}")
            print(f"New Order of the curve: {n}")
            print(f"New Elliptic curve: {E}")
            
        elif choice == 4:
            get_flag(E, G, pub_key)
            
        elif choice == 5:
            print("Goodbye!")
            break
        else:
            print("Invalid choice! Please try again.")


if __name__ == "__main__":
    challenge()