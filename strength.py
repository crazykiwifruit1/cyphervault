import math
import string
import random
import random_word
def entropy(inp):
    l = len(inp)
    lowercase = set(string.ascii_lowercase)
    uppercase = set(string.ascii_uppercase)
    numbers = set(string.digits)
    special = set(string.punctuation)
    space = set(' ')                #get if certain character types are in input
    usedinpassword = set()
    for char in inp:
        if char in lowercase:
            usedinpassword.update(lowercase)
        elif char in uppercase:
            usedinpassword.update(uppercase)
        elif char in numbers:
            usedinpassword.update(numbers)
        elif char in special:
            usedinpassword.update(special)
        elif char in space:
            usedinpassword.update(space)
    r = len(usedinpassword)
    if r == 0 or l == 0:
        strength = 0
    else:
        strength = l*math.log2(r) #mathematical formula to determine entropy of the password (bits)

    return int(strength)

def checksubstring(password, path, minlength=3):
    lowercase = password.lower()             #makes all letters lowercase
    found = []
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as file:
            for line in file:
                word = line.strip().lower()
                if len(word) >= minlength and word in lowercase:        #checks words in the file
                    found.append(word)            #appends found words to the list
    except FileNotFoundError:
        print(f"File not found at {path}") #this ultimately will not be seen by client as file is server side
    return found


SYMBOLS = '!@#$%^&*()-_=+[]{}<>?'

import random
import string
from random_word import RandomWords

SYMBOLS = '!@#$%^&*()-_=+[]{}<>?'

def generate_random(length):
    all_chars = string.ascii_letters + string.digits + SYMBOLS
    return ''.join(random.choice(all_chars) for i in range(length))

def generate_memorable_password(strength, length):
    if not (1 <= strength <= 10):
        raise ValueError("Strength must be between 1 and 10.")

    r = RandomWords()
    

    num_words = max(2, strength) if strength < 7 else strength + 1

   
    use_numbers = strength >= 3
    use_symbols = strength >= 5
    use_capitalization = strength >= 4

    password_parts = []
    
    while len(''.join(password_parts)) < (length or 999):  # length limit applied at the end
        word = r.get_random_word()
        if not word or not word.isalpha():
            continue

        if use_capitalization:
            word = ''.join(
                c.upper() if random.random() > 0.7 else c.lower()
                for c in word
            )
        password_parts.append(word)

        if use_numbers and random.random() > 0.5:
            password_parts.append(str(random.randint(0, 99)))

        if use_symbols and random.random() > 0.5:
            password_parts.append(random.choice(SYMBOLS))

        if len(password_parts) >= num_words * (3 if use_symbols else 2):
            break

    password = ''.join(password_parts)
    return password[:length] if length else password


