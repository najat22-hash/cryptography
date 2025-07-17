import random

def is_prime(n):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True

def generate_prime_q():
    while True:
        q = random.randint(1000, 10000)  # adjust the range as needed
        if is_prime(q):
            return q

q = generate_prime_q()
print("Prime q:", q)
import numpy as np

# Define the modulus
q = 17

# Define the key matrix A
A = np.array([[2371, 470699208, 45321], [5689, 1211, 67543]])

# Define the plaintext matrix M11
M11 = np.array([[2345, 87654], [43251, 654]])

# Define the modulus operation
def mod(x, q):
    return x % q

# Apply the modulus operation to the matrices
A_mod = np.vectorize(lambda x: mod(x, q))(A)
M11_mod = np.vectorize(lambda x: mod(x, q))(M11)

# Calculate the ciphertext block C11
C11 = np.dot(M11_mod, A_mod) % q

# Calculate the decryption matrix A'
x1, x2 = A_mod[0, 0], A_mod[1, 0]
y1, y2 = A_mod[0, 1], A_mod[1, 1]
det = (x1 * y2 - x2 * y1) % q
det_inv = pow(det, -1, q)
A_prime = np.array([[y2 * det_inv % q, (-x2 * det_inv) % q], [(-y1 * det_inv) % q, x1 * det_inv % q], [0, 0]])

# Decrypt C11 using A'
M11_decrypted = np.dot(C11[:, :2], A_prime[:2, :2]) % q

# Verify that M11_decrypted is equal to M11_mod
assert np.array_equal(M11_decrypted, M11_mod)