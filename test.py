import os
import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from PIL import Image

def sign_data(data, private_key):
    signature = private_key.sign(
        data,
        ec.ECDSA(hashes.SHA256())
    )
    return signature

def verify_signature(data, signature, public_key):
    try:
        public_key.verify(
            signature,
            data,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except Exception as e:
        print("La vérification de la signature a échoué :", e)
        return False

def generate_ec_keys():
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()

def perform_diffie_hellman(private_key):
    peer_private_key = ec.generate_private_key(ec.SECP256R1())
    peer_public_key = peer_private_key.public_key()
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)

    # Derive a secure AES key from the shared secret
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_secret)

    return derived_key

def encrypt_data(data, key):
    iv = os.urandom(16)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_data

def decrypt_data(encrypted_data, key):
    iv = encrypted_data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(decrypted_padded_data) + unpadder.finalize()

def create_blank_image():
    return Image.new('RGBA', (100, 100), color='white')

def hide_secret_in_image(secret, image):
    width, height = image.size
    secret_bin = ''.join(format(byte, '08b') for byte in secret)
    idx = 0

    pixels = list(image.getdata())
    for i in range(len(pixels)):
        pixel = list(pixels[i])
        for n in range(4):
            if idx < len(secret_bin):
                pixel[n] = pixel[n] & ~1 | int(secret_bin[idx])
                idx += 1
            if idx == len(secret_bin):
                pixels[i] = tuple(pixel)
                break
        else:
            pixels[i] = tuple(pixel)
            continue
        break

    image.putdata(pixels)
    return image

def main():
    start_time = time.time()
    
    private_key, public_key = generate_ec_keys()
    derived_key = perform_diffie_hellman(private_key)

    user_input = input("Veuillez entrer le texte à chiffrer: ")
    data = user_input.encode()

    encrypted_data = encrypt_data(data, derived_key)
    decrypted_data = decrypt_data(encrypted_data, derived_key)

    signature = sign_data(derived_key, private_key)

    img = create_blank_image()
    stego_image = hide_secret_in_image(derived_key, img)
    stego_image.save('stego_image.png')

    print("Données chiffrées (en bytes):", encrypted_data)
    print("Signature numérique (en bytes):", signature)
    print("Données déchiffrées (en texte):", decrypted_data.decode())

    with open("output.txt", "w") as f:
        f.write("Données chiffrées (en bytes): {}\n".format(encrypted_data))
        f.write("Données déchiffrées (en texte): {}\n".format(decrypted_data.decode()))
        f.write("Signature numérique (en bytes): {}\n".format(signature))

    end_time = time.time()
    print("Temps d'exécution: {:.2f} secondes".format(end_time - start_time))

if __name__ == "__main__":
    main()