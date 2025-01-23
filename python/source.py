from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app, resources={r"/crypto": {"origins": "http://localhost:5173"}})

from Crypto.Cipher import DES 
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes 
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from tkinter import Tk
from tkinter.filedialog import askopenfilename
import hashlib
import os

def base64Encrypt(s):
    baseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    binary = ''.join(format(ord(char), '08b') for char in s)
    cipher = ''

    while len(binary) % 6 != 0:
        binary += '0'
    
    for i in range(0, len(binary),6):
        chunk = binary[i:i+6]
        cipher += baseChars[int(chunk, 2)]
    while len(cipher) % 4 != 0:
        cipher += '='
    return cipher

def caesarEncrypt(s, direction, shift):
    cipher = ''
    if direction == 'left':
        for i in s:
            char = i
            if char.isalpha():
                if char.isupper():
                    char = chr((ord(char) + shift - 65) % 26 + 65)
                else:
                    char = chr((ord(char) + shift - 97) % 26 + 97)
            cipher += char
    elif direction == 'right':
        for i in s:
            char = i
            if char.isalpha():
                if char.isupper():
                    char = chr((ord(char) - shift - 65) % 26 + 65)
                else:
                    char = chr((ord(char) - shift - 97) % 26 + 97)
            cipher += char

    return cipher

def MonoalphabeticEncrypt(s):
    cipher = ''
    key = {
    'A': 'S', 'B': 'Y', 'C': 'E', 'D': 'C', 'E': 'T', 'F': 'B', 'G': 'F',
    'H': 'A', 'I': 'G', 'J': 'H', 'K': 'W', 'L': 'I', 'M': 'N', 'N': 'R',
    'O': 'J', 'P': 'D', 'Q': 'Z', 'R': 'L', 'S': 'U', 'T': 'M', 'U': 'P',
    'V': 'V', 'W': 'Q', 'X': 'X', 'Y': 'O', 'Z': 'K', 'a': 's', 'b': 'y', 
    'c': 'e', 'd': 'c', 'e': 't', 'f': 'b', 'g': 'f', 'h': 'a', 'i': 'g', 
    'j': 'h', 'k': 'w', 'l': 'i', 'm': 'n', 'n': 'r', 'o': 'j', 'p': 'd', 
    'q': 'z', 'r': 'l', 's': 'u', 't': 'm', 'u': 'p', 'v': 'v', 'w': 'q',
    'x': 'x', 'y': 'o', 'z': 'k'
    }
    for char in s:
        if char in key:
            cipher += key[char]
        else:
            cipher += char
    return cipher

def vignereEncrypt(s):
    key = "NEITB"
    cipher = ''
    for i in range(len(s)):
        if s[i].isalpha():
            
            shift = ord(key[i % len(key)]) - ord('A')

            if s[i].isupper(): 
                newChar = chr((ord(s[i]) - ord('A') + shift) % 26 + ord('A'))
            else:  
                newChar = chr((ord(s[i]) - ord('a') + shift) % 26 + ord('a'))
                
            cipher += newChar
        else:
            cipher += s[i]
    return cipher

def desEncrypt(s):
    key = get_random_bytes(8)
    cipher = DES.new(key, DES.MODE_ECB)
    
    padded_s = pad(s.encode('utf-8'), DES.block_size)
    encryptedText = cipher.encrypt(padded_s)
    cipher = encryptedText.hex()
    return cipher

def aesEncrypt(s, choice):
    if choice == "new":
        key = get_random_bytes(16)  # AES key size is 16 bytes (128 bits)

        # Save the key for future decryption
        with open("aes_key.key", "wb") as f:
            f.write(key)
    elif choice == "existing":
        if not os.path.exists("aes_key.key"):
            return "KEY FILE NOT FOUND"

        # Load the existing key
        with open("aes_key.key", "rb") as f:
            key = f.read()
        print("Existing key loaded.")
    else:
        print("Invalid choice. Please enter 'new' or 'existing'.")
        return "INVALID CHOICE"

    # Encrypt the string
    aes_cipher = AES.new(key, AES.MODE_ECB)  # AES in ECB mode
    padded_s = pad(s.encode('utf-8'), AES.block_size)  # Padding the string to match block size
    cipher = aes_cipher.encrypt(padded_s)

    # Save the ciphertext to a file
    with open("ciphertext_aes.txt", "wb") as f:
        f.write(cipher)

    return "ENCRYPTION SUCCESSFUL"

def rsaEncrypt(s, choice):
    if choice == "new":
        # Generate RSA key pair
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()

        # Save private and public keys
        with open("private_rsa.pem", "wb") as f:
            f.write(private_key)
        with open("public_rsa.pem", "wb") as f:
            f.write(public_key)

    elif choice == "existing":
        # Check if key files exist
        if not os.path.exists("public_rsa.pem"):
            return "FILE NOT FOUND"

        # Load the public key from the existing file
        with open("public_rsa.pem", "rb") as f:
            public_key = f.read()

        key = RSA.import_key(public_key)
    else:
        return "INVALID CHOICE"

    # Encrypt with public key
    rsa_cipher = PKCS1_OAEP.new(RSA.import_key(public_key))
    encryptedText = rsa_cipher.encrypt(s.encode('utf-8'))

    # Save ciphertext
    with open("ciphertext_rsa.txt", "wb") as f:
        f.write(encryptedText)

    return "FILE CREATED"
    
def base64Decrypt(cipher):
    cipher = cipher.rstrip('=')
    baseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    binary = ''.join(format(baseChars.index(char),'06b') for char in cipher)
    decipher = ''
    for i in range(0, len(binary), 8):
        byte = binary[i:i+8]
        if byte != '' :
            decipher += chr(int(byte,2))
    return decipher

def caesarDecrypt(cipher, how, shift, shift_value):
    if(how == 'shift'):
        decipher = ""
        if(shift == 'left'):
            for char in cipher:
                if char.isalpha():
                    shifted = chr((ord(char) - shift_value))
                    if char.isupper():
                        if ord(shifted) < ord('A'):
                            shifted = chr(ord(shifted) + 26)
                    else:
                        if ord(shifted) < ord('a'):
                            shifted = chr(ord(shifted) + 26)
                    decipher += shifted
                else:
                    decipher += char
        elif(shift == 'right'):
            for char in cipher:
                if char.isalpha():
                    shifted = chr((ord(char) + shift_value))
                    if char.isupper():
                        if ord(shifted) > ord('Z'):
                            shifted = chr(ord(shifted) - 26)
                    else:
                        if ord(shifted) > ord('z'):
                            shifted = chr(ord(shifted) - 26)
                    decipher += shifted
                else:
                    decipher += char

        return decipher
    else:
        result = {}
        deciphe = ""
        for shift_value in range(1, 27):
            for char in cipher:
                if char.isalpha():
                    shifted = chr((ord(char) - shift_value))
                    if char.isupper():
                        if ord(shifted) < ord('A'):
                            shifted = chr(ord(shifted) + 26)
                    else:
                        if ord(shifted) < ord('a'):
                            shifted = chr(ord(shifted) + 26)
                    deciphe += shifted
                else:
                    deciphe += char
            result[shift_value] = deciphe
        return result

def MonoalphabeticDecrypt(cipher):
    key = {
    'A': 'S', 'B': 'Y', 'C': 'E', 'D': 'C', 'E': 'T', 'F': 'B', 'G': 'F',
    'H': 'A', 'I': 'G', 'J': 'H', 'K': 'W', 'L': 'I', 'M': 'N', 'N': 'R',
    'O': 'J', 'P': 'D', 'Q': 'Z', 'R': 'L', 'S': 'U', 'T': 'M', 'U': 'P',
    'V': 'V', 'W': 'Q', 'X': 'X', 'Y': 'O', 'Z': 'K', 'a': 's', 'b': 'y', 
    'c': 'e', 'd': 'c', 'e': 't', 'f': 'b', 'g': 'f', 'h': 'a', 'i': 'g', 
    'j': 'h', 'k': 'w', 'l': 'i', 'm': 'n', 'n': 'r', 'o': 'j', 'p': 'd', 
    'q': 'z', 'r': 'l', 's': 'u', 't': 'm', 'u': 'p', 'v': 'v', 'w': 'q',
    'x': 'x', 'y': 'o', 'z': 'k'
    }
    decipher = ''
    reverse = {v:k for k,v in key.items()}
    for char in cipher:
        if char in reverse:
            decipher += reverse[char]
        else:
            decipher += char

def vignereDecrypt(cipher):
    key = "NEITB"
    decipher = ''
    for i in range(len(cipher)):
        if cipher[i].isalpha():
            shift = ord(key[i % len(key)]) - ord('A')

            if cipher[i].isupper():
                newChar = chr((ord(cipher[i]) - ord('A') - shift + 26) % 26 + ord('A'))
            else:
                newChar = chr((ord(cipher[i]) - ord('a') - shift + 26) % 26 + ord('a'))
                
            decipher += newChar
        else:
            decipher += cipher[i]
    return decipher

def desDecrypt(cipher, key_hex):
    try:
        key = bytes.fromhex(key_hex) 
    except ValueError:
        return "Invalid key format. Please provide a valid 16-character hex key."


    if len(key) != 8:
        return "Invalid key length. DES requires an 8-byte key."

    try:
        if not isinstance(cipher, bytes):
            raise ValueError("Ciphertext must be in hexadecimal format.")
    except (SyntaxError, ValueError):
        return "Invalid ciphertext format. Please provide a valid hex-encoded ciphertext."

    try:
        des_cipher = DES.new(key, DES.MODE_ECB)
        decrypted_padded = des_cipher.decrypt(cipher)
        decipher = unpad(decrypted_padded, DES.block_size).decode('utf-8')
        return decipher
    except (ValueError, KeyError) as e:
        return f"Error during decryption: {str(e)}"

def aesDecrypt():
    if not os.path.exists("aes_key.key"):
        print("Error: Key file 'aes_key.key' not found. Cannot decrypt without a key.")
        return "KEY FILE NOT FOUND"

    # Load the key from the file
    with open("aes_key.key", "rb") as f:
        key = f.read()

    # Check if the ciphertext file exists
    if not os.path.exists("ciphertext_aes.txt"):
        print("Error: Ciphertext file 'ciphertext_aes.txt' not found. Encrypt something first.")
        return "CIPHERTEXT FILE NOT FOUND"

    # Load the ciphertext from the file
    with open("ciphertext_aes.txt", "rb") as f:
        ciphertext = f.read()

    try:
        # Initialize AES cipher in ECB mode
        aes_cipher = AES.new(key, AES.MODE_ECB)

        # Decrypt and remove padding
        padded_plaintext = aes_cipher.decrypt(ciphertext)
        plaintext = unpad(padded_plaintext, AES.block_size).decode('utf-8')

        print("Decryption successful. The plaintext is:")
        print(plaintext)
        return plaintext
    except (ValueError, KeyError) as e:
        print("Error during decryption:", e)
    return "DECRYPTION FAILED"

def rsaDecrypt():
    print("Select the RSA-encrypted ciphertext file:")
    Tk().withdraw()
    cipher_file = askopenfilename()
    if not cipher_file:
        print("No file selected. Exiting.")
        return None

    with open(cipher_file, "rb") as f:
        cipher = f.read()

    print("Select the RSA private key file:")
    priv_key_file = askopenfilename()
    if not priv_key_file:
        print("No file selected. Exiting.")
        return None

    with open(priv_key_file, "rb") as f:
        private_key = RSA.import_key(f.read())

    rsa_cipher = PKCS1_OAEP.new(private_key)
    try:
        decipher = rsa_cipher.decrypt(cipher).decode('utf-8')
    except Exception as e:
        print(f"Error during RSA decryption: {e}")
        return None

@app.route('/crypto', methods=['POST'])
def crypto():
    data = request.get_json()
    operation = data.get("operation")
    algorithm = data.get("algorithm")
    input_text = data.get("input")
    result = None
    
    if operation == "encryption":
        if algorithm == "Base64":
            result = base64Encrypt(input_text)
        elif algorithm == "Caesar Cipher":
            direction = data.get("direction")
            shift = data.get("shift")
            result = caesarEncrypt(input_text, direction, shift)
        elif algorithm == "Monoalphabetic Substitution Cipher":
            result = MonoalphabeticEncrypt(input_text)
        elif algorithm == "Vigenère Cipher":
            result = vignereEncrypt(input_text)
        elif algorithm == "DES":
            result = desEncrypt(input_text)
        # elif algorithm == "AES":
        #     key = data.get("key")
        #     result = aesEncrypt(input_text, key)
        # elif algorithm == "RSA":
        #     key = data.get("key")
        #     result = rsaEncrypt(input_text, key)
        else:
            return jsonify({"error": "Unsupported encryption algorithm"}), 400
    elif operation == "decryption":
        if algorithm == "Base64":
            result = base64Decrypt(input_text)
        elif algorithm == "Caesar Cipher":
            how = data.get("decryptionMethod")
            if how == 'shift':
                shift = data.get("direction")
                shift_value = data.get("shift")
                result = caesarDecrypt(input_text, how, shift, shift_value)
            else:
                result = caesarDecrypt(input_text, how, '', 0)
        elif algorithm == "Monoalphabetic Substitution Cipher":
            result = MonoalphabeticDecrypt(input_text)
        elif algorithm == "Vigenère Cipher":
            result = vignereDecrypt(input_text)
        elif algorithm == "DES":
            byte_obj = bytes.fromhex(input_text)
            key = data.get("key")
            result = desDecrypt(byte_obj, key)
        # elif algorithm == "AES":
        #     key = data.get("key")
        #     result = aesDecrypt(input_text, key)
        # elif algorithm == "RSA":
        #     key = data.get("key")
        #     result = rsaDecrypt(input_text, key)  
        else:
            return jsonify({"error": "Unsupported decryption algorithm"}), 400
    elif operation == "hashing":
        if algorithm == "MD5":
            result = hashlib.md5(input_text.encode()).hexdigest()
        elif algorithm == "SHA-1":
            result = hashlib.sha1(input_text.encode()).hexdigest()
        elif algorithm == "SHA-256":
            result = hashlib.sha256(input_text.encode()).hexdigest()
        elif algorithm == "SHA-512":
            result = hashlib.sha512(input_text.encode()).hexdigest()
        else:
            return jsonify({"error": "Unsupported hash algorithm"}), 400
    
    if result is None:
        return jsonify({"error": "An error occurred"}), 500
    return jsonify({"result": result})

if __name__ == '__main__':
    app.run(debug=True)