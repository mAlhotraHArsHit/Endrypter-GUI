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
def encrypt():
    print("Choose Encryption Algorithm")
    print("(1) Base64")
    print("(2) Caesar Cipher")
    print("(3) Monoalphabetic Substitution Cipher")
    print("(4) Vignere Cipher")
    print("(5) DES")
    print("(6) AES")
    print("(7) RSA")
    opt = int(input())
    cipher = ""

    if opt == 1:
        s = input("Enter the string: ")
        baseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        binary = ''.join(format(ord(char), '08b') for char in s)

        while len(binary) % 6 != 0:
            binary += '0'
        
        for i in range(0, len(binary),6):
            chunk = binary[i:i+6]
            cipher += baseChars[int(chunk, 2)]
        while len(cipher) % 4 != 0:
            cipher += '='

    elif opt == 2:
        s = input("Enter the string: ")
        print("(1) Right shift")
        print("(2) Left shift")
        direction = int(input())
        print("Number of shifts: ")
        shift = int(input())
        if direction == 1:
            for i in s:
                char = i
                if char.isalpha():
                    if char.isupper():
                        char = chr((ord(char) + shift - 65) % 26 + 65)
                    else:
                        char = chr((ord(char) + shift - 97) % 26 + 97)
                cipher += char
        elif direction == 2:
            for i in s:
                char = i
                if char.isalpha():
                    if char.isupper():
                        char = chr((ord(char) - shift - 65) % 26 + 65)
                    else:
                        char = chr((ord(char) - shift - 97) % 26 + 97)
                cipher += char
        else:
            print("Not a valid option")

    elif opt == 3:
        s = input("Enter the string: ")
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

    elif opt == 4:
        s = input("Enter the string: ")
        key = "NEITB"
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
  

    elif opt == 5:
        s = input("Enter the string: ")
        key = get_random_bytes(8)
        print("Generated key (hex):", key.hex())

        cipher = DES.new(key, DES.MODE_ECB)
        
        padded_s = pad(s.encode('utf-8'), DES.block_size)
        encryptedText = cipher.encrypt(padded_s)
        cipher = encryptedText
    
    
    elif opt == 6:
        s = input("Enter the string to encrypt: ")

        # Ask whether to generate a new key or use an existing one
        choice = input("Do you want to generate a new key or use an existing one? (new/existing): ").strip().lower()

        if choice == "new":
            key = get_random_bytes(16)  # AES key size is 16 bytes (128 bits)
            print("Generated key (hex):", key.hex())

            # Save the key for future decryption
            with open("aes_key.key", "wb") as f:
                f.write(key)
            print("Key saved to 'aes_key.key'.")
        elif choice == "existing":
            if not os.path.exists("aes_key.key"):
                print("Error: Key file 'aes_key.key' not found. Generate a new key first.")
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

        print("Encryption complete. Ciphertext saved to 'ciphertext_aes.txt'.")
        return "ENCRYPTION SUCCESSFUL"
        
    elif opt == 7:
        # RSA encryption
        s = input("Enter the string: ")

        # Ask whether to generate a new key pair or use an existing one
        choice = input("Do you want to generate a new key pair or use an existing one? (new/existing): ").strip().lower()

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

            print("New RSA key pair generated and saved.")
        elif choice == "existing":
            # Check if key files exist
            if not os.path.exists("public_rsa.pem"):
                print("Error: Public key file (public_rsa.pem) not found. Generate a new key pair first.")
                return "FILE NOT FOUND"

            # Load the public key from the existing file
            with open("public_rsa.pem", "rb") as f:
                public_key = f.read()

            key = RSA.import_key(public_key)
            print("Existing public key loaded.")
        else:
            print("Invalid choice. Please enter 'new' or 'existing'.")
            return "INVALID CHOICE"

        # Encrypt with public key
        rsa_cipher = PKCS1_OAEP.new(RSA.import_key(public_key))
        encryptedText = rsa_cipher.encrypt(s.encode('utf-8'))

        # Save ciphertext
        with open("ciphertext_rsa.txt", "wb") as f:
            f.write(encryptedText)

        print("Encryption complete. Ciphertext saved to 'ciphertext_rsa.txt'.")
        return "FILE CREATED"
    
    return cipher

def decrypt():
    print("Choose Decryption Algorithm")
    print("(1) Base64")
    print("(2) Caesar Cipher")
    print("(3) Monoalphabetic Substitution Cipher")
    print("(4) Vignere Cipher")
    print("(5) DES")
    print("(6) AES")
    print("(7) RSA")
    decipher = ""
    opt = int(input())
    
    if(opt == 1):
        cipher = input("Enter the string: ")
        cipher = cipher.rstrip('=')
        baseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        binary = ''.join(format(baseChars.index(char),'06b') for char in cipher)
        for i in range(0, len(binary), 8):
            byte = binary[i:i+8]
            if byte != '' :
                decipher += chr(int(byte,2))

    elif(opt == 2):
        cipher = input("Enter the string: ")
        print("Choose how to decrypt - ")
        print("(1) By shift")
        print("(2) All 26 combination")
        how = int(input())
        if(how == 1):
            print("Choose shift - ")
            print("(1) Left Shift")
            print("(2) Right Shift")
            shift = int(input())
            if(shift == 1):
                print("Enter Left Shift Value- ")
                shift_value = int(input())
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
            elif(shift == 2):
                shift_value = int(input("Enter the right shift value: "))
                decipher = ""
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
            else:
                print("Invalid shift direction.")
        else:
            print("Here are all 26 combinations of Caesar cipher decryption:")
            for shift_value in range(1, 27):
                deciphe = ""
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
                print(f"Shift {shift_value}: {deciphe}")

    elif(opt == 3):
        cipher = input("Enter the string: ")

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
        reverse = {v:k for k,v in key.items()}
        for char in cipher:
            if char in reverse:
                decipher += reverse[char]
            else:
                decipher += char

    elif(opt == 4):
        cipher = input("Enter the string: ")
        key = "NEITB"
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

   
    elif opt == 5:
        cipher = input("Enter the string: ")
        print("Enter the secret key (hex-encoded, 16 characters):")
        key_hex = input().strip()

        try:
            key = bytes.fromhex(key_hex) 
        except ValueError:
            print("Invalid key format. Please provide a valid 16-character hex key.")
            return None

    
        if len(key) != 8:
            print("Invalid key length. DES requires an 8-byte key.")
            return None

        try:
          
            
            if not isinstance(cipher, bytes):
                raise ValueError("Ciphertext must be in bytes format.")
        except (SyntaxError, ValueError):
            print("Invalid ciphertext format. Please provide a valid bytes object (e.g., b'...').")
            return None

        try:
            des_cipher = DES.new(key, DES.MODE_ECB)
            decrypted_padded = des_cipher.decrypt(cipher)
            decipher = unpad(decrypted_padded, DES.block_size).decode('utf-8')
        except (ValueError, KeyError) as e:
            print("Error during decryption:", e)
            return None
    elif opt == 6:
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
    elif opt == 7:
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

    return decipher

def hashh():
    print("Choose hashing algorithm")
    print("MD5 (1)")
    print("SHA-1 (2)")
    print("SHA-256 (3)")
    print("SHA 512 (4)")

    opt = int(input())
    s = input("Enter string: ").encode()
    if opt == 1:
        result = hashlib.md5(s).hexdigest()
        print("MD5 Hash:", result)
    elif opt == 2:
        result = hashlib.sha1(s).hexdigest()
        print("SHA-1 Hash:", result)
    elif opt == 3:
        result = hashlib.sha256(s).hexdigest()
        print("SHA-256 Hash:", result)
    elif opt == 4:
        result = hashlib.sha512(s).hexdigest()
        print("SHA-512 Hash:", result)
    else:
        print("Invalid option.")

print("Choose\n(1) Encryption\n(2) Decryption\n(3) Hashing")

opt = int(input())

if(opt == 1):
    ans = encrypt()
    print(ans)
elif(opt == 2):
    ans = decrypt()
    print(ans)
elif(opt == 3):
    hashh()
else:
    print("Not a valid option")
