import os, binascii
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP, AES

# Initialize key size
key_size = 2048

# Generate public and private keys for A 
A_private_key = RSA.generate(key_size)
f = open('A_private_key.pem','wb')
f.write(A_private_key.export_key('PEM'))
f.close()

A_public_key = A_private_key.publickey()
f = open('A_public_key.pem','wb')
f.write(A_public_key.export_key('PEM'))
f.close()

# Generate public and private keys for B
B_private_key = RSA.generate(key_size)
f = open('B_private_key.pem','wb')
f.write(B_private_key.export_key('PEM'))
f.close()

B_public_key = B_private_key.publickey()
f = open('B_public_key.pem','wb')
f.write(B_public_key.export_key('PEM'))
f.close()

print("Mechanism 1 => E(PUb, [N1 || IDa])")
# A generates a nonce and sends it, along with their identification, to B encrypted with B's public key with message authentication code
N1 = os.urandom(16)
print("N1: ", binascii.hexlify(N1))

IDa = b"Alice"
print("IDa: ", IDa)

AtoB_1 = N1 + IDa
print("AtoB_1: ", binascii.hexlify(AtoB_1))

cipher_B = PKCS1_OAEP.new(B_public_key)
encrypted_message = cipher_B.encrypt(AtoB_1)
print("1. encrypted_message : ", binascii.hexlify(encrypted_message))

# B receives the message and decrypts it with B's private key
cipher_B = PKCS1_OAEP.new(B_private_key)
decrypted_message = cipher_B.decrypt(encrypted_message)
print("1. decrypted_message: ", binascii.hexlify(decrypted_message))
print("----------------------------------------------------------------------------------")

print("Mechanism 2 => E(PUa, [N1 || N2])")
# B generates another nonce and sends it back to A encrypted with A's public key
N2 = os.urandom(16)
print("N2: ", binascii.hexlify(N2))

BtoA_2 = N1 + N2
print("BtoA_2: ", binascii.hexlify(BtoA_2))

PUa = RSA.importKey(open('A_public_key.pem').read())
cipher_A = PKCS1_OAEP.new(PUa)
encrypted_message = cipher_A.encrypt(BtoA_2)
print("2. encrypted_message: ", binascii.hexlify(encrypted_message))

# A receives the message and decrypts it with A's private key
PRa = RSA.importKey(open('A_private_key.pem').read())
cipher_A = PKCS1_OAEP.new(PRa)
decrypted_message = cipher_A.decrypt(encrypted_message)
print("2. decrypted_message: ", binascii.hexlify(decrypted_message))
print("----------------------------------------------------------------------------------")

print("Mechanism 3 => E(PUb, N2)")
# A sends N2 back to B encrypted with B's public key
AtoB_2 = N2
print("AtoB_2: ", binascii.hexlify(AtoB_2))

PUb = RSA.importKey(open('B_public_key.pem').read())
cipher_B = PKCS1_OAEP.new(PUb)
encrypted_message = cipher_B.encrypt(AtoB_2)
print("3. encrypted_message : ", binascii.hexlify(encrypted_message))

# B receives the message and decrypts it with B's private key
cipher_B = PKCS1_OAEP.new(B_private_key)
decrypted_message = cipher_B.decrypt(encrypted_message)
print("3. decrypted_message: ", binascii.hexlify(decrypted_message))
print("----------------------------------------------------------------------------------")

print("Mechanism 4 => E (PUb, E(PRa, Ks))")
# A generates a secret key and encrypts it with A's private key and B's public key
Ks = os.urandom(16)
AtoB_3 = Ks
print("4. AtoB_3: ", binascii.hexlify(AtoB_3))
PRa = RSA.importKey(open('A_private_key.pem').read())
cipher_A = PKCS1_OAEP.new(PRa)
encrypted_Ks = cipher_A.encrypt(AtoB_3)

PUb = RSA.importKey(open('B_public_key.pem').read())
cipher_B = PKCS1_OAEP.new(PUb)

# Split the message into chunks
chunk_size = 256
chunks = [Ks[i:i+chunk_size] for i in range(0, len(Ks), chunk_size)]

# Encrypt each chunk and concatenate the encrypted chunks
encrypted_chunks = []
for chunk in chunks:
    encrypted_chunks.append(cipher_B.encrypt(chunk))
encrypted_message = b''.join(encrypted_chunks)
print("4. encrypted_message: ", binascii.hexlify(encrypted_message))

# B receives the message and decrypts it with B's private key and A's public key
cipher_B = PKCS1_OAEP.new(B_private_key)
decrypted_message = cipher_B.decrypt(encrypted_message)
print("4. decrypted_message: ", binascii.hexlify(decrypted_message))
print("----------------------------------------------------------------------------------")