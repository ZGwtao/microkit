from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# Generate Ed25519 key pair
private_key = ed25519.Ed25519PrivateKey.generate()
public_key = private_key.public_key()

# Serialize private key to PEM
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# Serialize public key to raw bytes
public_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

# Save keys to files
with open("ed25519_private_key.pem", "wb") as f:
    f.write(private_pem)

with open("ed25519_public_key.bin", "wb") as f:
    f.write(public_bytes)
    print("Length of public key:", len(public_bytes))

print("Ed25519 key pair generated.")
