import hashlib
import secrets

def hash_password(password: str) -> str:
    # Hashes a password using SHA-256
    salt = secrets.token_hex(16) # Generate a 16 byte random salt
    hashed = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}:{hashed}" # Store salt and hash together

if __name__ == "__main__":
    password = input("Enter a password to hash: ")
    stored_hash = hash_password(password)
    print(f"Store Hash (Salt:Hash): {stored_hash}")

def verify_password(input_password: str, stored_hash: str) -> bool:
    """Verifies if the input password matches the stored hash."""
    salt,original_hash = stored_hash.split(":")
    hashed_attempt = hashlib.sha256((salt + input_password).encode()).hexdigest()
    return hashed_attempt == original_hash


check_password = input("Re-enter your password for verification: ")
if verify_password(check_password, stored_hash):
    print("✅ Password Verified!")
else:
    print("❌ Incorrect Password!")
