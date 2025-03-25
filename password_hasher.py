import hashlib

def hash_password(password: str) -> str:
    # Hashes a password using SHA-256
    hashed = hashlib.sha256(password.encode()).hexdigest()
    return hashed

if __name__ == "__main__":
    password = input("Enter a password to hash: ")
    hashed_password = hash_password(password)
    print(f"Hashed Password: {hashed_password}")

def verify_password(input_password: str, stored_hash: str) -> bool:
    """Verifies if the input password matches the stored hash."""
    return hash_password(input_password) == stored_hash


check_password = input("Re-enter your password for verification: ")
if verify_password(check_password, hashed_password):
    print("✅ Password Verified!")
else:
    print("❌ Incorrect Password!")
