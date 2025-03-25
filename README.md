# 🔐 Secure Password Hasher in Python

A simple password hashing and verification system using **SHA-256 with salting**. This project ensures password security by adding a random salt to each password before hashing, preventing rainbow table attacks.

## 🚀 Features  
- Hashes passwords using **SHA-256**  
- Generates a **random salt** for each password  
- Verifies passwords securely  
- Simple and easy-to-understand implementation  

## 📌 How It Works  
1. **Hash a Password** – Generates a unique hash for each password.  
2. **Salted Hashing** – A random salt ensures no two hashes are the same.  
3. **Verification** – Checks if an input password matches the stored hash.  

## 🛠 Installation & Usage  

### 1️⃣ Clone the Repository
```sh
git clone https://github.com/luka-babetzki/secure-password-hasher.git
cd secure-password-hasher
```
### 2️⃣ Run the Script
```sh
python password_hasher_salting.py
```
### 3️⃣ Register & Verify a Password
- Enter a password to hash.
- Re-enter the password to verify if it matches the stored hash.

### 📝 Example Usage
- Enter a password to hash: mysecurepassword
- Hashed Password: a1b2c3d4e5f6...
- Re-enter your password for verification: mysecurepassword
✅ Password Verified!
### 🔒 Why Use Salting?
Without salting, two identical passwords will generate the same hash. By adding a random salt, we ensure each hash is unique, making it much harder for attackers to crack passwords using rainbow tables.

## 🎯 Next Steps
1. Implement password storage in a secure database.
2. Use Argon2 for even stronger password hashing.
3. Build a simple authentication system.

## 👨‍💻 Want to reach out?
Feel free to message me on LinkedIn to suggest improvements! 🚀
