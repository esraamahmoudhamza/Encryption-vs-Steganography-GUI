# 🔐 Encryption vs Steganography GUI 

This is a Python-based GUI application that demonstrates the difference between **Encryption** and **Steganography**, built by a student of AI & Cybersecurity as part of a final project.

## 📌 Features

- 🔑 **Fernet Encryption** (AES-128 based symmetric encryption)
- 🖼️ **LSB Steganography** to hide and extract text inside images
- 🎨 Beautiful, dark-themed GUI using **CustomTkinter**
- 🧠 Educational and practical: shows both techniques side-by-side

## 🛠️ Technologies Used

- `Python 3.x`
- `CustomTkinter`
- `cryptography (Fernet)`
- `PIL (Pillow)`

## 💡 How it Works

### 🔒 Encryption Panel:
- Select an image
- Generate or paste a Fernet key
- Encrypt and decrypt image data using that key

### 🕵️‍♀️ Steganography Panel:
- Select an image
- Type your secret message
- Hide it inside the image using LSB
- Extract it anytime!

## 📂 Installation

```bash
pip install customtkinter cryptography pillow
python app.py
