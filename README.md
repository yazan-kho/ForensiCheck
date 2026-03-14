# 🔬 ForensiCheck

**ForensiCheck** is a Digital Forensics web application that analyzes the internal structure of files to detect hidden data, extension spoofing, and malicious manipulation. By examining binary magic bytes (signatures) and calculating Shannon entropy, it determines the true nature of a file regardless of its outer extension.

## ✨ Features

- **Magic Byte Signature Detection:** Inspects the deep binary structure of a file to determine its true format, bypassing simple extension changes.
- **Extension Integrity Check:** Compares the file's declared extension to its actual binary structure and flags any mismatches.
- **Shannon Entropy Analysis:** Calculates the randomness of a file's data (0-8 bits/byte) to identify if it is compressed, encrypted, or hiding malicious payloads.
- **Deep ZIP Container Inspection:** Distinguishes between formats that share the generic ZIP signature (like DOCX, JAR, APK, etc.) by scanning internal directory structures.
- **Sleek, Dynamic UI:** Provides a modern, responsive, and intuitive interface with drag-and-drop file upload capabilities.

## 🛠️ Built With

- **Backend:** Python, Flask, Werkzeug, Gunicorn
- **Frontend:** HTML5, CSS3, Vanilla JavaScript

## 💻 Running Locally

### Prerequisites
- Python 3.8+ 

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yazan-kho/ForensiCheck.git
   cd ForensiCheck
   ```

2. **(Optional but recommended) Create a virtual environment:**
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application:**
   ```bash
   python app.py
   ```
   *The server will start on `http://127.0.0.1:5000`*

## 📖 How to Use Locally

1. Open the web interface.
2. Drag and drop any file (up to 256 MB) into the upload zone, or click to browse files.
3. Click **Analyze File**.
4. View the detailed forensic verdict, signature matches, and entropy metrics. 

## 🌐 How to Start Online

1. Go to [ForensiCheck](https://forensicheck.onrender.com/)
2. Drag and drop any file (up to 256 MB) into the upload zone, or click to browse files.
3. Click **Analyze File**.
4. View the detailed forensic verdict, signature matches, and entropy metrics. 

## 👨‍💻 Author
**Yazan Khouli**
