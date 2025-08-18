# Web Vulnerability Scanner

## 📖 Project Overview
This project is a **Flask-based Web Vulnerability Scanner** designed to detect common web security issues such as:
- Cross-Site Scripting (XSS)
- SQL Injection
- Open Redirects
- Insecure Headers

It provides a simple **web interface** to input target URLs and view scan results.

---

## 🚀 Features
- User-friendly web interface built with **Flask**  
- Detects common vulnerabilities  
- Generates basic scan reports  
- Lightweight and easy to run locally  

---

## 🛠️ Installation & Setup

### Prerequisites
- Python 3.x  
- Flask library  

### Steps
```bash
# Clone the repository
git clone https://github.com/your-username/web-vulnerability-scanner.git
cd web-vulnerability-scanner

# Create virtual environment (optional but recommended)
python -m venv .venv
.\.venv\Scripts\activate   # for Windows
source .venv/bin/activate  # for Linux/Mac

# Install dependencies
pip install flask
