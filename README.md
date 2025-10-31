# 💰 SecureFinTech Pro  
### A Flask-Based Secure Financial Web Application  

---

## 🧩 Overview

**SecureFinTech Pro** is a Flask-based financial web application built with advanced security controls.  
It provides a secure environment for managing user profiles, financial transactions, and document uploads while enforcing strict authentication, encryption, and audit logging standards.  

The application demonstrates real-world FinTech security practices, including password hashing, AES-256 data encryption, session management, and validation against common web vulnerabilities such as SQL Injection, XSS, and CSRF.

---

## ⚙️ Features

- 🔐 **User Authentication:** Secure registration and login using bcrypt password hashing  
- 🧾 **Transaction Management:** Add, view, and manage deposits and withdrawals with encrypted notes  
- 🧠 **Profile Management:** Update personal info with validation and encrypted SSN storage  
- 🧱 **File Upload Security:** Only safe file types allowed; size and name validation enforced  
- 🕵️ **Audit Logging:** Tracks all major user actions with timestamp, IP, and event details  
- ⏳ **Session Timeout:** Automatic logout after 30 minutes of inactivity  
- 🧰 **Error Handling:** Generic error pages to prevent data leakage  
- 🧮 **Data Encryption:** AES-256 encryption (Fernet) for sensitive information  
- 🖥️ **Modern UI:** Responsive HTML/CSS templates with password strength indicators and validation feedback  

---

## 🧠 Technology Stack

| Layer | Technology |
|--------|-------------|
| **Backend** | Flask (Python) |
| **Frontend** | HTML5, CSS3, FontAwesome |
| **Database** | SQLite3 |
| **Security** | bcrypt, cryptography (Fernet), Werkzeug |
| **Logging** | Python `logging` module |
| **Encryption** | AES-256 symmetric encryption |

---

## 🚀 Getting Started

### **1️⃣ Prerequisites**
Make sure Python 3.10+ is installed.

```bash
pip install flask bcrypt cryptography werkzeug
