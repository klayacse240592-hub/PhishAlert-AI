# 🛡️ PhishGuard — AI/ML Based Phishing Detection & Prevention System

> B.Tech Project | AI/ML Based Phishing Detection and Prevention System

---

## 📋 Project Overview

PhishGuard is a full-stack web application that uses Machine Learning heuristics and AI-powered analysis to detect phishing URLs and emails in real time.

**Features:**
- 🔐 User authentication (Register/Login with JWT)
- 🔍 URL phishing analysis with 12+ detection checks
- 📧 Email phishing analysis with 8+ detection checks  
- 📊 Dashboard with charts and statistics
- 📋 Full scan history with filters
- 🧠 Threat Intelligence page
- 💾 SQLite database (no setup needed)
- 📱 Responsive design

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| Backend | Python 3, Flask REST API |
| Database | SQLite (via SQLAlchemy) |
| Auth | JWT (JSON Web Tokens) |
| ML Engine | Rule-based scoring + heuristics |

---

## 🚀 How to Run (Step by Step)

### Prerequisites
- Python 3.8 or higher installed
- pip (Python package manager)

### Step 1: Download/Extract the project
Extract the zip file to a folder, e.g. `C:\Users\YourName\PhishGuard`

### Step 2: Start the Backend

**On Windows:**
```
Double-click: start_backend.bat
```

**On Mac/Linux:**
```bash
chmod +x start_backend.sh
./start_backend.sh
```

**Or manually:**
```bash
cd backend
pip install -r requirements.txt
python app.py
```

You should see:
```
✅ Database initialized
* Running on http://127.0.0.1:5000
```

### Step 3: Open the Frontend
Open `frontend/index.html` in your browser (Chrome/Firefox/Edge).

### Step 4: Register & Use
1. Click "Create one" to register a new account
2. Fill in your name, email, and password
3. Start scanning URLs and emails!

---

## 📁 Project Structure

```
PhishGuard/
├── backend/
│   ├── app.py          # Flask API server (routes)
│   ├── models.py       # Database models (User, ScanResult)
│   ├── analyzer.py     # ML/AI phishing detection engine
│   └── requirements.txt
├── frontend/
│   └── index.html      # Complete frontend (single file)
├── start_backend.bat   # Windows quick-start
├── start_backend.sh    # Mac/Linux quick-start
└── README.md
```

---

## 🔬 How the ML Detection Works

The analyzer uses a **weighted heuristic scoring system** (0–100 risk score):

### URL Analysis Checks:
| Check | Risk Added |
|-------|-----------|
| HTTP instead of HTTPS | +15 |
| IP address as domain | +30 |
| Suspicious TLD (.xyz, .tk, etc.) | +20 |
| Brand impersonation | +25 |
| URL shortener used | +20 |
| @ symbol in URL | +25 |
| Suspicious keywords | +7–15 |
| Excessive subdomains | +15 |
| Very long URL | +10 |
| Trusted domain bonus | -25 |

### Email Analysis Checks:
| Check | Risk Added |
|-------|-----------|
| Phishing keywords (3+) | +35 |
| Urgency language | +10–20 |
| Credential harvesting | +20 |
| Suspicious URLs embedded | +25 |
| Generic greeting | +10 |
| Spelling errors | +10 |
| Threatening language | +15 |
| Excessive CAPS/! | +10–15 |

### Verdict Thresholds:
- **SAFE**: 0–29
- **SUSPICIOUS**: 30–59  
- **PHISHING**: 60–100

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
|--------|---------|-------------|
| POST | /api/register | Create account |
| POST | /api/login | Login |
| GET | /api/me | Get current user |
| POST | /api/scan/url | Analyze URL |
| POST | /api/scan/email | Analyze email |
| GET | /api/dashboard | Dashboard stats |
| GET | /api/history | All scan history |
| GET | /api/health | Server health check |

---

## 🎓 Project Information

- **Title:** AI/ML Based Phishing Detection and Prevention System
- **Tech:** Python, Flask, SQLite, HTML/CSS/JS, JWT, ML Heuristics
- **Purpose:** B.Tech Curriculum Project

---

## 🔮 Future Enhancements (for viva)
1. Integration with VirusTotal API for real-time threat intelligence
2. Browser extension for passive URL monitoring
3. Deep learning model (LSTM/BERT) for better email classification
4. Email header analysis
5. Screenshot capture and visual analysis of phishing sites
6. Bulk CSV upload for batch scanning
