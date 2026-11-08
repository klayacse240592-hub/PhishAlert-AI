# 🛡️ PhishGuard – AI-Powered Multi-Layer Phishing Detection & Prevention Platform

> B.Tech Project | AI/ML Based Phishing Detection and Prevention System

---

## 📋 Project Overview

PhishGuard is a full-stack web application that uses machine learning heuristics and AI-powered analysis to detect phishing URLs and emails.

### Features
- 🔐 User authentication (Register/Login with JWT)
- 🔍 URL phishing analysis with 12+ detection checks
- 📧 Email phishing analysis with 8+ detection checks
- 📊 Dashboard with charts and statistics
- 📋 Full scan history with filters
- 🧠 Threat Intelligence page
- 💾 SQLite database
- 🔊 Automatic voice output for scan verdicts
- 📱 Responsive design
- 🐳 Docker-based deployment
- 🧪 Selenium automated testing

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Frontend | HTML5, CSS3, JavaScript |
| Backend | Python 3, Flask REST API |
| Database | SQLite, SQLAlchemy |
| Authentication | JWT |
| Detection Engine | Rule-based scoring and heuristics |
| Containerization | Docker, Docker Compose |
| Web Server | Nginx |
| Automation Testing | Selenium WebDriver |
| Browser | Google Chrome |

---

## 🚀 How to Run the Project

### Prerequisites
- Python installed
- Docker Desktop installed
- Google Chrome browser
- Selenium installed for automated testing

### Method 1: Run Using Docker (Recommended)

**Step 1: Open the project directory**

Open Command Prompt and navigate to the project folder:

```cmd
cd /d "C:\Users\YourName\Downloads\PhishAlert-AI\PhishAlert-AI"
```

**Step 2: Build and start containers**

```cmd
docker compose up -d --build
```

**Step 3: Check running containers**

```cmd
docker compose ps
```

**Step 4: Open the application**

Open Chrome and visit:

```text
http://localhost:8080
```

The frontend is served through Nginx, while the Flask backend runs inside a Docker container.

**Step 5: Stop the containers**

```cmd
docker compose down
```

To start the already-built containers again:

```cmd
docker compose up -d
```

---

### Method 2: Run Without Docker

**Start the backend:**

```cmd
cd backend
pip install -r requirements.txt
python app.py
```

Then open the frontend using the appropriate local web server configuration.

---

## 🧪 Selenium Automation Testing

Selenium WebDriver is used to automate browser testing of the PhishGuard application.

### Step 1: Install Selenium

```cmd
python -m pip install selenium
```

### Step 2: Run the Docker application

```cmd
docker compose up -d
```

### Step 3: Execute the Selenium test

From the main project directory:

```cmd
python test_selenium.py
```

### Automated test cases

1. Verify that the PhishGuard website opens.
2. Verify the website title.
3. Perform manual login.
4. Verify dashboard access.
5. Navigate to the Detection page.
6. Test URL scanning.
7. Test email scanning.
8. Verify that scan results are displayed.
9. Check browser speech synthesis support.

### Expected Result

```text
TEST 1: Opening PhishGuard
PASSED: Website opened successfully

TEST 2: Login
PASSED: Dashboard loaded

TEST 4: Detection navigation
PASSED: Detection page opened

TEST 5: URL scanning
PASSED: URL scan produced a result

TEST 7: Email scanning
PASSED: Email scan produced a result

ALL COMPLETED TESTS PASSED!
```

*Note: Actual output may vary. The voice check verifies browser speech synthesis support; it does not independently verify audible playback.*

---

## 📁 Project Structure

```text
PhishAlert-AI/
│
├── backend/
│   ├── app.py
│   ├── models.py
│   ├── analyzer.py
│   └── requirements.txt
│
├── frontend/
│   └── index.html
│
├── extension/
│
├── Dockerfile
├── docker-compose.yml
├── test_selenium.py
└── README.md
```

---

## 🔬 How the ML Detection Works

The analyzer uses a weighted heuristic scoring system (0–100 risk score).

### URL Analysis Checks

| Check | Risk Added |
|---|---:|
| HTTP instead of HTTPS | +15 |
| IP address as domain | +30 |
| Suspicious TLD | +20 |
| Brand impersonation | +25 |
| URL shortener | +20 |
| @ symbol in URL | +25 |
| Suspicious keywords | +7–15 |
| Excessive subdomains | +15 |
| Very long URL | +10 |
| Trusted domain bonus | -25 |

### Email Analysis Checks

| Check | Risk Added |
|---|---:|
| Phishing keywords | +35 |
| Urgency language | +10–20 |
| Credential harvesting | +20 |
| Suspicious URLs | +25 |
| Generic greeting | +10 |
| Spelling errors | +10 |
| Threatening language | +15 |
| Excessive CAPS/! | +10–15 |

### Verdict Thresholds

- **SAFE:** 0–29
- **SUSPICIOUS:** 30–59
- **PHISHING:** 60–100

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | /api/register | Create account |
| POST | /api/login | Login |
| GET | /api/me | Get current user |
| POST | /api/scan/url | Analyze URL |
| POST | /api/scan/email | Analyze email |
| GET | /api/dashboard | Dashboard statistics |
| GET | /api/history | Scan history |
| GET | /api/health | Server health check |

---

## 🐳 Docker Deployment

The project uses Docker Compose to run the frontend and backend as separate services.

| Service | Technology | Port |
|---|---|---|
| Frontend | Nginx Alpine | 8080 |
| Backend | Python Flask | 5000 |
| Database | SQLite | Persistent Docker volume |

### Docker Commands

Build and start:

```cmd
docker compose up -d --build
```

View running containers:

```cmd
docker compose ps
```

View logs:

```cmd
docker compose logs
```

Stop containers:

```cmd
docker compose down
```

---

## 🎓 Project Information

- **Title:** AI/ML Based Phishing Detection and Prevention System
- **Technology:** Python, Flask, SQLite, HTML, CSS, JavaScript, JWT
- **Containerization:** Docker and Docker Compose
- **Automation Testing:** Selenium WebDriver
- **Purpose:** B.Tech Curriculum Project

---

## 🔮 Future Enhancements

1. Integration with VirusTotal API for real-time threat intelligence.
2. Browser extension for passive URL monitoring.
3. Deep learning models (LSTM/BERT) for better email classification.
4. Email header analysis.
5. Screenshot capture and visual analysis of phishing websites.
6. Bulk CSV upload for batch scanning.
