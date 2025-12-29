````md
# Email Phishing Classifier

A web-based **Email Phishing Detection System** built with **Flask** and **Machine Learning**.  
Users can upload **.eml** email files, and the app classifies them as **Phishing/Spam** or **Legitimate**, along with a **confidence score**.

This project was developed as part of the **Digital Forensics Lab**.

---

## Project Structure

Key files and folders in this repository:

- `app.py` — Main Flask application
- `train_model.py` — Model training script
- `model.joblib` — Trained Logistic Regression model
- `database.db` — SQLite database (auto-created on first run)
- `requirements.txt` — Python dependencies
- `templates/` — HTML templates for the web interface
- `static/` — CSS and JavaScript assets
- `uploads/` — Uploaded email files
- `README.md` — Project documentation

---

## Features

- User registration and login
- Upload emails in `.eml` format
- Phishing detection with confidence score
- Per-user email history
- Dashboard with phishing vs. legitimate email statistics
- Secure password hashing
- SQLite-based storage

---

## Detection Approach

Classification is based on a **hybrid approach**: Machine Learning + Rule-Based security checks.  
The final result combines the ML prediction with rule-based signals to improve robustness.

### Machine Learning Components

- Full email text (subject + body)
- URL count / presence signals
- TF-IDF vectorization
- Logistic Regression classifier

### Rule-Based Security Checks

- URL presence in the email body
- Suspicious phishing keywords (e.g., `urgent`, `verify`, `bank`, `login`)
- JavaScript or `<script>` injection detection
- Base64-encoded content detection
- Suspicious attachment extensions (e.g., `.exe`, `.zip`, `.js`)
- Punycode domain detection (`xn--`)
- SPF failure detection
- DKIM failure detection

---

## Technologies Used

- Python
- Flask
- SQLite
- scikit-learn
- pandas
- joblib
- HTML / CSS / JavaScript

---

## Getting Started

### 1) Install Dependencies

```bash
pip install -r requirements.txt
````

### 2) (Optional) Train the Model

```bash
python train_model.py
```

### 3) Run the Flask App

```bash
python app.py
```

### 4) Open in Your Browser

```text
http://127.0.0.1:5000
```

---

## Usage

1. Register a new user account
2. Log in to the system
3. Upload a `.eml` email file
4. View the classification result and confidence score
5. Review email history and dashboard statistics

---

## Dataset

**CEAS_08 Dataset**

* Contains labeled phishing and legitimate emails
* Used for training the Logistic Regression model

---

## Future Improvements

* Real-time email scanning
* Deep learning models (LSTM / BERT)
* Browser extension support
* Email server integration (IMAP)
* Advanced email header analysis

