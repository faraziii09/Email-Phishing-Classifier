Email Phishing Classifier Web App

This project is a Flask-based web application that allows users to upload emails and automatically detect phishing or spam content using a machine learning model (Logistic Regression). It includes modern phishing detection features such as URL analysis, suspicious attachments, script checks, and header verification.

Features

User Authentication: Registration and login system with hashed passwords.

Email Upload & Classification: Users can upload .eml files to classify as Legitimate or Phishing/Spam.

Dashboard & History: View past uploaded emails, classification results, and statistics.

Modern Features for Detection:

Detect URLs and suspicious patterns (e.g., punycode, scripts, base64).

Check attachments for risky extensions.

Analyze email headers for SPF and DKIM failures.

Secure Storage: Uploaded emails are stored with unique filenames; sensitive data is stored in a SQLite database (local only).

Installation

Clone the repository

git clone <your-repo-url>
cd <repo-folder>


Create a virtual environment and install dependencies

python -m venv venv
source venv/bin/activate   # Linux/Mac
venv\Scripts\activate      # Windows
pip install -r requirements.txt


Prepare required files

Model: model.joblib – Pre-trained Logistic Regression model.

Database: database.db will be auto-created on first run.

Uploads Folder: Ensure an uploads/ folder exists (app will create it automatically).

⚠️ The original training CSV is not included due to size constraints. You can train your own model using train_model.py and your dataset.

Run the application

python app.py


Visit http://127.0.0.1:5000 to access the app.

New users should register first, then login to upload emails.
