# Cloud Security Posture Dashboard
A sleek, real-time web application to visualize AWS cloud security findings and monitor your cloud environment's security posture.

## Tech Stack
- Python
- Flask
- boto3
- HTML
- CSS
- JavaScript
- Chart.js

## Screenshots

![Dashboard Overview](screenshots/dashboard-overview.png)
*The main dashboard view showing summary cards and severity distribution.*

![Findings Table](screenshots/findings-table.png)
*Detailed security findings table with dynamic filtering by severity and category.*

## Installation

1. Clone the repo:
   ```bash
   git clone <repo-url>
   ```
2. Navigate into the project and create a virtual environment:
   ```bash
   python -m venv venv
   
   # Activate it on Windows:
   venv\Scripts\activate
   
   # Activate it on macOS/Linux:
   source venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Add AWS credentials (e.g., via `aws configure`) or skip this step to run in demo mode using sample data.
5. Run the Flask server:
   ```bash
   python backend/app.py
   ```
6. Open `http://localhost:5000` in your browser (The Flask application automatically serves the frontend dashboard).
