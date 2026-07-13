from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
import os
import json
from botocore.exceptions import NoCredentialsError

# Import our custom AWS security checks
from security_checks import run_all_checks

# Initialize the Flask application
# We set static_folder and static_url_path to serve our frontend files easily
app = Flask(__name__, static_folder="../frontend", static_url_path="/")
CORS(app)  # Enable Cross-Origin Resource Sharing if needed for local dev

def get_demo_findings():
    """Load mock data from the sample JSON file."""
    data_path = os.path.join(os.path.dirname(__file__), 'data', 'sample_findings.json')
    try:
        with open(data_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return []

@app.route("/")
def index():
    """Serve the main index.html dashboard."""
    return send_from_directory(app.static_folder, "index.html")

@app.route("/api/findings")
def api_findings():
    """
    REST API Endpoint to fetch security findings.
    Tries to pull live AWS data. If no credentials exist, returns demo data.
    """
    try:
        # Attempt to run live AWS checks
        findings = run_all_checks()
        return jsonify({
            "mode": "live",
            "findings": findings
        })
    except NoCredentialsError:
        # Fallback to demo mode if AWS credentials are not configured
        demo_findings = get_demo_findings()
        return jsonify({
            "mode": "demo",
            "message": "AWS credentials not found. Showing demo data.",
            "findings": demo_findings
        })
    except Exception as e:
        # Catch-all for other errors (e.g. permission issues)
        print(f"Error fetching live data: {e}")
        return jsonify({
            "mode": "error",
            "message": "Error fetching live data. Showing demo data.",
            "findings": get_demo_findings()
        }), 500

if __name__ == "__main__":
    # Run the server in debug mode on port 5000
    app.run(debug=True, host="0.0.0.0", port=5000)
