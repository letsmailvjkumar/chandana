from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import os
from dotenv import load_dotenv

app = Flask(__name__)
CORS(app)
API_KEY = os.getenv('VIRUSTOTAL_API_KEY')

@app.route('/detect', methods=['POST'])
def detect_threat():
    data = request.get_json()
    ip_address = data.get('ip')

    if not ip_address:
        return jsonify({"error": "IP address is required"}), 400

    # VirusTotal API request
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    
    # Use headers to pass the API key
    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY
    }

    response = requests.get(url, headers=headers)

    # Log the response status and data for debugging
    print(f"VirusTotal response status: {response.status_code}")
    print(f"VirusTotal response body: {response.text}")

    # Check if the request was successful
    if response.status_code == 200:
        result = response.json()
        detected_malicious = result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
        
        if detected_malicious > 0:
            return jsonify({
                "message": "Threat Detected",
                "details": result
            }), 200
        else:
            return jsonify({"message": "No Threat Detected", "details": result}), 200
    else:
        return jsonify({"error": "Invalid IP address or no data found", "details": response.json()}), 404

if __name__ == '__main__':
    app.run(debug=True)
