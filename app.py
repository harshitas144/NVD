from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename
import os
from nmap_parser import parse_nmap_xml
from nvd_lookup import search_cves
from llm_recommender import recommend_patch

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'xml'}

# Ensure upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part in request"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    if not allowed_file(file.filename):
        return jsonify({"error": "Invalid file type, XML required"}), 400

    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)

    try:
        # Parse Nmap XML
        services = parse_nmap_xml(file_path)
        if not services:
            return jsonify({"error": "No open services found in Nmap scan"}), 404

        results = []
        for service in services:
            product = service['product']
            version = service['version']
            if product == 'unknown' or version == 'unknown':
                continue  # Skip if no product/version info

            # Search CVEs
            cves = search_cves(product, version)
            if not cves:
                continue  # Skip if no CVEs found

            # Generate recommendations
            system_info = f"Service: {service['service']} on {service['ip']}:{service['port']}/{service['protocol']}"
            recommendation = recommend_patch(cves, system_info)

            results.append({
                "service": service,
                "cves": cves,
                "recommendation": recommendation
            })

        # Clean up uploaded file
        os.remove(file_path)

        return jsonify({"results": results})
    except Exception as e:
        return jsonify({"error": f"Processing error: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True)
