from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import traceback
from utils.visualization import generate_strength_graph
from utils.hashcat import simulate_cracking
from models.genai import get_password_suggestions

app = Flask(__name__)
CORS(app)

# Root route to serve the main page
@app.route("/", methods=["GET"])
def home():
    return render_template("index.html")

# About page route
@app.route("/about", methods=["GET"])
def about():
    return render_template("about.html")

# API route to check server status
@app.route("/api/status", methods=["GET"])
def api_status():
    return jsonify({"message": "Password Generator API is running", "status": "healthy"}), 200

# API route to analyze password strength
@app.route("/api/analyze", methods=["POST"])
def analyze_password():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400
            
        password = data.get("password", "")
        if not password:
            return jsonify({"error": "Password is required"}), 400

        strength_data = generate_strength_graph(password)
        cracking_data = simulate_cracking(password)
        
        # Get password suggestions
        security_level = data.get("security_level", 3)
        suggestions = get_password_suggestions(password, security_level)

        # Return the data structure that the JavaScript expects
        return jsonify({
            "entropy": strength_data["entropy_data"],
            "graph_data": {
                "strength_meter": strength_data["strength_meter"],
                "common_passwords": strength_data["common_passwords"],
                "crack_time_data": cracking_data,
                "entropy_data": strength_data["entropy_data"]  # Add this for JavaScript access
            },
            "suggestions": suggestions
        })
    except Exception as e:
        print(f"Error in analyze_password: {str(e)}")
        print(traceback.format_exc())
        return jsonify({"error": "Internal server error"}), 500

# API route to get password suggestions
@app.route("/api/suggest", methods=["POST"])
def suggest_password():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400
            
        password = data.get("password", "")
        security_level = data.get("security_level", 3)

        if not password:
            return jsonify({"error": "Password is required"}), 400

        suggestions = get_password_suggestions(password, security_level)
        return jsonify(suggestions)
    except Exception as e:
        print(f"Error in suggest_password: {str(e)}")
        print(traceback.format_exc())
        return jsonify({"error": "Internal server error"}), 500

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
