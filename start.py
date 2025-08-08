#!/usr/bin/env python3
"""
Startup script for Password Generator Application
Checks dependencies and starts the Flask server
"""

import sys
import os
import subprocess
import importlib.util

def check_dependencies():
    """Check if all required dependencies are installed"""
    required_packages = [
        'flask',
        'flask_cors',
        'scikit-learn',
        'numpy',
        'pandas',
        'openai',
        'zxcvbn',
        'matplotlib',
        'cryptography',
        'requests'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        if importlib.util.find_spec(package) is None:
            missing_packages.append(package)
    
    if missing_packages:
        print("❌ Missing dependencies:")
        for package in missing_packages:
            print(f"   - {package}")
        print("\nInstalling missing dependencies...")
        
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing_packages)
            print("✅ Dependencies installed successfully!")
        except subprocess.CalledProcessError:
            print("❌ Failed to install dependencies. Please run:")
            print("   pip install -r requirements.txt")
            return False
    
    return True

def check_data_files():
    """Check if required data files exist"""
    required_files = [
        "data/balanced_passwords.csv",
        "data/rockyou.txt",
        "models/password_classifier.joblib"
    ]
    
    missing_files = []
    
    for file_path in required_files:
        if not os.path.exists(file_path):
            missing_files.append(file_path)
    
    if missing_files:
        print("⚠️ Missing data files:")
        for file_path in missing_files:
            print(f"   - {file_path}")
        
        print("\nGenerating missing data files...")
        
        # Generate strong passwords if missing
        if not os.path.exists("data/strong_passwords.txt"):
            print("Generating strong passwords...")
            subprocess.run([sys.executable, "strong_generated_password.py"])
        
        # Generate balanced dataset if missing
        if not os.path.exists("data/balanced_passwords.csv"):
            print("Generating balanced dataset...")
            subprocess.run([sys.executable, "balanced_password.py"])
        
        # Train model if missing
        if not os.path.exists("models/password_classifier.joblib"):
            print("Training password classifier...")
            subprocess.run([sys.executable, "train_model.py"])
    
    return True

def main():
    """Main startup function"""
    print("🚀 Starting Password Generator Application")
    print("=" * 50)
    
    # Check dependencies
    print("Checking dependencies...")
    if not check_dependencies():
        sys.exit(1)
    
    # Check data files
    print("Checking data files...")
    if not check_data_files():
        print("⚠️ Some data files are missing, but the application will still run")
    
    print("✅ All checks passed!")
    print("Starting Flask application...")
    print("=" * 50)
    print("🌐 Application will be available at: http://localhost:5000")
    print("📊 API endpoints: http://localhost:5000/api/")
    print("=" * 50)
    print("Press Ctrl+C to stop the server")
    print("=" * 50)
    
    # Start the Flask application
    try:
        from app import app
        app.run(debug=True, host="0.0.0.0", port=5000)
    except KeyboardInterrupt:
        print("\n👋 Application stopped by user")
    except Exception as e:
        print(f"❌ Error starting application: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 