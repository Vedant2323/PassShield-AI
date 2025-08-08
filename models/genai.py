import os
import re
import random
import string
import requests
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Constants for password generation
LOWERCASE = string.ascii_lowercase
UPPERCASE = string.ascii_uppercase
DIGITS = string.digits
SPECIAL = "!@#$%^&*()-_=+[]{}|;:,.<>?"

def get_openai_suggestion(password, security_level=3):
    """
    Get password improvement suggestions using OpenAI's API.
    
    Args:
        password (str): The password to analyze
        security_level (int): The desired security level (1-5)
        
    Returns:
        dict: A dictionary with suggestions and feedback
    """
    api_key = os.environ.get("OPENAI_API_KEY")
    
    if not api_key:
        return {
            "error": "OpenAI API key not found. Please set the OPENAI_API_KEY environment variable."
        }
    
    # Sanitize password for API call (don't send actual password)
    sanitized_info = {
        "length": len(password),
        "has_lowercase": bool(re.search(r'[a-z]', password)),
        "has_uppercase": bool(re.search(r'[A-Z]', password)),
        "has_digits": bool(re.search(r'\d', password)),
        "has_special": bool(re.search(r'[^a-zA-Z0-9]', password)),
        "patterns": detect_patterns(password),
        "security_level": security_level
    }
    
    try:
        # Construct the API request
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        }
        
        # Adjust the prompt based on security level
        security_description = get_security_level_description(security_level)
        
        payload = {
            "model": "gpt-3.5-turbo",
            "messages": [
                {
                    "role": "system",
                    "content": f"You are a password security expert. You'll be given characteristics of a password (not the actual password) and need to provide advice on improving it and suggest three stronger alternatives. The user has requested a {security_description} security level."
                },
                {
                    "role": "user",
                    "content": f"Password characteristics: {sanitized_info}. Provide advice on why this password might be weak and suggest three stronger alternatives that match the requested security level ({security_description})."
                }
            ],
            "temperature": 0.7,
            "max_tokens": 300
        }
        
        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers=headers,
            json=payload
        )
        
        if response.status_code == 200:
            suggestion = response.json()["choices"][0]["message"]["content"]
            return {
                "ai_suggestion": suggestion,
                "generated_by": "OpenAI GPT-3.5"
            }
        else:
            return {
                "error": f"API error: {response.status_code}",
                "message": response.text
            }
    
    except Exception as e:
        return {
            "error": f"Failed to get AI suggestion: {str(e)}",
            "suggestions": get_fallback_suggestions(password, security_level)
        }

def get_security_level_description(level):
    """
    Get a description of the security level.
    
    Args:
        level (int): Security level (1-5)
        
    Returns:
        str: Description of the security level
    """
    descriptions = {
        1: "basic (suitable for low-risk accounts)",
        2: "moderate (suitable for regular online accounts)",
        3: "strong (suitable for email and social media)",
        4: "very strong (suitable for financial accounts)",
        5: "maximum (suitable for critical infrastructure and high-value targets)"
    }
    
    return descriptions.get(level, "standard")

def get_fallback_suggestions(password, security_level=3):
    """
    Generate password improvement suggestions without using AI.
    
    Args:
        password (str): The password to analyze
        security_level (int): The desired security level (1-5)
        
    Returns:
        dict: A dictionary with suggestions and feedback
    """
    weaknesses = []
    improvements = []
    
    # Check password length based on security level
    min_length = 8 + (security_level * 2)  # 10-18 chars depending on level
    if len(password) < min_length:
        weaknesses.append(f"Your password is too short for the requested security level")
        improvements.append(f"Use at least {min_length} characters")
    
    # Check character types
    if not re.search(r'[a-z]', password):
        weaknesses.append("Missing lowercase letters")
        improvements.append("Add lowercase letters")
    
    if not re.search(r'[A-Z]', password):
        weaknesses.append("Missing uppercase letters")
        improvements.append("Add uppercase letters")
    
    if not re.search(r'\d', password):
        weaknesses.append("Missing numbers")
        improvements.append("Add numeric digits")
    
    # Special characters (required for level 2+)
    if security_level >= 2 and not re.search(r'[^a-zA-Z0-9]', password):
        weaknesses.append("Missing special characters (required for this security level)")
        improvements.append("Add special characters like !@#$%^&*")
    
    # Number of special characters (for higher levels)
    if security_level >= 4:
        special_count = sum(1 for c in password if not c.isalnum())
        if special_count < 2:
            weaknesses.append("Not enough special characters for high security level")
            improvements.append("Use at least 2 special characters")
    
    # Check for common patterns
    patterns = detect_patterns(password)
    if patterns:
        pattern_str = ", ".join(patterns)
        weaknesses.append(f"Contains common patterns ({pattern_str})")
        improvements.append("Avoid sequential characters and common patterns")
    
    # Generate alternative passwords
    alternatives = generate_alternative_passwords(password, security_level, 3)
    
    return {
        "weaknesses": weaknesses,
        "improvements": improvements,
        "alternative_passwords": alternatives,
        "generated_by": "Rule-based system"
    }

def detect_patterns(password):
    """
    Detect common patterns in a password.
    
    Args:
        password (str): The password to analyze
        
    Returns:
        list: List of detected patterns
    """
    patterns = []
    lower_pwd = password.lower()
    
    # Check for keyboard sequences
    keyboard_sequences = ["qwerty", "asdfgh", "zxcvbn", "qwertyuiop", "asdfghjkl", "zxcvbnm"]
    for seq in keyboard_sequences:
        if seq in lower_pwd:
            patterns.append("keyboard sequence")
            break
    
    # Check for numerical sequences
    num_sequences = ["123", "456", "789", "012", "987", "654", "321"]
    for seq in num_sequences:
        if seq in password:
            patterns.append("numerical sequence")
            break
    
    # Check for repeated characters
    if re.search(r'(.)\1{2,}', password):  # Same character repeated 3+ times
        patterns.append("repeated characters")
    
    # Check for common words
    common_words = ["password", "admin", "user", "login", "welcome", "letmein", "secret"]
    for word in common_words:
        if word in lower_pwd:
            patterns.append("common word")
            break
    
    # Check for years
    if re.search(r'19\d{2}|20\d{2}', password):
        patterns.append("year pattern")
    
    return patterns

def generate_alternative_passwords(original_password, security_level=3, count=3):
    """
    Generate alternative stronger passwords based on the original password.
    
    Args:
        original_password (str): The original password
        security_level (int): The desired security level (1-5)
        count (int): Number of alternatives to generate
        
    Returns:
        list: List of alternative passwords
    """
    alternatives = []
    
    for _ in range(count):
        # Adjust password characteristics based on security level
        length = 8 + (security_level * 2)  # 10-18 characters
        
        # Character type requirements
        min_lowercase = max(1, length // 5)
        min_uppercase = max(1, length // 5)
        min_digits = max(1, length // 5)
        
        # Special chars based on security level
        min_special = 0
        if security_level >= 2:
            min_special = 1
        if security_level >= 4:
            min_special = 2
        
        remaining = length - (min_lowercase + min_uppercase + min_digits + min_special)
        
        # Distribute remaining characters randomly
        add_lowercase = random.randint(0, remaining)
        remaining -= add_lowercase
        
        add_uppercase = random.randint(0, remaining)
        remaining -= add_uppercase
        
        add_digits = random.randint(0, remaining)
        remaining -= add_digits
        
        add_special = remaining
        
        # Generate the characters
        chars = []
        chars.extend(random.choices(LOWERCASE, k=min_lowercase + add_lowercase))
        chars.extend(random.choices(UPPERCASE, k=min_uppercase + add_uppercase))
        chars.extend(random.choices(DIGITS, k=min_digits + add_digits))
        chars.extend(random.choices(SPECIAL, k=min_special + add_special))
        
        # Shuffle the characters
        random.shuffle(chars)
        
        # Create the password
        alternative = ''.join(chars)
        alternatives.append(alternative)
    
    return alternatives

def get_password_suggestions(password, security_level=3):
    """
    Get suggestions for improving a password.
    
    Args:
        password (str): The password to analyze
        security_level (int): The desired security level (1-5)
        
    Returns:
        dict: A dictionary with suggestions and feedback
    """
    # Try to get AI suggestions if API key is available
    if os.environ.get("OPENAI_API_KEY"):
        try:
            suggestions = get_openai_suggestion(password, security_level)
            if "error" not in suggestions:
                return suggestions
        except Exception as e:
            print(f"Error using OpenAI API: {e}")
    
    # Fall back to rule-based suggestions
    return get_fallback_suggestions(password, security_level) 