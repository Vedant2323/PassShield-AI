import re
import random
import string
import json
from models.entropy import get_strength_score, calculate_charset_size

def generate_strength_graph(password):
    """
    Generate data for visualizing password strength.
    
    Args:
        password (str): The password to analyze
        
    Returns:
        dict: Data for visualizing password strength
    """
    # Calculate the password strength score (0-100)
    strength_score = get_strength_score(password)
    
    # Calculate character set size
    charset_size = calculate_charset_size(password)
    
    # Analyze password composition
    composition = analyze_password_composition(password)
    
    # Generate data for the strength meter
    strength_meter = {
        "score": strength_score,
        "category": get_strength_category(strength_score),
        "color": get_strength_color(strength_score)
    }
    
    # Generate comparison data with common passwords
    common_passwords = [
    {"password": "123456", "score": get_strength_score("123456")},
    {"password": "password", "score": get_strength_score("password")},
    {"password": "123456789", "score": get_strength_score("123456789")},
    {"password": "qwerty", "score": get_strength_score("qwerty")},
    {"password": "12345", "score": get_strength_score("12345")},
    {"password": "12345678", "score": get_strength_score("12345678")},
    {"password": "111111", "score": get_strength_score("111111")},
    {"password": "123123", "score": get_strength_score("123123")},
    {"password": "admin", "score": get_strength_score("admin")},
    {"password": "welcome", "score": get_strength_score("welcome")},
    {"password": "password1", "score": get_strength_score("password1")},
    {"password": "1234", "score": get_strength_score("1234")},
    {"password": "P@ssw0rd", "score": get_strength_score("P@ssw0rd")},
    {"password": "letmein", "score": get_strength_score("letmein")},
    {"password": "abc123", "score": get_strength_score("abc123")},
    {"password": "monkey", "score": get_strength_score("monkey")},
    {"password": "sunshine", "score": get_strength_score("sunshine")},
    {"password": "football", "score": get_strength_score("football")},
    {"password": "iloveyou", "score": get_strength_score("iloveyou")},
    {"password": "123", "score": get_strength_score("123")},
    {"password": "welcome1", "score": get_strength_score("welcome1")},
    {"password": "passw0rd", "score": get_strength_score("passw0rd")},
    {"password": "zaq1zaq1", "score": get_strength_score("zaq1zaq1")},
    {"password": "1qaz2wsx", "score": get_strength_score("1qaz2wsx")},
    {"password": "qwertyuiop", "score": get_strength_score("qwertyuiop")},
    {"password": "asdfghjkl", "score": get_strength_score("asdfghjkl")},
    {"password": "login", "score": get_strength_score("login")},
    {"password": "123qwe", "score": get_strength_score("123qwe")},
    {"password": "trustno1", "score": get_strength_score("trustno1")},
]

    
    # Generate data for entropy visualization
    entropy_data = {
        "password_length": len(password),
        "charset_size": charset_size,
        "possible_combinations": charset_size ** len(password) if charset_size > 0 else 0,
        "composition": composition
    }
    
    # Generate data for time-to-crack visualization based on different methods
    crack_time_data = generate_crack_time_data(password)
    
    return {
        "strength_meter": strength_meter,
        "common_passwords": common_passwords,
        "entropy_data": entropy_data,
        "crack_time_data": crack_time_data
    }

def analyze_password_composition(password):
    """
    Analyze the composition of a password.
    
    Args:
        password (str): The password to analyze
        
    Returns:
        dict: Analysis of password composition
    """
    # Count different character types
    lowercase_count = sum(1 for c in password if c.islower())
    uppercase_count = sum(1 for c in password if c.isupper())
    digit_count = sum(1 for c in password if c.isdigit())
    special_count = sum(1 for c in password if not c.isalnum())
    
    # Calculate percentages
    total_length = len(password)
    composition = {
        "lowercase": {
            "count": lowercase_count,
            "percentage": (lowercase_count / total_length) * 100 if total_length > 0 else 0
        },
        "uppercase": {
            "count": uppercase_count,
            "percentage": (uppercase_count / total_length) * 100 if total_length > 0 else 0
        },
        "digits": {
            "count": digit_count,
            "percentage": (digit_count / total_length) * 100 if total_length > 0 else 0
        },
        "special": {
            "count": special_count,
            "percentage": (special_count / total_length) * 100 if total_length > 0 else 0
        }
    }
    
    # Check for patterns
    patterns = []
    
    # Check for sequential characters
    sequences = ["abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "0123456789"]
    for seq in sequences:
        for i in range(len(seq) - 2):
            if seq[i:i+3] in password:
                patterns.append(f"Sequential characters: {seq[i:i+3]}")
                break
    
    # Check for repeated characters
    if re.search(r'(.)\1\1+', password):
        patterns.append("Repeated characters")
    
    # Check for keyboard patterns
    keyboard_patterns = ["qwerty", "asdfgh", "zxcvbn"]
    for pattern in keyboard_patterns:
        if pattern.lower() in password.lower():
            patterns.append(f"Keyboard pattern: {pattern}")
            break
    
    # Check for common words
    common_words = ["password", "admin", "user", "login", "welcome"]
    for word in common_words:
        if word.lower() in password.lower():
            patterns.append(f"Common word: {word}")
            break
    
    composition["patterns"] = patterns
    
    return composition

def get_strength_category(score):
    """
    Get the category of password strength based on score.
    
    Args:
        score (int): The password strength score (0-100)
        
    Returns:
        str: The password strength category
    """
    if score < 20:
        return "very weak"
    elif score < 40:
        return "weak"
    elif score < 60:
        return "medium"
    elif score < 80:
        return "strong"
    else:
        return "very strong"

def get_strength_color(score):
    """
    Get a color representing password strength.
    
    Args:
        score (int): The password strength score (0-100)
        
    Returns:
        str: Hex color code representing the strength
    """
    if score < 20:
        return "#FF0000"  # Red
    elif score < 40:
        return "#FF6600"  # Orange
    elif score < 60:
        return "#FFCC00"  # Yellow
    elif score < 80:
        return "#99CC00"  # Light Green
    else:
        return "#00CC00"  # Green

def generate_crack_time_data(password):
    """
    Generate data for visualizing password cracking time.
    
    Args:
        password (str): The password to analyze
        
    Returns:
        dict: Data for visualizing password cracking time
    """
    # Define attack speeds (attempts per second)
    attack_speeds = {
        "online_throttled": 100 / 3600,  # 100 attempts per hour
        "online_unthrottled": 10,  # 10 attempts per second
        "offline_slow_hash": 1000,  # 1,000 attempts per second (e.g., bcrypt)
        "offline_fast_hash": 1000000000,  # 1 billion attempts per second (e.g., MD5)
        "quantum_computer": 1000000000000  # Hypothetical quantum computer
    }
    
    # Calculate the number of possible combinations
    charset_size = calculate_charset_size(password)
    combinations = charset_size ** len(password)
    
    # Estimate the time to crack for each attack speed
    crack_times = {}
    for attack, speed in attack_speeds.items():
        # Average case is half the keyspace
        seconds = (combinations / 2) / speed
        
        # Format the time
        if seconds < 60:
            time_str = f"{seconds:.1f} seconds"
        elif seconds < 3600:
            time_str = f"{seconds / 60:.1f} minutes"
        elif seconds < 86400:
            time_str = f"{seconds / 3600:.1f} hours"
        elif seconds < 31536000:
            time_str = f"{seconds / 86400:.1f} days"
        elif seconds < 31536000 * 100:
            time_str = f"{seconds / 31536000:.1f} years"
        else:
            time_str = "centuries"
        
        crack_times[attack] = time_str
    
    return {
        "crack_times": crack_times,
        "combinations": combinations
    }

def generate_sample_passwords(count=10, min_length=8, max_length=16):
    """
    Generate sample passwords of varying strength.
    
    Args:
        count (int): The number of passwords to generate
        min_length (int): The minimum password length
        max_length (int): The maximum password length
        
    Returns:
        list: A list of generated passwords with their strength scores
    """
    passwords = []
    
    # Define character sets
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    special = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    # Generate weak passwords
    weak_count = count // 3
    for _ in range(weak_count):
        length = random.randint(4, 7)
        char_set = random.choice([lowercase, digits])
        password = ''.join(random.choice(char_set) for _ in range(length))
        score = get_strength_score(password)
        passwords.append({"password": password, "score": score})
    
    # Generate medium passwords
    medium_count = count // 3
    for _ in range(medium_count):
        length = random.randint(8, 10)
        char_set = lowercase + uppercase + digits
        password = ''.join(random.choice(char_set) for _ in range(length))
        score = get_strength_score(password)
        passwords.append({"password": password, "score": score})
    
    # Generate strong passwords
    strong_count = count - weak_count - medium_count
    for _ in range(strong_count):
        length = random.randint(12, max_length)
        char_set = lowercase + uppercase + digits + special
        password = ''.join(random.choice(char_set) for _ in range(length))
        score = get_strength_score(password)
        passwords.append({"password": password, "score": score})
    
    return passwords 