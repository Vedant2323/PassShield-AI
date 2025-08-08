import math
import re
import zxcvbn
from models.classifier import PasswordClassifier

# Initialize the ML classifier
try:
    ml_classifier = PasswordClassifier()
    ML_MODEL_AVAILABLE = ml_classifier.model_exists()
    if ML_MODEL_AVAILABLE:
        print("🤖 ML Model loaded successfully!")
    else:
        print("⚠️ ML Model not available, using rule-based scoring only")
except Exception as e:
    print(f"⚠️ Error loading ML model: {e}")
    ML_MODEL_AVAILABLE = False

def calculate_entropy(password):
    """
    Calculate the entropy of a password using Shannon's entropy formula.
    
    Args:
        password (str): The password to evaluate
        
    Returns:
        float: The calculated entropy in bits
    """
    # Use zxcvbn for a more accurate entropy calculation
    result = zxcvbn.zxcvbn(password)
    
    # Return the guesses entropy from zxcvbn
    entropy = result['guesses_log10'] * math.log(10, 2)
    
    return round(entropy, 2)

def calculate_charset_size(password):
    """
    Calculate the size of the character set used in a password.
    
    Args:
        password (str): The password to evaluate
        
    Returns:
        int: The size of the character set
    """
    has_lowercase = bool(re.search(r'[a-z]', password))
    has_uppercase = bool(re.search(r'[A-Z]', password))
    has_digits = bool(re.search(r'\d', password))
    has_symbols = bool(re.search(r'[^a-zA-Z0-9]', password))
    
    charset_size = 0
    if has_lowercase:
        charset_size += 26
    if has_uppercase:
        charset_size += 26
    if has_digits:
        charset_size += 10
    if has_symbols:
        charset_size += 33  # Approximation of common symbols
    
    return max(charset_size, 1)  # Ensure charset size is at least 1

def estimate_cracking_time(password):
    """
    Estimate the time it would take to crack a password.
    
    Args:
        password (str): The password to evaluate
        
    Returns:
        dict: A dictionary containing the cracking time estimates
    """
    # Use zxcvbn for a more accurate estimation
    result = zxcvbn.zxcvbn(password)
    
    # Extract the crack time information
    crack_times = {
        'online_throttling': result['crack_times_display']['online_throttling_100_per_hour'],
        'online_no_throttling': result['crack_times_display']['online_no_throttling_10_per_second'],
        'offline_slow_hash': result['crack_times_display']['offline_slow_hashing_1e4_per_second'],
        'offline_fast_hash': result['crack_times_display']['offline_fast_hashing_1e10_per_second'],
        'score': result['score']  # 0-4 score, 0 being very weak, 4 being very strong
    }
    
    return crack_times

def get_strength_score(password):
    """
    Get a strength score for a password from 0 to 100.
    Uses trained ML model when available, falls back to rule-based scoring.
    
    Args:
        password (str): The password to evaluate
        
    Returns:
        int: A score from 0 to 100, where 0 is very weak and 100 is very strong
    """
    # Try to use ML model first if available
    if ML_MODEL_AVAILABLE and ml_classifier:
        try:
            # Get ML prediction (True = strong, False = weak)
            ml_prediction = ml_classifier.predict(password)
            
            # Convert ML prediction to score range
            if ml_prediction:
                # ML says strong - give score between 60-100
                base_score = 60 + (len(password) * 2)  # Length bonus
                complexity_bonus = sum([
                    bool(re.search(r'[a-z]', password)),
                    bool(re.search(r'[A-Z]', password)),
                    bool(re.search(r'\d', password)),
                    bool(re.search(r'[^a-zA-Z0-9]', password))
                ]) * 5
                ml_score = min(100, base_score + complexity_bonus)
            else:
                # ML says weak - give score between 0-40
                ml_score = max(0, 20 - len(password))
            
            # Apply rule-based penalties for specific patterns
            penalty = 0
            
            # Check for common weak patterns
            if re.search(r'^[a-z]+$', password):  # Only lowercase
                penalty += 10
            if re.search(r'^[A-Z]+$', password):  # Only uppercase
                penalty += 10
            if re.search(r'^\d+$', password):  # Only digits
                penalty += 15
            if len(set(password)) < len(password) * 0.5:  # Too many repeated characters
                penalty += 5
            if password.lower() in ['password', 'admin', 'user', 'login', 'welcome', '123456', 'qwerty']:
                penalty += 20
            
            # Check for sequential patterns
            if re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', password.lower()):
                penalty += 10
            if re.search(r'(123|234|345|456|567|678|789|012|987|654|321)', password):
                penalty += 10
            
            # SEVERE PENALTY for banned terms (especially for Barclays mode)
            banned_terms = ['barclays', 'bank', 'password', '123', 'admin', 'user', 'login', 'welcome', 'letmein']
            for term in banned_terms:
                if term.lower() in password.lower():
                    penalty += 50  # Severe penalty for banned terms
                    break
            
            # Additional penalties for weak patterns
            if len(password) < 8:  # Too short
                penalty += 15
            if not re.search(r'[a-z]', password) and not re.search(r'[A-Z]', password):  # No letters
                penalty += 20
            if not re.search(r'\d', password):  # No digits
                penalty += 10
            if not re.search(r'[^a-zA-Z0-9]', password):  # No special characters
                penalty += 5
            
            # Specific penalty for only uppercase letters (common weak pattern)
            if re.search(r'^[A-Z]+\d*$', password):  # Only uppercase + optional digits
                penalty += 30  # Heavy penalty for this pattern
            
            final_score = max(0, min(100, ml_score - penalty))
            return final_score
            
        except Exception as e:
            print(f"⚠️ ML model prediction failed: {e}, falling back to rule-based scoring")
    
    # Fallback to rule-based scoring (original logic)
    # Use zxcvbn for scoring
    result = zxcvbn.zxcvbn(password)
    
    # Convert zxcvbn score (0-4) to a 0-100 scale
    base_score = result['score'] * 20  # Reduced from 25 to 20
    
    # Add bonus points for various factors
    bonus = 0
    
    # Length bonus (reduced)
    length = len(password)
    if length > 16:
        bonus += 10
    elif length > 12:
        bonus += 8
    elif length > 8:
        bonus += 5
    elif length > 6:
        bonus += 2  # Reduced from 5 to 2
    
    # Complexity bonus (reduced)
    complexity = sum([
        bool(re.search(r'[a-z]', password)),
        bool(re.search(r'[A-Z]', password)),
        bool(re.search(r'\d', password)),
        bool(re.search(r'[^a-zA-Z0-9]', password))
    ])
    bonus += complexity * 1.5  # Reduced from 2.5 to 1.5
    
    # Penalty for common patterns
    penalty = 0
    
    # Check for common weak patterns
    if re.search(r'^[a-z]+$', password):  # Only lowercase
        penalty += 10
    if re.search(r'^[A-Z]+$', password):  # Only uppercase
        penalty += 10
    if re.search(r'^\d+$', password):  # Only digits
        penalty += 15
    if len(set(password)) < len(password) * 0.5:  # Too many repeated characters
        penalty += 5
    if password.lower() in ['password', 'admin', 'user', 'login', 'welcome', '123456', 'qwerty']:
        penalty += 20
    
    # Check for sequential patterns
    if re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', password.lower()):
        penalty += 10
    if re.search(r'(123|234|345|456|567|678|789|012|987|654|321)', password):
        penalty += 10
    
    # SEVERE PENALTY for banned terms (especially for Barclays mode)
    banned_terms = ['barclays', 'bank', 'password', '123', 'admin', 'user', 'login', 'welcome', 'letmein']
    for term in banned_terms:
        if term.lower() in password.lower():
            penalty += 50  # Severe penalty for banned terms
            break
    
    final_score = max(0, min(100, base_score + bonus - penalty))
    return final_score 