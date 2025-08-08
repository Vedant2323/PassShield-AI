import os
import re
import subprocess
import math
import tempfile
import random
from datetime import datetime
from models.entropy import calculate_charset_size

def simulate_cracking(password):
    """
    Simulate cracking of a password with or without hashcat.
    
    Args:
        password (str): The password to simulate cracking
        
    Returns:
        dict: The results of the simulation
    """
    # Try to use hashcat if it's available
    if is_hashcat_available():
        try:
            return hashcat_simulation(password)
        except Exception as e:
            print(f"Hashcat simulation failed: {e}")
            # Fall back to estimated simulation
    
    # Fallback to estimate simulation
    return estimate_cracking_simulation(password)

def is_hashcat_available():
    """
    Check if hashcat is available on the system.
    
    Returns:
        bool: True if hashcat is available, False otherwise
    """
    try:
        result = subprocess.run(
            ["hashcat", "--version"], 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            timeout=5
        )
        return result.returncode == 0
    except (subprocess.SubprocessError, FileNotFoundError):
        return False

def hashcat_simulation(password):
    """
    Simulate cracking a password using hashcat.
    
    Args:
        password (str): The password to simulate cracking
        
    Returns:
        dict: The results of the simulation
    """
    # Create a temporary file for the hash
    with tempfile.NamedTemporaryFile(mode='w+', delete=False) as hash_file:
        # Use MD5 for quick simulation (not secure, but good for demo)
        from hashlib import md5
        hash_str = md5(password.encode()).hexdigest()
        hash_file.write(hash_str)
        hash_file_path = hash_file.name
    
    try:
        # Run hashcat in benchmark mode for this hash
        cmd = [
            "hashcat", 
            "-m", "0",  # MD5 mode
            "-a", "3",  # Brute force attack
            "--quiet",
            "--runtime", "10",  # Limit runtime to 10 seconds
            hash_file_path
        ]
        
        # Execute hashcat
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
            text=True
        )
        
        # Parse the output
        if result.returncode == 0 and "Recovered" in result.stdout:
            # Password was cracked
            speed_match = re.search(r"(\d+\.?\d*)\s*H/s", result.stdout)
            speed = float(speed_match.group(1)) if speed_match else 1000
            
            # Calculate the estimated time based on the speed
            possible_combinations = estimate_combinations(password)
            estimated_seconds = possible_combinations / (speed * 2)  # Average case is half the keyspace
            
            return {
                "method": "hashcat",
                "speed": f"{speed} H/s",
                "estimated_time": format_time(estimated_seconds),
                "possible_combinations": possible_combinations,
                "was_cracked": True,
                "time_taken": "10 seconds (limited for demo)"
            }
        else:
            # If hashcat couldn't crack it in the time limit
            return {
                "method": "hashcat",
                "result": "Password not cracked in the time limit",
                "hashcat_output": result.stdout,
                "was_cracked": False
            }
    
    except subprocess.TimeoutExpired:
        return {
            "method": "hashcat",
            "result": "Hashcat simulation timed out",
            "was_cracked": False
        }
    except Exception as e:
        return {
            "method": "hashcat",
            "error": str(e),
            "was_cracked": False
        }
    finally:
        # Clean up the temporary file
        if os.path.exists(hash_file_path):
            os.unlink(hash_file_path)

def estimate_cracking_simulation(password):
    """
    Estimate cracking time without using hashcat.
    
    Args:
        password (str): The password to analyze
        
    Returns:
        dict: The results of the estimation
    """
    # Constants for different cracking speeds
    SPEEDS = {
        "online_service": 100,  # Attempts per hour
        "online_no_ratelimit": 10,  # Attempts per second
        "offline_slow_hash": 10000,  # Attempts per second (e.g., bcrypt)
        "offline_fast_hash": 10000000000,  # Attempts per second (e.g., MD5)
        "specialized_hardware": 100000000000000  # Attempts per second (e.g., custom ASIC)
    }
    
    # Calculate the number of possible combinations
    possible_combinations = estimate_combinations(password)
    
    # Calculate time estimates
    time_estimates = {}
    for scenario, speed in SPEEDS.items():
        time_sec = possible_combinations / (speed * 2)  # Average case is half the keyspace
        time_estimates[scenario] = format_time(time_sec)
    
    # Estimate the time to crack with a simplified dictionary+rules approach
    dictionary_estimate = estimate_dictionary_time(password)
    
    return {
        "method": "estimation",
        "complexity": get_complexity_description(password),
        "possible_combinations": possible_combinations,
        "estimated_time": time_estimates,
        "dictionary_approach": dictionary_estimate,
        "charset_size": calculate_charset_size(password)
    }

def estimate_combinations(password):
    """
    Estimate the number of possible combinations for a password.
    
    Args:
        password (str): The password to analyze
        
    Returns:
        int: The estimated number of combinations
    """
    # Get the character set size
    charset_size = calculate_charset_size(password)
    
    # Calculate the number of possible combinations
    combinations = charset_size ** len(password)
    
    return combinations

def estimate_dictionary_time(password):
    """
    Estimate the time to crack a password using dictionary + rules approach.
    
    Args:
        password (str): The password to analyze
        
    Returns:
        dict: Dictionary with time estimates
    """
    # Constants for estimation
    DICT_SIZES = {
        "common": 10000,  # Common passwords
        "medium": 1000000,  # Medium-sized dictionary
        "large": 100000000  # Large dictionary with rules
    }
    
    # Estimate based on password complexity
    complexity = get_password_complexity(password)
    
    if complexity == "very_weak":
        crackability = "Likely in common dictionary"
        dict_type = "common"
        modifier = 0.8  # High chance in common dictionary
    elif complexity == "weak":
        crackability = "Possible with medium dictionary"
        dict_type = "medium"
        modifier = 0.5  # Moderate chance in medium dictionary
    elif complexity == "medium":
        crackability = "Might require large dictionary with rules"
        dict_type = "large"
        modifier = 0.3  # Lower chance even with large dictionary
    else:
        crackability = "Unlikely to be cracked with dictionary approach"
        dict_type = "large"
        modifier = 0.05  # Very low chance
    
    # Estimate attempts needed
    attempts_needed = int(DICT_SIZES[dict_type] * modifier)
    
    # Calculate time at different speeds
    time_online = attempts_needed / 100  # 100 per hour
    time_offline = attempts_needed / 1000000  # 1 million per second
    
    return {
        "crackability": crackability,
        "dictionary_type": dict_type,
        "estimated_attempts": attempts_needed,
        "time_online": format_time(time_online * 3600),  # Convert to seconds
        "time_offline": format_time(time_offline)
    }

def get_password_complexity(password):
    """
    Get the complexity level of a password.
    
    Args:
        password (str): The password to analyze
        
    Returns:
        str: The complexity level ("very_weak", "weak", "medium", "strong", "very_strong")
    """
    length = len(password)
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[^a-zA-Z0-9]', password))
    
    char_types = sum([has_lower, has_upper, has_digit, has_special])
    
    if length < 6:
        return "very_weak"
    elif length < 8 or char_types < 2:
        return "weak"
    elif length < 10 or char_types < 3:
        return "medium"
    elif length < 12 or char_types < 4:
        return "strong"
    else:
        return "very_strong"

def get_complexity_description(password):
    """
    Get a description of the password complexity.
    
    Args:
        password (str): The password to analyze
        
    Returns:
        str: Description of the password complexity
    """
    complexity = get_password_complexity(password)
    
    descriptions = {
        "very_weak": "Very Weak: This password could be cracked almost instantly.",
        "weak": "Weak: This password could be cracked within minutes to hours.",
        "medium": "Medium: This password would take hours to days to crack.",
        "strong": "Strong: This password would take days to months to crack.",
        "very_strong": "Very Strong: This password would take months to years to crack."
    }
    
    return descriptions.get(complexity, "Unknown complexity")

def format_time(seconds):
    """
    Format a time in seconds to a human-readable string.
    
    Args:
        seconds (float): The time in seconds
        
    Returns:
        str: A human-readable time string
    """
    if seconds < 1:
        return "less than a second"
    elif seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f} minutes"
    elif seconds < 86400:
        hours = seconds / 3600
        return f"{hours:.1f} hours"
    elif seconds < 2592000:
        days = seconds / 86400
        return f"{days:.1f} days"
    elif seconds < 31536000:
        months = seconds / 2592000
        return f"{months:.1f} months"
    else:
        years = seconds / 31536000
        return f"{years:.1f} years" 