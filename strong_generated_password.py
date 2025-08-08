import random
import string

def generate_human_like_strong_passwords(n=100000):
    """
    Generates a list of human-like but strong passwords.
    Combines words, numbers, and symbols in random patterns.
    """
    words = [
        "summer", "winter", "london", "secure", "happy",
        "gaming", "tiger", "coffee", "travel", "bluesky",
        "forest", "ocean", "future", "phoenix", "sunrise",
        "cyber", "storm", "matrix", "galaxy", "nova"
    ]
    specials = "!@#$%^&*()_+-=<>?"

    strong_passwords = []

    for _ in range(n):
        # Pick 2 distinct words
        word1 = random.choice(words)
        word2 = random.choice(words)
        while word2 == word1:
            word2 = random.choice(words)

        # Random capitalization
        if random.random() > 0.3:
            word1 = word1.capitalize()
        if random.random() > 0.3:
            word2 = word2.capitalize()

        # Random number (3–4 digits)
        number = str(random.randint(100, 9999))

        # Random special chars
        special1 = random.choice(specials)
        special2 = random.choice(specials)

        # Random pattern
        patterns = [
            f"{word1}{special1}{number}{word2}{special2}",
            f"{special1}{word1}{number}{special2}{word2}",
            f"{word1}{number}{special1}{word2}{special2}",
            f"{word1}{special1}{word2}{number}{special2}"
        ]
        password = random.choice(patterns)

        # Ensure length ≥ 12
        if len(password) < 12:
            extra_chars = ''.join(random.choices(string.ascii_letters + string.digits + specials, k=12 - len(password)))
            password += extra_chars

        strong_passwords.append(password)

    return strong_passwords


# Save to file
strong_passwords = generate_human_like_strong_passwords()
with open('data/strong_passwords.txt', 'w', encoding='utf-8') as f:
    for pwd in strong_passwords:
        f.write(pwd + '\n')

print("✅ 100,000 human-like strong passwords generated and saved to data/strong_passwords.txt")
