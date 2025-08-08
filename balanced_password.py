import random
import string
import pandas as pd

# ------------------------------
# Helper: Generate humanized strong password
# ------------------------------
def generate_humanized_strong(length=12):
    words = ["Blue", "Sun", "Sky", "River", "Tech", "Data", "Secure", "Cloud", "Lion", "Mars"]
    password = random.choice(words) + str(random.randint(10, 99)) + random.choice(["!", "@", "#", "$", "%", "&", "*"])
    
    # Sometimes make them shorter or longer for variety
    if random.random() < 0.3:
        password = password[:length]  
    elif len(password) < length:
        extra_chars = ''.join(random.choices(string.ascii_letters + string.digits, k=length - len(password)))
        password += extra_chars
    
    return password

# ------------------------------
# Load Weak Passwords (RockYou)
# ------------------------------
with open("data/rockyou.txt", "r", encoding="latin-1", errors="ignore") as f:
    weak_passwords = [line.strip() for line in f if line.strip()]

# ------------------------------
# Generate Strong Passwords
# ------------------------------
strong_passwords = [generate_humanized_strong(random.randint(10, 16)) for _ in range(100000)]

# ------------------------------
# Add "long weak" and "short strong" edge cases
# ------------------------------
long_weak = [pwd + "123" for pwd in random.sample(weak_passwords, 2000)]  # Long but weak
short_strong = [generate_humanized_strong(8) for _ in range(2000)]  # Short but strong

weak_passwords.extend(long_weak)
strong_passwords.extend(short_strong)

# ------------------------------
# Equal sampling for balance
# ------------------------------
sample_size = min(len(strong_passwords), len(weak_passwords))
weak_sample = random.sample(weak_passwords, sample_size)
strong_sample = random.sample(strong_passwords, sample_size)

# ------------------------------
# Label the data
# ------------------------------
labeled_data = [(pwd, 1) for pwd in weak_sample] + [(pwd, 0) for pwd in strong_sample]

# Shuffle
random.shuffle(labeled_data)

# ------------------------------
# Add 5% Label Noise
# ------------------------------
flip_count = int(0.05 * len(labeled_data))
flip_indices = random.sample(range(len(labeled_data)), flip_count)
for idx in flip_indices:
    pwd, label = labeled_data[idx]
    labeled_data[idx] = (pwd, 1 - label)

# ------------------------------
# Save to TXT
# ------------------------------
with open("data/balanced_passwords.txt", "w", encoding="utf-8") as f:
    for pwd, _ in labeled_data:
        f.write(pwd + "\n")

# ------------------------------
# Save to CSV
# ------------------------------
df = pd.DataFrame(labeled_data, columns=["password", "label"])
df.to_csv("data/balanced_passwords.csv", index=False)

print(f"✅ Balanced dataset created: {sample_size} weak + {sample_size} strong (with noise)")
