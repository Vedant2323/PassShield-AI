# Data Directory

This directory contains the data used for training and evaluating the password strength classifier.

## RockYou Dataset

The RockYou dataset is a collection of passwords that were leaked from the RockYou website in 2009. It contains approximately 14 million passwords and is commonly used for password research and security testing.

### Obtaining the Dataset

Due to the size of the dataset and its sensitive nature, it is not included in this repository. You can obtain it from various security research sources.

1. Download the dataset from a security research resource
2. Place the file `rockyou.txt` in this directory
3. Ensure the file is in plain text format with one password per line

### Processing the Dataset

Once you have the dataset, you can use the following script to preprocess it:

```python
import pandas as pd

# Load the dataset
with open('data/rockyou.txt', 'r', encoding='latin-1', errors='ignore') as file:
    passwords = [line.strip() for line in file]

# Create a DataFrame
df = pd.DataFrame({'password': passwords})

# Remove empty passwords
df = df[df['password'].str.len() > 0]

# Save the processed dataset
df.to_csv('data/processed_rockyou.csv', index=False)
```

### Ethics and Responsible Use

This dataset should be used for educational and research purposes only. Do not use these passwords for unauthorized access to any system.

## Alternative Datasets

If you cannot obtain the RockYou dataset, you can use alternative datasets such as:

- SecLists password lists (https://github.com/danielmiessler/SecLists)
- Weakpass password lists (https://weakpass.com/)
- Hashes.org password lists

These can be used as substitutes, but the model's performance may vary. 