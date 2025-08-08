from models.classifier import PasswordClassifier

clf = PasswordClassifier()
clf.train("data/balanced_passwords.csv")