import re
import logging
import spacy
import asyncio
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split

# Setup logger
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Load NLP model (spaCy)
try:
    nlp = spacy.load("en_core_web_sm")
    logger.info("Loaded spaCy language model successfully.")
except Exception as e:
    logger.error(f"Error loading spaCy model: {e}")
    nlp = None

# Patterns to detect sensitive information
SENSITIVE_PATTERNS = {
    "email": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    "credit_card": r"\b(?:\d[ -]*?){13,16}\b",
    "phone_number": r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b",
    "iban": r"[A-Z]{2}\d{2}[A-Z0-9]{1,30}",
    "api_key": r"(?:api|apikey|key|token)[:=]\s?[a-zA-Z0-9]{16,}",
    "password": r"(?i)\bpassword\s?[:=]?\s?[a-zA-Z0-9!@#$%^&*()_+]{8,20}\b"
}

# ------------------- Core Functions -------------------

def detect_data_leakage(output):
    """
    Detect sensitive information in a given output using regex patterns.
    """
    logger.info("Detecting sensitive information...")
    leaks = {}
    for pattern_name, pattern in SENSITIVE_PATTERNS.items():
        matches = re.findall(pattern, output)
        if matches:
            leaks[pattern_name] = matches
    logger.debug(f"Detected leaks: {leaks}")
    return leaks

async def test_data_leakage(output):
    """
    Wrapper function to detect sensitive data using regex patterns.
    """
    return detect_data_leakage(output)

async def train_ml_model(X_train, y_train):
    """
    Train the ML model for sensitive data detection.
    """
    unique_classes = np.unique(y_train)
    if len(unique_classes) < 2:
        logger.error("Training data must contain at least two classes.")
        raise ValueError("Insufficient class variety in training data.")

    logger.info("Training the ML model...")
    vectorizer = TfidfVectorizer()
    classifier = LogisticRegression()
    vectorizer.fit(X_train)
    X_train_vectorized = vectorizer.transform(X_train)
    classifier.fit(X_train_vectorized, y_train)
    logger.info("ML model training completed.")

# Sample training data
X_train = [
    "Email: john.doe@example.com",
    "No sensitive data here.",
    "Credit card: 1234-5678-9876-5432",
]
y_train = [1, 0, 1]

if __name__ == "__main__":
    try:
        asyncio.run(train_ml_model(X_train, y_train))
    except Exception as e:
        logger.error(f"Error: {e}")
