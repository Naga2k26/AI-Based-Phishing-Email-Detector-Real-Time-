import os
import pickle
from typing import List, Dict


class PhishingDetector:
    """Simple wrapper around a vectorizer + classifier stored in `models/`.

    If the model files are missing the detector still provides a safe
    fallback so the app does not crash (it returns classification 'unknown').
    """

    def __init__(self, model_path=None, vectorizer_path=None):
        base = os.path.abspath(os.path.dirname(__file__))
        self.model_path = model_path or os.path.join(base, 'models', 'phishing_detector.pkl')
        self.vectorizer_path = vectorizer_path or os.path.join(base, 'models', 'vectorizer.pkl')

        self.model = None
        self.vectorizer = None

        # Try to load model and vectorizer if present
        try:
            with open(self.vectorizer_path, 'rb') as f:
                self.vectorizer = pickle.load(f)
        except Exception:
            self.vectorizer = None

        try:
            with open(self.model_path, 'rb') as f:
                self.model = pickle.load(f)
        except Exception:
            self.model = None

    def predict(self, email_text: str) -> Dict:
        """Return a standardized prediction dict.

        Keys:
            - email_data: dict with at least 'body'
            - classification: 'phishing'|'legitimate'|'unknown'
            - confidence: float between 0.0 and 1.0
            - threat_indicators: list
        """
        email_data = {
            'subject': '',
            'from': '',
            'to': '',
            'body': email_text
        }

        if not self.model or not self.vectorizer:
            return {
                'email_data': email_data,
                'classification': 'unknown',
                'confidence': 0.0,
                'threat_indicators': []
            }

        # Vectorize and predict
        try:
            X = self.vectorizer.transform([email_text])
            # Use predict_proba if available
            if hasattr(self.model, 'predict_proba'):
                probs = self.model.predict_proba(X)[0]
                # assume classes are ['legitimate', 'phishing'] or similar
                # pick the phishing probability if available
                if len(probs) == 2:
                    phishing_prob = probs[1]
                else:
                    phishing_prob = max(probs)

                classification = 'phishing' if phishing_prob >= 0.5 else 'legitimate'
                confidence = float(phishing_prob)
            else:
                pred = self.model.predict(X)[0]
                classification = str(pred)
                confidence = 1.0

            return {
                'email_data': email_data,
                'classification': classification,
                'confidence': confidence,
                'threat_indicators': []
            }
        except Exception:
            return {
                'email_data': email_data,
                'classification': 'unknown',
                'confidence': 0.0,
                'threat_indicators': []
            }


if __name__ == '__main__':
    # quick local test
    d = PhishingDetector()
    print('Model loaded:', bool(d.model))
    print('Vectorizer loaded:', bool(d.vectorizer))
    print(d.predict('This is a test email about your account.'))
