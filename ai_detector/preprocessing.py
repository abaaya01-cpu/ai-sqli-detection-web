import re
import unicodedata
from urllib.parse import unquote
MAX_INPUT = 8192

def normalize(value):
    text = unicodedata.normalize('NFKC', str(value)[:MAX_INPUT]).lower()
    for _ in range(2):
        decoded = unquote(text, errors='replace')[:MAX_INPUT]
        if decoded == text:
            break
        text = decoded
    return re.sub(r'\s+', ' ', text).strip()

def fingerprint(value):
    text = re.sub(r'/\*.*?\*/', '', normalize(value))
    text = re.sub(r'\d+', '<n>', text)
    return re.sub(r'\s+', '', text)
