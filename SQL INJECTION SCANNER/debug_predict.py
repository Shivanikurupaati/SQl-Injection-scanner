from ml.predict import SQLInjectionPredictor
import urllib.parse
import sys
import os

# Add current dir to path
sys.path.append(os.getcwd())

print("Loading predictor...")
p = SQLInjectionPredictor()
url = "https://google.com/search?q=test"
print(f"URL: {url}")
parsed = urllib.parse.urlparse(url)
print(f"Scheme: {parsed.scheme}, Netloc: {parsed.netloc}")
print(f"Query: {parsed.query}")
params = urllib.parse.parse_qs(parsed.query)
print(f"Params: {params}")

print("Predicting...")
res = p.predict(url)
print(f"Result: {res}")
