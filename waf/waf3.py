import datetime
import csv
import re
import urllib.parse
from flask import Flask, request, Response, make_response, render_template
from werkzeug.routing import BaseConverter
from transformers import DistilBertTokenizer
import requests
import torch

app = Flask(__name__)

# Custom URL regex converter
class RegexConverter(BaseConverter):
    def __init__(self, url_map, *items):
        super(RegexConverter, self).__init__(url_map)
        self.regex = items[0]

app.url_map.converters['regex'] = RegexConverter

# Load denylist
with open("denylist.txt") as f:
    denylist = [s.strip() for s in f.readlines()]

# Initialize log files
log_path = "log/"
with open(f"{log_path}block.txt", "w"), open(f"{log_path}through.txt", "w"):
    pass
with open("../analysis/block.csv", "w", newline="") as block_csv:
    csv.writer(block_csv).writerow(["date", "ip", "path", "body", "cookie", "is_abnormal"])
with open("../analysis/through.csv", "w", newline="") as through_csv:
    csv.writer(through_csv).writerow(["date", "ip", "path", "body", "cookie", "is_abnormal"])

# Load DistilBERT tokenizer
tokenizer = DistilBertTokenizer.from_pretrained("distilbert-base-uncased")

# Backend URL
backend_url = "http://localhost:8080"

@app.route("/<regex('.*'):path>", methods=["GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"])
def proxy(path):
    # Build full URL with query string
    full_url = f"{backend_url}/{path}"
    if request.query_string:
        full_url += f"?{request.query_string.decode()}"

    # Extract client data
    date_data = datetime.datetime.now()
    ip_data = request.remote_addr
    path_data = path
    body_data = request.get_data(as_text=True)
    cookie_data = "; ".join([f"{k}={v}" for k, v in request.cookies.items()])

    # Check request with WAF
    is_abnormal = waf(full_url, path, body_data, cookie_data)
    log_data = {
        "date": str(date_data),
        "ip": ip_data,
        "path": path_data,
        "body": body_data,
        "cookie": cookie_data,
        "is_abnormal": is_abnormal,
    }

    # Log blocked requests
    if is_abnormal == 1:
        with open(f"{log_path}block.txt", "a") as block_txt:
            block_txt.write(f"{log_data}\n")
        with open("../analysis/block.csv", "a", newline="") as block_csv:
            csv.writer(block_csv).writerow(log_data.values())
        return render_template("waffle.html"), 403

    # Log allowed requests
    with open(f"{log_path}through.txt", "a") as through_txt:
        through_txt.write(f"{log_data}\n")
    with open("../analysis/through.csv", "a", newline="") as through_csv:
        csv.writer(through_csv).writerow(log_data.values())

    # Forward request to backend
    try:
        resp = requests.request(
            method=request.method,
            url=full_url,
            headers={k: v for k, v in request.headers.items() if k.lower() != "host"},
            cookies=request.cookies,
            data=request.get_data(),
            allow_redirects=False,
        )
    except requests.RequestException as e:
        return f"Error forwarding request: {e}", 500

    # Build response to client
    excluded_headers = {"content-encoding", "content-length", "transfer-encoding", "connection"}
    headers = {k: v for k, v in resp.headers.items() if k.lower() not in excluded_headers}
    response = make_response(resp.content, resp.status_code)
    response.headers.extend(headers)

    return response

def waf(url, path, body, cookie):
    """Check if a request is abnormal."""
    # Localhost loop protection
    if request.remote_addr == "127.0.0.1" and "5000" in path:
        return 1

    # Check signature rules
    if not signature(path, body, cookie):
        return 1

    # Predict abnormality with model
    return prediction(url)

def signature(path, body, cookie):
    """Check denylist patterns in path, body, or cookies."""
    for pattern in denylist:
        if re.search(pattern, path, re.IGNORECASE):
            return False
        if body and re.search(pattern, body, re.IGNORECASE):
            return False
        if cookie and re.search(pattern, cookie, re.IGNORECASE):
            return False
    return True

def preprocess(url):
    """Preprocess URL for model input."""
    decoded_url = urllib.parse.unquote(url).lower()
    return torch.tensor(tokenize_url(decoded_url), dtype=torch.long)

def prediction(url):
    """Predict if the URL is abnormal using the trained model."""
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = torch.load("../saved_model/Distilbert_Model_A_full.pth", map_location=device)
    model.eval()

    input_tensor = preprocess(url).to(device)
    with torch.no_grad():
        logits = model(input_tensor).logits
        return int(torch.sigmoid(logits).item() > 0.5)

def tokenize_url(url, tokenizer=tokenizer, max_length=512):
    """Tokenize URL using DistilBERT tokenizer."""
    tokens = tokenizer(
        url,
        max_length=max_length,
        padding="max_length",
        truncation=True,
        return_tensors="pt",
    )
    return tokens["input_ids"]

if __name__ == "__main__":
    app.run("0.0.0.0", port=5002)
