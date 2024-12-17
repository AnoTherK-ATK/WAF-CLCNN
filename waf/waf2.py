import datetime
import json
from os import write
import re
import subprocess
import urllib.parse
import csv

from markupsafe import escape
from flask import (Flask, Response, make_response, render_template,
                   request)
from werkzeug.routing import BaseConverter
import numpy as np
import torch

from urllib.parse import unquote
from transformers import DistilBertTokenizer

app = Flask(__name__)
class RegexConverter(BaseConverter):
    def __init__(self, url_map, *items):
        super(RegexConverter, self).__init__(url_map)
        self.regex = items[0]

app.url_map.converters['regex'] = RegexConverter

with open("denylist.txt") as f:
    denylist = [s.strip() for s in f.readlines()]

# 4 log files initialization
with open('log/block.txt', 'w') as block_txt:
    block_txt.write('')
with open('log/through.txt', 'w') as through_txt:
    through_txt.write('')
with open('../analysis/block.csv', 'w', newline='') as block_csv:
    block_writer = csv.writer(block_csv)
    block_writer.writerow(['date', 'ip', 'path', 'body', 'cookie', 'is_abnormal'])
with open('../analysis/through.csv', 'w', newline='') as through_csv:
    through_writer = csv.writer(through_csv)
    through_writer.writerow(['date', 'ip', 'path', 'body', 'cookie', 'is_abnormal'])

url = "http://localhost:8080/"
tokenizer = DistilBertTokenizer.from_pretrained('distilbert-base-uncased')
@app.route('/<regex(".*"):path>', methods=["GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"])
def post(path):
    # Extract URL query 
    query = request.query_string
    if query != b'':
        path += "?" + query.decode()

    # Extract cookies
    cookie = ""
    for i, v in request.cookies.items():
        cookie += i + "=" + v + ";"

    date_data = datetime.datetime.now()
    ip_data = request.remote_addr
    path_data = escape(path)
    body_data = escape((request.get_data()).decode('UTF-8'))
    cookie_data = escape(cookie)

    is_abnormal = waf(url, path, str(body_data), str(cookie_data))
    msg_txt = str({"date": str(date_data), "ip": ip_data, "path": str(path_data), "body": str(body_data), "cookie": str(cookie_data), "is_abnormal": is_abnormal}) + "\n"

    if is_abnormal == 1:
        with open('log/block.txt', 'a') as block_txt:
            block_txt.write(msg_txt)
        with open('../analysis/block.csv', 'a', newline='') as block_csv:
            block_writer = csv.writer(block_csv)
            block_writer.writerow([date_data, str(ip_data), path_data, body_data, cookie_data, is_abnormal])
        return render_template('waffle.html')
    else:
        with open('log/through.txt', 'a') as through_txt:
            through_txt.write(msg_txt)
        with open('../analysis/through.csv', 'a', newline='') as through_csv:
            through_writer = csv.writer(through_csv)
            through_writer.writerow([date_data, str(ip_data), path_data, body_data, cookie_data, is_abnormal])

    try:
        proc = subprocess.run(["curl", "-X", request.method, "-i", "-A", request.user_agent.string, url + path, "-H", "Cookie: " + cookie, "-H", "Content-Type:" + request.headers.getlist("Content-Type")[0], "--data", request.get_data().decode()], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except:
        proc = subprocess.run(["curl", "-X", request.method, "-i", "-A", request.user_agent.string, url + path, "-H", "Cookie: " + cookie, "--data", request.get_data().decode()], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    splited_res = proc.stdout.split("\r\n\r\n".encode("utf-8"), 1)
    if len(splited_res) == 1:
        res = make_response("")
    else:
        res = make_response(splited_res[1])

    for v in splited_res[0].split("\r\n".encode("utf-8")):
        if v.startswith(b'Set-Cookie'):
            s = v.split(":".encode("utf-8"), 1)[1].split("=".encode("utf-8"), 1)
            res.set_cookie(s[0].decode("utf-8"), s[1].split(";".encode("utf-8"), 1)[0].decode('utf-8'))

    return res

def waf(url, path, body, cookie):
    if request.remote_addr == "127.0.0.1" and "5000" in path:
        return 1  # Không có mẫu khớp
    if not signature(path, body, cookie):
        # If a pattern match is found, it's 100% abnormal
        return 1
    else:
        return prediction(url + path)

def signature(path, body, cookie):
    for val in denylist:
        m = re.match(val, path, re.IGNORECASE)
        if m is None and body != "":
            m = re.match(val, str(body), re.IGNORECASE)
        if m is None and cookie != "":
            m = re.match(val, str(cookie), re.IGNORECASE)
        if m is not None:
            return False
    return True

def preprocess(url):
    # URL decode
    URL_decoded_url = urllib.parse.unquote(url).lower()
    # Convert to PyTorch tensor
    model_input_url = torch.tensor(tokenize_urls_with_bert(URL_decoded_url), dtype=torch.long)
    return model_input_url

def prediction(url):
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = torch.load('../saved_model/Distilbert_Model_A_full.pth', map_location=device)
    model.eval()

    model_input_url = preprocess(url).to(device)
    with torch.no_grad():
        result = model(model_input_url)
        # Lấy logits từ SequenceClassifierOutput
        logits = result.logits

        # Áp dụng sigmoid và tính toán nhãn dự đoán
        predicted = (torch.sigmoid(logits)).float()

    return predicted.item()

def tokenize_urls_with_bert(url, tokenizer=tokenizer, max_length=512):

    """
    Tokenize URLs and prepare inputs as torch.Tensor for BERT models.

    Args:
        urls (list): List of URL strings.
        max_length (int): Maximum token length.
        sample_index (int): Index to log a sample input for verification.

    Returns:
        dict: A dictionary containing input_ids and attention_mask as torch.Tensor.
    """
    # Load tokenizer
    # tokenizer = DistilBertTokenizer.from_pretrained('distilbert-base-uncased')

    # Decode URLs
    # decoded_urls = [unquote(url).lower() for url in urls]
    # Log a sample URL before tokenization
    # if 0 <= sample_index < len(decoded_urls):
    #     print("Sample URL before processing:", decoded_urls[sample_index])
    # else:
    #     print(f"Sample index {sample_index} is out of bounds for the provided URLs.")

    # Tokenize URLs
    tokenized_inputs = tokenizer(
        url,
        max_length=max_length,
        padding="max_length",
        truncation=True,
        return_tensors="pt"  # Return as PyTorch Tensors
    )

    # Log a sample tokenized input
    # if 0 <= sample_index < len(decoded_urls):
    #     print("Sample tokenized URL (input_ids):", tokenized_inputs["input_ids"][sample_index])
    #     print("Sample tokenized URL (attention_mask):", tokenized_inputs["attention_mask"][sample_index])

    return tokenized_inputs["input_ids"]


app.run("0.0.0.0")
