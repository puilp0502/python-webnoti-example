import base64
import datetime
import os
from urllib import parse

import jwt
import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from flask import Flask, render_template, send_file, request

from webnoti import Notification, send_notification, get_private_key, utils

app = Flask(__name__)


@app.route('/')
def index():
    private_key = get_private_key('privkey.pem', b'password')
    server_key = utils.encode_public_key(private_key.public_key())
    return render_template('index.html', server_key=server_key)


@app.route('/service-worker.js')  # If you want your notification to work across all site, this should be at /
def serve_sw():
    return send_file('static/js/worker.js')


@app.route('/register-push', methods=['POST'])
def test_webnoti():
    try:
        subscription = request.json['subscription']
    except KeyError:
        return 'Fail', 400
    resp = send_notification(subscription, 'Hello from server!', 'http://hakk.kr',
                             get_private_key('privkey.pem', b'password', True))
    print(resp.text)
    return 'Success'


if __name__ == '__main__':
    app.run(debug=True, port=5000)
