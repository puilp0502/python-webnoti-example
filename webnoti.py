import os
import datetime
import base64
from urllib import parse
import jwt
import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from flask import Flask, render_template, send_file, request

import helper

app = Flask(__name__)


@app.route('/')
def index():
    private_key = helper.get_private_key('privkey.pem', b'password')
    server_key = helper.encode_public_key(private_key.public_key())
    return render_template('index.html', server_key=server_key)


@app.route('/service-worker.js')  # If you want your notification to work across all site, this should be at /
def serve_sw():
    return send_file('static/js/worker.js')


@app.route('/register-push', methods=['POST'])
def register_push():
    try:
        subscription = request.json['subscription']
        print(subscription)
    except KeyError:
        return 'Fail'

    curve = ec.SECP256R1()
    backend = default_backend()

    endpoint = subscription['endpoint']
    # Retrieve client's key
    client_public_key_bytes = helper.fill_padding(subscription['keys']['p256dh'])
    client_public_key_bytes = base64.urlsafe_b64decode(client_public_key_bytes)
    client_public_key = ec.EllipticCurvePublicNumbers\
        .from_encoded_point(curve, client_public_key_bytes).public_key(backend)
    client_auth_secret = helper.fill_padding(subscription['keys']['auth'])
    client_auth_secret = base64.urlsafe_b64decode(client_auth_secret)
    print('Receiver Public Key:', subscription['keys']['p256dh'])
    print('Auth Secret:', subscription['keys']['auth'])

    salt = os.urandom(16)
    print('Salt:', base64.urlsafe_b64encode(salt))

    # Generate Server Public & Private Key pair
    server_private_key = ec.generate_private_key(curve, backend)
    server_public_key = server_private_key.public_key()
    server_public_key_bytes = server_public_key.public_numbers().encode_point()
    # Derive shared secret using ECDH
    shared_secret = server_private_key.exchange(ec.ECDH(), client_public_key)
    print('Server Public Key:', helper.encode_public_key(server_public_key))
    print('Server Private Key:', helper.dump_private_key(server_private_key))

    # Generate PRK (according to spec)
    auth_info = b'Content-Encoding: auth\x00'
    prk = helper.hkdf(client_auth_secret, shared_secret, auth_info, 32)
    print('IKM:', base64.urlsafe_b64encode(shared_secret))
    print('PRK:', base64.urlsafe_b64encode(prk))

    # Derive the Content Encryption Key
    encryption_key_info = helper.create_info(b'aesgcm', client_public_key_bytes, server_public_key_bytes)
    encryption_key = helper.hkdf(salt, prk, encryption_key_info, 16)
    print('CEK Info:', base64.urlsafe_b64encode(encryption_key_info))
    print('CEK:', base64.urlsafe_b64encode(encryption_key))

    # Derive the Nonce
    nonce_info = helper.create_info(b'nonce', client_public_key_bytes, server_public_key_bytes)
    nonce = helper.hkdf(salt, prk, nonce_info, 12)
    print('Nonce Info:', base64.urlsafe_b64encode(nonce_info))
    print('Nonce:', base64.urlsafe_b64encode(nonce))

    # Generate padding
    # Length of the padding, up to 65535 bytes
    padding_length = 32
    print('Padding:', padding_length)
    # Append the length of the padding to the front
    padding = padding_length.to_bytes(2, byteorder='big')
    # Repeat null to the end
    padding += b'\x00' * padding_length

    # Actual data to send
    plaintext = 'Hello from server!'.encode('utf-8')

    # Time to encrypt!
    encryptor = Cipher(
        algorithms.AES(encryption_key),
        modes.GCM(nonce),
        backend=backend
    ).encryptor()

    ciphertext = encryptor.update(padding + plaintext) + encryptor.finalize() + encryptor.tag
    print('Ciphertext:', base64.urlsafe_b64encode(ciphertext))

    # Read server's VAPID private server key (whose public key was sent to browser)
    vapid_priv_server_key = helper.get_private_key('privkey.pem', b'password', generate=False)
    vapid_pub_server_key_bytes = vapid_priv_server_key.public_key().public_numbers().encode_point()
    vapid_pub_server_key_b64 = base64.urlsafe_b64encode(vapid_pub_server_key_bytes).decode('utf-8').strip('=')

    # Build VAPID using JWT
    parsed_endpoint = parse.urlparse(endpoint)
    origin = parsed_endpoint.scheme + '://' + parsed_endpoint.netloc
    expires_at = datetime.datetime.now() + datetime.timedelta(hours=12)
    claims = {
        'aud': origin.strip(), # Audience
        'exp': str(int(expires_at.timestamp())).strip(),
        'sub': 'mailto:example@hakk.kr',
    }
    vapid = jwt.encode(claims, vapid_priv_server_key, algorithm='ES256')
    print('Authorization:', vapid)

    ttl = 30
    headers = {
        'TTL': str(ttl),
        'Authorization': 'WebPush ' + vapid.decode('utf-8'),
        'Encryption': 'salt='+base64.urlsafe_b64encode(salt).decode('utf-8'),
        'Content-Type': 'application/octet-stream',
        'Crypto-Key': 'dh='+base64.urlsafe_b64encode(server_public_key_bytes).decode('utf-8')+'; ' +
                      'p256ecdsa='+vapid_pub_server_key_b64,
        'Content-Encoding': 'aesgcm',
        'Content-Length': str(len(ciphertext)),
    }
    r = requests.post(subscription['endpoint'], headers=headers, data=ciphertext)
    print(r.text)
    print(r.status_code)
    return 'Success'

if __name__ == '__main__':
    app.run(debug=True, port=5000)
