from flask import Flask, render_template, send_file, request

from webnoti import send_notification, get_private_key
from webnoti.utils import encode_public_key

app = Flask(__name__)


@app.route('/')
def index():
    private_key = get_private_key('privkey.pem', b'password')
    server_key = encode_public_key(private_key.public_key())
    return render_template('index.html', server_key=server_key)


@app.route('/service-worker.js')  # If you want your notification to work across all site, this should be at /
def serve_sw():
    return send_file('static/js/worker.js')


@app.route('/register-push', methods=['POST'])
def test_webnoti():
    try:
        subscription = request.json['subscription']
    except KeyError:
        return 'Subscription object does not exist', 400
    resp = send_notification(subscription, 'Hello from server!',
                             'https://hakk.kr', get_private_key('privkey.pem', b'password'))
    return 'Success'

if __name__ == '__main__':
    app.run(debug=True, port=5000)
