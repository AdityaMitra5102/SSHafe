url='project.mukham.in'
secretpath='/etc/secrets'
threshold=600

import os
from flask import *
from cryptography.fernet import Fernet
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity
import datetime
import json
import pickle
from fido2 import features
from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, ECDH, SECP256R1
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import base64
import subprocess
import requests

os.system(f'sudo chmod -R 777 {secretpath}')

features.webauthn_json_mapping.enabled = True

app=Flask(__name__, static_url_path='')

try:
	fernetkey=open(f'{secretpath}/fernetkey', 'rb').read()
except:
	fernetkeytemp=Fernet.generate_key()
	open(f'{secretpath}/fernetkey', 'wb').write(fernetkeytemp)
	fernetkey=open(f'{secretpath}/fernetkey', 'rb').read()

open(f'{secretpath}/url.txt', 'w').write(url)

f=Fernet(fernetkey)
app.secret_key=fernetkey

rp= PublicKeyCredentialRpEntity(name='Test', id=url)
server=Fido2Server(rp)

def b64decode(encoded):
	while len(encoded)%4!=0:
		encoded=encoded+'='
	return base64.urlsafe_b64decode(encoded)

def read_creds():
	try:
		credentials=pickle.loads(open(f'{secretpath}/creds', 'rb').read())
	except:
		credentials={}
	return credentials

def write_creds(credentials):
	open(f'{secretpath}/creds', 'wb').write(pickle.dumps(credentials))
	if credentials!= read_creds():
		print("WRITING ERROR")

def get_users():
	users=[]
	with open('/etc/passwd', 'r') as file:
		for line in file:
			if 'nologin' in line:
				continue
			users.append(str(line).split(':')[0].strip())
	return users

def notify_admin(user, func):
	try:
		subprocess.Popen(f'NotifyTG {user} {func}'.split()).wait()
	except exception as e:
		print(e)

def change_user_passwd(user, password):
	if user not in get_users():
		return False
	proc = subprocess.Popen(f'sudo passwd {user}'.split(), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	proc.communicate(f'{password}\n{password}\n'.encode())
	modify_user(user, 'unlock')
	return True

def modify_user(username, func='lock'):
	if username not in get_users():
		return False
	config=open(f'{secretpath}/locked.conf', 'r').read()
	fline=config.split('\n')[0]
	fline=fline[len('Match User'):]
	locked_users=fline.split(',')
	locked_users=[item.strip() for item in locked_users]
	locked_users=[x for x in locked_users if any(c.isalpha() for c in x)]
	if func=='lock':
		if username not in locked_users:
			print("Notify lock")
			notify_admin(username, func)
			locked_users.append(username)
	if func=='unlock':
		if username in locked_users:
			print("Notify unlock")
			notify_admin(username, func)
			locked_users.remove(username)
	locked_users_string=','.join(locked_users)
	if len(locked_users)==0:
		locked_users_string=','
	filecont=f'''Match User {locked_users_string}
	Banner /etc/ssh/locked_banner.txt
	ForceCommand echo "Account locked. Unlock at https://{url}/unlock."; exit 1
	PasswordAuthentication no
	PubkeyAuthentication no'''
	open(f'{secretpath}/locked.conf', 'w').write(filecont)
	subprocess.Popen(f'sudo cp {secretpath}/locked.conf /etc/ssh/sshd_config.d/locked.conf'. split()).wait()
	subprocess.Popen(f'sudo systemctl reload ssh'.split()).wait()
	return True

def get_ip():
	return requests.get('https://api.ipify.org').text

def is_local(request):
	ip=str(request.remote_addr)
	print('IP ', ip)
	return ip in ['127.0.0.1', '::1', get_ip()]


def create_banner():
	banner=f'Account locked due to probable brute force attack. Unlock at https://{url}/unlock.\n'
	open(f'{secretpath}/locked_banner.txt', 'w').write(banner)
	subprocess.Popen(f'sudo cp {secretpath}/locked_banner.txt /etc/ssh/locked_banner.txt'.split()).wait()
	subprocess.Popen(f'sudo systemctl reload ssh'.split()).wait()

create_banner()

@app.route('/blockuser', methods=["POST"])
def blockuser():
	if not is_local(request):
		return 'Unauthorized', 403
	user=request.form.get('user')
	if modify_user(user, 'lock'):
		return f'Locked {user}'
	else:
		return f'Lock failed {user}'


@app.route('/gettoken', methods=['POST'])
def gettoken():
	if not is_local(request):
		return 'Unauthorized', 403
	user=request.form.get('user')
	if user not in get_users():
		return 'User not available', 404
	ts=int(datetime.datetime.now().timestamp())
	dat={'user': user, 'ts': ts}
	enc=f.encrypt(json.dumps(dat).encode()).decode()
	print(enc)
	return f'https://{url}/signup?token={enc}'

@app.route('/signup')
def signup():
	token=request.args.get('token').encode()
	dat=json.loads(f.decrypt(token))
	currtime=int(datetime.datetime.now().timestamp())
	if (currtime-dat['ts'])>threshold:
		return 'Expired', 403
	if dat['user'] not in get_users():
		return 'User not available', 403
	return render_template('register.html', token=token.decode())

@app.route('/api/register/begin', methods=['POST'])
def register_begin():
	token=request.args.get('token').encode()
	dat=json.loads(f.decrypt(token))
	currtime=int(datetime.datetime.now().timestamp())
	if (currtime-dat['ts'])>threshold:
		return 'Expired', 403
	if dat['user'] not in get_users():
		return 'User not available', 403
	credentials=read_creds()
	usercreds=credentials.get(dat['user'], [])

	options, state=server.register_begin(
		PublicKeyCredentialUserEntity(
			id=dat['user'].encode(),
			name=dat['user'],
			display_name=dat['user'],
		),
		usercreds,
		user_verification='discouraged',
		resident_key_requirement='required'
	)
	session['state']=state
	return jsonify(dict(options))

@app.route('/api/register/complete', methods=['POST'])
def register_complete():
	token=request.args.get('token').encode()
	dat=json.loads(f.decrypt(token))
	currtime=int(datetime.datetime.now().timestamp())
	if (currtime-dat['ts'])>threshold:
		return 'Expired', 403
	if dat['user'] not in get_users():
		return 'User not available', 403

	response=request.json
	auth_data=server.register_complete(session['state'], response)
	credentials=read_creds()
	usercreds=credentials.get(dat['user'], [])
	usercreds.append(auth_data.credential_data)
	credentials[dat['user']]=usercreds
	write_creds(credentials)
	return jsonify({'status': 'Ok'})

@app.route('/unlock')
def authenticate():
	return render_template('authenticate.html')

@app.route('/api/authenticate/begin', methods=["POST"])
def authenticate_begin():
	priv = generate_private_key(SECP256R1(), default_backend())
	session["priv"] = priv.private_bytes(serialization.Encoding.PEM,  serialization.PrivateFormat.PKCS8,  serialization.NoEncryption()).decode()
	pub_raw = priv.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
	options, state= server.authenticate_begin(challenge=pub_raw, user_verification='discouraged')
	session['state']=state
	return jsonify(dict(options))

@app.route('/api/authenticate/complete', methods=["POST"])
def authenticate_complete():
	response=request.json
	cdjb64=response['response']['clientDataJSON']
	cdj=b64decode(cdjb64)
	challenge=json.loads(cdj)['challenge']
	oldchallenge=b64decode(session['state']['challenge'])
	userHandle=b64decode(response['response']['userHandle']).decode()
	credentials=read_creds()
	usercreds=credentials.get(userHandle, [])
	state=session.pop('state')
	state['challenge']=challenge
	server.authenticate_complete(state, usercreds, response)
	
	raw=b64decode(challenge)
	client_pub_bytes=raw[:65]
	iv=raw[65:77]
	ciphertext=raw[77:]
	priv = load_pem_private_key(session.pop("priv").encode(), password=None, backend=default_backend())
	client_pub = ec.EllipticCurvePublicKey.from_encoded_point(SECP256R1(), client_pub_bytes)
	shared = priv.exchange(ECDH(), client_pub)
	key = HKDF(algorithm=hashes.SHA256(), length=32, salt=oldchallenge, info=b"", backend=default_backend()).derive(shared)
	plaintext = AESGCM(key).decrypt(iv, ciphertext, None).decode()
	if not change_user_passwd(userHandle, plaintext):
		return "Error", 500
	return 'ok'
