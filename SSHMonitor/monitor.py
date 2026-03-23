from model import detector
from convert import convert_lines
import subprocess
import os
import threading
import datetime
authfile='/var/log/auth.log'

blocking=[]
blocked={}

MAX_BUF=200
buf=[]

def get_users():
	users=[]
	with open('/etc/passwd', 'r') as file:
		for line in file:
			if 'nologin' in line:
				continue
			users.append(str(line).split(':')[0].strip())
	return users

def block_user(username):
	if username not in get_users():
		print(f'{username} not blocked because not valid user')
		return
	currtime=int(datetime.datetime.now().timestamp())
	if username in blocking or (username in blocked and currtime-blocked[username]<20):
		return
	blocking.append(username)
	os.system(f'BlockUser {username}')
	blocked[username]=int(datetime.datetime.now().timestamp())
	blocking.remove(username)

def check_log_line(linex):
	try:
		line=linex.decode(errors='ignore')
		processed=convert_lines([line])
		if len(processed)<1:
			continue
		log=processed[0]
		result=detector.ingest_log(log)
		if log['prediction']['alert']:
			print(f'Probable brute force on {log["username"]}')
			threading.Thread(target=block_user, args=(log['username'],)).start()
	except:
		print('Error processing log')

def check_buf():
	while True:
		try:
			if len(buf)> MAX_BUF:
				print('Flusing Buffer')
				buf=[]
			while len(buf)>1:
				linex=buf.pop(0)
				check_log_line(linex)
		except:
			pass

def monitor():
	proc=subprocess.Popen(f'tail -n 0 -f {authfile}'.split(), stdout=subprocess.PIPE)
	print('Monitoring')
	for linex in proc.stdout:
		buf.append(linex)
		
if __name__=='__main__':
	threading.Thread(target=check_buf).start()
	monitor()
