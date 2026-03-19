file= 'auth.log'
outfile= 'log.csv'

import re
import pandas as pd

pattern = r'(?P<timestamp>\S+) (?P<host>\S+) (?P<process>\S+): (?P<message>.+)'
ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'

def extract_user(message):
    m = re.search(r' user (\S+)', message)
    if m:
        return m.group(1)
    m = re.search(r'(\S+) from ', message)
    if m:
        return m.group(1)
    return None

def convert_csv(file, outfile):
	with open(file, 'r') as fl1:
		lines=fl1.readlines()
		rows=convert_lines(lines)
		df=pd.DataFrame(rows).assign(timestamp=lambda df: pd.to_datetime(df['timestamp']))
		df.to_csv(outfile, index=False)					

def convert_lines(lines):
	rows=[]
	for line in lines:
		linex=line.strip()
		if 'sshd' not in linex:
			continue
		m = re.match(pattern, linex)
		if m:
			x=m.groupdict()
			if 'from' in x['message'] and not x['message'].startswith('Received disconnect'):
				#print(x)
				ip=re.search(ip_pattern, x['message'])
				if not ip:
					continue
				msgarr=x['message'].split(' ')
				log={}
				log['timestamp']=x['timestamp']
				log['source_ip']=ip.group()
				log['username']=extract_user(x['message'])
				log['event_type']=msgarr[0]+' '+msgarr[1]
				if log['event_type']=='Disconnected from':
					log['event_type']='Disconnected'
					log['status']='normal_logout'
				if log['event_type'].startswith('Accept'):
					log['status']='success'
				if 'Failed' in log['event_type'] or 'Invalid' in log['event_type']:
					log['status']='auth_fail'
					log['event_type']='Failed password'
				if 'status' not in log:
					log['status']='other'		
				if log['status'] != 'other':
					rows.append(log)
						
	return rows
					
if __name__=='__main__':
	convert_csv(file, outfile)
