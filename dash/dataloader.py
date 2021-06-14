from dotenv import load_dotenv
import multiprocessing
from tqdm import tqdm
import pandas as pd
import numpy as np
import database
import parser
import utils
import json
import os

DataDir = os.getcwd()+'/Data/HoneyPot/'
WebLogs = os.listdir('%sweb' % DataDir)
SSHLogs = os.listdir('%sssh' % DataDir)

def load_log_data(fname):
	log_data = {'requests':[],
				'IPs':[]}
	raw_data = open(fname,'r').read().split('\n')
	header = raw_data[0]
	raw_reqs = raw_data[1:]
	log_data['start'] = header[header.find('[')+1:-1]
	ind = 0
	for request in raw_reqs:
		if len(request) and (request.find('{')>=0 and request.find('}')>=0):
			
			try:
				dic = json.loads(request)
				log_data['requests'].append(dic)
				if 'IP' in dic.keys():
					if dic['IP'] not in log_data['IPs']:
						log_data['IPs'].append(dic['IP'])
				else:
					[log_data['IPs'].append(k) for k in dic.keys()]
			except:
				pass
			
			
		ind += 1
	return log_data

def load_webattack_data():
	attackers = []
	print('\033[1m\033[42m[-] Parsing %s HoneyPot WebLogs\033[0m' % len(WebLogs))
	meta_data = dict()
	for wlog in WebLogs:
		meta_data[wlog] = dict()
		p = '%sweb/%s' % (DataDir,wlog)
		ldat = load_log_data(p)
		for addr in ldat['IPs']:
			if addr not in attackers:
				attackers.append(addr)
		# Other data [Start Time and raw_requests]
		if 'start' in ldat.keys():
			meta_data[wlog]['start'] = ldat['start']
		if 'requests' in ldat.keys():
			meta_data[wlog]['requests'] = ldat['requests']
			# print('\033[1m\033[33m[+] %d requests on %s\033[0m' % (len(ldat['requests']),ldat['start']))
			d =  wlog[:wlog.find('.log')].split('_')[0].replace('-','/')
			t = wlog[:wlog.find('.log')].split('_')[1].replace('-',':')
		print('\033[1m\033[33m[-] %d Requests from\t%d Unique Attackers on\t %s @ %s\033[0m' % 
		  (len(ldat['requests']),len(ldat['IPs']),d,t))
	# TODO: Parse for further data
	print('\033[1m\033[41m\t\t\t%d Unique Attackers Seen\033[0m' % len(attackers))
	return attackers, meta_data

def parse_auth_file(fname):
	attackers = []
	data= {'events':[]}
	raw_data = open(fname,'r').read().split('\n')
	for lines in tqdm(raw_data):
		if lines.find('Invalid User'):
			ind = lines.find('from ')
			ip = lines[ind+5:].split(' port ')[0]
			date = ' '.join(lines.split(' ')[:3])
			if ip not in attackers:
				attackers.append(ip)
			data['events'].append([ip, date])
	return attackers, data

def load_sshattack_data():
	attackers = []
	attempts = []
	print('[-] Parsing %s HoneyPot AuthLogs' % len(SSHLogs))
	for f in SSHLogs:
		fn = '%sssh/%s' % (DataDir, f)
		ftype = utils.cmd('file %s | cut -d ":" -f 2'%fn,False).pop()
		if 'ASCII' in ftype.split(' '):
			print('[-] Loading %s' % fn)
			# process the log file
			attacks, events = parse_auth_file(fn)
		else:
			if fn.split('.')[-1] == 'gz':
				print('[-] Deflating %s' % fn)
				os.system('gunzip %s' % fn)
				fplain = '.'.join(fn.split('.')[:-1]) 
				# Process the decompressed log file 
				attacks, events = parse_auth_file(fplain)
				# Parse Events 
				os.system('gzip %s' % fplain)
		print('[-] %d Unique Attackers seen in %s' % (len(attacks),fn))
		for a in attacks:
			if a not in attackers:
				attackers.append(a)
		for e in events:
			events.append(e)
	print('[-] %d Total IPs have tried to access SSH Unauthorized' % len(attackers))
	print('[-] %d Total Events Logged' % len(attempts))
	return attackers, attempts

def load_addr():
	if os.path.isfile('.env'):
		ip = load_dotenv('SERVER')
	else:
		ip = ''
	return ip

def pull_file(fname,ip):
	loc = '/home/n0d3/HomeAlone/code/logs/web/'
	base = 'sftp root@%s:%s' % (ip,loc)
	gcmd = '#!/bin/bash\n'+base
	gcmd += " <<< $'get %s'" % fname
	gcmd +='\nmv %s Data/HoneyPot/web/%s' % (fname,fname)
	gcmd +='\nrm $0\n#EOF'
	tmpf = utils.create_random_filename('.sh')
	open(tmpf,'w').write(gcmd)
	utils.cmd('bash %s >>/dev/null 2>&1' % tmpf,False)
	try: os.remove(tmpf)
	except: pass


def check_hash(b,l,f):
	h = '%s sha256sum %s/%s' % (b, l,f)
	hstr = utils.cmd(h,False).pop().split(' ')[0]
	return hstr


def check_for_updates(ip, hashes):
	# Get file list 
	print('\033[1m\033[42m[-] Checking in with Server\033[0m')
	base = 'ssh root@%s' % ip
	loc = '/home/n0d3/HomeAlone/code/logs/web'
	files = '%s ls %s' % (base,loc)
	worker = multiprocessing.Pool(30)
	for filename in utils.cmd(files,False):
		# hstr= check_hash(base,loc,filename)
		hevent = worker.apply_async(check_hash,(base,loc,filename))
		hstr = hevent.get()
		if hstr not in hashes.keys():
			print('[+] Downloading new log %s' % filename)
			# pull_file(filename,ip)
			worker.apply_async(pull_file, (filename,ip))


def extract_country_codes(ip_list):
	countries = {}
	for addr in ip_list:
		record = database.lookup(addr)
		countries[addr] = record.country_short
	print('  - %d unique countries represented' % len(list(set(list(countries.values())))))
	return countries


def main():
	
	files = {}
	for wl in WebLogs:
		h = utils.file_hash('%sweb/%s' % (DataDir,wl))
		files[h] = wl
	for al in SSHLogs:
		a = utils.file_hash('%sssh/%s' % (DataDir, al))
		files[a] = al

	load_dotenv()
	honey = os.getenv('SERVER')	
	check_for_updates(honey, files)

	# Load Attack Data
	attackers, attack_data = load_webattack_data()
	# attackers, tries = load_sshattack_data()
	# Get Hashsums of existing log files to check if they've
	# changed in the future 


	## ANALYSIS 
	print('\033[1m\033[32m'+'='*50+'\033[0m')
	print('\033[3m\033[37m# Analyzing Web Attack Data...\033[0m')
	countries = extract_country_codes(attackers)



if __name__ == '__main__':
	main()
