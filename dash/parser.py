import pandas as pd
import numpy as np
import dataloader 
import datetime
import database
import json

def pull_dates(attack_data):
	dates = dict()
	for e in list(attack_data.keys()):
		d = e[:e.find('.log')].split('_')[0].split('-')
		t = e[:e.find('.log')].split('_')[1].split('-')
		dates[datetime.datetime(
			int(d[2]), int(d[0]), int(d[1]),
			int(t[0]), int(t[1]), int(t[2]))] = e
	return dates

def organize_dataframe(attackers, attack_data):
	df = dict()
	dates = []
	countries = dataloader.extract_country_codes(attackers)
	# Date | N Events | Country | country code | continent
	for day in list(pull_dates(attack_data).values()):
		log = attack_data[day]
		df[day] = {}
		dates.append(log['start'])
		counts = extract_counts_per_country(countries,log)
		for country in list(counts.keys()):
			df[day][country] = counts[country]
	return df

def extract_counts_per_country(codes,data):
	counts = dict()
	lut = get_iso_codes()
	for ip in list(codes.keys()):
		let3 = np.array(lut)[np.where(np.array(lut)[:,1]==codes[ip])][0][2]
		counts[let3] = 0
	for event in data['requests']:
		addr = list(event.keys())[0]
		if addr in codes.keys():
			c = np.array(lut)[np.where(np.array(lut)[:,1]==codes[addr])[0][0],2]
			
		elif addr=='IP':
			c = np.array(lut)[np.where(np.array(lut)[:,1]==codes[event['IP']])[0][0],2]
		counts[c] += 1
	return counts

def get_iso_codes():
	return pd.read_csv('Data/IP/iso3to2.txt',sep='\t')