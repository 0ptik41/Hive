from flask import Flask, render_template, redirect, url_for, request
from dotenv import load_dotenv
import plotly.graph_objs as go
import plotly.express as px
import pandas as pd
import numpy as np
import dataloader 
import database
import plotly  
import parser
import utils
import json
import time 
import sys 
import os

DataDir = os.getcwd()+'/Data/HoneyPot/'
WebLogs = os.listdir('%sweb' % DataDir)
SSHLogs = os.listdir('%sssh' % DataDir)
load_dotenv()
honey = os.getenv('SERVER')
files = {}
for wl in WebLogs:
    h = utils.file_hash('%sweb/%s' % (DataDir,wl))
    files[h] = wl
for al in SSHLogs:
    a = utils.file_hash('%sssh/%s' % (DataDir, al))
    files[a] = al

app = Flask(__name__)

def create_plot():
    requests, domain, labels = process_logs()
    df = dict(Time=domain, Requests=requests)
    # data = px.scatter(df,x='Time',y='Requests')
    
    data = go.Figure(dict({"layout": 
                            {"title":
                                {"text": "HoneyPot Activity"},
                            }}))
    data.add_traces(go.Scatter(
                        x=df['Time'],
                        y=df['Requests'],
                        mode='lines'))

    data.update_layout(xaxis=dict(
                    tickmode='array',
                    tickvals=domain,
                    ticktext=labels))
    with open('templates/plot.html', 'w') as f:
        f.write(data.to_html(include_plotlyjs='cdn'))


def process_logs():
    # dataloader.check_for_updates(honey, files)
    attackers, attack_data = dataloader.load_webattack_data()
    dated = parser.pull_dates(attack_data)
    ordered = list(dated.keys())
    ordered.sort()
    labels = []
    dat = []
    i = 0
    for d in ordered:
        dat.append(len(attack_data[dated[d]]['requests']))
        labels.append(d.strftime("%m/%d/%Y, %H:%M:%S"))
    requests = np.array(dat)    
    domain = np.array(list(range(len(ordered))))
    return requests, domain, labels


@app.route('/')
def home():
    attackers, attack_data = dataloader.load_webattack_data()
    logs = os.listdir('%sweb/' % (DataDir))
    dated = parser.pull_dates(attack_data)
    ordered = list(dated.keys())
    ordered.sort()
    links = {}
    for d in ordered:
        links[d] = dated[d]
    return render_template('home.html', columns=links)

@app.route('/world/<log>')
def worldmap(log):
    if os.path.isfile('templates/%s.html' % log):
        os.remove('templates/%s.html' % log)
    attackers, attack_data = dataloader.load_webattack_data()
    # Create figure 
    fig = go.Figure(dict({"layout":
                            {"title": " Threat Map"}}))
    # Add Map 
    code = parser.get_iso_codes()
    if log not in list(attack_data.keys()):
        print('Unknown log %s' % log)
    lut = dataloader.extract_country_codes(attackers)
    counts = parser.extract_counts_per_country(lut,attack_data[log])
    print(counts)
    label=pd.DataFrame(counts.keys(),columns=['Country'])
    df = pd.DataFrame.from_dict(parser.extract_counts_per_country(lut,attack_data[log]),
                                    orient='index',columns=['Attacks'])
    print(df)
    fig = px.choropleth(df,locations=label['Country'],color=df['Attacks'],color_continuous_scale=px.colors.sequential.Plasma)
    with open('templates/%s.html' % log,'w') as f:
        f.write(fig.to_html(include_plotlyjs='cdn'))
    return render_template('%s.html' % log)

@app.route('/update')
def update():
    dataloader.check_for_updates(honey, files)
    attackers, attack_data = load_webattack_data()
    countries = extract_country_codes(attackers)
    return redirect('/activity')

@app.route('/activity')
def index():
    bar = create_plot()
    return render_template('plot.html')


###  Assets 
@app.route('/honey.png')
def honey():
    return open('templates/honey.png','rb').read()

if __name__ == '__main__':
	app.run('127.0.0.1', port=8080)
