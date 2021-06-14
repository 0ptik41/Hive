# HIVE 
A test to develop a cool personal dashboard system for data collected in HoneyPot [project](https://github.com/0ptik41/HomeAlone). 

## Features so far
- View charts of visits in the browser 
- Automatically updates local copies of log data when
  copies on remote server are modified
- View daily traffic for any log file on World Map 
- Offline GeoIP lookup (download IP2Location database into dash/Data/IP)

An example of what the Dashboard looks like ![dash](https://raw.githubusercontent.com/0ptik41/Hive/master/honeydata.gif)

## TODO 
There are a lot of things I want to add. Only just started experimenting with this, and it's been a great way to gain more insight from the data I've been accumulating. This is a cool start, but it's far from yielding meaningful insights for security researchers.

- Make malicious requests to Honeypots searchable 
- More charts on statistics about visitors
  o By IP: Time of day, types of payloads, etc.
- Index requests that match real IOCs,

![map](https://raw.githubusercontent.com/0ptik41/Hive/master/exMap.png)