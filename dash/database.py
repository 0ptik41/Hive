import IP2Location, os

dbfile = os.path.join('Data','IP','IP2LOCATION-LITE-DB1.BIN')
database = IP2Location.IP2Location(dbfile)

def lookup(ip):
	return database.get_all(ip)