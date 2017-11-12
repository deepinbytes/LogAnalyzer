# LogAnalyzer
Flask app that reads apache logs line by line and returns the following information and exposes REST API: 

1. list of unique IP addresses

2. list of unique IP addresses with country and number of hits

3. list of all activity per IP address

4. detect SQLi with found entries

5. detect remote file inclusion with found entries

6. detect web shells with found entries


Packages Used:

pygeoip: returns the geolocation of target IP address

How to use:

1. Configure the path outputs in "app.py"
2. Put the log file in the input folder
3. Run the flask app "app.py"

API ENDPoints:

1. Fetch unique IP addresses-GET http://SERVER:5000/getuniqueaddress
2. Fetch activity per IP addresses -GET http://SERVER:5000/getactivitiesperip
3. Detect SQLI attack Entries-GET http://SERVER:5000/getsqliattacks
4. Detect Remote File Inclusion Entries -GET http://SERVER:5000/getfileinclusionattacks
5. Detect Web shells in the Entries - GET http://SERVER:5000/getwebshellattacks


