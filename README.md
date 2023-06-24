# HoneyBadger
a lightweight network traffic manager in python

This is still an active project with much development and testing required

## HoneyBadger Functionality Breakdown

1. This script sets up a simple server using Flask in Python. Each time the server receives a request, it triggers the `handle_request` function.

2. When a request comes in, the script extracts the IP address and User-Agent from the request headers. It then uses these to determine if the connection is safe or not.

3. The safety check consists of two parts: 

    a. Threat Check: It uses AlienVault's Open Threat Exchange (OTX) API to see if the IP address is associated with any known threats. 

    b. Bot Check: It checks the User-Agent string (which provides information about the software making the request) against a comprehensive list of known bot User-Agents. This is done to identify whether the request is made by a bot or not.

4. If the connection is deemed safe, it gets added to a list of safe connections and the server responds with a message saying "Connection accepted". 

5. If the connection is deemed unsafe, the script adds the details to a "honeypot". A honeypot is a system intended to mimic likely targets of cyberattacks to detect, deflect, or study attempts to gain unauthorized access. In this case, it's storing the information in a .txt file labeled "Malicious_Traffic.txt" for later analysis. 

6. The server's response includes a mirror of public-facing data fetched from a specified URL. This data could be used for further analysis.

The script logs all activity, which could be very useful for future analysis and debugging. 

Please note that to run this script, you'll need to replace the placeholder values ('Your-AlienVault-OTX-API-Key' and URLs) with the actual ones according to your setup.

## Features to be added

- Exception and error handling will be added soon 
- functionality for safe traffic as shown and used for the malicious traffic minus the redirect to honeypot. in this way the program will create two seperate files one labeled Malicious_Traffic.txt and one labeled Safe_Traffic.txt
- Function to block the nefarious traffic real time on the endpoint's firewall realtime if the threat_check function returns OTX listed IPs
- a safer handling of the OTX API key for security purposes
- More robust options to customize what is deemed unsafe traffic
