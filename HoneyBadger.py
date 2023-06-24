from flask import Flask, request, jsonify
from user_agents import parse
from geoip2.database import Reader
import requests
import logging
from OTXv2 import OTXv2

app = Flask(__name__)
reader = Reader('/path/to/GeoLite2-City.mmdb')
otx = OTXv2('Your-AlienVault-OTX-API-Key')

logging.basicConfig(filename='app.log', level=logging.INFO)

malicious_logger = logging.getLogger('malicious_traffic')
malicious_handler = logging.FileHandler('Malicious_Traffic.txt')
malicious_logger.addHandler(malicious_handler)

safe_connections = []
response = requests.get('https://raw.githubusercontent.com/monperrus/crawler-user-agents/master/crawler-user-agents.json')
bot_agents = [bot['pattern'] for bot in response.json()]

@app.route('/')
def handle_request():
    user_agent = parse(request.headers.get('User-Agent'))
    ip = request.remote_addr
    geo_data = reader.city(ip)
    logging.info(f'Handling request from {ip} with user agent {user_agent}')

    if not is_safe(ip, user_agent):
        add_to_honeypot(ip, user_agent, geo_data)
    else:
        safe_connections.append((ip, user_agent, geo_data))

    return jsonify({"data": get_mirror_data()})

def is_safe(ip, user_agent):
    is_threat_flag = is_threat(ip)
    is_bot_flag = is_bot(user_agent)
    
    if is_threat_flag or is_bot_flag:
        malicious_logger.info(f'Malicious connection from {ip} with user agent {user_agent}')
        return False

    return True

def is_threat(ip):
    threat_info = otx.get_indicator_details_by_section('IPv4', ip, 'general')
    return threat_info['pulse_info']['count'] != 0

def is_bot(user_agent):
    agent_str = str(user_agent).lower()
    return any(bot in agent_str for bot in bot_agents)

def add_to_honeypot(ip, user_agent, geo_data):
    with open('honeypot.txt', 'a') as file:
        file.write(f'{ip}: {str(user_agent)}, {str(geo_data)}\n')
    logging.info(f'Added {ip} to the honeypot')

def get_mirror_data():
    public_data = requests.get("https://api.publicdata.example.com/data")
    return public_data.json()

if __name__ == "__main__":
    app.run()
