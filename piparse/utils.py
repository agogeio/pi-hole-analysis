""" Utility Functions for PiParse """

import json
import re
import whois

def check_is_ip(ip_address) -> bool:
    """ Accepts a string and returns True if it is an IP address """
    IP_REGEX = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
    if re.search(IP_REGEX, ip_address):
        return True
    else:
        return False

    
def get_whois(domain_list) -> list:
    """ Accepts a URL list and returns whois data in form a list of dictionaries"""
    whois_list = [] 
    try:
        with open(domain_list, 'r', encoding='utf-8') as domains:
            for domain in domains:
                domain = domain.strip()
                if not check_is_ip(domain):
                    try:
                        whois_info = str(whois.whois(domain))
                        whois_json = json.loads(whois_info)
                        whois_list.append(whois_json)
                        
                        print(f'{domain} added to whois_data')
                    except Exception as err:
                        print(f'Whois error - {err}')
    except Exception as err:
        print(err)
  
    return whois_list


def write_whois_to_log(whois_data, log_path) -> None:
    """ Accepts a list of whois dictionaries and writes them to a JSON file """
    try:
        with open(log_path, 'w', encoding='utf-8') as whois_file:
            json.dump(whois_data, whois_file, indent=4)
    except Exception as err:
        print(err)