import os 

from colorama import Fore
from piparse import *

if __name__ == '__main__':
    sb_api_key = os.environ.get('safe_browsing')

    PIHOLE_LOG = 'Logs/pihole.log'
    ROOT_DOMAIN_LOG = 'Logs/root_domain.log'
    TEST_LOG = 'Logs/test.log'
    WHOIS_JSON = 'Logs/whois.json'

    try:
        unique_urls = pihole.extract_urls_from_pihole_log(PIHOLE_LOG)
    except FileNotFoundError as err:
        print(err)
    else:
        if len(unique_urls) == 0:
            print('No URLs found in PiHole log, or there was an error processing the file')
        else:
            pihole.write_urls_to_log(unique_urls, ROOT_DOMAIN_LOG)
            whois_list = utils.get_whois(ROOT_DOMAIN_LOG)
            utils.write_whois_to_log(whois_list, WHOIS_JSON)
    
    try:
        with open(ROOT_DOMAIN_LOG, 'r', encoding='utf-8') as root_domains_file:
            root_domains = root_domains_file.read().splitlines()
    except FileNotFoundError as err:
        print(err)
    else:
        for domain in root_domains:
            result = safebrowsing.get_safe_browsing_report(domain, sb_api_key)
            
            if result['Result']:
                print(Fore.RED + f'{result["URL"]} is a malicious URL')
            else:
                print(Fore.GREEN + f'{result["URL"]} is not a malicious URL')
                
    results = utils.get_domain_newer_than_year(WHOIS_JSON, 2021)
    print(results)