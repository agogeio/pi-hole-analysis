import os 
import piparse
from colorama import Fore


if __name__ == '__main__':
    sb_api_key = os.environ.get('safe_browsing')

    PIHOLE_FILE = 'Logs/pihole.log'
    ROOT_DOMAIN_FILE = 'Logs/root_domain.log'
    TEST_FILE = 'Logs/test.log'
    WHOIS_FILE = 'Logs/whois.json'

    try:
        unique_urls = piparse.extract_urls_from_pihole_log(PIHOLE_FILE)
    except FileNotFoundError as err:
        print(err)
    else:
        if len(unique_urls) == 0:
            print('No URLs found in PiHole log, or there was an error processing the file')
        else:
            piparse.write_urls_to_log(unique_urls, ROOT_DOMAIN_FILE)
            # piparse.whois_list = piparse.get_whois(ROOT_DOMAIN_FILE)
            # piparse.write_whois_to_log(piparse.whois_list, WHOIS_FILE)
    
    # try:
    #     with open(ROOT_DOMAIN_FILE, 'r', encoding='utf-8') as root_domains_file:
    #         root_domains = root_domains_file.read().splitlines()
    # except FileNotFoundError as err:
    #     print(err)
    # else:
    #     for domain in root_domains:
    #         result = piparse.get_safe_browsing_report(domain, sb_api_key)
            
    #         if result['Result']:
    #             print(Fore.RED + f'{result["URL"]} is a malicious URL')
    #         else:
    #             print(Fore.GREEN + f'{result["URL"]} is not a malicious URL')