""" PiHole Log Functionality """

import json
from piparse import utils

CONDITIONS = ['local', 'blacklisted', 'blocked', 'error', 'query']

def extract_urls_from_pihole_log(pihole_input_file) -> list:
    """ Accepts a PiHole log file and returns a list of unique URLs """
    url_list = list()   #? Lists are sortable because they are indexed
    url_set = set()     #? Sets are will not contain duplicates

    try:
        with open(pihole_input_file, 'r', encoding='utf-8') as pihole_log:
            pihole_log = pihole_log.read()
    except FileNotFoundError as err:
        print(err)
    else:
        with open(pihole_input_file, 'r', encoding='utf-8') as pihole_log:
            for line in pihole_log:
                pihole_record = line.split(' ')

                if pihole_record[4].find('-dhcp') == -1:
                    if utils.check_is_ip(pihole_record[8]):
                        url_set.add(pihole_record[8])
                    else:
                        root_domain = get_root_domain(pihole_record[8])
                        url_set.add(root_domain)

        for url in url_set:
            url_list.append(url)

        for condition in CONDITIONS:
            url_list.remove(condition)

    url_list.sort()
    return url_list


def get_root_domain(url) -> str:
    """ Accepts FQDN and returns root domain """

    url_list = url.split('.')
    if len(url_list) >= 2:
        root_domain = f'{url_list[-2]}.{url_list[-1]}'
        return root_domain
    else:
        return url


def write_urls_to_log(url_list, log_path) -> None:
    """ Accepts a list of URLs and writes them to a text file """
    #? Remember if you open a file with 'w' it will create the file if it doesn't exist
    with open(log_path, 'w', encoding='utf-8') as url_file:
        for url in url_list:
            url_file.write(url + '\n')


def get_domain_newer_than_year(newer_than_year, whois_file) -> dict:
    whois_data = whois_file
    
    try:
        with open(whois_data, 'r', encoding='utf-8') as whois_file:
            whois_data = json.load(whois_file)    
    except Exception as err:
        print(err)
    else:
        for domain in whois_data:
            
            try:
                if not domain['domain_name']:
                    continue
                
                if not domain['creation_date']:
                    print(f">>> {domain['domain_name']} - with no creation date")
                    continue
                
            except KeyError as err:
                print(f'Key Error of: {err} for domain: {domain["domain_name"]}')
                
            else:
                if type(domain['domain_name']) == list: 
                    domain_name = domain['domain_name'][0]
                elif type(domain['domain_name']) == str:
                    domain_name = str(domain["domain_name"])
            
                if type(domain['creation_date']) == list: 
                    creation_date = domain['creation_date'][0]
                else:
                    creation_date = str(domain["creation_date"])


                creation_date_list = creation_date.split(' ')
                creation_year_month_day = creation_date_list[0]
                creation_year = creation_year_month_day.split('-')[0]
              
                if int(creation_year) > int(newer_than_year):
                    print(f'{domain_name} - {creation_year}')


if __name__ == '__main__':

    PIHOLE_FILE = 'Logs/pihole.log'
    ROOT_DOMAIN_FILE = 'Logs/root_domain.log'
    TEST_FILE = 'Logs/test.log'
    WHOIS_FILE = 'Logs/whois.json'


    try:
        unique_urls = extract_urls_from_pihole_log(PIHOLE_FILE)
    except FileNotFoundError as err:
        print(err)
    else:
        if len(unique_urls) == 0:
            print('No URLs found in PiHole log, or there was an error processing the file')
        else:
            write_urls_to_log(unique_urls, ROOT_DOMAIN_FILE)
            whois_list = utils.get_whois(ROOT_DOMAIN_FILE)
            utils.write_whois_to_log(whois_list, WHOIS_FILE)
    