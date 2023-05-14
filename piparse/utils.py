
import re

def check_is_ip(ip_address) -> bool:
    """ Accepts a string and returns True if it is an IP address """
    IP_REGEX = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
    if re.search(IP_REGEX, ip_address):
        return True
    else:
        return False