#!/usr/bin/env python3

from __future__ import print_function

import os
import re
import sys

from urllib.request import urlopen, Request

ADBLOCK_HOSTS_FILE = "/etc/dnsmasq.d/adblock.hosts"

VALID_HOSTNAME_REGEX = re.compile('^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$', re.IGNORECASE)


def read_simple_list(url):
    host_list = []

    simple_list = get_url_content(url)
    for line in simple_list.split("\n"):
        if is_valid_hostname(line):
            host_list.append(line)

    return host_list


def read_abp_list(url):
    host_list = []

    abp_list = get_url_content(url)
    for line in abp_list.split("\n"):
        if line.startswith("||") and line.endswith("^"):
            line = line[2:-1]
            if is_valid_hostname(line):
                host_list.append(line)

    return host_list


def read_hosts_file(url):
    host_list = []

    hosts_file = get_url_content(url)
    for line in hosts_file.split("\n"):
        strip_size = 0
        
        if line.startswith("127.0.0.1"):
            strip_size = 10
        elif line.startswith("0.0.0.0"):
            strip_size = 8
        elif line.startswith("::1"):
            strip_size = 4
        elif line.startswith("::"):
            strip_size = 3
        
        if strip_size > 0 and is_valid_hostname(line):
            host_list.append(line)

    return host_list

def get_url_content(url):
    url_request = Request(url, headers={"User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:60.0) Gecko/20100101 Firefox/60.0"})
    
    url = urlopen(url_request)
   
    url_content_charset = url.headers.get_content_charset()
    if url_content_charset is None:
        url_content_charset = sys.getdefaultencoding()

    url_content = url.read().decode(url_content_charset)
    return url_content

def is_valid_hostname(hostname):
    if hostname.endswith('.'):
        hostname = hostname[:-1]

    if len(hostname) < 1 or len(hostname) > 253:
        return False

    if hostname == "localhost" or hostname.endswith(".localdomain") or hostname.endswith(".local"):
        return False

    return all(VALID_HOSTNAME_REGEX.match(hn_part) for hn_part in hostname.split('.'))


def write_adblock_hosts_file(blocklist):
    with open(ADBLOCK_HOSTS_FILE, "w") as hosts_file:
        for host in blocklist:
            if os.environ['PIXELSERV_IP4']:
                hosts_file.write("{} {}\n".format(os.environ['PIXELSERV_IP4'], host))
            if os.environ['PIXELSERV_IP6']:
                hosts_file.write("{} {}\n".format(os.environ['PIXELSERV_IP6'], host))


if __name__ == "__main__":
    hosts_to_block = set()

    blocklists_simple = []
    if len(os.environ['BLOCKLISTS_SIMPLE']) > 0:
        blocklists_simple = os.environ['BLOCKLISTS_SIMPLE'].split(",")

    blocklists_abp = [] 
    if len(os.environ['BLOCKLISTS_ABP']) > 0:
        blocklists_abp = os.environ['BLOCKLISTS_ABP'].split(",")
    
    blocklists_hosts = []
    if len(os.environ['BLOCKLISTS_HOSTS']) > 0:
        blocklists_hosts = os.environ['BLOCKLISTS_HOSTS'].split(",")
    
    domain_blacklist = []
    if len(os.environ['DOMAIN_BLACKLIST']) > 0:
        domain_blacklist = os.environ['DOMAIN_BLACKLIST'].split(",")

    domain_whitelist = []
    if len(os.environ['DOMAIN_WHITELIST']) > 0:
        domain_whitelist = os.environ['DOMAIN_WHITELIST'].split(",")

    for sbl in blocklists_simple:
        for host in read_simple_list(sbl):
            hosts_to_block.add(host)

    for abpl in blocklists_abp:
        for host in read_abp_list(abpl):
            hosts_to_block.add(host)

    for hf in blocklists_hosts:
        for host in read_hosts_file(hf):
            hosts_to_block.add(host)
    
    for domain in domain_blacklist:
        hosts_to_block.add(domain)

    for domain in domain_whitelist:
        if domain in hosts_to_block:
            hosts_to_block.remove(domain)

    write_adblock_hosts_file(sorted(hosts_to_block))
