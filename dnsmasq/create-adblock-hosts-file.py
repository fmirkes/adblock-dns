#!/usr/bin/env python3

from __future__ import print_function

import os
import re
import sys

from urllib.request import urlopen, Request

simple_blocklists = ["https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt",
                     "https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt",
                     "https://s3.amazonaws.com/lists.disconnect.me/simple_malware.txt"]

abp_lists = ["https://filters.adtidy.org/extension/chromium/filters/15.txt",
             "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt",
             "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt",
             "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/resource-abuse.txt",
             "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy.txt"]

hosts_files = []

adblock_hosts_file = "/etc/dnsmasq.d/adblock.hosts"

valid_hostname_regex = re.compile('^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$', re.IGNORECASE)


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
        if line.startswith("127.0.0.1") or line.startswith("0.0.0.0"):
            line = line[10:].strip()
            if is_valid_hostname(line):
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

    if hostname is "localhost" or hostname.endswith(".localdomain") or hostname.endswith(".local"):
        return False

    return all(valid_hostname_regex.match(hn_part) for hn_part in hostname.split('.'))


def write_adblock_hosts_file(blocklist):
    with open(adblock_hosts_file, "w") as hosts_file:
        for host in blocklist:
            hosts_file.write("{} {}\n".format(os.environ['PIXELSERV_IP'], host))

blocklist = set()

for sbl in simple_blocklists:
    for host in read_simple_list(sbl):
        blocklist.add(host)

for abpl in abp_lists:
    for host in read_abp_list(abpl):
        blocklist.add(host)

for hf in hosts_files:
    for host in read_hosts_file(hf):
        blocklist.add(host)

write_adblock_hosts_file(sorted(blocklist))
