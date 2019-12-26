#!/usr/bin/env python2

from __future__ import print_function

import os
import re
import urllib2

simple_blocklists = ["https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt",
                     "https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt",
                     "https://s3.amazonaws.com/lists.disconnect.me/simple_malware.txt"]

abp_lists = ["https://filters.adtidy.org/extension/chromium/filters/15.txt",
             "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt",
             "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt",
             "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/resource-abuse.txt",
             "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy.txt"]

hosts_files = []

dnsmasq_block_conf_path = "/etc/dnsmasq.d/adblock.conf"

valid_hostname_regex = re.compile('^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$', re.IGNORECASE)


def read_simple_list(url):
    host_list = []

    simple_list = urllib2.urlopen(build_url_req(url)).read()
    for line in simple_list.split("\n"):
        if is_valid_hostname(line):
            host_list.append(line)

    return host_list


def read_abp_list(url):
    host_list = []

    abp_list = urllib2.urlopen(build_url_req(url)).read()
    for line in abp_list.split("\n"):
        if line.startswith("||") and line.endswith("^"):
            line = line[2:-1]
            if is_valid_hostname(line):
                host_list.append(line)

    return host_list


def read_hosts_file(url):
    host_list = []

    hosts_file = urllib2.urlopen(build_url_req(url)).read()
    for line in hosts_file.split("\n"):
        if line.startswith("127.0.0.1"):
            line = line[10:].strip()
            if is_valid_hostname(line):
                host_list.append(line)

    return host_list


def build_url_req(url):
    return urllib2.Request(url, headers={"User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:60.0) Gecko/20100101 Firefox/60.0"})


def is_valid_hostname(hostname):
    if hostname.endswith('.'):
        hostname = hostname[:-1]

    if len(hostname) < 1 or len(hostname) > 253:
        return False

    if hostname is "localhost" or hostname.endswith(".localdomain") or hostname.endswith(".local"):
        return False

    return all(valid_hostname_regex.match(hn_part) for hn_part in hostname.split('.'))


def write_dnsmasq_block_conf(blocklist):
    conf = []
    for host in blocklist:
        conf.append("address=/{}/{}\n".format(host, os.environ['PIXELSERV_IP']))

    conf_file = open(dnsmasq_block_conf_path, "w")
    conf_file.writelines(conf)
    conf_file.close()


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

write_dnsmasq_block_conf(sorted(blocklist))
