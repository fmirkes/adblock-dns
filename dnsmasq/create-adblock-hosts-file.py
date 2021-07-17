#!/usr/bin/env python3

from __future__ import print_function

import os
import re
import sys

from urllib.request import urlopen, Request

ADBLOCK_HOSTS_FILE = "/etc/dnsmasq.d/adblock.hosts"

INVALID_HOSTNAMES = ["localhost", "local", "ip6-localhost", "ip6-loopback"]
INVALID_DOMAINS = [".local", ".localdomain"]
VALID_HOSTNAME_REGEX = re.compile(
    '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$', re.IGNORECASE)

HOSTS_FILE_BLOCK_IPS = ["127.0.0.1", "0.0.0.0", "::1", "::"]


def fetch_and_convert_simple_list(url):
    host_list = []

    simple_list = fetch_url_content(url)
    for line in simple_list.split("\n"):
        if is_valid_hostname(line):
            host_list.append(line)

    return host_list


def fetch_and_convert_abp_list(url):
    host_list = []

    abp_list = fetch_url_content(url)
    for line in abp_list.split("\n"):
        if line.startswith("||") and line.endswith("^"):
            line = line[2:-1]
            if is_valid_hostname(line):
                host_list.append(line)

    return host_list


def fetch_and_convert_hosts_file(url):
    host_list = []

    hosts_file = fetch_url_content(url)
    for line in hosts_file.split("\n"):
        for ip in HOSTS_FILE_BLOCK_IPS:
            if line.startswith(ip):
                hostname = line[len(ip):].strip()
                if is_valid_hostname(hostname):
                    host_list.append(hostname)
                break

    return host_list


def fetch_url_content(url):
    url_request = Request(url, headers={
                          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:60.0) Gecko/20100101 Firefox/60.0"})

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

    if hostname in INVALID_HOSTNAMES:
        return False

    for domain in INVALID_DOMAINS:
        if hostname.endswith(domain):
            return False

    return all(VALID_HOSTNAME_REGEX.match(hn_part) for hn_part in hostname.split('.'))


def get_env_list(env_var):
    if len(os.environ[env_var]) > 0:
        return os.environ[env_var].split(",")
    return []


def write_adblock_hosts_file(blocklist):
    with open(ADBLOCK_HOSTS_FILE, "w") as hosts_file:
        for host in blocklist:
            if os.environ['PIXELSERV_IP4']:
                hosts_file.write("{} {}\n".format(
                    os.environ['PIXELSERV_IP4'], host))
            if os.environ['PIXELSERV_IP6']:
                hosts_file.write("{} {}\n".format(
                    os.environ['PIXELSERV_IP6'], host))


if __name__ == "__main__":
    hosts_to_block = set()

    blocklists_simple = get_env_list('BLOCKLISTS_SIMPLE')
    blocklists_abp = get_env_list('BLOCKLISTS_ABP')
    blocklists_hosts = get_env_list('BLOCKLISTS_HOSTS')

    domain_blacklist = get_env_list('DOMAIN_BLACKLIST')
    domain_whitelist = get_env_list('DOMAIN_WHITELIST')

    for sbl in blocklists_simple:
        hosts_to_block.update(fetch_and_convert_simple_list(sbl))

    for abpl in blocklists_abp:
        hosts_to_block.update(fetch_and_convert_abp_list(abpl))

    for hf in blocklists_hosts:
        hosts_to_block.update(fetch_and_convert_hosts_file(hf))

    for domain in domain_blacklist:
        hosts_to_block.add(domain)

    for domain in domain_whitelist:
        if domain in hosts_to_block:
            hosts_to_block.remove(domain)

    write_adblock_hosts_file(sorted(hosts_to_block))
