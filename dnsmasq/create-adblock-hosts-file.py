#!/usr/bin/env python3

import os
import re
import sys

from enum import Enum, auto
from queue import Queue
from threading import Thread, Lock
from urllib.request import urlopen, Request

ADBLOCK_HOSTS_FILE = "/etc/dnsmasq.d/adblock.hosts"

INVALID_HOSTNAMES = ["localhost", "local", "ip6-localhost", "ip6-loopback"]
INVALID_DOMAINS = [".local", ".localdomain"]
VALID_HOSTNAME_REGEX = re.compile(
    '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$', re.IGNORECASE)

HOSTS_FILE_BLOCK_IPS = ["127.0.0.1", "0.0.0.0", "::1", "::"]


class BLOCKLIST_TYPE(Enum):
    ABP = auto(),
    HOSTS_FILE = auto(),
    SIMPLE = auto()


def thread_get_hosts_to_block(blocklist_queue, hosts_to_block, hosts_to_block_lock):
    blocklist = blocklist_queue.get()
    while blocklist is not None:
        hosts = get_hosts_to_block(blocklist)
        with hosts_to_block_lock:
            hosts_to_block.update(hosts)
        blocklist = blocklist_queue.get()


def get_hosts_to_block(blocklist):
    list_type, url = blocklist

    fetch_and_convert_list = {
        BLOCKLIST_TYPE.ABP: fetch_and_convert_abp_list(url),
        BLOCKLIST_TYPE.HOSTS_FILE: fetch_and_convert_abp_list(url),
        BLOCKLIST_TYPE.SIMPLE: fetch_and_convert_simple_list(url)
    }

    if list_type in fetch_and_convert_list:
        return fetch_and_convert_list[list_type]
    return []


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


def fetch_and_convert_simple_list(url):
    host_list = []

    simple_list = fetch_url_content(url)
    for line in simple_list.split("\n"):
        if is_valid_hostname(line):
            host_list.append(line)

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
    host_to_block_threads = []

    blocklist_queue = Queue()
    hosts_to_block = set()
    hosts_to_block_lock = Lock()

    for _ in range(os.cpu_count()):
        thread = Thread(target=thread_get_hosts_to_block, args=(
            blocklist_queue, hosts_to_block, hosts_to_block_lock))

        thread.start()
        host_to_block_threads.append(thread)

    blocklists_simple = get_env_list('BLOCKLISTS_SIMPLE')
    blocklists_abp = get_env_list('BLOCKLISTS_ABP')
    blocklists_hosts = get_env_list('BLOCKLISTS_HOSTS')

    domain_blacklist = get_env_list('DOMAIN_BLACKLIST')
    domain_whitelist = get_env_list('DOMAIN_WHITELIST')

    for url in blocklists_abp:
        blocklist_queue.put((BLOCKLIST_TYPE.ABP, url))
    for url in blocklists_hosts:
        blocklist_queue.put((BLOCKLIST_TYPE.HOSTS_FILE, url))
    for url in blocklists_simple:
        blocklist_queue.put((BLOCKLIST_TYPE.SIMPLE, url))
    for thread in host_to_block_threads:
        blocklist_queue.put(None)

    for thread in host_to_block_threads:
        thread.join()

    for domain in domain_blacklist:
        hosts_to_block.add(domain)

    for domain in domain_whitelist:
        if domain in hosts_to_block:
            hosts_to_block.remove(domain)

    write_adblock_hosts_file(sorted(hosts_to_block))
