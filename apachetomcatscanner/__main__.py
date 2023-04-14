#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : __main__.py
# Author             : Podalirius (@podalirius_)
# Date created       : 24 Jul 2022

import threading
import os

from apachetomcatscanner.Reporter import Reporter
from apachetomcatscanner.Config import Config
from apachetomcatscanner.VulnerabilitiesDB import VulnerabilitiesDB
from apachetomcatscanner.utils.scan import scan_worker, scan_worker_url, monitor_thread
from sectools.windows.ldap import get_computers_from_domain, get_servers_from_domain, get_subnets
from sectools.network.domains import is_fqdn
from sectools.network.ip import is_ipv4_cidr, is_ipv4_addr, is_ipv6_addr, expand_cidr, expand_port_range
from concurrent.futures import ThreadPoolExecutor

from apachetomcatscanner.init_args import options

VERSION = "3.5"

banner = """Apache Tomcat Scanner v%s - by @podalirius_\n""" % VERSION


def load_targets(options, config):
    targets = []

    # Loading targets from domain computers
    if options.auth_dc_ip is not None and options.auth_user is not None and (
            options.auth_password is not None or options.auth_hashes is not None) and options.servers_only is False:
        if options.debug:
            print("[debug] Loading targets from computers in the domain '%s'" % options.auth_domain)
        targets += get_computers_from_domain(
            auth_domain=options.auth_domain,
            auth_dc_ip=options.auth_dc_ip,
            auth_username=options.auth_user,
            auth_password=options.auth_password,
            auth_hashes=options.auth_hashes,
            use_ldaps=options.ldaps,
            __print=True
        )

    # Loading targets from domain servers
    if options.auth_dc_ip is not None and options.auth_user is not None and (
            options.auth_password is not None or options.auth_hashes is not None) and options.servers_only is True:
        if options.debug:
            print("[debug] Loading targets from servers in the domain '%s'" % options.auth_domain)
        targets += get_servers_from_domain(
            auth_domain=options.auth_domain,
            auth_dc_ip=options.auth_dc_ip,
            auth_username=options.auth_user,
            auth_password=options.auth_password,
            auth_hashes=options.auth_hashes,
            use_ldaps=options.ldaps,
            __print=True
        )

    # Loading targets from subnetworks of the domain
    if options.auth_dc_ip is not None and options.auth_user is not None and (
            options.auth_password is not None or options.auth_hashes is not None):
        if options.debug:
            print("[debug] Loading targets from servers in the domain '%s'" % options.auth_domain)
        targets += get_subnets(
            auth_domain=options.auth_domain,
            auth_dc_ip=options.auth_dc_ip,
            auth_username=options.auth_user,
            auth_password=options.auth_password,
            auth_hashes=options.auth_hashes,
            use_ldaps=options.ldaps,
            __print=True
        )

    # Loading targets line by line from a targets file
    if options.targets_file is not None:
        if os.path.exists(options.targets_file):
            if options.debug:
                print("[debug] Loading targets line by line from targets file '%s'" % options.targets_file)
            f = open(options.targets_file, "r")
            for line in f.readlines():
                targets.append(line.strip())
            f.close()
        else:
            print("[!] Could not open targets file '%s'" % options.targets_file)

    # Loading targets from a single --target option
    if len(options.target) != 0:
        if options.debug:
            print("[debug] Loading targets from --target options")
        for target in options.target:
            targets.append(target)

    # Loading targets from a single --target-url option
    if len(options.target_url) != 0:
        if options.debug:
            print("[debug] Loading targets from --target-url options")
        for target in options.target_url:
            targets.append(target)

    # Sort uniq on targets list
    targets = sorted(list(set(targets)))

    final_targets = []
    # Parsing target to filter IP/DNS/CIDR
    for target in targets:
        if is_ipv4_cidr(target):
            final_targets += [("ip", ip) for ip in expand_cidr(target)]
        elif is_ipv4_addr(target):
            final_targets.append(("ipv4", target))
        elif is_ipv6_addr(target):
            final_targets.append(("ipv6", target))
        elif is_fqdn(target):
            final_targets.append(("fqdn", target))
        elif target.startswith("http://") or target.startswith("https://"):
            final_targets.append(("url", target))
        else:
            if options.debug:
                print("[debug] Target '%s' was not added." % target)

    final_targets = sorted(list(set(final_targets)))
    return final_targets


def load_ports(options, config):
    ports = []
    if "," in options.target_ports:
        for port in options.target_ports.split(','):
            ports += expand_port_range(port.strip())
    else:
        ports = expand_port_range(options.target_ports.strip())
    ports = sorted(list(set(ports)))
    return ports


def main(args_options):
    config = Config()
    config.set_debug_mode(args_options.debug)
    config.set_no_colors(args_options.no_colors)
    config.set_request_available_schemes(only_http=args_options.only_http, only_https=args_options.only_https)
    config.set_request_timeout(args_options.request_timeout)
    config.set_request_proxies(args_options.proxy_ip, args_options.proxy_port)
    # config.set_request_no_check_certificate(options.no_check_certificate)
    config.set_list_cves_mode(args_options.list_cves)
    config.set_show_cves_descriptions_mode(args_options.show_cves_descriptions)

    config.load_credentials_from_options(args_options.tomcat_username, args_options.tomcat_password,
                                         args_options.tomcat_usernames_file, args_options.tomcat_passwords_file)

    vulns_db = VulnerabilitiesDB(config=config)
    reporter = Reporter(config=config, vulns_db=vulns_db)

    # Parsing targets and ports
    targets = load_targets(args_options, config)
    ports = load_ports(args_options, config)

    targets_urls = [t for t in targets if t[0] == "url"]
    targets_others = [t for t in targets if t[0] != "url"]
    total_targets = len(targets_others) * len(ports) + len(targets_urls)

    if total_targets != 0:
        if args_options.proxy_ip is not None and args_options.proxy_port is not None:
            if len(targets_others) != 0 and len(targets_urls) != 0:
                print("[+] Targeting %d ports on %d hosts, and %d urls, through proxy %s:%d." % (
                    len(ports), len(targets_others), len(targets_urls), args_options.proxy_ip, args_options.proxy_port))
            elif len(targets_others) == 0 and len(targets_urls) != 0:
                print("[+] Targeting %d urls, through proxy %s:%d." % (
                    len(targets_urls), args_options.proxy_ip, args_options.proxy_port))
            elif len(targets_others) != 0 and len(targets_urls) == 0:
                print("[+] Targeting %d ports on %d hosts, through proxy %s:%d." % (
                    len(ports), len(targets_others), args_options.proxy_ip, args_options.proxy_port))
        else:
            if len(targets_others) != 0 and len(targets_urls) != 0:
                print("[+] Targeting %d ports on %d hosts, and %d urls." % (
                len(ports), len(targets_others), len(targets_urls)))
            elif len(targets_others) == 0 and len(targets_urls) != 0:
                print("[+] Targeting %d urls." % (len(targets_urls)))
            elif len(targets_others) != 0 and len(targets_urls) == 0:
                print("[+] Targeting %d ports on %d hosts." % (len(ports), len(targets_others)))

        # Exploring targets
        if len(targets) != 0 and args_options.threads != 0:
            print("[+] Searching for Apache Tomcats servers on specified targets ...")

            monitor_data = {"actions_performed": 0, "total": total_targets, "lock": threading.Lock()}
            with ThreadPoolExecutor(max_workers=min(args_options.threads, 1 + monitor_data["total"])) as tp:
                tp.submit(monitor_thread, reporter, config, monitor_data)
                for target_type, target in targets:
                    if target_type == "url":
                        tp.submit(scan_worker_url, target, reporter, config, monitor_data)
                    else:
                        for port in ports:
                            tp.submit(scan_worker, target, port, reporter, config, monitor_data)
            print("[+] All done!")

        # if options.export_xlsx is not None:
        #     reporter.export_xlsx(options.export_xlsx)

        # if options.export_sqlite is not None:
        #     reporter.export_sqlite(options.export_sqlite)

    else:
        print("[!] Cannot start scan: no targets loaded.")


if __name__ == '__main__':
    main(args_options=options)
