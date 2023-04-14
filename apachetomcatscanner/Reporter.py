#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : Reporter.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2022

import json
import os.path
import traceback

from apachetomcatscanner.init_args import options


class Reporter(object):
    """
    Documentation for class Reporter
    """
    data = {}

    def __init__(self, config, vulns_db):
        super(Reporter, self).__init__()
        self.config = config
        self.vulns_db = vulns_db
        self._new_results = []

    def report_result(self, computer_ip, computer_port, result, credentials_found):
        computer_port = str(computer_port)

        finding = result.copy()
        finding["computer_ip"] = computer_ip
        finding["computer_port"] = computer_port
        finding["credentials_found"] = credentials_found

        if computer_ip not in self.data.keys():
            self.data[computer_ip] = {}
        if str(computer_port) not in self.data[computer_ip].keys():
            self.data[computer_ip][computer_port] = {}
        self.data[computer_ip][computer_port] = finding
        self._new_results.append(finding)

    def print_new_results(self):
        # global list_for_cve_and_description
        list_for_cve_and_description = []
        try:
            for finding in self._new_results:
                if not self._new_results:
                    continue
                if finding["manager_accessible"]:
                    if self.config.no_colors:
                        prompt = "[>] [Apache Tomcat/%s] on %s:%s (manager: accessible) on %s "
                    else:
                        prompt = "[>] [Apache Tomcat/\x1b[1;95m%s\x1b[0m] on \x1b[1;93m%s\x1b[0m:\x1b[1;93m%s\x1b[0m (manager: \x1b[1;92maccessible\x1b[0m) on \x1b[4;94m%s\x1b[0m "
                    print(prompt % (
                    finding["version"], finding["computer_ip"], finding["computer_port"], finding["manager_url"]))

                    if len(finding["credentials_found"]) != 0:
                        for statuscode, creds in finding["credentials_found"]:
                            if len(creds["description"]) != 0:
                                if self.config.no_colors:
                                    prompt = "  | Valid user: %s | password: %s | %s"
                                else:
                                    prompt = "  | Valid user: \x1b[1;92m%s\x1b[0m | password: \x1b[1;92m%s\x1b[0m | \x1b[94m%s\x1b[0m"
                                print(prompt % (creds["username"], creds["password"], creds["description"]))
                            else:
                                if self.config.no_colors:
                                    prompt = "  | Valid user: %s | password: %s"
                                else:
                                    prompt = "  | Valid user: \x1b[1;92m%s\x1b[0m | password: \x1b[1;92m%s\x1b[0m"
                                print(prompt % (creds["username"], creds["password"]))

                elif not finding["manager_accessible"]:
                    manager_url_info = None

                # List of cves
                if self.config.list_cves_mode == True and self.config.show_cves_descriptions_mode == False:
                    cve_list = self.vulns_db.get_vulnerabilities_of_version_sorted_by_criticity(finding["version"],
                                                                                                colors=True,
                                                                                                reverse=True)
                    cve_list = [cve_colored for cve_colored, cve_content in cve_list]
                    if len(cve_list) != 0:
                        print("  | CVEs: %s" % ', '.join(cve_list))

                # CVE DESCRIPTION EDITED
                elif self.config.show_cves_descriptions_mode == True:
                    cve_list = self.vulns_db.get_vulnerabilities_of_version_sorted_by_criticity(finding["version"],
                                                                                                colors=True,
                                                                                                reverse=True)

                    for cve_colored, cve_content in cve_list:

                        # I'm sorry, Python
                        target_info = None
                        if finding['scheme'] and finding['target'] and finding['computer_port']:
                            target_info = f"{finding['scheme']}://{finding['target']}:{finding['computer_port']}"

                        apache_ver_info = None
                        if finding['version']:
                            apache_ver_info = f"ApacheTomcat {finding['version']}"

                        if finding["manager_accessible"]:

                            if not finding["manager_url"]:
                                manager_url_info = None

                            else:
                                manager_url_info = finding["manager_url"]

                        cred_info = None
                        if finding["credentials_found"]:
                            cred_info = finding["credentials_found"]

                        cve_content_info = None
                        if cve_content['cve']['id']:
                            cve_content_info = cve_content['cve']['id']

                        severity = None
                        if cve_content["cvss"]['criticity']:
                            severity = cve_content["cvss"]['criticity'].lower()

                        cve_description = None
                        if cve_content["description"]:
                            cve_description = cve_content["description"]

                        ref_cve = None
                        for i in cve_content["references"]:
                            if "nvd.nist.gov" in i:
                                ref_cve = i


                        list_for_cve_and_description.append({"Target": target_info,
                                                             "Apache Tomcat Version": apache_ver_info,
                                                             "Link to manager": manager_url_info,
                                                             "Credentials": cred_info,
                                                             "CVE": cve_content_info,
                                                             "Criticity": severity,
                                                             "Description": cve_description,
                                                             "Reference": ref_cve})
                        s = 1

                        print("  | %s: %s" % (cve_colored, cve_content["description"]))

                export_json(path_to_file=options.export_json, content=list_for_cve_and_description)
                self._new_results.remove(finding)

        except Exception as e:
            if self.config.debug_mode:
                print("[Error in %s] %s" % (__name__, e))
                traceback.print_exc()

def export_json(path_to_file, content):
    basepath = os.path.dirname(path_to_file)
    filename = os.path.basename(path_to_file)
    if basepath not in [".", ""]:
        if not os.path.exists(basepath):
            os.makedirs(basepath)
        path_to_file = basepath + os.path.sep + filename
    else:
        path_to_file = filename

    f = open(path_to_file, 'w')
    f.write(json.dumps(content))
    f.close()
