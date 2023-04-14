import argparse
import sys



def parseArgs():
    parser = argparse.ArgumentParser(description="A python script to scan for Apache Tomcat server vulnerabilities.")
    parser.add_argument("-v", "--verbose", default=False, action="store_true", help="Verbose mode. (default: False)")
    parser.add_argument("--debug", default=False, action="store_true", help="Debug mode, for huge verbosity. (default: False)")
    parser.add_argument("-C", "--list-cves", default=False, action="store_true", help="List CVE ids affecting each version found. (default: False)")
    parser.add_argument("--show-cves-descriptions", default=False, action="store_true", help="Show description of found CVEs. (default: False)")
    parser.add_argument("-T", "--threads", default=250, type=int, help="Number of threads (default: 250)")
    parser.add_argument("-s", "--servers-only", default=False, action="store_true", help="If querying ActiveDirectory, only get servers and not all computer objects. (default: False)")
    parser.add_argument("--no-colors", default=False, action="store_true", help="Disable colored output. (default: False)")
    parser.add_argument("--only-http", default=False, action="store_true", help="Scan only with HTTP scheme. (default: False, scanning with both HTTP and HTTPs)")
    parser.add_argument("--only-https", default=False, action="store_true", help="Scan only with HTTPs scheme. (default: False, scanning with both HTTP and HTTPs)")
    # parser.add_argument("--no-check-certificate", default=False, action="store_true", help="Do not check certificate. (default: False)")

    group_export = parser.add_argument_group("Export results")
    group_export.add_argument("--export-xlsx", dest="export_xlsx", type=str, default=None, required=False, help="Output XLSX file to store the results in.")
    group_export.add_argument("--export-json", dest="export_json", type=str, default=None, required=False, help="Output JSON file to store the results in.")
    group_export.add_argument("--export-sqlite", dest="export_sqlite", type=str, default=None, required=False, help="Output SQLITE3 file to store the results in.")

    group_configuration = parser.add_argument_group("Advanced configuration")
    group_configuration.add_argument("-PI", "--proxy-ip", default=None, type=str, help="Proxy IP.")
    group_configuration.add_argument("-PP", "--proxy-port", default=None, type=int, help="Proxy port")
    group_configuration.add_argument("-rt", "--request-timeout", default=5, type=int, help="Set the timeout of HTTP requests.")
    group_configuration.add_argument("--tomcat-username", default=None, help="Single tomcat username to test for login.")
    group_configuration.add_argument("--tomcat-usernames-file", default=None, help="File containing a list of tomcat usernames to test for login")
    group_configuration.add_argument("--tomcat-password", default=None, help="Single tomcat password to test for login.")
    group_configuration.add_argument("--tomcat-passwords-file", default=None, help="File containing a list of tomcat passwords to test for login")

    group_targets_source = parser.add_argument_group("Targets")
    group_targets_source.add_argument("-tf", "--targets-file", default=None, type=str, help="Path to file containing a line by line list of targets.")
    group_targets_source.add_argument("-tt", "--target", default=[], type=str, action='append', help="Target IP, FQDN or CIDR.")
    group_targets_source.add_argument("-tu", "--target-url", default=[], type=str, action='append', help="Target URL to the tomcat manager.")
    group_targets_source.add_argument("-tp", "--target-ports", default="80,443,8080,8081,9080,9081,10080", type=str, help="Target ports to scan top search for Apache Tomcat servers.")
    group_targets_source.add_argument("-ad", "--auth-domain", default="", type=str, help="Windows domain to authenticate to.")
    group_targets_source.add_argument("-ai", "--auth-dc-ip", default=None, type=str, help="IP of the domain controller.")
    group_targets_source.add_argument("-au", "--auth-user", default=None, type=str, help="Username of the domain account.")
    group_targets_source.add_argument("-ap", "--auth-password", default=None, type=str, help="Password of the domain account.")
    group_targets_source.add_argument("-ah", "--auth-hashes", default=None, type=str, help="LM:NT hashes to pass the hash for this user.")
    group_targets_source.add_argument("--ldaps", default=False, action="store_true", help="Use LDAPS (default: False)")
    group_targets_source.add_argument("--subnets", default=False, action="store_true", help="Get all subnets from the domain and use them as targets (default: False)")

    args = parser.parse_args()

    if (args.targets_file is None) and (len(args.target) == 0) and (len(args.target_url) == 0) and (args.auth_user is None and (args.auth_password is None or args.auth_hashes is None)):
        parser.print_help()
        print("\n[!] No targets specified.")
        sys.exit(0)

    if (args.auth_password is not None) and (args.auth_hashes is not None):
        parser.print_help()
        print("\n[!] Options --auth-password/--auth-hashes are mutually exclusive.")
        sys.exit(0)

    if (args.auth_dc_ip is None) and (args.auth_user is not None and (args.auth_password is not None or args.auth_hashes is not None)):
        parser.print_help()
        print("\n[!] Option --auth-dc-ip is required when using --auth-user, --auth-password, --auth-hashes, --auth-domain")
        sys.exit(0)

    return args


options = parseArgs()
