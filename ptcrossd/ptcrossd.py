#!/usr/bin/python3
"""
    Copyright (c) 2023 Penterep Security s.r.o.

    ptcrossd - crossdomain.xml misconfigurations testing tool

    ptcrossd is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    ptcrossd is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with ptcrossd.  If not, see <https://www.gnu.org/licenses/>.
"""

import argparse
import os
import re
import sys; sys.path.append(__file__.rsplit("/", 1)[0])
import urllib

import requests
import defusedxml.ElementTree as DEFUSED_ET

from _version import __version__
from ptlibs import ptjsonlib, ptprinthelper, ptmisclib, ptnethelper

class PtCrossd:
    def __init__(self, args):
        self.ptjsonlib  = ptjsonlib.PtJsonLib()
        self.headers    = ptnethelper.get_request_headers(args)
        self.use_json   = args.json
        self.timeout    = args.timeout
        self.cache      = args.cache
        self.proxies    = {"http": args.proxy, "https": args.proxy}

    def run(self, args):
        rel_path, url = self._adjust_url(args.url)
        ptprinthelper.ptprint(f"Testing: {url}", "TITLE", not self.use_json, colortext=True)

        try:
            response, response_dump = ptmisclib.load_url_from_web_or_temp(url, method="GET", headers=self.headers, proxies=self.proxies, timeout=self.timeout, redirects=False, verify=False, cache=self.cache, dump_response=True)
        except requests.RequestException:
            self.ptjsonlib.end_error(f"Cannot connect to server", self.use_json)

        if response.headers.get("Access-Control-Allow-Origin"):
            ptprinthelper.ptprint(f"Response Header: Access-Control-Allow-Origin: {response.headers.get('Access-Control-Allow-Origin')}", "INFO", not self.use_json)
            if response.headers.get("Access-Control-Allow-Origin") == "*":
                self.ptjsonlib.add_vulnerability("PTWV-OPEN-CORS-HEADER", request=response_dump["request"], response=response_dump["response"])

        if response.status_code == 200:
            if response.headers.get("Content-Type") in ["application/xml", "text/plain"]:
                self.ptjsonlib.add_node(self.ptjsonlib.create_node_object("webpage", properties={"url": url, "name": rel_path, "WebPageType": "crossdomain_xml"}))
                self._process_crossdomain_xml(response, response_dump)
            else:
                self.ptjsonlib.end_error(f"Expected Content-Type is application/xml, got {response.headers.get('Content-Type')}", self.use_json)
        else:
            self.ptjsonlib.end_error(f"crossdomain.xml not found", self.use_json)

        if self.use_json:
            ptprinthelper.ptprint(self.ptjsonlib.get_result_json())

    def _process_crossdomain_xml(self, response, response_dump) -> None:
        try:
            tree = DEFUSED_ET.fromstring(response.text)
        except DEFUSED_ET.ParseError:
            self.ptjsonlib.end_error("Error parsing provided XML file", self.use_json)
        except DEFUSED_ET.EntitiesForbidden:
            self.ptjsonlib.end_error("[Malicious] Forbidden entities found, program will exit", self.use_json)

        if not self.use_json:
            import xml.etree.ElementTree as ET
            ptprinthelper.ptprint("XML content:", "TITLE", not self.use_json)
            element = ET.XML(response.text)
            ET.indent(element)
            ptprinthelper.ptprint(ptprinthelper.get_colored_text(ET.tostring(element, encoding='unicode'), "INFO"), newline_above=True)
        self._allow_access_from_test(tree, response_dump)

    def _allow_access_from_test(self, tree, response_dump) -> bool:
        has_open_cors = False
        has_non_secure_communication = False
        acf_elements = tree.findall("allow-access-from")
        if acf_elements:
            for acf_element in acf_elements:
                if "domain" in acf_element.keys() and acf_element.attrib["domain"] == "*":
                    has_open_cors = True
                if "secure" in acf_element.keys() and not acf_element.attrib["secure"]:
                    has_non_secure_communication = True
            if has_open_cors:
                ptprinthelper.ptprint("Open CORS vulnerability detected", "VULN", not self.use_json, newline_above=True)
                self.ptjsonlib.add_vulnerability("PTWV-OPEN-CORS", request=response_dump["request"], response=response_dump["response"])
            if has_non_secure_communication:
                ptprinthelper.ptprint("Non-secure communication detected", "VULN", not self.use_json, newline_above=True)
                self.ptjsonlib.add_vulnerability("PTWV-NON-SECURE-CORS", request=response_dump["request"], response=response_dump["response"])
        else:
            self.ptjsonlib.end_error("No allow-access-from elements were found", self.use_json)


    def _adjust_url(self, url: str) -> str:
        o = urllib.parse.urlparse(url)
        if not re.match("https?$", o.scheme):
            self.ptjsonlib.end_error("Missing or wrong scheme - only HTTP/HTTPS schemas are supported", self.use_json)
        if not o.netloc:
            self.ptjsonlib.end_error("Invalid URL provided", self.use_json)

        if not o.path.endswith("/crossdomain.xml"):
            pass
        elif not o.path or o.path == "/":
            o = o._replace(path="/crossdomain.xml")
        else:
            o = o._replace(path='/'.join([i for i in o.path.split("/") if i]) + "/crossdomain.xml")

        return (o.path, urllib.parse.urlunparse((o.scheme, o.netloc, o.path, "", "", "")))


def get_help():
    return [
        {"description": ["crossdomain.xml misconfigurations testing tool"]},
        {"usage": ["ptcrossd <options>"]},
        {"usage_example": [
            "ptcrossd -u https://www.example.com/crossdomain.xml",
            "ptcrossd -u https://www.example.com/"
        ]},
        {"options": [
            ["-u",  "--url",                    "<url>",            "Connect to URL"],
            ["-p",  "--proxy",                  "<proxy>",          "Set proxy (e.g. http://127.0.0.1:8080)"],
            ["-T",  "--timeout",                "<timeout>",        "Set timeout (default to 10)"],
            ["-c",  "--cookie",                 "<cookie>",         "Set cookie"],
            ["-ua", "--user-agent",             "<user-agent>",     "Set User-Agent header"],
            ["-H",  "--headers",                "<header:value>",   "Set custom header(s)"],
            ["-C",  "--cache",                  "",                 "Cache requests (load from tmp in future)"],
            ["-v",  "--version",                "",                 "Show script version and exit"],
            ["-h",  "--help",                   "",                 "Show this help message and exit"],
            ["-j",  "--json",                   "",                 "Output in JSON format"],
        ]
        }]


def parse_args():
    parser = argparse.ArgumentParser(add_help="False")
    parser.add_argument("-u",  "--url",         type=str, required=True)
    parser.add_argument("-p",  "--proxy",       type=str)
    parser.add_argument("-c",  "--cookie",      type=str)
    parser.add_argument("-ua", "--user-agent",  type=str, default="Penterep Tools")
    parser.add_argument("-T",  "--timeout",     type=int, default=10)
    parser.add_argument("-H",  "--headers",     type=ptmisclib.pairs, nargs="+")
    parser.add_argument("-j",  "--json",        action="store_true")
    parser.add_argument("-C",  "--cache",       action="store_true")
    parser.add_argument("-v",  "--version",     action="version", version=f"{SCRIPTNAME} {__version__}")

    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        ptprinthelper.help_print(get_help(), SCRIPTNAME, __version__)
        sys.exit(0)

    args = parser.parse_args()
    ptprinthelper.print_banner(SCRIPTNAME, __version__, args.json)
    return args


def main():
    global SCRIPTNAME
    SCRIPTNAME = "ptcrossd"
    requests.packages.urllib3.disable_warnings()
    requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
    args = parse_args()
    script = PtCrossd(args)
    script.run(args)


if __name__ == "__main__":
    main()
