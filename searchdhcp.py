#!/usr/bin/env python3
# 7/22/20 GitStoph
# Splunk script to search windows AND PaloAlto DHCP logs
##################################################
import sys
import os
from time import sleep
import splunklib.results as results
import splunklib.client as client
from dotenv import load_dotenv
import getpass
import argparse
import re
from rich.console import Console
from rich.table import Table
import socket

"""
This script was intended to be run from the bin, so it needs to add the /opt/splunkscripts directory to path
to access all the libraries it needs, as well as the .env configuration file. Please note this is an example,
and not necessarily how secure credentials should be handled.
"""

console = Console()
os.chdir('/opt/splunkscripts')
current_dir = os.getcwd()
sys.path.append(current_dir)
fpath = os.getcwd()
load_dotenv(os.path.join(fpath, '.env'))

def get_args():
    parser = argparse.ArgumentParser(
        description='Splunk DHCP search tool.')
    parser.add_argument('-s', '--search',required=False,type=str,default='None',action='store', help='String to search?')
    args = parser.parse_args()
    return args


def build_service():
    """Builds the service object using the client function after grabbing the necessary fields from a .env file."""
    service = client.connect(host=os.getenv('SPLUNK_HOST'),
                            port=os.getenv('SPLUNK_PORT'),
                            scheme=os.getenv('SPLUNK_SCHEME'),
                            username=os.getenv('SPLUNK_USER'),
                            password=os.getenv('SPLUNK_PASS'))
    return service


def is_ipaddress(query):
    """Checks to see if the query is an IP. Returns true/false accordingly."""
    try:
        socket.inet_aton(query)
        return True
    except socket.error:
        return False


def format_mac_windhcp(mac: str) -> str:
    """Windows DHCP logs MAC addresses without any punctuations and in complete uppercase. This will produce that output by replacing any listed characters and returning the
    alphanumerics back in uppercase, then joining them together in one string."""
    try:
        mac = re.sub('[.:-]', '', mac).upper()
        mac = ''.join(mac.split())
        return mac
    except AssertionError as error:
        print(error)
        pass


def query_windhcp(query):
    """Uses the format_mac_windhcp to create a potential MAC to search which gets plugged into the searchquery_normal format line. The rest of the line is formatted with the original
    query string in case it wasn't a MAC address originally passed. kwargs are added to do a normal search over the last 72hours. Stats are printed out to the console.log to let the
    user know the status of their search. Logs are then extracted from the job and returned."""
    console.log("[green] Searching Windows DHCP logs..")
    if is_ipaddress(query) == True:
        mac = query
    else:
        mac = format_mac_windhcp(query)
    searchquery_normal = 'search index=ops_app_dhcp signature!="DNS*" (description=*{0}* OR dest=*{0}* OR dest_ip=*{0}* OR mac=*{1}* )| table date time description dest dest_ip mac signature host'.format(query, mac)
    kwargs_normalsearch = {'exec_mode': 'normal', 'earliest_time': '-72h', 'latest_time': 'now'}
    job = service.jobs.create(searchquery_normal, **kwargs_normalsearch)
    # A normal search returns the job's SID right away, so we need to poll for completion
    while True:
        while not job.is_ready():
            pass
        stats = {"isDone": job["isDone"],
                 "doneProgress": float(job["doneProgress"])*100,
                  "scanCount": int(job["scanCount"]),
                  "eventCount": int(job["eventCount"]),
                  "resultCount": int(job["resultCount"])}
        console.log(f"[purple]{stats['doneProgress']}%   [blue]{stats['scanCount']} scanned   [yellow]{stats['eventCount']} matched   [green]{stats['resultCount']} results")
        if stats["isDone"] == "1":
            console.log("[blue]\n[!] Done!\n")
            break
        sleep(1)
    logs = [x for x in results.ResultsReader(job.results())]
    job.cancel()
    return logs


def dedupe_windhcp_logs(logs):
    """Dedupe by MAC address. """
    macs = set()
    nodupes = []
    for x in logs:
        if 'mac' in x.keys():
            y = tuple(sorted(x.items()))[5]
            if y not in macs:
                macs.add(y)
                nodupes.append(x)
    return nodupes


def format_mac_padhcp(macaddress: str) -> str:
    """Takes a MAC address in any format and makes it lowercase with : as the separator
    between characters.
    """
    try:
        mac = re.sub('[.:-]', '', macaddress).lower()
        mac = ''.join(mac.split())
        assert mac.isalnum()
        mac = ":".join(["%s" % (mac[i:i+2]) for i in range(0, len(mac), 2)])
        return mac
    except AssertionError as error:
        print(error)
        pass


def query_padhcp(query):
    """Uses the format_mac_windhcp to create a potential MAC to search which gets plugged into the searchquery_normal format line. The rest of the line is formatted with the original
    query string in case it wasn't a MAC address originally passed. kwargs are added to do a normal search over the last 72hours. Stats are printed out to the console.log to let the
    user know the status of their search. Logs are then extracted from the job and returned."""
    console.log("[green] Searching PA DHCP logs..")
    if is_ipaddress(query) == True:
        mac = query
    else:
        mac = format_mac_padhcp(query)
    searchquery_normal = 'search index=sec_net_firewall sourcetype="pan:system" log_subtype=dhcp (description=*{0}* OR description=*{1}*)| table generated_time dvc_name description'.format(query, mac)
    kwargs_normalsearch = {'exec_mode': 'normal', 'earliest_time': '-72h', 'latest_time': 'now'}
    job = service.jobs.create(searchquery_normal, **kwargs_normalsearch)
    # A normal search returns the job's SID right away, so we need to poll for completion
    while True:
        while not job.is_ready():
            pass
        stats = {"isDone": job["isDone"],
                 "doneProgress": float(job["doneProgress"])*100,
                  "scanCount": int(job["scanCount"]),
                  "eventCount": int(job["eventCount"]),
                  "resultCount": int(job["resultCount"])}
        console.log(f"[purple]{stats['doneProgress']}%   [blue]{stats['scanCount']} scanned   [yellow]{stats['eventCount']} matched   [green]{stats['resultCount']} results")
        if stats["isDone"] == "1":
            console.log("[blue]\n[!] Done!\n")
            break
        sleep(1)
    logs = [x for x in results.ResultsReader(job.results())]
    job.cancel()
    return logs


def dedupe_padhcp_logs(logs):
    """Dedupe by description field. """
    macs = set()
    nodupes = []
    for x in logs:
        y = tuple(sorted(x.items()))[0]
        if y not in macs:
            macs.add(y)
            nodupes.append(x)
    return nodupes


def pretty_windows_output(logs):
    """Builds the rich table, adds the columns, adds the rows, then prints it nicely in green. This is for Windows DHCP logs."""
    if len(logs) != 0:
        try:
            table = Table(show_header=True, header_style="cyan", show_lines=True)
            table.add_column("date", justify="center")
            table.add_column("time", justify="center")
            table.add_column("description", justify="center")
            table.add_column("dest", justify="center")
            table.add_column("dest_ip", justify="center")
            table.add_column("mac", justify="center")
            table.add_column("signature", justify="center")
            table.add_column("host", justify="center")
            for u in logs:
                table.add_row(u['date'], u['time'], u['description'], u['dest'], u['dest_ip'],
                            u['mac'], u['signature'], u['host'])
            console.print(table, style='green')
            print("\n")
        except:
            console.print("[!] Error: ", sys.exc_info(), style='bold red')
            pass
    else:
        console.log("[red]No Windows DHCP logs located.")


def pretty_pa_output(logs):
    """Builds the rich table, adds the columns, adds the rows, then prints it nicely in green. This is for PaloAlto DHCP logs."""
    if len(logs) != 0:
        try:
            table = Table(show_header=True, header_style="cyan", show_lines=True)
            table.add_column("generated_time", justify="center")
            table.add_column("dvc_name", justify="center")
            table.add_column("description", justify="center")
            for u in logs:
                table.add_row(u['generated_time'], u['dvc_name'], u['description'])
            console.print(table, style='green')
            print("\n")
        except:
            console.print("[!] Error: ", sys.exc_info(), style='bold red')
            pass
    else:
        console.log("[red]No PA DHCP logs located.")


def main():
    try:
        args = get_args()
        global service
        service = build_service()
        try:
            pretty_windows_output(dedupe_windhcp_logs(query_windhcp(args.search)))
        except:
            console.log("[red] No windows DHCP logs were found.")
        try:
            pretty_pa_output(dedupe_padhcp_logs(query_padhcp(args.search)))
        except:
            console.log("[red] No PA DHCP logs were found.")
        console.log("[yellow][!] Done.")
        exit()
    except KeyboardInterrupt:
        console.log("[red]\n[!!!] Ctrl + C Detected!")
        console.log("[red][XXX] Exiting script now..")
        exit()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        console.log("[red]\n[!!!] Ctrl + C Detected!")
        console.log("[red][XXX] Exiting script now..")
        exit()