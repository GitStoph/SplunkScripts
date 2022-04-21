#!/usr/bin/env python3
# 7/22/20 GitStoph
# Splunk script to search windows logs for 4624s to tie users to machines.
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
        description='This script searches your splunk windows logs for EventCode 4624 to attempt to map usernames to a computer name.')
    parser.add_argument('-s', '--search',required=False,type=str,default='None',action='store', help='Username to search?')
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


def query_win_users(query):
    """Uses the format_mac_windhcp to create a potential MAC to search which gets plugged into the searchquery_normal format line. The rest of the line is formatted with the original
    query string in case it wasn't a MAC address originally passed. kwargs are added to do a normal search over the last 72hours. Stats are printed out to the console.log to let the
    user know the status of their search. Logs are then extracted from the job and returned.
    The index will need to be updated to be relevant to your splunk environment."""
    console.log("[green] Searching Windows OS logs..")
    searchquery_normal = 'search index=my_relevant_windows_index user={0} EventCode=4624 app="win:local" | table host EventCode user'.format(query)
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


def dedupe_win_logs(logs):
    """Dedupe by MAC address. """
    macs = set()
    nodupes = []
    for x in logs:
        if 'host' in x.keys():
            y = tuple(sorted(x.items()))[1]
            if y not in macs:
                macs.add(y)
                nodupes.append(x)
    return nodupes


def pretty_windows_output(logs):
    """Creates the pretty table, and prints it in green."""
    if len(logs) != 0:
        try:
            table = Table(show_header=True, header_style="cyan", show_lines=True)
            table.add_column("User", justify="center")
            table.add_column("Host", justify="center")
            table.add_column("EventCode", justify="center")
            for u in logs:
                table.add_row(u['user'], u['host'], u['EventCode'])
            console.print(table, style='green')
            print("\n")
        except:
            console.print("[!] Error: ", sys.exc_info(), style='bold red')
            pass
    else:
        console.log("[red]No Windows User logs located.")


def main():
    try:
        args = get_args()
        global service
        service = build_service()
        try:
            pretty_windows_output(dedupe_win_logs(query_win_users(args.search)))
        except:
            console.log("[red] No windows User logs were found.")
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