#!/usr/bin/env python3
# 7/9/21 GitStoph
# Splunk script to search windows DHCP logs
##################################################
import sys
import os
from time import sleep
import splunklib.results as results
import splunklib.client as client
from dotenv import load_dotenv
import argparse
from rich.console import Console
from rich.table import Table

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
global timeoptions
timeoptions = ['15m', '30m', '1h', '4h', '8h', '12h', '16h', '24h']

def get_args():
    parser = argparse.ArgumentParser(
        description='Splunk firewall log search tool. Be smart with your args, or face a mile of output. Script will *attempt* to dedupe output. Use the "-o" flag to print the output you should include in a netadmin ticket.')
    parser.add_argument('-a', '--action',required=False,type=str, default=argparse.SUPPRESS,
        nargs='?', help="OPTIONAL: 'allowed' is the only acceptable arg. Scripts default to anything but allowed. ")
    parser.add_argument('-d', '--dest',required=False,type=str, default=argparse.SUPPRESS,
        nargs='?', help="OPTIONAL: Destination IP for the query?")
    parser.add_argument('-o', '--output',required=False,type=str, default=argparse.SUPPRESS,
        nargs='?', help="OPTIONAL: Pass this arg to view the full output for a ticket.")
    parser.add_argument('-s', '--source',required=False,type=str, default=argparse.SUPPRESS,
        nargs='?', help="OPTIONAL: Source IP for the query?")
    parser.add_argument('-t', '--time',required=False,type=str, default='30m',action='store',
        help="OPTIONAL: How far back should we look? Default is '30m'. Max is '24h'. Options are: {0}".format(str(timeoptions)))
    parser.add_argument('-u', '--user',required=False,type=str, default=argparse.SUPPRESS,
        nargs='?', help='OPTIONAL: Scope results to a user?')
    args = parser.parse_args()
    return args


def build_search_query(args):
    """Update the index to your particular firewall's index. Also note that your table options may differ. This code is suited
    to work immediately for PaloAlto network logs.
    First it looks to see if time args are passed, and if so, updates the query with that info. If not, it defaults to the last 30m.
    If the action arg is passed, it updates the query accordingly, but defaults to anything but allowed.
    If destination info is passed, it updates the query with it.
    If source ip info is passed, it updates the query with it.
    If a username is passed, it updates the query with it.
    Finally it tells the output to return as a table, which returns a clean dict for the script to use."""
    query = 'search index=sec_net_firewall '
    if 'time' in args:
        if args.time in timeoptions:
            kwargs_normalsearch = {'exec_mode': 'normal', 'earliest_time': "-{0}".format(args.time), 'latest_time': 'now'}
        else:
            console.log("[red]{0} was not a valid time option. Time set to 30m.")
            kwargs_normalsearch = {'exec_mode': 'normal', 'earliest_time': '-30m', 'latest_time': 'now'}
    else:
        console.log("[yellow]Using default 30m time for query.")
        kwargs_normalsearch = {'exec_mode': 'normal', 'earliest_time': '-30m', 'latest_time': 'now'}
    if 'action' in args:
        if args.action == 'allowed':
            query += "action=allowed "
        else:
            console.log("[red]{0} was passed for an action. Query will parse as 'action!=allowed'".format(args.action))
            query += "action!=allowed "
    else:
        query += "action!=allowed "
    if 'dest' in args:
        query += "dest_ip={0} ".format(args.dest)
    if 'source' in args:
        query += "src_ip={0} ".format(args.source)
    if 'user' in args:
        query += "user=*{0} ".format(args.user)
    query += "| table _time host src_zone src_interface src_ip user dest_zone dest_interface dest_ip dest_port transport application rule action bytes"
    console.log("[green]Query to be used: {0}.".format(query))
    return query, kwargs_normalsearch


def build_service():
    """Builds the service object using the client function after grabbing the necessary fields from a .env file."""
    service = client.connect(host=os.getenv('SPLUNK_HOST'),
                            port=os.getenv('SPLUNK_PORT'),
                            scheme=os.getenv('SPLUNK_SCHEME'),
                            username=os.getenv('SPLUNK_USER'),
                            password=os.getenv('SPLUNK_PASS'))
    return service


def query_fw(query, kwargsearch):
    """Uses the format_mac_windhcp to create a potential MAC to search which gets plugged into the searchquery_normal format line. The rest of the line is formatted with the original
    query string in case it wasn't a MAC address originally passed. kwargs are added to do a normal search over the last 72hours. Stats are printed out to the console.log to let the
    user know the status of their search. Logs are then extracted from the job and returned."""
    console.log("[yellow]Searching firewall logs..")
    job = service.jobs.create(query, **kwargsearch)
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
            console.log("[yellow][!] Search Completed!\n")
            break
        sleep(1)
    logs = [x for x in results.ResultsReader(job.results())]
    job.cancel()
    return logs


def dedupe_firewall_logs(logs):
    """Dedupes by concatenating application, dest_ip, dest_port, and src_ip fields. """
    macs = set()
    nodupes = []
    for x in logs:
        z = tuple(sorted(x.items()))
        y = z[2]+z[5]+z[6]+z[12]
        if y not in macs:
            macs.add(y)
            nodupes.append(x)
    return nodupes


def full_log_output(logs):
    """Builds the rich table, adds the columns, adds the rows, then prints it nicely in green.
    This option prints the full results of the splunk table. I hope your console is wide."""
    logkeys = ['_time', 'host', 'src_zone', 'src_interface', 'src_ip', 'user',
    'dest_zone', 'dest_interface', 'dest_ip', 'dest_port', 'transport', 'application',
    'rule', 'action', 'bytes']
    if len(logs) != 0:
        try:
            table = Table(show_header=True, header_style="cyan", show_lines=True)
            table.add_column("_time", justify="center")
            table.add_column("host", justify="center")
            table.add_column("src_zone", justify="center")
            table.add_column("src_int", justify="center")
            table.add_column("src_ip", justify="center")
            table.add_column("user", justify="center")
            table.add_column("dest_zone", justify="center")
            table.add_column("dest_int", justify="center")
            table.add_column("dest_ip", justify="center")
            table.add_column("dest_port", justify="center")
            table.add_column("transport", justify="center")
            table.add_column("application", justify="center")
            table.add_column("rule", justify="center")
            table.add_column("action", justify="center")
            table.add_column("bytes", justify="center")
            for u in logs:
                for key in logkeys:
                    if key not in u.keys():
                        u[key] = 'Missing.'
            for u in logs:
                table.add_row(u['_time'].split('.')[0], u['host'],
                u['src_zone'], u['src_interface'], u['src_ip'], u['user'], u['dest_zone'],
                u['dest_interface'], u['dest_ip'], u['dest_port'], u['transport'],
                u['application'], u['rule'], u['action'], u['bytes'])
            console.print(table, style='green')
            print("\n")
        except:
            console.print("[!] Error: ", sys.exc_info(), style='bold red')
            pass
    else:
        console.log("[red]No firewall logs located.")


def short_log_output(logs):
    """Builds the rich table, adds the columns, adds the rows, then prints it nicely in green.
    This option prints an abbreviated output of the table with more basic info."""
    logkeys = ['_time', 'host', 'src_zone', 'src_interface', 'src_ip', 'user',
    'dest_zone', 'dest_interface', 'dest_ip', 'dest_port', 'transport', 'application',
    'rule', 'action', 'bytes']
    if len(logs) != 0:
        try:
            table = Table(show_header=True, header_style="cyan", show_lines=True)
            table.add_column("_time", justify="center")
            table.add_column("host", justify="center")
            table.add_column("src_ip", justify="center")
            table.add_column("dest_ip", justify="center")
            table.add_column("dest_port", justify="center")
            table.add_column("application", justify="center")
            table.add_column("action", justify="center")
            for u in logs:
                for key in logkeys:
                    if key not in u.keys():
                        u[key] = 'Missing.'
            for u in logs:
                table.add_row(u['_time'].split('.')[0], u['host'],
                u['src_ip'], u['dest_ip'], u['dest_port'], u['application'], u['action'])
            console.print(table, style='green')
            print("\n")
        except:
            console.print("[!] Error: ", sys.exc_info(), style='bold red')
            pass
    else:
        console.log("[red]No firewall logs located.")


def main():
    try:
        args = get_args()
        global service
        service = build_service()
        query, ksearch = build_search_query(args)
        try:
            if 'output' in args:
                full_log_output(dedupe_firewall_logs(query_fw(query, ksearch)))
            else:
                short_log_output(dedupe_firewall_logs(query_fw(query, ksearch)))
        except:
            console.print("[!] Error: ", sys.exc_info(), style='bold red')
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