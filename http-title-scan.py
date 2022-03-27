#!/usr/bin/env python3

import queue as Queue
import requests
import signal
import re
import threading
import logging
import argparse
import ipaddress
import sys
import coloredlogs
from time import sleep
from pyfiglet import Figlet

logger = logging.getLogger(__name__)
stop_requested = False
url_queue=Queue.Queue()
file_queue=Queue.Queue()
headers={"User-Agent": "Mozilla/5.0 (Windows NT 6.3; WOW64; rv:44.0) Gecko/20100101 Firefox/44.0"}



def banner():
    figlet = Figlet(font='slant')
    print(figlet.renderText("Mass Web-Title Scanner"))

def signal_handler(sig, frame):
    print('You pressed Ctrl+C!')
    global stop_requested 
    stop_requested = True
    sys.exit(0)


def args_parse():
    parser = argparse.ArgumentParser(description="Mass WebSite Title Scanner")
    ip_group = parser.add_mutually_exclusive_group(required=True)
    ip_group.add_argument('-ip', '--ipaddresses', type=str,help='IP address or IP range in format (x.x.x.x-x.x.x.x or x.x.x.x/24). Subnet is multile of 8')
    ip_group.add_argument('-f', '--ipfile', type=argparse.FileType('r'), help='Filename with path of IP addresses/ domains.')
    parser.add_argument('-p', '--ports', nargs='+', type=int, help='Ports for web service. All ports will be scanned for each IP. Space seperated' , default=['80'])
    parser.add_argument('-t', '--threads', type=int , help='Number of concurrent scans of IP addresses', default=10)
    parser.add_argument('-d', '--loglevel', type=str, help="Debug Level Setup.", default='INFO', choices=['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG'])
    parser.add_argument('-o', '--outputfile', type=argparse.FileType('a'), help="Output file name with path", default="http_identified_titles.txt")
    parser.add_argument('-l', '--logfile', help='log to file', dest='logfile', default=None)  

    args = parser.parse_args()
    return args


# Verifies/ tests args and return dictionary
def get_args(args):
    dargs = {}
    loglevel = ""
    if args.loglevel:
        if args.loglevel == 'INFO':
            loglevel = logging.INFO
        if args.loglevel == 'CRITICAL':
            loglevel = logging.CRITICAL
        if args.loglevel == 'ERROR':
            loglevel = logging.ERROR
        if args.loglevel == 'WARNING':
            loglevel = logging.WARNING
        if args.loglevel == 'DEBUG':
            loglevel = logging.DEBUG

        logger.setLevel(level=loglevel)
        stream_formatter = logging.Formatter('%(levelname)s - %(message)s')

        console_handler = logging.StreamHandler()
        console_handler.setLevel(level=loglevel)
        console_handler.setFormatter(stream_formatter)
        logger.addHandler(console_handler)

        if args.logfile:
            file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            file_handler = logging.FileHandler(args.logfile)
            file_handler.setLevel(level=loglevel)
            file_handler.setFormatter(file_formatter)
            logger.addHandler(file_handler)

        coloredlogs.install(logger=logger)
            
    
    if args.ipaddresses:
        try:
            ip_range = []
            if '/' in args.ipaddresses:
                for ip in list(ipaddress.ip_network(args.ipaddresses,False).hosts()):
                    ip_range.append(str(ip))
            elif "-" in args.ipaddresses:
                start = args.ipaddresses.split('-')[0]
                end = args.ipaddresses.split('-')[1]
                start_int = int(ipaddress.ip_address(start).packed.hex(), 16)
                end_int = int(ipaddress.ip_address(end).packed.hex(), 16)
                ip_range = [ipaddress.ip_address(ip).exploded for ip in range(start_int, end_int+1)]
            else:
                try:
                    if ipaddress.ip_address(args.ipaddresses):
                        ip_range = [args.ipaddresses]
                except:
                    logger.warning("Unable to categorize input IP/ file. Likely to disrupt program functionality.")
                    ip_range = [args.ipaddresses]

            dargs['ips'] = ip_range

            logger.info(f'Sucessfully fetched IP Addresses via range/ subnet')
            logger.debug(f'IP Ranges Identfied {ip_range}')
        except:
            logger.error('Cannot parse Input. Format not identified. Quiting')
            exit(1)
  
    if args.ipfile:
        with args.ipfile as file:
            lines = file.readlines()
            ip_range = [str(ip).strip() for ip in lines]
            dargs['ips'] = ip_range

            logger.info(f'Sucessfully fetched IP Addresses from file')
            logger.debug(f'IP Ranges Identfied {ip_range}')

    if args.ports:
        dargs['ports'] = args.ports
    
    if args.threads:
        if args.threads > 40  or args.threads < 1:
            logger.error("Threads value must be between 1 or 40")
            exit(1)
        else:
            if len(dargs['ips']) < 10:
                dargs['threads'] = len(dargs['ips'])
            else:
                dargs['threads'] = args.threads
            logger.debug(f"Thread value : {args.threads}")

    if args.outputfile:
        dargs['output'] = args.outputfile

    return dargs


# def init_file(filename):
#     ip_list = []
#     with open(filename,"r") as f:
#         for line in f.readlines():
#             ip = line.strip()
#             ip_list.append(ip)
#     return ip_list

def init(ip_range, ports):
        # ip_list=init_file(filename)
        for port in ports:
            port=str(port)
            for ip in ip_range:
                if "443" in port:
                    url="https://"+ip+":"+port
                else:
                    url="http://"+ip+":"+port
                url_queue.put(url)



def scan():
    global url_queue
    global file_queue
    url = ""
    while not stop_requested:
        try:
            url=url_queue.get(block=False)
        except:
            break
        try:
            r = requests.get(url, timeout=30, headers=headers, verify=False, allow_redirects=True)
            status_code = r.status_code
            response_url = r.url
            html_text = r.content
            title = re.search(r'<title>(.*)</title>', r.content.decode('utf-8'))  # get the title
            if title:
                title = title.group(1).strip().strip("\r").strip("\n")
            else:
                title = "None"
            server, language = "", ""
            for header in r.headers:
                if header == "Server":
                    server = r.headers[header]
                if "X-Powered-By" == header:
                    language = r.headers[header]
            file_queue.put(url + "\t" + str(status_code) + "\t" + title)
            logger.info(url+"\t" + str(status_code) + "\t" + f"{title}\t" + f"{server}\t" + f"{language}\t")
        except:
            logger.error(f"Request handling failed against {url}")
        finally:
            url_queue.task_done()

def main(dargs):
    init(dargs['ips'], dargs['ports'])

    sleep(1)
    thread_list=[]
    for i in range(dargs['threads']):
        t = threading.Thread(target=scan)
        thread_list.append(t)
        t.daemon = True
        t.start()
    for t in thread_list:
        t.join()

    with dargs['output'] as f:
        while True:
            try:
                line = file_queue.get(block=False)
            except:
                break
            f.write(line + "\n")

if __name__=="__main__":
    banner()
    signal.signal(signal.SIGINT, signal_handler)
    args = args_parse()
    dargs = get_args(args)
    print(dargs)
    main(dargs)
