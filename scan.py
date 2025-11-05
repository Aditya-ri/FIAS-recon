#!/usr/bin/env python3 

import socket 
import argparse 
from ipaddress import ip_network,ip_address
import sys
import threading
from queue import Queue
import json
from colorama import Fore, Style, init
import random


def main():

    print_banner()

    # use parser  for : pick the user input and hand it out to the script
    parser = argparse.ArgumentParser(description ="A Simple Python network scanner")

    # Add arguments
    parser.add_argument("-t", "--target",
                        dest ="target", # value defined by author of argparse library that take -t as target
                        help="Target to scan.(e.g. , 192.168.1.1, 192.168.1.0/24, example.com)",
                        required=True)
    
    parser.add_argument("-p", "--ports",
                        dest ="ports",
                        help="port to scan.(e.g., 80, 443, 1-1000 )",
                        required=True)
    
    parser.add_argument("-w", "--workers",
                        dest ="workers",
                        help="Number of concurrent threads (default: 100)",
                        default=100,
                        type= int)

    #parse the arg
    
    args = parser.parse_args()
   

    target_list= get_target_ips(args.target)
    port_list=get_target_ports(args.ports)

    print(f"[*]Target(s) to scan:")
    for ip in target_list:
        print(f"-> {ip}")

    print(f"\n[*]port(s) to scan:")    
    print(f"->{port_list}")

    print(f"[*] Scanning {len(target_list)} target(s) and {len(port_list)} port(s)....")

    NUM_WORKER= args.workers # a variable for how many worker(threads) to create

    for ip in target_list:
        print(f"\n -----result for {ip}-----")

        #1. Create new job queue
        job_queue = Queue()

        #2 create the shared result list AND the lock to protect it
        open_ports_found =[]
        results_lock = threading.Lock()

        #3. hire the workwer (create and start the thread)
        for i in range (NUM_WORKER):
            t= threading.Thread(
                target=worker,
                args=(job_queue, ip, open_ports_found, results_lock)
            )
            t.daemon = True # this let the script exit even if threads are stuck
            t.start()

        #4. load the truck(fill the queue with jobs)
        for port in port_list:
            job_queue.put(port)    

         #5 wait for all the jobs to be done"
        job_queue.join()

        if not open_ports_found:
            print(f"[-] No open ports found in the specific list.")
        else :
            open_ports_found.sort(key=lambda x: x['port'])
            print(f"\n [+]  Open ports found:")

            for item in open_ports_found:
                #using string formatting to align things nicely
                print(f" -Port {item['port']:<5} : {item['banner']}")


    print("\n [*] scan complete.")


def print_banner():
    """Print the FIAS splash screen"""    
    # this auto -reset the color after each print
    init(autoreset=True)

    fias_art_1= r"""
      ___                       ___           ___     
     /\__\                     /\  \         /\__\    
    /:/ _/_       ___         /::\  \       /:/ _/_   
   /:/ /\__\     /\__\       /:/\:\  \     /:/ /\  \  
  /:/ /:/  /    /:/__/      /:/ /::\  \   /:/ /::\  \ 
 /:/_/:/  /    /::\  \     /:/_/:/\:\__\ /:/_/:/\:\__\
 \:\/:/  /     \/\:\  \__  \:\/:/  \/__/ \:\/:/ /:/  /
  \::/__/       ~~\:\/\__\  \::/__/       \::/ /:/  / 
   \:\  \          \::/  /   \:\  \        \/_/:/  /  
    \:\__\         /:/  /     \:\__\         /:/  /   
     \/__/         \/__/       \/__/         \/__/     
    """
    fias_art_2=r'''
     .----------------.  .----------------.  .----------------.  .----------------. 
    | .--------------. || .--------------. || .--------------. || .--------------. |
    | |  _________   | || |     _____    | || |      __      | || |    _______   | |
    | | |_   ___  |  | || |    |_   _|   | || |     /  \     | || |   /  ___  |  | |
    | |   | |_  \_|  | || |      | |     | || |    / /\ \    | || |  |  (__ \_|  | |
    | |   |  _|      | || |      | |     | || |   / ____ \   | || |   '.___`-.   | |
    | |  _| |_       | || |     _| |_    | || | _/ /    \ \_ | || |  |`\____) |  | |
    | | |_____|      | || |    |_____|   | || ||____|  |____|| || |  |_______.'  | |
    | |              | || |              | || |              | || |              | |
    | '--------------' || '--------------' || '--------------' || '--------------' |
     '----------------'  '----------------'  '----------------'  '----------------' 
    '''

    fias_art_3= r'''
        ___    ___     ___     ___   
       | __|  |_ _|   /   \   / __|  
       | _|    | |    | - |   \__ \  
      _|_|_   |___|   |_|_|   |___/  
    _| """ |_|"""""|_|"""""|_|"""""| 
    "`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-' 

    '''
    fias_art_4= r'''
              _        _          _                  _        
            /\ \     /\ \       / /\               / /\      
           /  \ \    \ \ \     / /  \             / /  \     
          / /\ \ \   /\ \_\   / / /\ \           / / /\ \__  
         / / /\ \_\ / /\/_/  / / /\ \ \         / / /\ \___\ 
        / /_/_ \/_// / /    / / /  \ \ \        \ \ \ \/___/ 
       / /____/\  / / /    / / /___/ /\ \        \ \ \       
      / /\____\/ / / /    / / /_____/ /\ \   _    \ \ \      
     / / /   ___/ / /__  / /_________/\ \ \ /_/\__/ / /      
    / / /   /\__\/_/___\/ / /_       __\ \_\\ \/___/ /       
    \/_/    \/_________/\_\___\     /____/_/ \_____\/        
                                                         
    '''
    
    art_gallery = [fias_art_1,fias_art_2, fias_art_3, fias_art_4]

    color_palette = [Fore.CYAN, Fore.GREEN, Fore.RED, Fore.YELLOW, Fore.MAGENTA, Fore.BLUE, Fore.LIGHTMAGENTA_EX]

    random_color = random.choice(color_palette)
    random_art = random.choice(art_gallery)

    print(random_color+random_art)

    print(Fore.RED + "    The FIAS Recon Scanner.")
    print(Fore.LIGHTWHITE_EX + "    ------------------------------------------")
    print(Fore.LIGHTBLUE_EX + "    :  Author: ADITYA CHHIMPA                :")
    print(Fore.LIGHTBLUE_EX + "    :  GitHub: https://github.com/Aditya-ri  :")
    print(Fore.LIGHTWHITE_EX + "    ------------------------------------------")
    print("\nEXplore the Scanner LANDSCAPE......")


def get_target_ips(target_str):
    """
    takes a target string and return a list of ip address.
    handles single IP, CIDRblock, or Hostname
    """
    target=[]

    try:
        #check if it is a CIDR network(e.g., 192.168.1.0/24)
        network=ip_network(target_str, strict=False)
        for ip in network.hosts():
            target.append(str(ip))
    except ValueError:
        try:
            #check if its a single ip
            ip=ip_address(target_str)
            target.append(str(ip))
        except ValueError:
            #if not a network ip, assume its a hostname
            try:
                ip=socket.gethostbyname(target_str)
                target.append(str(ip))
            except socket.gaierror:                
                print(f"[!] ERROR: Cannot resolve host name'{target_str}. Exiting.")
                sys.exit(1)

    return target
            
def get_target_ports(port_str):
    """
    take a port string (e.g., "80,443,22-100") and return a list of integers
    """
    # use a set to auutomatically handle duplicate (e.g., "80,80")
    port_set = set()
    # first, split  by comma to get individual entries
    entries = port_str.split(',')

    for entry in entries :
        entry = entry.strip() #clean up any whitespaces

        try:
            #check if it's a range
            if '-' in entry:
                # it's a range "22-1000"
                start, end = entry.split('-')
                start_port = int(start)
                end_port = int(end)
                
                # a user can also enter 100-22 so we have to swap
                if start_port > end_port:
                    start_port, end_port = end_port, start_port

                # all port should be in range 1-65535
                for port in range (start_port, end_port + 1):
                    if 1<= port <= 65535:
                        port_set.add(port)  

            elif entry.isdigit():
                # for its a single port like "80"
                port = int(entry)
                if 1 <= port <= 65535:
                    port_set.add(port)

            else:
                # it's invalid text
                if entry :# don't warn on empt string from "80,,443"
                    print(f"[!] warning: skipping invalid port entry '{entry}'")    

        except ValueError:
            # error from int() conversion or bad split
            print(f"[!] warning : skipping invalid port format'{entry}'")            
 
    return sorted(list(port_set))

def scan_port (ip, port, timeout=1.0):
    """
    attempts a TCP connect scan on a simgle ip or port
    return true if open , false if close/unfiltered
    """
    # create a new socket object
    # AF_INET = IPv4
    # SOCK_STREAM = TTCP

    try: 
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)

            if s.connect_ex((ip,port))==0: # s.connect_ex ko ek input dena hota h but hame ip and port dono ki jarurath to ek tuple bna diya
                return True
    except socket.error as e:
        # Handle potential errors (e.g., network unreachable)
        # print(f"[!] Socket error for {ip}:{port} -> {e}")
        pass # Just treat it as not open

    return False

_probes_cache = None

def get_probes():
    """
    Loads the probes.json file into our _probes_cache
    """
    global _probes_cache
    if _probes_cache:
        return _probes_cache
    
    try:
        with open('probes.json', 'r') as f:
            _probes_cache = json.load(f) # json file ko as a python ki tarah store kiya h
            return _probes_cache
        
    except FileNotFoundError:
        print("[!] Error: 'probes.json' not found. Banner grabbing diasbled ")
        _probes_cache = [] # Set to empty list to prevent re-trying
        return[]

    except json.JSONDecodeError:
        print("[!] Error: 'probes.json' is badly formatted. Check syntax.")
        _probes_cache = []
        return []
    
def probe_port(ip, port, timeout=2.0):
    """
    Connects, probes, and identifies the service using probe.json
    """    

    print(f"-> Probing port {port}...")

    port = int(port)

    #1. load our "brains"
    probes= get_probes()

    # NEW debug block
    if not probes:
        print("[FATAL] get_probes() retuned an empty list . File not found or is empty/corrupt.")
        # we can't continue, so just return
        return "Error: Probe file empty or not found"
    
    print(f"-> Loaded {len(probes)} probe rules.")
    # end of new debug block

    #2. find the right probe for this port
    probe_to_try = None
    for p in probes:
        # type checking debug
       # print(f"[Debug] Checking port{port} (type{type(port)}) against ports {p['ports']} (type{type(p['ports'][0])})")
        print("----------------------------")
        
        if port in p['ports']:
            probes_to_try = p
            break

    #3. if it's a "special case" like SSL, handle it and exit
    if probe_to_try and probe_to_try['probe'] == "special_ssl":
        return probe_to_try['name'] # it will return "http ssl"
# ye connection response nhi dekhta upto my consideration and just sy its there
    
    #4. default: just connect and listen (our old falback)
    banner = "Unknown (No probe match)"
    probe_data = b"" # here "" means empy string and b means raw data like 104, 309 etc we are adding this to send nothing

    if probe_to_try:
        print(f" Found probe rule : {probe_to_try['name']}")
        #if a text probe exists, prepare it
        if probe_to_try['probe']:
            #replace ip placeholder and encode to bytes
            probe_str = probes_to_try['probe'].replace('{ip}', ip)
            probe_data = probe_str.encode('utf-8')
    else:
        print(" ** No probe rule found for this port")        

    #5. The actual connection logic 
    try :
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip,port))

            # send the probe if we have one
            if probe_data:
                print(f"[Debug] Sending probe: {probe_data}")
                s.sendall(probe_data)
            
            s.shutdown(socket.SHUT_WR) # connection not closed but put on hold to recieve the reponse
            # listen for the reply
            banner_bytes = s.recv(1024)            
            banner = banner_bytes.decode('utf-8', errors='ignore').strip()

            if not banner:
                return "Unknown (No banner returned)"
            
            # till now we are taking about the sending and recieving of probe now we will match it
            if probe_to_try and probe_to_try['match']:
                if probe_to_try['match'] in banner:
                    return f"{probe_to_try['name']} ({banner.split('\n')[0]})"
                else:
                    # we got a reply, but it didn't match
                    return f"Unknown({banner.split('\n')[0]})"

            else:
                # no probe was defined, so just return the raw banner
                return f"Raw banner: {banner.split('\n')[0]}"

    except socket.timeout:
        return "Unknown (Connection timed out)"
    except socket.error:
        return "Unknown (Connection refused/reset)"           


# we need to assign a thread to run the job simultaneously
def worker(q, ip , open_ports, lock):
    #the function each thread will run
    while True:
        port = None
        try:
            #1.get a job from the queue
            port=q.get(timeout=1)

        except:
        #if queue is empty or we timeout, the thread is done
            break
        #2 run the job(using th efunction we defined earlier)
        try:
            if scan_port(ip,port):

                # * we are adding a new function grabing the banner
                banner= probe_port(ip, port)
                #3 get the key - matlab jaise koi ek value apni vlur ka result de rha h aur dusra aa jaye to yah race condition hogi to har ek ko ek key ka wait karna hoga millisecond
                with lock:
                    # * store the result as a dictionary
                    result={'port': port, 'banner': banner}
                    open_ports.append(result)
        finally:
            q.task_done()        

if __name__=="__main__":
    main()
        
