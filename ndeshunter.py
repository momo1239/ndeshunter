import argparse
import threading
import queue
import ipaddress
import os
import requests
import logging
import socket
from impacket import uuid
from impacket.dcerpc.v5 import transport, epm

socket.setdefaulttimeout(5)

RED = '\033[91m'
RESET = '\033[0m'

logging.basicConfig(level=logging.CRITICAL)

print_lock = threading.Lock()
vulnerable_targets = []
vulnerable_targets_lock = threading.Lock()

NDES_PATH = "/certsrv/mscep"

def check_ndes_endpoint(ip):
    url = f"http://{ip}{NDES_PATH}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code in [200, 403, 401]:
            return True
    except requests.RequestException:
        pass
    return False

def parse_input_line(line):
    line = line.strip()
    if not line:
        return []
    try:
        if '/' in line:
            return [str(ip) for ip in ipaddress.ip_network(line, strict=False)]
        else:
            ipaddress.ip_address(line)
            return [line]
    except ValueError:
        return [line]

class RPCDump:
    KNOWN_PROTOCOLS = {
        135: {'bindstr': r'ncacn_ip_tcp:%s[135]'},
        139: {'bindstr': r'ncacn_np:%s[\pipe\epmapper]'},
        443: {'bindstr': r'ncacn_http:[593,RpcProxy=%s:443]'},
        445: {'bindstr': r'ncacn_np:%s[\pipe\epmapper]'},
        593: {'bindstr': r'ncacn_http:%s'}
    }

    def __init__(self, port=135):
        self.__port = port
        self.__stringbinding = ''

    def dump(self, remoteName, remoteHost):
        entries = []
        self.__stringbinding = self.KNOWN_PROTOCOLS[self.__port]['bindstr'] % remoteName
        rpctransport = transport.DCERPCTransportFactory(self.__stringbinding)
        rpctransport.setRemoteHost(remoteHost)
        rpctransport.set_dport(self.__port)
        try:
            rpctransport.set_connect_timeout(5)
        except AttributeError:
            pass
        dce = rpctransport.get_dce_rpc()
        try:
            dce.set_rpc_timeout(5)
        except AttributeError:
            pass
        try:
            dce.connect()
            resp = epm.hept_lookup(None, dce=dce)
            dce.disconnect()
            return resp
        except:
            return []

def worker(ip_queue, progress):
    while True:
        ip = ip_queue.get()
        if ip is None:
            ip_queue.task_done()
            break

        output_messages = [f"Testing {ip}"]
        try:
            dumper = RPCDump(port=135)
            entries = dumper.dump(ip, ip)
            if entries:
                for entry in entries:
                    binding = epm.PrintStringBinding(entry['tower']['Floors'])
                    tmpUUID = str(entry['tower']['Floors'][0])
                    exe_name = epm.KNOWN_UUIDS.get(
                        uuid.uuidtup_to_bin(uuid.string_to_uuidtup(tmpUUID))[:18], b'N/A'
                    ).decode('utf-8', errors='ignore').lower()
                    if 'ndes' in exe_name or 'mscep' in exe_name or 'certsrv.exe' in exe_name:
                        output_messages.append(f"\nPotential NDES server detected on {ip}")
                        if check_ndes_endpoint(ip):
                            output_messages.append(f"{RED}Vulnerable NDES endpoint found: http://{ip}{NDES_PATH}{RESET}")
                            with vulnerable_targets_lock:
                                vulnerable_targets.append(ip)
                        else:
                            output_messages.append(f"No NDES endpoint found on {ip}")
                        break
        except Exception:
            pass
        finally:
            with print_lock:
                print('\n'.join(output_messages))
            with progress.get_lock():
                progress.value += 1
            ip_queue.task_done()

def run_ndes_scan(ip_list):
    num_worker_threads = 10
    ip_queue = queue.Queue()

    class Progress:
        def __init__(self, total):
            self.value = 0
            self.total = total
            self._lock = threading.Lock()

        def get_lock(self):
            return self._lock

    progress = Progress(len(ip_list))

    threads = []
    for _ in range(num_worker_threads):
        t = threading.Thread(target=worker, args=(ip_queue, progress))
        t.start()
        threads.append(t)

    try:
        for ip in ip_list:
            ip_queue.put(ip.strip())
        ip_queue.join()
        for _ in range(num_worker_threads):
            ip_queue.put(None)
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        for _ in range(num_worker_threads):
            ip_queue.put(None)
        for t in threads:
            t.join()

def main():
    try:
        parser = argparse.ArgumentParser(description='Scan for exposed NDES endpoints.')
        parser.add_argument('-t', '--target', required=True, help='IP address, CIDR, hostname, or file containing targets')
        args = parser.parse_args()

        user_input = args.target
        if os.path.isfile(user_input):
            ip_list = []
            with open(user_input, 'r') as file:
                for line in file:
                    ip_list.extend(parse_input_line(line))
            ip_list = list(set(ip_list))
        else:
            ip_list = list(set(parse_input_line(user_input)))

        run_ndes_scan(ip_list)

        if vulnerable_targets:
            with print_lock:
                print(f"\n{RED}Vulnerable NDES targets found:{RESET}")
                for target in vulnerable_targets:
                    print(f" - {target}")
                print(f"\nSuggested command:")
                for target in vulnerable_targets:
                    print(f"{RED}impacket-ntlmrelayx -t http://{target}/certsrv/mscep_admin/ -smb2support")
        else:
            print("\nNo vulnerable NDES endpoints found.")

    except KeyboardInterrupt:
        print("\nInterrupted by user. Exiting.")

if __name__ == "__main__":
    main()
