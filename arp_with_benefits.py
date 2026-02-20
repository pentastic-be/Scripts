#!/usr/bin/env python3
'''
	Copyright 2026 Pentastic

        This program is free software: you can redistribute it and/or modify
        it under the terms of the GNU General Public License as published by
        the Free Software Foundation, either version 3 of the License, or
        (at your option) any later version.

        This program is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
        GNU General Public License for more details.

        You should have received a copy of the GNU General Public License
        along with this program.  If not, see <http://www.gnu.org/licenses/>.

        This script listens for arp requests and checks which ones will remain unanswered.
        This allows you to claim that ip on your own machine and check for inbound traffic.
        
        This should work on Linux using Python3
'''

import os
import time
import threading
import argparse
from datetime import datetime, timedelta
from scapy.all import (
    ARP,
    Ether,
    srp,
    sniff,
    get_if_list,
    get_if_addr,
    get_if_hwaddr
)

hosts = {}
lock = threading.Lock()
own_ip = None
own_mac = None
stop_event = threading.Event()


def list_interfaces():
    interfaces = get_if_list()
    print("Available interfaces:\n")
    for i, iface in enumerate(interfaces):
        print(f"[{i}] {iface}")
    return interfaces


def select_interface():
    interfaces = list_interfaces()
    while True:
        try:
            choice = int(input("\nSelect interface number: "))
            return interfaces[choice]
        except (ValueError, IndexError):
            print("Invalid selection. Try again.")


def arp_sniffer(interface):
    def process_packet(packet):
        if not packet.haslayer(ARP):
            return

        arp = packet[ARP]

        # Ignore packets from ourselves
        if arp.hwsrc.lower() == own_mac.lower():
            return

        now = datetime.now()

        with lock:
            # Track sender (psrc)
            if arp.psrc != own_ip:
                if arp.psrc not in hosts:
                    hosts[arp.psrc] = {
                        "mac": arp.hwsrc,
                        "status": "Unknown",
                        "last_seen": now,
                        "arp_requests": 1
                    }
                else:
                    hosts[arp.psrc]["last_seen"] = now
                    hosts[arp.psrc]["mac"] = arp.hwsrc
                    hosts[arp.psrc]["arp_requests"] += 1

            # Track target of ARP request (pdst)
            if arp.op == 1 and arp.pdst != own_ip:
                if arp.pdst not in hosts:
                    hosts[arp.pdst] = {
                        "mac": "Unknown",
                        "status": "Unknown",
                        "last_seen": now,
                        "arp_requests": 1
                    }
                else:
                    hosts[arp.pdst]["arp_requests"] += 1

    sniff(
        iface=interface,
        filter="arp",
        prn=process_packet,
        store=False,
        stop_filter=lambda x: stop_event.is_set()
    )


def check_host(ip, interface, timeout=1):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    answered, _ = srp(packet, timeout=timeout, iface=interface, verbose=False)
    return len(answered) > 0


def monitor_hosts(interface, interval):
    while not stop_event.is_set():
        time.sleep(interval)

        with lock:
            ips = list(hosts.keys())

        for ip in ips:
            if ip == own_ip:
                continue

            alive = check_host(ip, interface)
            with lock:
                hosts[ip]["status"] = "Online" if alive else "Offline"

        print_table(interval)


def print_table(interval):
    os.system("clear")
    print(f"ARP Monitor - Refresh every {interval}s")
    print(f"Interface IP: {own_ip}")
    print(f"Interface MAC: {own_mac}\n")

    print("{:<16} {:<20} {:<10} {:<8} {}".format(
        "IP", "MAC", "Status", "ARP#", "Last Seen"))
    print("-" * 85)

    with lock:
        sorted_hosts = sorted(
            hosts.items(),
            key=lambda item: (
                item[1]["status"] != "Offline",   # Offline first
                -item[1]["arp_requests"],         # Most requested first
                item[0]                           # Stable IP sort
            )
        )

        for ip, data in sorted_hosts:
            print("{:<16} {:<20} {:<10} {:<8} {}".format(
                ip,
                data["mac"],
                data["status"],
                data["arp_requests"],
                data["last_seen"].strftime("%H:%M:%S")
            ))


def main():
    global own_ip, own_mac

    parser = argparse.ArgumentParser(description="ARP Network Monitor")
    parser.add_argument(
        "--interval",
        type=int,
        default=5,
        help="Refresh/check interval in seconds (default: 5)"
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=300,
        help="Total runtime in seconds (default: 300 = 5 minutes)"
    )

    args = parser.parse_args()

    interface = select_interface()
    own_ip = get_if_addr(interface)
    own_mac = get_if_hwaddr(interface)

    print(f"\nListening on {interface}")
    print(f"IP: {own_ip} | MAC: {own_mac}")
    print(f"Interval: {args.interval}s | Duration: {args.duration}s\n")

    sniffer_thread = threading.Thread(
        target=arp_sniffer,
        args=(interface,),
        daemon=True
    )

    monitor_thread = threading.Thread(
        target=monitor_hosts,
        args=(interface, args.interval),
        daemon=True
    )

    sniffer_thread.start()
    monitor_thread.start()

    end_time = datetime.now() + timedelta(seconds=args.duration)

    while datetime.now() < end_time:
        time.sleep(1)

    stop_event.set()
    print("\nMonitoring finished.\n")


if __name__ == "__main__":
    main()
