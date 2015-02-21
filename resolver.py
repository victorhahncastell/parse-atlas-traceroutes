#!/usr/bin/env python3

import threading
from ipaddress import ip_address, IPv4Address, IPv6Address

import logging
l = logging.getLogger(__name__)

class Resolver:
    def __init__(self, controller):
        self.c = controller
        self.resolve_dns = False
        self.resolve_whois = False
        self.nameservers = ["8.8.8.8", "8.8.4.4"]
        self.preresolved_dns = {}
        self.preresolved_whois = {}
        self.preresolve_lock_dns = {}
        self.preresolve_lock_whois = {}
        self.preresolve_addrs = []
        self.dnspython_present = False

        global dns  # for import
        # Standard library DNS resolve stuff
        import socket

        self.socket = socket
        self.socket.setdefaulttimeout(1)

        try:  # Speedy DNS resolver
            import dns.resolver
            import dns.reversename

            self.dnspython_present = True
        except ImportError as e:
            l.warn("Could not load module dnspython. DNS resolution may be quite slow. Error was: " + str(e))
        if self.dnspython_present:
            self.dns_client = dns.resolver.Resolver()
            self.dns_client.nameservers = self.nameservers
            self.dns_client.lifetime = 1  # don't spend more than a second per query

        global cymruwhois
        try:  # Whois
            import cymruwhois
        except ImportError as e:
            l.error(
                "Could not load module cymruwhois. Whois information (AS etc.) will not be provided. Error was: " + str(
                    e))
            self.resolve_whois = False


    def preresolve(self, addrs, concurrent_threads=100):
        if self.resolve_dns:
            self.preresolve_dns(addrs, concurrent_threads)
        if self.resolve_whois:
            self.preresolve_whois(addrs, concurrent_threads)

    def preresolve_dns(self, addrs, concurrent_threads=100):
        PreresolveManager(list(addrs), self.lookup_dns, 1, concurrent_threads)

    def preresolve_whois(self, addrs, concurrent_threads=10):
        PreresolveManager(list(addrs), self.lookup_whois, 100, concurrent_threads)

    def lookup_dns(self, addr):
        """
        Get a reverse DNS name.
        Names we have resolved will be cached and used for any further requests to this resolver.
        @param addr: The IP address or a list of addresses to resolve.
        @return: Reverse domain name as string or none.
        @rtype: str
        """
        if isinstance(addr, (str, IPv4Address, IPv6Address)):        # just one address given as arg
            return self._lookup_dns_single(ip_address(addr))
        else:                                          # multiple addresses given as arg
            for item in addr:
                self._lookup_dns_single(ip_address(item))

    def _lookup_dns_single(self, addr):
        if addr not in self.preresolve_lock_dns:
            self.preresolve_lock_dns[addr] = threading.Lock()
        self.preresolve_lock_dns[addr].acquire()

        if addr in self.preresolved_dns:  # answer already in cache?
            ret = self.preresolved_dns[addr]
        else:
            l.debug("Cache miss on single DNS lookup for address " + str(addr) + ".")
            answer = self._lookup_dns(addr)
            self.preresolved_dns[addr] = answer   # cache this shit!
            ret = answer
        self.preresolve_lock_dns[addr].release()
        return ret

    def _lookup_dns(self, addr):
        """
        Actually performs the lookup. Call lookup_dns() instead which handles caching.
        @param addr: The IP address to resolve.
        @return: Reverse domain name as string or False.
        @rtype: str
        """
        if self.dnspython_present:
            try:
                reversename = dns.reversename.from_address(str(addr))
                answer = self.dns_client.query(reversename, "PTR")
                string = str(answer.rrset.items[0])
                return string
            except Exception as e:
                l.info("DNS lookup failed for " + str(addr) + ".")  # just an info, not all IPs have reverse DNS
                return False
        else:
            try:
                return self.socket.gethostbyaddr(addr)
            except Exception as e:
                l.info("DNS lookup failed for " + str(addr) + ". Error was: " + str(
                    e))  # just an info, not all IPs have reverse DNS
                return False


    def lookup_whois(self, addr):
        """
        Get whois information on an IP address.
        @param addr: The IP address or a list of addresses to resolve.
        @return: Structures whois data as returned by cymruwhois (includes eg. .asn, .owner) or False
        @rtype: dictionary
        """
        if isinstance(addr, (str, IPv4Address, IPv6Address)):        # just one address given as arg
            return self._lookup_whois_single(ip_address(addr))
        else:                                          # multiple addresses given as arg
            return self._lookup_whois_multiple(addr)

    def _lookup_whois_single(self, addr):
        client = cymruwhois.Client()
        if addr not in self.preresolve_lock_whois:
            self.preresolve_lock_whois[addr] = threading.Lock()
        self.preresolve_lock_whois[addr].acquire()

        if addr in self.preresolved_whois:         # answer already in cache?
            ret = self.preresolved_whois[addr]
        else:                                      # actually perform lookup
            l.debug("Cache miss on single whois lookup for address " + str(addr) + ".")
            try:
                ret = client.lookup(addr)
            except Exception as e:
                l.warn("Whois lookup failed for " + str(addr) + ". Error was: " + str(e))
                ret = False
            self.preresolved_whois[addr] = ret    # cache this shit!
        self.preresolve_lock_whois[addr].release()
        return ret

    def _lookup_whois_multiple(self, addr_list):
        client = cymruwhois.Client()
        for item in addr_list:
            item = ip_address(item)
            if item not in self.preresolve_lock_whois:
                self.preresolve_lock_whois[item] = threading.Lock()
            self.preresolve_lock_whois[item].acquire()

            ret = dict()
            if ip_address(item) in self.preresolved_whois:         # answer already in cache?
                ret[item] = self.preresolved_whois[item]
                addr_list.remove(item) # remove found items from the to do list (will use this later for online lookups)

        if len(addr_list) > 0:                              # is there still something to look up online?
            try:
                online = client.lookupmany_dict(addr_list)
            except Exception as e:
                l.warn("Mass whois lookup failed for " + str(addr_list) + ". Error was: " + str(e))
                online = dict()
            ret.update(online)

            for this_addr, this_result in online.items():      # cache this shit!
                self.preresolved_whois[ip_address(this_addr)] = this_result

        for item in addr_list:
            item = ip_address(item)
            self.preresolve_lock_whois[item].release()

        return ret

    def print_ip(self, addr):
        """
        Build a nice formatted output string from an IP address, using reverse DNS and Whois data depending
        on this object's configuration.
        @param addr: The IP address to
        """
        addr_output = str(addr)
        whois_output = ""

        if self.resolve_dns:  # get reverse DNS
            dns = self.lookup_dns(addr)
            if dns:
                addr_output = dns + " (" + addr_output + ")"

        if self.resolve_whois:  # get Whois info
            whois = self.lookup_whois(addr)
            if whois and whois.asn != "NA":
                whois_output = " in AS " + whois.asn + " " + whois.owner

        return addr_output + whois_output




class PreresolveManager:
    """
    Dispatches threads to run a specified task.
    """

    def __init__(self, workload, worker_function, items_per_thread = 1, concurrent_threads = 100):
        self.workload = workload
        self.worker_function = worker_function
        self.items_per_thread = items_per_thread
        self.concurrent_threads = concurrent_threads
        self.current_item = 0
        self.current_item_lock = threading.Lock()

        for i in range(1, self.concurrent_threads):
            thread = threading.Thread(target=self.get_work)
            thread.start()

    def get_work(self):
        """
        Thread call this back when their task is done to see if there's more work for them.
        """
        while True:
            self.current_item_lock.acquire()
            if self.current_item < len(self.workload):
                work_package = self._prepare_work()
            else:
                work_package = None
            self.current_item_lock.release()

            # Actually do your work, bloody thread
            if work_package:
                self.worker_function(work_package)
            else:
                break  # that's it, you're fired

    def _prepare_work(self):
        """
        Only call with self.current_item_lock acquired!
        """
        if self.current_item + self.items_per_thread < len(self.workload):
            start_index = self.current_item
            end_index = self.current_item + self.items_per_thread
            self.current_item += self.items_per_thread
        else:
            start_index = self.current_item
            end_index = len(self.workload) - 1
            self.current_item = len(self.workload)

        work_package = self.workload[start_index : end_index]
        return work_package
