#!/usr/bin/env python3
from functools import lru_cache
from ipaddress import ip_address, IPv4Address, IPv6Address
import logging
from importlib import import_module
from datetime import datetime
from collections import defaultdict, OrderedDict
from itertools import tee
import threading

try:
    json = import_module('simplejson')
except ImportError as e:
    json = import_module('json')

l = logging.getLogger(__name__)


class ICMPAnswer:
    # Unaccounted for (only sometimes present):
    # "icmpext": {
    # "obj": [
    # {
    #             "class": 1,
    #             "mpls": [
    #                 {
    #                     "exp": 0,
    #                     "label": 341059,
    #                     "s": 1,
    #                     "ttl": 1
    #                 }
    #             ],
    #             "type": 1
    #         }
    #     ],
    #     "rfc4884": 0,
    #     "version": 2
    # }
    def __init__(self, data):
        self.no_answer = data.get('x') == '*'
        self.rawdata = data

    def check_answer(self):
        if self.no_answer:
            raise ValueError('No answer received.')

    @property
    def ip(self):
        self.check_answer()
        return ip_address(self.rawdata['from'])

    @property
    def rtt(self):
        return self.rawdata['rtt']

    @property
    def size(self):
        return self.rawdata['size']

    @property
    def ttl(self):
        return self.rawdata['ttl']


class ICMPHop:
    def __init__(self, controller, data):
        assert 'hop' in data, "C'est ne pas une ICMP hop!"
        self.c = controller
        self.rawdata = data
        self.number = data['hop']
        self._answers = None
        self._endpoints = None

    def __str__(self):
        if len(list(self.answers)) < 1:
            return 'No answers'
        else:
            if len(self.endpointset) == 1:  # just one IP answered, as it should be
                ip_output = self.c.res.print_ip(self.endpoints)
            else:  # answers from different IPs o.O
                ip_output = "[Answers from "
                first = True
                for endpoint in self.endpointset:
                    if First:
                        First = False
                    else:
                        ip_output += ", "
                    ip_output += endpoint.ip
                ip_output += "]"
            return '{} TTL: {h.ttl:.2f} RTT: {h.rtt:.2f}ms'.format(ip_output,
                                                                   h=self)  # TODO: There could be multiple endpoints

    @property
    def all_answers(self):
        if self._answers is None:
            self._answers = []
            for a in self.rawdata['result']:
                self._answers.append(ICMPAnswer(a))
        return self._answers

    @property
    def answers(self):
        for a in self.all_answers:
            if not a.no_answer:
                yield a

    def get_average(self, attr):
        count = 0
        asum = 0
        for a in self.answers:
            count += 1
            asum += getattr(a, attr)
        if count == 0:
            return 'No answers'
        else:
            return asum / count

    @property
    def rtt(self):
        return self.get_average('rtt')

    @property
    def ttl(self):
        return self.get_average('ttl')

    @property
    def endpoints(self):
        return ', '.join(map(str, self.endpointset))

    @property
    def endpointset(self):
        if self._endpoints is None:
            self._endpoints = set(map(lambda a: a.ip, self.answers))
        return self._endpoints

    # Returns all IP addresses involved in this hop
    def all_addr(self):
        return self.endpointset


class ICMPTraceroute:
    # Unaccounted for:
    # "af": 4,
    # "fw": 4660,
    # "group_id": 1839034,
    # "lts": 955,
    # "msm_id": 1839034,
    # "msm_name": "Traceroute",
    # "paris_id": 7,
    # "prb_id": 11572,
    def __init__(self, controller, data):
        self.c = controller
        # Just in case someone decides to pipe in bogus data
        msg = 'This is not an ICMP traceroute! THIS IS SPARTA!'
        assert data['type'] == 'traceroute' and data['proto'] == 'ICMP', msg
        self.rawdata = data
        self._hops = None

    def __str__(self):
        result = list()
        result.append(
            'Traceroute(probe={t.probe}, from={t.from_addr}, to={t.dst_addr}, src={t.src_addr}, duration={t.duration})'.format(
                t=self
            ))
        result.append('Hops:')
        for num, hop in self.hops.items():
            result.append(' ' * 2 + '{:>2}: '.format(num) + str(hop))
        return '\n'.join(result)

    def __repr__(self):
        result = list()
        for hop in self.hops.values():
            if hop.endpoints == '':
                result.append('*')
            else:
                result.append(hop.endpoints)
        return ';'.join(result)

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            raise ValueError('Cannot compare ICMP Traceroute to {}.'.format(other.__class__))
        for num, hop in self.hops.items():
            ownset = hop.endpointset
            otherhop = other.hops.get(num)
            if otherhop is None:
                # route length changed
                return False
            otherset = otherhop.endpointset
            if len(ownset) < 1 or len(otherset) < 1:
                # No answers received for one of the trace hops, compare the next one
                continue
            elif not ownset == otherset:
                return False
        return True

    @property
    def hops(self):
        if self._hops is None:
            self._hops = OrderedDict()
            for h in self.rawdata['result']:
                hop = ICMPHop(self.c, h)
                self._hops[h['hop']] = hop
        return self._hops

    @property
    def size(self):
        return self.rawdata['size']

    @property
    def src_addr(self):
        return ip_address(self.rawdata['src_addr'])

    @property
    def dst_addr(self):
        return ip_address(self.rawdata['dst_addr'])

    @property
    def destination(self):
        return (self.rawdata['dst_name'], self.dst_addr)

    @property
    def probe(self):
        return (self.rawdata['prb_id'])

    @property
    def from_addr(self):
        """
        @return: The logical (external) address of the probe. This gets important if the probe is hidden behind NAT.
        @rtype: ip_address
        """
        return ip_address(self.rawdata['from'])

    @property
    def start(self):
        return datetime.fromtimestamp(int(self.rawdata['timestamp']))

    @property
    def end(self):
        return datetime.fromtimestamp(int(self.rawdata['endtime']))

    @property
    def duration(self):
        return self.end - self.start

    # Returns all IPs addresses involved in this trace
    def all_addr(self):
        set = {self.src_addr, self.from_addr, self.dst_addr}
        for hop in self.hops.values():
            new_addresses = hop.all_addr()
            set.update(new_addresses)
        return set


class Measurement:
    types = {
        ('traceroute', 'ICMP'): ICMPTraceroute,
    }

    rawdata = None
    content = []

    def __init__(self, controller, data, limit_probes=[]):
        self.c = controller
        self.l = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.limit_probes = limit_probes

        # Save raw data and parse it into objects
        self.rawdata = data
        self.parse()

    def parse(self):
        for entry in self.rawdata:
            type = self.entry_type(entry)  # if this is a valid entry we understand, get its class
            if type:
                obj = type(self.c, entry)  # build nice and shiny object from raw data

                # Finally, check if additional constraints are met and if so, return this object.
                valid = (not self.limit_probes or obj.probe in self.limit_probes)
                if valid:
                    self.content.append(obj)
            else:
                l.warn("Raw data contains an entry I don't understand: " + entry)

    def entry_type(self, rawentry):
        type_signature = (rawentry['type'], rawentry['proto'])
        return self.types[type_signature]

    # Returns all IPs addresses involved in this measurement
    def all_addr(self):
        addrs = set()
        for object in self.content:
            addrs.update(object.all_addr())
        return addrs


class Controller:
    def __init__(self):
        # Controllers provide a resolver which looks up IP addresses and stuff online.
        # If the user specified the numerical flag, this resolver is just a dummy.
        self.res = Resolver(self)

        self.measurements = []
        self.auto_preresolve = False

    def add_measurement(self, filename, limit_probes=[]):
        # Read the input data from file and create a measurement object from it
        self.measurements.append(Measurement(self, json.load(filename), limit_probes))
        if self.auto_preresolve:
            self.res.preresolve(self.all_addr())

    def all_addr(self):
        addrs = set()
        for measurement in self.measurements:
            addrs.update(measurement.all_addr())
        return addrs


class CLI:
    def __init__(self):
        # First, parse the command line arguments:
        from argparse import ArgumentParser, FileType

        parser = ArgumentParser()
        parser.add_argument('--loglevel', default='ERROR', choices=['INFO', 'DEBUG', 'WARN', 'ERROR'], help="Log level", type=str.upper)
        parser.add_argument('--probe', '-p', type=int,
                            help='Probe ID. If specified, only consider results from this probe.', action='append')
        parser.add_argument('--numerical', '-n',
                            help="Work offline, print stuff numerically, disable any lookups. Short for -d and -w.",
                            action='store_const', const=True)
        parser.add_argument('--no-resolve-dns', '-d', dest='resolve_dns', help="Don't resolve reverse DNS names.", action='store_false', default=True)
        parser.add_argument('--no-get-whois', '-w', dest='get_whois', help="Do not provide Whois information on IP addresses.", action='store_false', default=True)
        parser.add_argument('--no-preresolve', dest='preresolve', help="Try to resolve all IP addresses at once.", action='store_false', default=True)
        parser.add_argument('command', choices=['stability', 'print'], help="Select what to do.")
        parser.add_argument('file', type=FileType(), help='JSON file')
        self.args = parser.parse_args()


        # Create and feed the control hub:
        self.c = Controller()
        self.c.add_measurement(self.args.file, self.args.probe)

        # Online resolver options:
        if self.args.numerical:
            self.args.resolve_dns = False
            self.args.get_whois = False
        self.c.res.resolve_dns = self.args.resolve_dns
        self.c.res.resolve_whois = self.args.get_whois

        # Set the log level
        loglevel = getattr(logging, self.args.loglevel.upper(), None)
        if not isinstance(loglevel, int):
            raise ValueError('Invalid log level: {}'.format(self.args.loglevel))
        logging.basicConfig(level=loglevel)


        # All setup done, now actually do what the user actually wants
        if self.args.command == "print":
            self.trace_print()
        elif self.args.command == 'stability':
            self.route_stability()


    def route_stability(self):
        tracelist = defaultdict(OrderedDict)
        for measurement in self.c.measurements:
            for trace in measurement.content:
                tracelist[trace.probe][trace.start] = trace
        for startpoint, traces in tracelist.items():
            errors = list()
            errors_occured = False
            l.info('Comparing routes for {}'.format(startpoint))
            first = None
            last = None
            for a, b in pairwise(traces.values()):
                if first is None:
                    first = a
                last = b
                if a != b:
                    l.warn('Route changed for {} between {} and {}!'.format(startpoint, a.start, b.start))
                    errors.append((a, b))
                    errors_occured = True
                else:
                    l.debug('No change for {} between {} and {}'.format(startpoint, a.start, b.start))
            if errors_occured:
                print(
                    'Route changed {}/{} times for probe {} (IP {}) in {}'.format(len(errors), len(traces), startpoint,
                                                                                  first.from_addr,
                                                                                  last.start - first.start))
            else:
                print('Route stable for {} ({} traces)'.format(startpoint, len(traces)))


    def trace_print(self):
        if self.args.preresolve:
            self.c.res.preresolve(self.c.all_addr())
        for measurement in self.c.measurements:
            for trace in measurement.content:
                print(trace)
                print()


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

    @property
    def resolve_dns(self):
        return self._resolve_dns

    @resolve_dns.setter
    def resolve_dns(self, value):
        self._resolve_dns = value
        global dns  # for import
        if self.resolve_dns:
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

    @property
    def resolve_whois(self):
        return self._resolve_whois

    @resolve_whois.setter
    def resolve_whois(self, value):
        self._resolve_whois = value
        global cymruwhois
        if self.resolve_whois:
            try:  # Whois
                import cymruwhois
            except ImportError as e:
                l.error(
                    "Could not load module cymruwhois. Whois information (AS etc.) will not be provided. Error was: " + str(
                        e))
                self.resolve_whois = False

    def preresolve(self, addrs, concurrent_threads=100):
        if self.resolve_dns:
            PreresolveManager(list(addrs), self.lookup_dns, 1, concurrent_threads)
        if self.resolve_whois:
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
        @return: Structures whois data as returned by cymruwhois (includes eg. .asn, .owner)
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
            try:
                ret = client.lookup(addr)
            except Exception as e:
                l.warn("Whois lookup failed for " + str(addr) + ". Error was: " + str(e))
                ret = False
            self.preresolved_whois[addr] = ret    # cache this shit!
        self.preresolve_lock_whois[addr].release()
        return ret

    def _lookup_whois_multiple(self, addr):
        client = cymruwhois.Client()
        for item in addr:
            item = ip_address(item)
            if item not in self.preresolve_lock_whois:
                self.preresolve_lock_whois[item] = threading.Lock()
            self.preresolve_lock_whois[item].acquire()

            ret = dict()
            if ip_address(item) in self.preresolved_whois:         # answer already in cache?
                ret[item] = self.preresolved_whois[addr]
                addr.remove(item) # remove found items from the to do list (will use this later for online lookups)

        if len(addr) > 0:                              # is there still something to look up online?
            try:
                online = client.lookupmany_dict(addr)
            except Exception as e:
                l.warn("Mass whois lookup failed for " + str(addr) + ". Error was: " + str(e))
                online = dict()
            ret.update(online)

            for this_addr, this_result in online.items():      # cache this shit!
                self.preresolved_whois[ip_address(this_addr)] = this_result

        for item in addr:
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
                addr_output = dns + " (" + addr + ")"

        if self.resolve_whois:  # get Whois info
            whois = self.lookup_whois(addr)
            if whois:
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

            if work_package:
                self.worker_function(work_package)
            else:
                break

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


def pairwise(iterable):
    """
    s -> (s0,s1), (s1,s2), (s2, s3), ...
    Stolen from https://docs.python.org/3/library/itertools.html#recipes
    """
    a, b = tee(iterable)
    next(b, None)
    return zip(a, b)


def pairwise_compare(elements):
    for a, b in pairwise(elements):
        yield a == b


if __name__ == '__main__':
    ui = CLI()
