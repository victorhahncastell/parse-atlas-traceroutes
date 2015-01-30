#!/usr/bin/env python3
from functools import lru_cache
from ipaddress import ip_address
import logging
from importlib import import_module
from datetime import datetime
from collections import defaultdict, OrderedDict
from itertools import tee

try:
    json = import_module('simplejson')
except ImportError as e:
    json = import_module('json')

l = logging.getLogger(__name__)


class ICMPAnswer:
    # Unaccounted for (only sometimes present):
    # "icmpext": {
    # "obj": [
    #         {
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
            return '{} TTL: {h.ttl:.2f} RTT: {h.rtt:.2f}ms'.format(self.c.res.ip(self.endpoints), h=self)

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
        result.append('Traceroute(probe={t.probe}, from={t.ip}, to={t.dst_addr}, src={t.src_addr}, duration={t.duration})'.format(
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
    def ip(self):
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


class Measurement:
    types = {
        ('traceroute', 'ICMP'): ICMPTraceroute,
    }

    def __init__(self, controller, data, limit_probes = []):
        self.c = controller
        self.l = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.limit_probes = limit_probes

        # Save raw data and parse it into objects
        self.rawdata = data
        self.content = []
        self.parse()

    def parse(self):
        for entry in self.rawdata:
            type = self.entry_type(entry) # if this is a valid entry we understand, get its class
            if type:
                obj = type(self.c, entry)         # build nice and shiny object from raw data

                # Finally, check if additional constraints are met and if so, return this object.
                valid = (not self.limit_probes or obj.probe in self.limit_probes)
                if valid:
                    self.content.append(obj)
            else:
                l.warn("Raw data contains an entry I don't understand: " + entry)

    def entry_type(self, entry):
        type_signature = (entry['type'], entry['proto'])
        return self.types[type_signature]


class Controller:
    def __init__(self):
        # First, parse the command line arguments:
        from argparse import ArgumentParser, FileType
        parser = ArgumentParser()
        parser.add_argument('--loglevel', default='ERROR', choices=['INFO', 'DEBUG', 'WARN', 'ERROR'], help="Log level")
        parser.add_argument('--probe', '-p', type=int, help='Probe ID. If specified, only consider results from this probe.', action='append')
        parser.add_argument('--numerical', '-n', help="Print IP addresses and other stuff numerically, do not resolve online", action='store_const', const=True)
        parser.add_argument('command', choices=['stability', 'print'], help="Select what to do.")
        parser.add_argument('file', type=FileType(), help='JSON file')
        args = parser.parse_args()

        # Controllers provide a resolver which looks up IP addresses and stuff online.
        # If the user specified the numerical flag, this resolver is just a dummy.
        self._res = Resolver(self, args.numerical)

        loglevel = getattr(logging, args.loglevel.upper(), None)
        if not isinstance(loglevel, int):
            raise ValueError('Invalid log level: {}'.format(args.loglevel))
        logging.basicConfig(level=loglevel)

        self.mesasurement = Measurement(self, json.load(args.file), args.probe)

        if args.command == "print":
            self.trace_print()
        if args.command == 'stability':
            self.route_stability()


    @property
    def res(self):
        return self._res


    def route_stability(self):
        tracelist = defaultdict(OrderedDict)
        for trace in self.mesasurement.content:
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
                print('Route changed {}/{} times for probe {} (IP {}) in {}'.format(len(errors), len(traces), startpoint, first.ip, last.start - first.start))
            else:
                print('Route stable for {} ({} traces)'.format(startpoint, len(traces)))


    def trace_print(self):
        for trace in self.mesasurement.content:
            print(trace)
            print()



class Resolver:
    def __init__(self, controller, num):
        self.c = controller
        self.num = num

        if not self.num:
            try:
                import socket
                self.socket = socket
                self.socket.setdefaulttimeout(1)
                from cymruwhois import Client as CymruClient
                self.whois = CymruClient()
            except ImportError as e:
                l.error("Could not load module cymruwhois. IP addresses and stuff will be printed as is and not be resolved. Error was: " + e.__str__())
                self.num = True

    @lru_cache(1500)
    def lookup(self, what):
        try:
            res = self.whois.lookup(what) # get Whois
        except Exception as e:
            l.warn("Whois failed! Error was: " + e.__str__())
            return False

        try:
            dnsres = self.socket.gethostbyaddr(what)
        except OSError as e:
            dnsres = [what]

        res.__dict__['dns'] = dnsres[0]
        return res


    def ip(self, addr):
        if self.num:
            return self.ip_num(addr)
        else:
            return self.ip_res(addr)

    def ip_num(self, addr):
        return addr

    def ip_res(self, addr):
        info = self.lookup(addr)
        if info:
            return info.dns + " (" + addr + ") in AS " + info.asn + " " + info.owner
        else:
            return self.ip_num(addr)

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


def main():
    c = Controller()

if __name__ == '__main__':
    main()
