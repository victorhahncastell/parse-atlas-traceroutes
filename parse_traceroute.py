#!/usr/bin/env python3
from ipaddress import ip_address
import logging
from importlib import import_module
from datetime import datetime

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
    def __init(self, data):
        self.no_answer = data.get('x') == '*'
        self.rawdata = data

    def check_answer(self):
        if self.no_answer:
            raise ValueError('No answer received.')

    @property
    def ip(self):
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
    def __init__(self, data):
        assert 'hop' in data, "C'est ne pas une ICMP hop!"
        self.rawdata = data
        self.number = data['hop']
        self._answers = None

    @property
    def all_answers(self):
        if self._answers is None:
            self._answers = []
            for a in self.rawdata['result']:
                self._answers.append(ICMPAnswer(a))
        return self._answers

    @property
    def answers(self):
        for a in self.answers:
            if not a.no_answer:
                yield a

    def get_average(self, attr):
        count = 0
        asum = 0
        for a in self.answers:
            count += 1
            asum += getattr(a, attr)
        return asum / count

    @property
    def rtt(self):
        return self.get_average('rtt')

    @property
    def ttl(self):
        return self.get_average('ttl')

    @property
    def endpoints(self):
        return set(map(lambda a: a.ip, self.answers))


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
    def __init__(self, data):
        # Just in case someone decides to pipe in bogus data
        msg = 'This is not an ICMP traceroute! THIS IS SPARTA!'
        assert data['type'] == 'traceroute' and data['proto'] == 'ICMP', msg
        self.rawdata = data
        self._hops = None

    def __str__(self):
        result = list()
        result.append('Traceroute(from={t.ip}, to={t.dst_addr}, src={t.src_addr}, duration={t.duration})'.format(
            t=self
        ))
        result.append('Hops:')
        for num, hop in self.hops.items():
            result.append(' ' * 2 + '{:>2}: '.format(num) + str(hop))
        return '\n'.join(result)

    @property
    def hops(self):
        if self._hops is None:
            self._hops = {}
            for h in self.rawdata['result']:
                hop = ICMPHop(h)
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


class RIPEAtlas:
    types = {
        ('traceroute', 'ICMP'): ICMPTraceroute,
    }

    def __init__(self, data):
        self.l = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.rawdata = data

    def __iter__(self):
        for entry in self.rawdata:
            type_signature = (entry['type'], entry['proto'])
            if type_signature in self.types:
                yield self.types[type_signature](entry)


def main():
    from argparse import ArgumentParser, FileType

    parser = ArgumentParser()
    parser.add_argument('--loglevel', default='WARNING', help="Loglevel", action='store')
    parser.add_argument('--file', '-f', type=FileType(), help='JSON file')
    args = parser.parse_args()
    loglevel = getattr(logging, args.loglevel.upper(), None)
    if not isinstance(loglevel, int):
        raise ValueError('Invalid log level: {}'.format(args.loglevel))
    logging.basicConfig(level=loglevel)
    ra = RIPEAtlas(json.load(args.file))
    for trace in ra:
        print(trace)


if __name__ == '__main__':
    main()

