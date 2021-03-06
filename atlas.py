#!/usr/bin/env python3

from datetime import datetime
from ipaddress import ip_address
from collections import defaultdict, OrderedDict

import logging
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




class ICMPHop():
    def __init__(self, controller, data):
        assert 'hop' in data, "C'est ne pas une ICMP hop!"
        self.c = controller
        self.rawdata = data
        self.number = data['hop']
        self._answers = []
        self._endpoints = set()

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
            return '{} TTL: {h.ttl:.2f} RTT: {h.rtt:.2f}ms'.format(ip_output, h=self)

    def __eq__(self, other):
        return self.equals(other)

    def equals(self, other, both_unanswered_equal = True, one_unanswered_equal = False, single_endpoint_equal = False,
               same_prefix_equal = False, same_as_equal = False):
        """
        Compare two hops. This function features a bunch of boolean "leniency options" which cause hops to be
        considered equal more easily. Set all of them to false to get a relatively strict comparison.
        Even with all these options disabled comparison is always address-based only. Volatile hop parameters like
        round-trip times are never considered. Remaining TTL is also not considered.
        @param other: Other hop to compare to
        @param both_unanswered_equal: If true, hops are considered equal if both did not receive any answer.
        @param one_unanswered_equal: If true, hops are considered equal if they effectively cannot compared because
            one of them did not receive any answers while the other did.
        @param single_endpoint_equal: If False, hops are considered equal if the endpointsets are exactly equal.
            If True, only one equal endpoint is required.
        @param same_prefix_equal: If true, IP address will be abtracted to published IP subnets before comparison.
            If abstraction is not possible (e.g. for private address space or networks not present in the public
            databse) two addresses in non-abstractable network will be considered equal
            while one abstractable and one non-abstractable address will not be.
            (Implementation note: This is the default behaviour using cymruwhois and ignoring the problem :D )
        @param same_as_equal: If true, IP address will be abstracted to published autonomous systems before comparison.
        @rtype: bool
        """
        if not isinstance(other, self.__class__):
            return False

        # Have both hops even received answers?
        if not self.answered() and not other.answered():  # both hops unanswered
            return both_unanswered_equal

        elif (not self.answered()) or (not other.answered()): # one hop unanswered
            return one_unanswered_equal

        # Both hops answered. Now see if these answers match.
        
        if same_prefix_equal or same_as_equal:  # abstracting addresses as user specified to get a more general view
            myendpoints = set()
            otherendpoints = set()
            for endpoint in self.endpointset:
                if same_prefix_equal:
                    myendpoints.add(self.c.res.lookup_whois(endpoint).prefix)
                elif same_as_equal:
                    myendpoints.add(self.c.res.lookup_whois(endpoint).asn)
            for endpoint in other.endpointset:
                if same_prefix_equal:
                    otherendpoints.add(self.c.res.lookup_whois(endpoint).prefix)
                elif same_as_equal:
                    otherendpoints.add(self.c.res.lookup_whois(endpoint).asn)

        else:                            # no abstraction chosen - will do an exact IP address comparison
            myendpoints = self.endpointset
            otherendpoints = other.endpointset

        if myendpoints == otherendpoints:         # full match - what more could you wish for
            return True
        else:                                     # no full match
            if single_endpoint_equal:             # has the user asked us to be lenient?
                return bool(myendpoints.intersection(otherendpoints))  # will be true if at least one endpoint is common
            else:
                return False

    @property
    def all_answers(self):
        if not len(self._answers):
            for a in self.rawdata['result']:
                self._answers.append(ICMPAnswer(a))
        return self._answers

    @property
    def answers(self):
        ret = []
        for a in self.all_answers:
            if not a.no_answer:
                ret.append(a)
        return ret

    def answered(self):
        if len(self.answers):
            return True
        else:
            return False

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
        if not len(self._endpoints):
            self._endpoints = set(map(lambda a: a.ip, self.answers))
        return self._endpoints

    # Returns all IP addresses involved in this hop
    def all_addr(self):
        return self.endpointset




class MeasurementEntry:
    def __init__(self, controller, data, index = None):
        self.c = controller
        self.rawdata = data

        # Per-probe index number of this measurement entry.
        # If not set now, user shall set this as soon after construction as possible.
        self.index = index

    @property
    def probe(self):
        return self.rawdata['prb_id']


class ICMPTraceroute(MeasurementEntry):
    # Unaccounted for:
    # "af": 4,
    # "fw": 4660,
    # "group_id": 1839034,
    # "lts": 955,
    # "msm_id": 1839034,
    # "msm_name": "Traceroute",
    # "paris_id": 7,
    # "prb_id": 11572,
    def __init__(self, controller, data, index = None):
        # Just in case someone decides to pipe in bogus data
        msg = 'This is not an ICMP traceroute! THIS IS SPARTA!'
        assert data['type'] == 'traceroute' and data['proto'] == 'ICMP', msg

        MeasurementEntry.__init__(self, controller, data, index)

        self._hops = None # for lazy initialization

    def __str__(self):
        result = list()
        result.append('Traceroute {t.index} for probe {t.probe}, duration {t.duration}:'.format(t=self))

        fromaddr = 'From: ' + self.c.res.print_ip(self.from_addr)
        if self.from_addr != self.src_addr:
            fromaddr += ', internal address ' + str(self.src_addr)
        result.append(fromaddr)
        result.append('To: ' + self.c.res.print_ip(self.dst_addr))

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
        return self.equals(other)


    def sylvaneq(self, other):
        """
        I was about to put "legacy __eq__ implementation" here but that doesn't sound friendly enough.
        So let's just say, an alternative one. :D
        """
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


    def equals(self, other,
               hop_both_unanswered_equal = True, hop_one_unanswered_equal = True, hop_single_endpoint_equal = False,
               hop_same_prefix_equal = False, hop_same_as_equal = False):
        if not isinstance(other, self.__class__):
            return False

        myhops_iter = iter(self.hops.values())
        otherhops_iter = iter(other.hops.values())
        while True:                                  # compare the trace hop by hop

            myhop = next(myhops_iter, None)
            otherhop = next(otherhops_iter, None)

            if myhop is None and otherhop is None:   # both traces compared successfully
                return True

            elif myhop is None or otherhop is None:        # One trace ended prematurely.
                if myhop is None: presenthop = otherhop    # Let's see if the other might effectively have ended as
                if otherhop is None: presenthop = myhop    # well. This accounts for missed last hops, causing bogus
                                                           # "no-answers" up to max TTL.
                if presenthop.answered:  # One trace ended while the other still has real, answered hops.
                    return False         # Those can never be equal!
                else:
                    continue       # Might be just some trailing no-answers. Let's keep looking...

            if not myhop.equals(otherhop,
                                hop_both_unanswered_equal, hop_one_unanswered_equal, hop_single_endpoint_equal,
                                hop_same_prefix_equal, hop_same_as_equal):
                return False  # if one pair of hops is not equal, same goes for the whole traces


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

    def __init__(self, controller, data, limit_probes=[]):
        self.c = controller
        self.l = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.limit_probes = limit_probes
        self.content = []

        # Save raw data and parse it into objects
        self._rawdata = data
        self._parse()


    def all_addr(self):
        """
        Returns all IPs addresses involved in this measurement.
        @rtype map<IPv4Address or IPv6Address>
        """
        addrs = set()
        for object in self.content:
            addrs.update(object.all_addr())
        return addrs

    def _parse(self):
        """
        Parses this object's raw data and builds an object structure.
        Don't call this twice or you'll duplicate the measurement entries.
        """

        # Each measurement entry will get a per-probe index number.
        # Need to do some counting for this.
        probeindices = defaultdict(int)

        for entry in self._rawdata:
            obj = self._entry_object(entry)  # if this is a valid entry we understand, build an object
            if obj:
                # Finally, check if additional constraints are met and if so, register this object and give it a
                # per-probe index number.
                valid = (not self.limit_probes or obj.probe in self.limit_probes)
                if valid:
                    self.content.append(obj)

                    obj.index = probeindices[obj.probe] # per-probe counting stuff, as mentioned.
                    probeindices[obj.probe] += 1

            else:
                l.warn("Raw data contains an entry I don't understand: " + entry)

    def _entry_object(self, rawentry):
        """
        Builds an object from a raw measurement entry.
        @param rawentry: A single, raw, parsed JSON measurement entry.
            You'll probably want to use json.load and iterate over the entries to get this.
        @type rawentry: dict
        @return: A specialized measurement entry object (e.g. a ICMPTraceroute if that happens to match your data).
        @rtype: MeasurementEntry
        """
        type_signature = (rawentry['type'], rawentry['proto'])
        klass = Measurement.types[type_signature]
        if klass:
            return klass(self.c, rawentry)
        else:
            return False












