#!/usr/bin/env python3

from resolver import Resolver
from atlas import Measurement, ICMPTraceroute
from collections import defaultdict, OrderedDict

from importlib import import_module

try:
    json = import_module('simplejson')
except ImportError as e:
    json = import_module('json')

import logging
l = logging.getLogger(__name__)

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




class RouteAnalyzer():
    """
    Determines route changes
    @ivar route_changes: A list of tuples showing route changes for each origin.
    """
    def __init__(self, measurement, hop_both_unanswered_equal = True, hop_one_unanswered_equal = True,
                 hop_single_endpoint_equal = False,
                 hop_same_prefix_equal = False, hop_same_as_equal = False,
                 index = None):
        """
        @param measurement: A measurement object (providing the data to analyze)
        @type measurement: Measurement

        """
        self.measurement = measurement
        self.tracelist = None
        self.route_changes = dict()

        # First, separate traces by originating probe and sort them chronologically
        # Traces are *most probably* already sorted by date. This is just to make sure.
        # It also means we (legitimably...?) trust the probe's time stamp over the JSON order.
        self.tracelist = defaultdict(OrderedDict)  # a dictionary with ordered dictionaries as values
        for trace in self.measurement.content:
            if isinstance(trace, ICMPTraceroute):  # only consider traceroute entries
                if (not index) or (trace.index in index): # provide index filtering if enabled
                    self.tracelist[trace.probe][trace.start] = trace

        # Compute one result for each originating probe
        for startpoint, traces in self.tracelist.items():
            self.route_changes[startpoint] = list()
            l.info('Comparing routes for {}'.format(startpoint))

            for traceA, traceB in pairwise(traces.values()):  # a is an iterator on the current element, b on the next one
                pass
                if not traceA.equals(traceB,
                                     hop_both_unanswered_equal, hop_one_unanswered_equal, hop_single_endpoint_equal,
                                     hop_same_prefix_equal, hop_same_as_equal):
                    l.warn('Route changed for probe {} between {} and {}!'.format(startpoint, traceA.start, traceB.start))
                    self.route_changes[startpoint].append((traceA, traceB))
                else:
                    l.debug('No change for probe {} between {} and {}'.format(startpoint, traceA.start, traceB.start))

    def change_count(self, probe):
        return len(self.route_changes[probe])

    def first_trace(self, probe):
        return self.tracelist[probe][next(iter(self.tracelist[probe]))]

    def last_trace(self, probe):
        return self.tracelist[probe][next(reversed(self.tracelist[probe]))]



from itertools import tee
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