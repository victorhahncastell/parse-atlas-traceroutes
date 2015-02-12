#!/usr/bin/env python3

from controller import Controller
from controller import RouteAnalyzer

import logging

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
        parser.add_argument('--no-resolve-dns', dest='resolve_dns', help="Don't resolve reverse DNS names.", action='store_false', default=True)
        parser.add_argument('--no-get-whois', dest='get_whois', help="Do not provide Whois information on IP addresses.", action='store_false', default=True)
        parser.add_argument('--no-preresolve', dest='preresolve', help="Try to resolve all IP addresses at once.", action='store_false', default=True)
        parser.add_argument('--details', '-d', help="Amount of details given with results.", type=int, choices=[0,1,2,3], default=0)
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
        ana = RouteAnalyzer(self.c.measurements[0])  # TODO?
        if len(self.c.measurements) > 1:
            print("Using first measurement only for route stability analysis!")

        if self.args.preresolve:
            if self.args.details >= 2:
                self.c.res.preresolve(self.c.all_addr())

        resultset = ana.route_changes.items()
        for probe, route_changes in resultset:
            first_trace = ana.first_trace(probe)
            last_trace = ana.last_trace(probe)

            if len(route_changes):  # yeah, had some:
                print('Route changed {}/{} times for probe {} ({}) in {}'.format(
                    len(route_changes), len(ana.tracelist[probe]), probe, self.c.res.print_ip(first_trace.from_addr),
                    last_trace.start - first_trace.start))

                if self.args.details == 1:
                    print("Indices of changed traces (change is from this index to the next): ", end='')
                    for traceA, traceB in route_changes:
                        trace_keys = list(ana.tracelist[probe].keys())
                        index = trace_keys.index(traceA.start)
                        print(index, end=' ')
                    print()
                elif self.args.details == 2:
                    print("Printing changesets:")
                    for traceA, traceB in route_changes:
                        print("Changeset {}:".format(route_changes.index((traceA, traceB)) + 1))
                        print(traceA)
                        print(traceB)
                        print()
                    print()
                    print()
            else:
                print('Route stable for probe {} ({} traces)'.format(probe, len(ana.tracelist[probe])))


    def trace_print(self):
        if self.args.preresolve:
            self.c.res.preresolve(self.c.all_addr())
        for measurement in self.c.measurements:
            for trace in measurement.content:
                print(trace)
                print()
