#!/usr/bin/env python3

from controller import Controller
from controller import RouteAnalyzer

import logging

class CLI:
    def __init__(self):
        # First, parse the command line arguments:
        from argparse import ArgumentParser, FileType

        parser = ArgumentParser()
        parser.add_argument('--loglevel', default='ERROR', choices=['INFO', 'DEBUG', 'WARN', 'ERROR'],
                            help="Log level", type=str.upper)
        parser.add_argument('--probe', '-p', type=int, action='append',
                            help='Probe ID. If specified, only consider results from this probe.')
        parser.add_argument('--details', '-d', type=int, choices=[0,1,2,3], default=0,
                            help="Amount of details given with results.")
        parser.add_argument('--no-stable-both-unans',
                            help="When comparing traceroutes, consides hops not equal if both received no answers.")
        parser.add_argument('command', help="Select what to do.", choices=['stability', 'print'])
        parser.add_argument('file', type=FileType(), help='JSON file')

        parser.add_argument('--numerical', '-n', action='store_const', const=True,
                            help="Work offline, print stuff numerically, disable any lookups. " +
                                 "Short for --no-resolve-dns and --no-get-whois.")

        group = parser.add_mutually_exclusive_group()
        group.add_argument('--resolve-dns', dest='resolve_dns', action='store_true', default=True,
                            help="Don't resolve reverse DNS names.")
        group.add_argument('--no-resolve-dns', dest='resolve_dns', action='store_false',
                            help="Don't resolve reverse DNS names.")

        group = parser.add_mutually_exclusive_group()
        group.add_argument('--resolve-whois', dest='resolve_whois', action='store_true', default=True,
                            help="Provide Whois information on IP addresses. Default.")
        group.add_argument('--no-resolve-whois', dest='resolve_whois', action='store_false',
                            help="Do not provide Whois information on IP addresses.")

        group = parser.add_mutually_exclusive_group()
        group.add_argument('--preresolve', dest='preresolve', action='store_true', default=True,
                            help="Try to resolve all IP addresses at once.")
        group.add_argument('--no-preresolve', dest='preresolve', action='store_false',
                            help="Don't try to resolve all IP addresses at once.")

        group = parser.add_mutually_exclusive_group()
        group.add_argument('--tracecmp-both-unans', dest='tracecmp_both_unans', action='store_true', default=True,
                           help="When comparing traceroutes, consider two hops equal if none received " +
                                "any answers. Default.")
        group.add_argument('--no-tracecmp-both-unans', dest='tracecmp_both_unans', action='store_false',
                           help="When comparing traceroutes, don't consider two hops equal if none received " +
                                "any answers.")

        group = parser.add_mutually_exclusive_group()
        group.add_argument('--tracecmp-one-unans', dest='tracecmp_one_unans', action='store_true',
                           help="When comparing traceroutes, consider two hops equal if one of them " +
                                "didn't receive any answers.")
        group.add_argument('--no-tracecmp-one-unans', dest='tracecmp_one_unans', action='store_false', default=False,
                           help="When comparing traceroutes, consider two hops equal if one of them " +
                                "didn't receive any answers. Default.")

        group = parser.add_mutually_exclusive_group()
        group.add_argument('--tracecmp-single-endpoint', dest='tracecmp_single_endpoint', action='store_true',
                           help="When comparing traceroutes and using more than one ping per hop, " +
                                "consider two hops equal if any IP address appears in both sets of replies.")
        group.add_argument('--no-tracecmp-single-endpoint', dest='tracecmp_single_endpoint', action='store_false',
                           default=False,
                           help="When comparing traceroutes and using more than one ping per hop, do not" +
                                "consider two hops equal if any IP address appears in both sets of replies. Default.")

        self.args = parser.parse_args()


        # Create and feed the control hub:
        self.c = Controller()
        self.c.add_measurement(self.args.file, self.args.probe)

        # Online resolver options:
        if self.args.numerical:
            self.args.resolve_dns = False
            self.args.resolve_whois = False
        self.c.res.resolve_dns = self.args.resolve_dns
        self.c.res.resolve_whois = self.args.resolve_whois

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
        ana = RouteAnalyzer(self.c.measurements[0],
                            self.args.tracecmp_both_unans, self.args.tracecmp_one_unans,
                            self.args.tracecmp_single_endpoint)
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
