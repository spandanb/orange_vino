#!/usr/bin/env python

import argparse
import utils.vino_utils as ut
from orc import Orc
import pdb

#http://stackoverflow.com/questions/11455218
class IfInfoAction(argparse.Action):
    """
     -p should only be passed if -i with arg passed
    """
    def __call__(self, parser, namespace, values, option_string=None):
        info = getattr(namespace, "info")
        if info == "ALL" or info == None:
            parser.error( "--info << name >> required before --property")
        else:
            setattr(namespace, self.dest, values)                   

class IfCreateAction(argparse.Action):
    """
     -m should only be passed if -c with arg passed
    """
    def __call__(self, parser, namespace, values, option_string=None):
        create = getattr(namespace, "create")
        if create == None:
            parser.error( "--create required before before --mesh")
        else:
            setattr(namespace, self.dest, values)                   

parser = argparse.ArgumentParser(description='ViNO command line interface')

parser.add_argument('-c', '--create', action='store_true',
                    help="create the topology specified by the topology file")
parser.add_argument('-i', '--info', nargs='?', const="ALL",
                    help="provide info on the queryied server(s)")
#TODO: -p is not implemented
parser.add_argument('-p', '--property', action=IfInfoAction,
                    help="provide info on the queryied server(s)")
parser.add_argument('-d', '--delete', nargs='?', const="ALL",
                    help="delete the server(s) with matching prefix")
parser.add_argument('-m', '--mesh', action='store_true',
                    help="create a mesh topology. Must be used with --create")

args = parser.parse_args()

if args.mesh and not args.create:
    parser.error( "--[m]esh must be used with --[c]reate")

orc = Orc(mesh=args.mesh)

if args.create:
    #Create topology
    orc.create_topology()
    #Print output
    map(ut.format_and_print, orc.get_topology())

if args.info:
    if args.info == "ALL":
       map(ut.format_and_print, orc.get_topology())
    else:
       orc.get_topology() #args.info

if args.delete:
    orc.delete_topology()

if not(args.create or args.info or args.delete):
    parser.print_help()
