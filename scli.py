#!/usr/bin/python2.7

"""Provides a CLI with support for some commands """

import argparse
import sys
import pprint
from servers import ServerManager
import os
import utils.vino_utils as ut

#Derived from: http://chase-seibert.github.io/blog/2014/03/21/python-multilevel-argparse.html
#This approach doesn't require the subparser name to be specified
class SCli(object):

    def __init__(self):
        parser = argparse.ArgumentParser(
            description='Pretends to be git',
            usage='''[--optional arguments] subcommand ...
Command-line interface for the Substrate API.

Positional arguments:
    <subcommand>
        list                List all VMs
        flavor-list         List all flavors
        image-list          List all images
        keypair-list        List all keypairs
        secgroup-list       List all secgroups
        boot                Boot a new server
'''
        )
        parser.add_argument('command', help='Subcommand to run')
        # parse_args defaults to [1:] for args, but you need to
        # exclude the rest of the args too, or validation will fail
        args = parser.parse_args(sys.argv[1:2])

        #Check for required env vars
        try:
            server_manager = ServerManager(os.environ["OS_USERNAME"],
                                           os.environ["OS_PASSWORD"],
                                           os.environ["OS_REGION_NAME"],
                                           os.environ["OS_TENANT_NAME"])
        except KeyError as err:
            print "Please specify a valid environment variables: {}".format(err.args[0])
            sys.exit(1)

        #Print list of VMs
        if args.command == "list":
            pprint.pprint(server_manager.get_servers())

        #Print image list
        elif args.command == "image-list":
            pprint.pprint(server_manager._call_api(service="nova", api="/images").json())

        #Print flavor list
        elif args.command == "flavor-list":
            pprint.pprint(server_manager._call_api(service="nova", api="/flavors").json())

        #List keypairs
        elif args.command == "keypair-list":
            pprint.pprint(server_manager._call_api(service="nova", api="/os-keypairs").json())

        #List secgroups
        elif args.command == "secgroup-list":
            pprint.pprint(server_manager._call_api(service="nova", api="/os-security-groups").json())

        #Boot VM
        elif args.command == "boot":
            self.boot(server_manager)

        elif args.command == "delete":
            self.delete(server_manager)

        else:
            print 'Unrecognized command'
            parser.print_help()
            exit(1)


    def boot(self, server_manager):
        parser = argparse.ArgumentParser(
            description='Boot a VM instance')
        #to have required named arguments, use combination of
        #prefixing arg with -- and required=True
        #NOTE: User can specify more than 1 of the required args
        parser.add_argument('--flavor', action='store', required=True)
        parser.add_argument('--image', action='store', required=True)
        parser.add_argument('--key-name', action='store')
        #comma separated list
        parser.add_argument('--security-groups', action='store')
        parser.add_argument('name')
        # now that we're inside a subcommand, ignore the first
        # TWO argvs, ie the command (git) and the subcommand (commit)
        args = parser.parse_args(sys.argv[2:])
        secgroups = []
        if args.security_groups:
            for s in args.security_groups.split(","):
                if s: secgroups.append(s)

        print "Booting server with name={} image={} flavor={} key_name={} secgroups={}".format(
            args.name, args.image, args.flavor, args.key_name, secgroups)
        server_manager.create_server(
            args.name, args.image, args.flavor, key_name=args.key_name, secgroups=secgroups)

    def delete(self, server_manager):
        parser = argparse.ArgumentParser(
            description='Delete a VM instance')
        #Identifier can be either uuid or name
        parser.add_argument('identifier', action='store')
        args = parser.parse_args(sys.argv[2:])

        if not ut.is_uuid(args.identifier):
            #determine UUID from name
            servers = server_manager.name_to_id(args.identifier)
            #delete first one
            to_delete = servers[0]
        else:
            to_delete = args.identifier

        print "Deleting {}".format(to_delete)
        server_manager._call_api(service='nova', api="/servers/{}".format(to_delete), verb="delete")


if __name__ == '__main__':
    SCli()
#   Example usage:
#   python scli.py boot --image Ubuntu64.2.1 --flavor m1.medium --key-name key_spandan --secgroups default,spandantb span_test_server
