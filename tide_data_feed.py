#!/usr/bin/env python3
# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
"""
------------------------------------------------------------------------

 Description:
  Sample script using ibtidelib to create a CSV feed from TIDE

 Requirements:
  Requires ibtidelib, requests

 Usage:
    tide_csv_feed.py [options]
        -h  help
        -o  <file> Output file
        -k  <key> TIDE apikey
        -f  <host,ip,url> feedtype
        -p  <profile>
        -t  <threatclass>
        -T  <threatproperty>
        -r  <rlimit> max number of records
        -d  debug output

 Author: Chris Marrison

 Date Last Updated: 20200429

 .. todo::
    * Alternate feed formats

Copyright 2019 Chris Marrison / Infoblox

Redistribution and use in source and binary forms,
with or without modification, are permitted provided
that the following conditions are met:

1. Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

------------------------------------------------------------------------
"""
__version__ = '0.9'
__author__ = 'Chris Marrison'

import os
import shutil
import logging
import argparse
import configparser
import requests
import ibtidelib

# ** Global Variables **
log = logging.getLogger(__name__)

# ** Functions **

def parseargs():
    '''
    Parse Arguments Using argparse

    Parameters:
        None

    Returns:
        Returns parsed arguments
    '''
    parse = argparse.ArgumentParser(description='Simple TIDE data feed example')
    parse.add_argument('-o', '--output', type=str,
                       help="Output to <filename>")
    parse.add_argument('-c', '--config', type=str, default='config.ini',
                       help="Overide Config file")
    parse.add_argument('-k', '--apikey', type=str,
                       help="Overide API Key")
    parse.add_argument('-f', '--feedtype', type=str, default='host',
                       help="Specify feed type <host(default), ip, url>")
    parse.add_argument('-t', '--threatclass', type=str,
                       help="Specify Threat Class for feed")
    parse.add_argument('-T', '--threatproperty', type=str,
                       help="Specify Threat Property for feed")
    parse.add_argument('-p', '--profile', type=str, default='IID',
                       help="Set profile for feed (default=IID)")
    parse.add_argument('-r', '--rlimit', type=int, default=100,
                       help="Set limit for number of records (default=100)")
    parse.add_argument('-d', '--debug', action='store_true',
                       help="Enable debug messages")

    return parse.parse_args()


def setup_logging(debug):
    '''
     Set up logging

     Parameters:
        debug (bool): True or False.

     Returns:
        None.

    '''
    # Set debug level
    if debug:
        logging.basicConfig(level=logging.DEBUG,
                            format='%(asctime)s %(levelname)s: %(message)s')
    else:
        logging.basicConfig(level=logging.INFO,
                            format='%(asctime)s %(levelname)s: %(message)s')

    return


def open_file(filename):
    '''
     Attempt to open file for output

     Parameters:
        filename (str): Name of file to open.

     Returns:
        file handler object.

    '''
    if os.path.isfile(filename):
        backup = filename+".bak"
        try:
            shutil.move(filename, backup)
            log.info("Outfile exists moved to {}".format(backup))
            try:
                handler = open(filename, mode='w')
                log.info("Successfully opened output file {}.".format(filename))
            except IOError as err:
                log.error("{}".format(err))
                handler = False
        except shutil.Error:
            log.warning("Could not back up existing file {}, "
                        "exiting.".format(filename))
            handler = False
    else:
        try:
            handler = open(filename, mode='w')
            log.info("Successfully opened output file {}.".format(filename))
        except IOError as err:
            log.error("{}".format(err))
            handler = False

    return handler


def main():
    '''
    * Main *

    Core logic when running as script

    '''

    # Local variables
    config = {}
    # Parse Arguments and configure
    args = parseargs()

    # Set up logging
    debug = args.debug
    setup_logging(debug)
    outputfile = args.output
    feedtype = args.feedtype
    profile = args.profile
    threatclass = args.threatclass
    threatproperty = args.threatproperty
    rlimit = str(args.rlimit)

    # Check config file
    if args.config:
        configfile = args.config
    else:
        configfile = 'config.ini'

    # Set API Key
    if args.apikey:
        apikey = args.apikey
    else:
        config = ibtidelib.read_tide_ini(configfile)
        apikey = config['api_key']
    if apikey == '':
        log.error('API Key not set.')
    else:
        # Assume API Key was set and continue

        # Set up output file
        if outputfile:
            outfile = open_file(outputfile)
            if not outfile:
                log.error('Failed to open output file for CSV.')
        else:
            outfile = False

        # CSV Data Feed Example
        log.debug('Requesting {} feed, using profile={}, threatclass={},'
                  'threatproperty={}, rlimit={}'
                  .format(feedtype,
                          profile,
                          threatclass,
                          threatproperty,
                          rlimit))
        rcode, rtext = ibtidelib.tideactivefeed(feedtype,
                                                apikey,
                                                profile=profile,
                                                threatclass=threatclass,
                                                threatproperty=threatproperty,
                                                format="csv",
                                                rlimit=rlimit)
        if rcode == requests.codes.ok:
            if outfile:
                log.info('Outputing feed to file {}'.format(outputfile))
                print(rtext, file=outfile)
                log.info('Output complete')
            else:
                print(rtext)
        else:
            print("Query Failed with response: {}".format(rcode))
            print("Body response: {}".format(rtext))

    return


# ** Main **
if __name__ == '__main__':
    # exitcode = main()
    # raise SystemExit(exitcode)
    main()

# ** End Main **
