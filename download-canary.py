#!/usr/bin/python
# -*- coding: utf-8 -*-
# Loic Lambiel ©
# License MIT

import argparse
import logging
import logging.handlers
import socket
import sys
import time
import urllib2


try:
    import bernhard
except ImportError:
    print("It look like riemann client (bernard) isn't installed. "
          "Please install it using pip install bernhard")
    sys.exit(1)


try:
    from configparser import ConfigParser
except ImportError:  # python 2
    from ConfigParser import ConfigParser


def main():
    parser = argparse.ArgumentParser(description='''
This script create download a small file from a given URL.
If any error occur during the process, an alarm is being sent
to riemann monitoring. time metric is also sent to riemann''')
    parser.add_argument('-version',
                        action='version',
                        version='%(prog)s 1.0, Loic Lambiel, exoscale')
    parser.add_argument('-url',
                        help='URL of the file to be downloaded',
                        required=True,
                        type=str,
                        dest='url')
    parser.add_argument('-alertstate',
                        help='Alert level to raise if the test fails',
                        required=False,
                        type=str,
                        default='critical',
                        dest='state')
    parser.add_argument('-env',
                        help='Environnement used in the riemann service',
                        required=True,
                        type=str,
                        dest='env')
    args = vars(parser.parse_args())
    return args


def downloadtest(args):
    URL = args['url']
    ENV = args['env']

    timeout = 30
    socket.setdefaulttimeout(timeout)

    logging.info('Downloading file for env %s', ENV)

    req = urllib2.Request(URL)
    response = urllib2.urlopen(req)
    response.read()

    logging.info('Download completed for env %s', ENV)


# main
if __name__ == "__main__":
    args = main()
    ENV = args['env']
    conf = ConfigParser()
    conf.read(("/etc/bernhard.conf",))
    logfile = "/var/log/download-canary-{}.log".format(ENV)
    logging.basicConfig(format=('%(asctime)s %(pathname)s '
                                '%(levelname)s:%(message)s'),
                        level=logging.DEBUG,
                        filename=logfile)
    logging.getLogger().addHandler(logging.StreamHandler())
    logging.getLogger('boto').setLevel(logging.CRITICAL)

    client = bernhard.SSLClient(host=conf.get('default', 'riemann_server'),
                                port=int(conf.get('default', 'riemann_port')),
                                keyfile=conf.get('default', 'tls_cert_key'),
                                certfile=conf.get('default', 'tls_cert'),
                                ca_certs=conf.get('default', 'tls_ca_cert'))

    logging.info('Test started for env %s', ENV)
    ENV = args['env']
    state = args['state']
    checkservice = "%s.download_canary.check" % ENV
    exectimeservice = "%s.download_canary.exectime" % ENV
    start_time = time.time()
    host = socket.gethostname()
    try:
        downloadtest(args)
        exectime = time.time() - start_time
        client.send({'host': host,
                     'service': exectimeservice,
                     'state': 'ok',
                     'tags': ['duration', ENV],
                     'ttl': 600,
                     'metric': exectime})
        client.send({'host': host,
                     'service': checkservice,
                     'state': 'ok',
                     'tags': ['download_canary.py', 'duration', ENV],
                     'ttl': 600,
                     'metric': 0})

        logging.info('Script completed successfully for env %s', ENV)

    except Exception as e:
        logging.exception("An exception occured. Exception is: %s", e)
        exectime = 61
        txt = "An exception occurred on download_canary.py: {}. \
               See logfile {} for more info".format(e, logfile)
        client.send({'host': host,
                     'service': checkservice,
                     'description': txt,
                     'state': state,
                     'tags': ['download_canary.py', 'duration', ENV],
                     'ttl': 600,
                     'metric': 1})
        client.send({'host': host,
                     'service': exectimeservice,
                     'state': 'ok',
                     'tags': ['duration', ENV],
                     'ttl': 600,
                     'metric': exectime})
        raise
