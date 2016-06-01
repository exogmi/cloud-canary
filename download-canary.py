#!/usr/bin/python
# -*- coding: utf-8 -*-
# Loic Lambiel ©
# License MIT

import sys
import argparse
import logging
import logging.handlers
import time
import socket
import urllib.request


try:
    import bernhard
except ImportError:
    print ("It look like riemann client (bernard) isn't installed. Please install it using pip install bernhard")
    sys.exit(1)


try:
    from configparser import ConfigParser
except ImportError:  # python 2
    from ConfigParser import ConfigParser

logfile = "/var/log/s3-canary.log"
logging.basicConfig(format='%(asctime)s %(pathname)s %(levelname)s:%(message)s', level=logging.DEBUG, filename=logfile)
logging.getLogger().addHandler(logging.StreamHandler())
logging.getLogger('boto').setLevel(logging.CRITICAL)


def main():
    parser = argparse.ArgumentParser(description='This script create download a small file from a given URL. If any error occur during the process, an alarm is being sent to riemann monitoring. time metric is also sent to riemann')
    parser.add_argument('-version', action='version', version='%(prog)s 1.0, Loic Lambiel, exoscale')
    parser.add_argument('-url', help='S3 user key', required=True, type=str, dest='key')
    parser.add_argument('-env', help='Environnement, ex: prod | qa etc..., will be used in the riemann service', required=True, type=str, dest='env')
    args = vars(parser.parse_args())
    return args


def downloadtest(args):
    URL = args['url']

    response = urllib.request.urlopen(URL)
    response.read()

# main
if __name__ == "__main__":
    args = main()
    conf = ConfigParser()
    conf.read(("/etc/bernhard.conf",))

    client = bernhard.SSLClient(host=conf.get('default', 'riemann_server'),
                                port=int(conf.get('default', 'riemann_port')),
                                keyfile=conf.get('default', 'tls_cert_key'),
                                certfile=conf.get('default', 'tls_cert'),
                                ca_certs=conf.get('default', 'tls_ca_cert'))
    ENV = args['env']
    exectimeservice = "%s.download_canary.exectime" % ENV
    start_time = time.time()
    try:
        downloadtest(args)
        exectime = time.time() - start_time
        host = socket.gethostname()
        client.send({'host': host,
                     'service': exectimeservice,
                     'state': 'ok',
                     'tags': ['duration', ENV],
                     'ttl': 600,
                     'metric': exectime})

        logging.info('Script completed successfully')

    except Exception as e:
        logging.exception("An exception occured. Exception is: %s", e)
        host = socket.gethostname()
        exectime = 61
        txt = 'An exception occurred on download_canary.py: %s. See logfile %s for more info' % (e, logfile)
        client.send({'host': host,
                     'service': exectimeservice,
                     'description': txt,
                     'state': 'critical',
                     'tags': ['s3_canary.py', 'duration', ENV],
                     'ttl': 600,
                     'metric': 1})
        raise
