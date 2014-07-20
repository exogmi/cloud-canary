#!/usr/bin/python
# -*- coding: utf-8 -*-
#Loic Lambiel ©
# License MIT

import sys, getopt, argparse
import logging, logging.handlers
import time
from datetime import datetime, timedelta
from pprint import pprint
import sys
import socket

try:
    from libcloud.compute.types import Provider
    from libcloud.compute.providers import get_driver
except ImportError:
    print "It look like libcloud module isn't installed. Please install it using pip install apache-libcloud"
    sys.exit(1)
 

try:
    import bernhard
except ImportError:
    print "It look like riemann client (bernard) isn't installed. Please install it using pip install bernhard"
    sys.exit(1)


logfile = "/var/log/api-canary.log"
logging.basicConfig(format='%(asctime)s %(pathname)s %(levelname)s:%(message)s', level=logging.DEBUG,filename=logfile)
logging.getLogger().addHandler(logging.StreamHandler())


def main():
    parser = argparse.ArgumentParser(description='This script perform a list_size API query on exoscale public cloud. If any error occur during the process, an alarm is being sent to riemann monitoring. time metric is also sent to riemann')
    parser.add_argument('-version', action='version', version='%(prog)s 1.0, Loic Lambiel, exoscale')
    parser.add_argument('-acskey', help='Cloudstack API user key', required=True, type=str, dest='acskey')
    parser.add_argument('-acssecret', help='Cloudstack API user secret', required=True, type=str, dest='acssecret')
    parser.add_argument('-riemannhost', help='Riemann monitoring host', required=True, type=str, dest='RIEMANNHOST')
    args = vars(parser.parse_args())
    return args

 
def list_size(args):
    API_KEY = args['acskey']
    API_SECRET_KEY = args['acssecret']

    cls = get_driver(Provider.EXOSCALE)
    driver = cls(API_KEY, API_SECRET_KEY)

    logging.info('Performing query')
	 
    size = driver.list_sizes() 

    micro = False

    for item in size:
        if item.name == 'Micro':
            micro = True

    if micro is False:
        raise Exception ("API call did not returned Micro instance type. This means the API isn't working correctly")
 
    logging.info('Script completed successfully')

#main
if __name__ == "__main__":
    args = main()
    RIEMANNHOST = args['RIEMANNHOST']
    start_time = time.time()
    try:
        list_size(args)
        exectime = time.time() - start_time
        client=bernhard.Client(host=RIEMANNHOST)
        host = socket.gethostname()
        client.send({'host': host,
                     'service': "api_canary.exectime",
                     'state': 'ok',
                     'tags': ['duration'],
                     'ttl': 600,
                     'metric': exectime})
        client.send({'host': host,
                     'service': "api_canary.check",
                     'state': 'ok',
                     'tags': ['api_canary.py', 'duration'],
                     'ttl': 600,
                     'metric': 1})
    except Exception as e:
        pass
        logging.exception("An exception occured. Exception is: %s", e)
        client=bernhard.Client(host=RIEMANNHOST)
        host = socket.gethostname()
        exectime = 61
        txt = 'An exception occurred on api_canary.py: %s. See logfile %s for more info' % (e,logfile)
        client.send({'host': host,
                     'service': "api_canary.check",
                     'description': txt,
                     'state': 'warning',
                     'tags': ['api_canary.py', 'duration'],
                     'ttl': 600,
                     'metric': 0})
        client.send({'host': host,
                     'service': "api_canary.exectime",
                     'state': 'ok',
                     'tags': ['duration'],
                     'ttl': 600,
                     'metric': exectime})
        sys.exit(1)


