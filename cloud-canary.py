#!/usr/bin/python
# -*- coding: utf-8 -*-
# Loic Lambiel ©
# License MIT

import sys
import argparse
import logging
import logging.handlers
import time
from pprint import pprint
import socket

try:
    from libcloud.compute.types import Provider
    from libcloud.compute.providers import get_driver
    from libcloud.compute.deployment import ScriptDeployment
    from libcloud.compute.deployment import MultiStepDeployment
    from libcloud.compute.base import NodeImage
except ImportError:
    print "It look like libcloud module isn't installed. Please install it using pip install apache-libcloud"
    sys.exit(1)


try:
    import bernhard
except ImportError:
    print "It look like riemann client (bernard) isn't installed. Please install it using pip install bernhard"
    sys.exit(1)


logfile = "/var/log/cloud-canary.log"
logging.basicConfig(format='%(asctime)s %(pathname)s %(levelname)s:%(message)s', level=logging.DEBUG, filename=logfile)
logging.getLogger().addHandler(logging.StreamHandler())


def main():
    parser = argparse.ArgumentParser(description='This script spawn an instance on exoscale public cloud and execute a dummy command thru SSH. If any error occur during the process, an alarm is being sent to riemann monitoring')
    parser.add_argument('-version', action='version', version='%(prog)s 1.0, Loic Lambiel, exoscale')
    parser.add_argument('-acskey', help='Cloudstack API user key', required=True, type=str, dest='acskey')
    parser.add_argument('-acssecret', help='Cloudstack API user secret', required=True, type=str, dest='acssecret')
    parser.add_argument('-riemannhost', help='Riemann monitoring host', required=True, type=str, dest='RIEMANNHOST')
    parser.add_argument('-zoneid', help='Cloudstack zoneid', required=True, type=str, dest='RIEMANNHOST')
    args = vars(parser.parse_args())
    return args


def deploy_instance(args):
    API_KEY = args['acskey']
    API_SECRET_KEY = args['acssecret']
    zoneid = args['zoneid']

    cls = get_driver(Provider.EXOSCALE)
    driver = cls(API_KEY, API_SECRET_KEY)

    size = [size for size in driver.list_sizes() if size.name == 'Micro'][0]
    images = driver.list_images()

    for i in images:
        if 'Linux Ubuntu 14.04 LTS 64-bit 10G' in i.extra['displaytext']:

            image = NodeImage(id=i.id, name=i.name, driver=driver)

    name = 'canary-check-' + zoneid

    script = ScriptDeployment('echo Iam alive !')
    msd = MultiStepDeployment([script])

    logging.info('Deploying instance %s', name)

    node = driver.deploy_node(name=name, image=image, size=size, zoneid=zoneid,
                              max_tries=1,
                              deploy=msd)

    nodename = str(node.name)
    nodeid = str(node.uuid)
    nodeip = str(node.public_ips)
    logging.info('Instance successfully deployed : %s, %s, %s', nodename, nodeid, nodeip)
    # The stdout of the deployment can be checked on the `script` object
    pprint(script.stdout)

    logging.info('Successfully executed echo command thru SSH')
    logging.info('Destroying the instance now')
    # destroy our canary node
    driver.destroy_node(node)

    logging.info('Successfully destroyed the instance %s', name)
    logging.info('Script completed')

# main
if __name__ == "__main__":
    args = main()
    RIEMANNHOST = args['RIEMANNHOST']
    start_time = time.time()
    try:
        deploy_instance(args)
        exectime = time.time() - start_time
        client = bernhard.Client(host=RIEMANNHOST)
        host = socket.gethostname()
        client.send({'host': host,
                     'service': "Cloud_canary.exectime",
                     'state': 'ok',
                     'tags': ['duration'],
                     'ttl': 3800,
                     'metric': exectime})
        client.send({'host': host,
                     'service': "Cloud_canary.check",
                     'state': 'ok',
                     'tags': ['cloud_canary.py', 'duration'],
                     'ttl': 3800,
                     'metric': 0})
    except Exception as e:
        logging.exception("An exception occured. Exception is: %s", e)
        client = bernhard.Client(host=RIEMANNHOST)
        host = socket.gethostname()
        txt = 'An exception occurred on cloud_canary.py: %s. See logfile %s for more info' % (e, logfile)
        client.send({'host': host,
                     'service': "Cloud_canary.check",
                     'description': txt,
                     'state': 'critical',
                     'tags': ['cloud_canary.py', 'duration'],
                     'ttl': 3800,
                     'metric': 1})
        raise
