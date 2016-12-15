#!/usr/bin/python
# -*- coding: utf-8 -*-
# Loic Lambiel ©
# License MIT

import argparse
import logging
import logging.handlers
import time
import socket
import uuid

import bernhard

from libcloud.compute.types import Provider
from libcloud.compute.providers import get_driver
from libcloud.compute.deployment import ScriptDeployment
from libcloud.compute.deployment import MultiStepDeployment
from libcloud.compute.base import NodeImage
from pythonjsonlogger import jsonlogger

try:
    from configparser import ConfigParser
except ImportError:  # python 2
    from ConfigParser import ConfigParser

logfile = "/var/log/cloud-canary.log"

logger = logging.getLogger()
logHandler = logging.StreamHandler()
formatter = jsonlogger.JsonFormatter()
logHandler.setFormatter(formatter)
logger.addHandler(logHandler)
logger.basicConfig(level=logging.DEBUG, filename=logfile)
uuid = str(uuid.uuid1())


def main():
    parser = argparse.ArgumentParser(description='This script spawn an instance on exoscale public cloud and execute a dummy command thru SSH. If any error occur during the process, an alarm is being sent to riemann monitoring')
    parser.add_argument('-version', action='version', version='%(prog)s 1.0, Loic Lambiel, exoscale')
    parser.add_argument('-acskey', help='Cloudstack API user key', required=True, type=str, dest='acskey')
    parser.add_argument('-acssecret', help='Cloudstack API user secret', required=True, type=str, dest='acssecret')
    parser.add_argument('-zone', help='Cloudstack zoneid', required=True, type=str, dest='zonename')
    parser.add_argument('-env', help='Environement ex. Prod', required=True, type=str, dest='env')
    parser.add_argument('-alertstate', help='The state of the alert to raise if the test fails', required=False, type=str, default='critical', dest='state')
    parser.add_argument('-endpoint', help='The API endpoint', required=False, type=str, default='api.exoscale.ch', dest='endpoint')
    args = vars(parser.parse_args())
    return args


def deploy_instance(args, d):
    API_KEY = args['acskey']
    API_SECRET_KEY = args['acssecret']
    zonename = args['zonename']
    endpoint = args['endpoint']
    env = args['env']

    cls = get_driver(Provider.EXOSCALE)
    driver = cls(API_KEY, API_SECRET_KEY, host=endpoint)

    name = 'canary-check-' + zonename + env

    ex_userdata = '''#cloud-config
    manage_etc_hosts: true
    fqdn: %s
    ''' % (name)

    location = [location for location in driver.list_locations() if location.name == zonename][0]

    size = [size for size in driver.list_sizes() if size.name == 'Micro'][0]
    images = driver.list_images()

    for i in images:
        if 'Linux Ubuntu 16.04 LTS 64-bit 10G' in i.extra['displaytext']:

            image = NodeImage(id=i.id, name=i.name, driver=driver)

    script = ScriptDeployment('cat /etc/hostname')
    msd = MultiStepDeployment([script])

    logger.info('Deploying instance %s', name)

    node = driver.deploy_node(name=name, image=image, size=size, location=location,
                              max_tries=1, userdata=ex_userdata,
                              deploy=msd)

    d['nodename'] = str(node.name)
    d['nodeid'] = str(node.uuid)
    d['nodeip'] = str(node.public_ips)
    d['nodepassword'] = str(node.password)
    logger.info('Instance successfully deployed : %s, %s, %s, %s', d['nodename'], d['nodeid'], d['nodeip'], d['nodepassword'])
    # The stdout of the deployment can be checked on the `script` object
    if not d['nodename'] == script.stdout:
        raise Exception('Node hostname does not match. there might be an issue with metadata serivce')

    logger.info('Successfully checked node hostname')
    logger.info('Destroying the instance now')
    # destroy our canary node
    driver.destroy_node(node)

    logger.info('Successfully destroyed the instance %s', name)
    logger.info('Script completed')

# main
if __name__ == "__main__":
    args = main()
    d = {}
    zonename = args['zonename']
    state = args['state']
    env = args['env']
    conf = ConfigParser()
    conf.read(("/etc/bernhard.conf",))

    client = bernhard.SSLClient(host=conf.get('default', 'riemann_server'),
                                port=int(conf.get('default', 'riemann_port')),
                                keyfile=conf.get('default', 'tls_cert_key'),
                                certfile=conf.get('default', 'tls_cert'),
                                ca_certs=conf.get('default', 'tls_ca_cert'))
    start_time = time.time()
    try:
        deploy_instance(args, d)
        exectime = time.time() - start_time
        host = socket.gethostname()
        client.send({'host': host,
                     'service': "Cloud_canary-" + zonename + env + ".exectime",
                     'state': 'ok',
                     'tags': ['duration'],
                     'ttl': 3800,
                     'metric': exectime})
        client.send({'host': host,
                     'service': "Cloud_canary-" + zonename + env + ".check",
                     'state': 'ok',
                     'tags': ['cloud_canary.py', 'duration'],
                     'ttl': 3800,
                     'metric': 0})
    except Exception as e:
        logger.exception("An exception occured. Exception is: %s", e)
        host = socket.gethostname
        txt = '%s | nodename = %s nodeid = %s nodeip = %s nodepassword = %s' % (e, d['nodename'], d['nodeid'], d['nodeip'], d['nodepassword'])
        client.send({'host': host,
                     'service': "Cloud_canary-" + zonename + env + ".check",
                     'description': txt,
                     'state': state,
                     'tags': ['cloud_canary.py', 'duration'],
                     'ttl': 3800,
                     'metric': 1})
        raise
