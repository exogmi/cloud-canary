#!/usr/bin/python
# -*- coding: utf-8 -*-
# Loic Lambiel ©
# License MIT

import argparse
import logging
import logging.handlers
import pprint
import socket
import sys
import time


try:
    from cs import CloudStack, CloudStackException
except ImportError:
    print("It look like cs module isn't installed. Please install it "
          "using pip install cs")
    sys.exit(1)

try:
    from paramiko.client import AutoAddPolicy, SSHClient
except ImportError:
    print("It look like paramiko module isn't installed. Please install it "
          "using pip install paramiko")
    sys.exit(1)


try:
    import bernhard
except ImportError:
    print("It look like riemann client (bernard) isn't installed. Please "
          "install it using pip install bernhard")
    sys.exit(1)

try:
    from configparser import ConfigParser
except ImportError:  # python 2
    from ConfigParser import ConfigParser


def ssh_execute_command(ip, command, username, password):
    with SSHClient() as client:
        client.set_missing_host_key_policy(AutoAddPolicy())
        # Will try to connect during 60 seconds
        not_connected = True
        first_try = time.time()
        while not_connected:
            try:
                args = {'username': username,
                        'timeout': 15,
                        'allow_agent': False,
                        'look_for_keys': False,
                        'banner_timeout': 15,
                        'password': password}
                client.connect(ip, **args)
                not_connected = False
            except Exception:
                if time.time() - first_try > 60:
                    raise
                else:
                    time.sleep(5)
        stdin, stdout, stderr = client.exec_command(command, get_pty=True)
        stdin.close()
        return stdout.read(), stderr.read()


def main():
    parser = argparse.ArgumentParser(description='''
This script spawn an instance on exoscale public cloud and execute a dummy
command thru SSH. If any error occur during the process, an alarm is being
sent to riemann monitoring''')
    parser.add_argument('-version', action='version',
                        version='%(prog)s 1.0, Loic Lambiel, exoscale')
    parser.add_argument('-acskey', help='Cloudstack API user key',
                        required=True, type=str, dest='acskey')
    parser.add_argument('-acssecret', help='Cloudstack API user secret',
                        required=True, type=str, dest='acssecret')
    parser.add_argument('-zonename', help='Cloudstack zone name',
                        required=True, type=str, dest='zonename')
    parser.add_argument('-alertstate',
                        help='Alert state to raise if the test fails',
                        required=False, type=str, default='critical',
                        dest='state')
    parser.add_argument('-endpoint', help='The API endpoint', required=False,
                        type=str, default='api.exoscale.ch', dest='endpoint')
    parser.add_argument('-template',
                        help='Template name to use for the deployment',
                        required=False, type=str,
                        default='Linux Ubuntu 16.04 LTS 64-bit 10G',
                        dest='template')
    parser.add_argument('-offering',
                        help='Service offering to use for the deployment',
                        required=False, type=str,
                        default='Micro',
                        dest='offering')
    args = vars(parser.parse_args())
    return args


def deploy_instance(args):
    api_key = args['acskey']
    secret_key = args['acssecret']
    zonename = args['zonename']
    endpoint = "https://" + args['endpoint'] + "/compute"
    template = args['template']
    offering = args['offering']

    logging.basicConfig(
        format='%(asctime)s %(pathname)s %(levelname)s:%(message)s',
        level=logging.DEBUG,
        filename=logfile)
    logging.getLogger().addHandler(logging.StreamHandler())

    cs = CloudStack(endpoint=endpoint,
                    key=api_key,
                    secret=secret_key)

    location = [location for location in cs.listZones()['zone']
                if location['name'].lower() == zonename.lower()][0]

    logging.info("Zone selected : %s", location)

    so = [so for so in cs.listServiceOfferings()['serviceoffering']
          if so['name'].lower() == offering.lower()][0]

    template = [i for i in cs.listTemplates(
                templatefilter='featured',
                fetch_list=True)
                if template.lower() in i['displaytext'].lower()][0]

    try:
        username = template['details']['username']
    except KeyError:
        username = 'ubuntu'

    name = 'canary-check-' + location['name'].lower()

    if endpoint != 'https://api.exoscale.ch/compute':
        name += '-pp'

    for node in cs.listVirtualMachines()['virtualmachine']:
        if node['name'] == name:
            raise Exception('Instance with same name already exists !')

    logging.info('Deploying instance %s', name)

    vm = cs.deployVirtualMachine(templateid=template['id'],
                                 zoneid=location['id'],
                                 serviceofferingid=so['id'],
                                 name=name)
    error_calls = 0
    while True:
        try:
            res = cs.queryAsyncJobResult(**vm)
        except CloudStackException:
            error_calls += 1
            if error_calls < 20:
                logging.info("failed async job result query, retrying")
            else:
                raise

        if res['jobstatus'] != 0:
            job = res['jobresult']
            break
        time.sleep(3)

    logging.debug(pprint.pformat(job))
    vm = job['virtualmachine']

    nodename = str(vm['name'])
    nodeid = str(vm['id'])
    nodeip = str(vm['nic'][0]['ipaddress'])
    logging.info('Instance successfully deployed : %s, %s, %s', nodename,
                 nodeid, nodeip)

    logging.info('Trying connecting thru SSH')
    command = "echo Hello World"
    stdout, stderr = ssh_execute_command(nodeip, command,
                                         username, vm['password'])
    if stdout != 'Hello World\r\n':
        raise Exception("Error executing ssh command")

    logging.info('Successfully executed echo command thru SSH')
    logging.info('Destroying the instance now')

    cs.destroyVirtualMachine(id=nodeid)

    logging.info('Successfully destroyed the instance %s', name)
    logging.info('Script completed')
    

# main
if __name__ == "__main__":
    args = main()
    zonename = args['zonename']
    state = args['state']
    endpoint = args['endpoint']
    if endpoint == "ppapi.exoscale.ch":
        env = "pp"
    else:
        env = "prod"
    logfile = "/var/log/cloud-canary-{}-{}.log".format(env, zonename)
    conf = ConfigParser()
    conf.read(("/etc/bernhard.conf",))
    if endpoint != 'api.exoscale.ch':
        zonename += '-pp'
    client = bernhard.SSLClient(host=conf.get('default', 'riemann_server'),
                                port=int(conf.get('default', 'riemann_port')),
                                keyfile=conf.get('default', 'tls_cert_key'),
                                certfile=conf.get('default', 'tls_cert'),
                                ca_certs=conf.get('default', 'tls_ca_cert'))
    start_time = time.time()
    try:
        deploy_instance(args)
        exectime = time.time() - start_time
        host = socket.gethostname()
        client.send({'host': host,
                     'service': "Cloud_canary-" + zonename + ".exectime",
                     'state': 'ok',
                     'tags': ['duration'],
                     'ttl': 3800,
                     'metric': exectime})
        client.send({'host': host,
                     'service': "Cloud_canary-" + zonename + ".check",
                     'state': 'ok',
                     'tags': ['cloud_canary.py', 'duration'],
                     'ttl': 3800,
                     'metric': 0})
    except Exception as e:
        logging.exception("An exception occured. Exception is: %s", e)
        host = socket.gethostname()
        txt = ("An exception occurred on cloud_canary.py: {}. See logfile {} "
               "for more info").format(e, logfile)
        client.send({'host': host,
                     'service': "Cloud_canary-" + zonename + ".check",
                     'description': txt,
                     'state': state,
                     'tags': ['cloud_canary.py', 'duration'],
                     'ttl': 3800,
                     'metric': 1})
        raise
