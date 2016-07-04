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

try:
    import boto
    import boto.s3.connection
    from boto.s3.key import Key
except ImportError:
    print ("It look like boto module isn't installed. Please install it using pip install boto")
    sys.exit(1)


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
logging.getLogger('boto').setLevel(logging.DEBUG)


class CustomError(Exception):

    def __init__(self, arg):
        self.msg = arg


def main():
    parser = argparse.ArgumentParser(description='This script create a file, read it and delete it on a s3 compliant storage. If any error occur during the process, an alarm is being sent to riemann monitoring. time metric is also sent to riemann')
    parser.add_argument('-version', action='version', version='%(prog)s 1.0, Loic Lambiel, exoscale')
    parser.add_argument('-key', help='S3 user key', required=True, type=str, dest='key')
    parser.add_argument('-secret', help='S3 user secret', required=True, type=str, dest='secret')
    parser.add_argument('-host', help='S3 host', required=True, type=str, dest='host')
    parser.add_argument('-bucket', help='S3 bucket', required=True, type=str, dest='bucket')
    parser.add_argument('-env', help='Environnement, ex: prod | qa etc..., will be used in the riemann service', required=True, type=str, dest='env')
    parser.add_argument('-alertstate', help='The state of the alert to raise if the test fails', required=False, type=str, default='critical', dest='state')
    args = vars(parser.parse_args())
    return args


def s3test(args):
    KEY = args['key']
    SECRET = args['secret']
    HOST = args['host']
    BUCKET = args['bucket']
    ENV = args['env']

    logging.info('Test started for env %s', ENV)

    conn = boto.connect_s3(
        aws_access_key_id=KEY,
        aws_secret_access_key=SECRET,
        host=HOST,
        calling_format=boto.s3.connection.OrdinaryCallingFormat(),
    )

    logging.info('Creating bucket %s', BUCKET)
    bucket = conn.create_bucket(BUCKET)
    logging.info('Bucket create for env %s', ENV)

    k = Key(bucket)
    k.key = 's3-canary'
    logging.info('Writing file')
    k.set_contents_from_string('This is a test of S3')
    logging.info('Write done for env %s', ENV)
    time.sleep(1)
    logging.info('Reading back the file for env %s', ENV)

    if k.get_contents_as_string() != "This is a test of S3":
        raise CustomError('Failed to read back the created file !')

    logging.info('File has been read back for env %s', ENV)
    logging.info('Deleting bucket for env %s', ENV)
    bucket.delete_key(k)
    logging.info('Bucket deleted for env %s', ENV)

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
    state = args['state']
    exectimeservice = "%s.s3_canary.exectime" % ENV
    checkservice = "%s.s3_canary.check" % ENV
    start_time = time.time()
    try:
        s3test(args)
        exectime = time.time() - start_time
        host = socket.gethostname()
        client.send({'host': host,
                     'service': exectimeservice,
                     'state': 'ok',
                     'tags': ['duration', ENV],
                     'ttl': 600,
                     'metric': exectime})
        client.send({'host': host,
                     'service': checkservice,
                     'state': 'ok',
                     'tags': ['s3_canary.py', 'duration', ENV],
                     'ttl': 600,
                     'metric': 0})

        logging.info('Script completed successfully for env %s', ENV)

    except Exception as e:
        logging.exception("An exception occured. Exception is: %s", e)
        host = socket.gethostname()
        exectime = 61
        txt = 'An exception occurred on s3_canary.py: %s. See logfile %s for more info' % (e, logfile)
        client.send({'host': host,
                     'service': checkservice,
                     'description': txt,
                     'state': state,
                     'tags': ['s3_canary.py', 'duration', ENV],
                     'ttl': 600,
                     'metric': 1})
        client.send({'host': host,
                     'service': exectimeservice,
                     'state': 'ok',
                     'tags': ['duration', ENV],
                     'ttl': 600,
                     'metric': exectime})
        raise
