cloud-canary
============

Python script that check cloud provider availability by creating a test instance.

The goal of the script is to schedule a recurring test on a given cloud provider (in our case exoscale) by creating a "canary instance", try to connect to it using SSH and finally destroy it. If any exception occur during the process, an alarm is sent to Riemann monitoring system.

The script relies on Apache Libcloud (https://libcloud.apache.org/) and Riemann (http://riemann.io/).

Requirements:

You may install the requirements using the following commands:

```
pip install apache-libcloud
pip install paramiko (may require python-dev package)
pip install bernhard

```

Script tested only on Ubuntu.
