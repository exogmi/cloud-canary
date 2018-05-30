cloud-canary
============

Bunch of Python scripts that perform various checks to test cloud provider availability.

- cloud-canary

The goal of the script is to schedule a recurring test on a given cloud provider (in our case exoscale) by creating a "canary instance", try to connect to it using SSH and finally destroy it. If any exception occur during the process, an alarm is sent to Riemann monitoring system. Exec time metric is also sent to Riemann to get the latency.

- api-canary

The goal of the script is to schedule a recurring test on a given cloud provider (in our case exoscale) by performing a test api call (list size). If any exception occur during the process, an alarm is sent to Riemann monitoring system. Exec time metric is also sent to Riemann to get the latency.

- s3-canary

The goal of the script is to schedule a recurring test on a given s3 provider by creating a file, read it's content and delete it. If any exception occur during the process, an alarm is sent to Riemann monitoring system. Exec time metric is also sent to Riemann to get the latency.

These scripts relies on the CS python CloudStack api wrapper (https://github.com/exoscale/cs) and Riemann (http://riemann.io/) and boto.

Requirements
------------

You may install the requirements using the following commands:

```
pip install cs
pip install paramiko (may require python-dev package)
pip install bernhard
pip install boto
```

Scripts tested only on Ubuntu and MacOS X.
