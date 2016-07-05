#!/bin/bash

echo -e "MOON Cloud\n\n******** Installing Network Isolation OpenStack Security Group"
pip2 install -r requirements.txt
cp probe_searchscan.py /usr/lib/python2.7/site-packages/testagent-0.1.0-py2.7.egg/testagent/probes/
echo -e "DONE"