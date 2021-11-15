#!/bin/bash
cd /home/ubuntu/webapp/todo
sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
    -a fetch-config \
    -m ec2 \
    -c file:/home/ubuntu/webapp/todo/logs/watch.json\
    -s
pip install -r requirements.txt