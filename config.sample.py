#!/usr/bin/env python

# vim: tabstop=4 shiftwidth=4 softtabstop=4 expandtab

'''
config.py
===============

This configuration file defines the user parameters and some defualt VM parameters
for cases where they were left out
'''


username=''
password=''
auth_url='http://iam.savitestbed.ca:5000/v2.0/'

#Default Parameters for Nodes
region_name = 'CORE'
tenant_name = 'demo2' #'ualberta'

#Prefix, appended to instance names
instance_prefix="fee_demo_"

#key pair name
key_name='key_spandan' 

#private and public key file path
#Example private key file path: '/home/savitb/user1/.ssh/id_rsa'
private_key_file=''

#default instance properties
image_name="image-3.0.1"
#image_name="Ubuntu64-1404-OVS"
flavor_name="m1.tiny" 
sec_group_name="default"
vm_user_name="ubuntu"

