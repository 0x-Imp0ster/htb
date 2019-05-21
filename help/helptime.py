'''
Quick script to show the differences in time between local system and HELP
'''
import requests
import os
r = requests.get('http://10.10.10.121/support/')
print('HELP time: \n' + r.headers['date'])
print('System time: ')
os.system('date')
