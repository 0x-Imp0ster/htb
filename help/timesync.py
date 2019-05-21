'''
The exploit for the ticket system won't work if the clocks are out of sync
This script syncs local system to be the same as HELP
'''
import os
import requests
from datetime import datetime

def time_sync():
    print('Original system date:')
    os.system('date')
    r = requests.get('http://10.10.10.121/support/')
    help_date = datetime.strptime(r.headers['date'],'%a, %d %b %Y %H:%M:%S %Z')
    date_string = help_date.strftime('%Y-%m-%d %H:%M:%S')
    cmd = 'timedatectl set-time "' + date_string + '"'
    os.system(cmd)
    print('HELP Datetime: ' + str(help_date))
    print('new system date: ')
    print(os.system('date'))
    return date_string

time_sync()
