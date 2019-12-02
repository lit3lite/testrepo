from scapy.all import *
import random

#dip='10.185.228.189'
#dip='192.168.98.33'
dip = '10.0.2.15'
dp=3389

rand_min=10
rand_max=60
default_sleep_time=10

ports_dic = {
        135: 'RPC/WMI',
        53: 'DNS',
        69: 'TFTP',
        80: 'HTTP, Kerberos authentication(http)',
        9389: 'Active Directory Web Services (ADWS), Active Directory Management Gateway Service',
        3269: 'Global Catalog',
        3268: 'Global Catalog',
        389: 'LDAP Server, ',
        636: 'LDAP SSL',
        500: 'IPsec ISAKMP',
        593: 'RPC over HTTPS',
        445: 'SMB',
        21: 'FTP',
        3343: 'Cluster Service',
        137: 'Cluster Administrator',
        139: 'NetBIOS Session Service',
        647: 'DHCP Failover',
        5722: 'RPC on Win 2008 Domain Controller',
        443: 'HTTPS, Certificate-based authentication',
        6600: 'Live migration',
        464: 'Kerberos Password V5',
        88: 'Kerberos',
        1801: 'MSMQ',
        2101: 'MSMQ-DCs',
        2107: 'MSMQ-Mgmt',
        2105: 'MSMQ-RPC',
        2103: 'MSMQ-RPC',
        102: 'X.400',
        110: 'POP3',
        3389: 'Terminal Services',
        3269: 'Global Catalog',
        3268: 'Global Catalog',
}


def check_open(dip,dp,sp=RandShort(),time_out=10):
    status = 'status none'
    response =  sr1(IP(dst=dip)/TCP(sport=sp, dport=dp,flags='S'),timeout=time_out)
    
    if response != None:
        if response[TCP].flags == 'SA':
            status = '{0}:{1} Open'.format(dip,dp)
        elif response[TCP].flags == 'R':
            status = '{0}:{1} Closed'.format(dip,dp)
        elif response[TCP].flags == 'RA':
            status = '{0}:{1} Closed'.format(dip,dp)
        else:
            status = '{0}:{1} {3}'.format(dip,dp,response.show())
    else:
        status = '{0}:{1} no response'.format(dip,dp)

    return status



def scan_ports(pd):
    for k,v in pd.items():
        print("port: {0}, descr: {1}".format(k,v))
        res = check_open(dip,k)
        print(res)
        sleep_interval = random.randint(rand_min, rand_max)
        sleep_interval += default_sleep_time
        print("Sleeping: {0} sec".format(sleep_interval))
        time.sleep(sleep_interval)



