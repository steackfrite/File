#!/bin/python3

### Import ###
import csv
import logging
import sys
import time
import xml.dom.minidom
### Import ###

### From ###
from xml.dom.minidom import parse
### From ###

### Perso ###
# Path
sys.path.append('/home/the-freeman/Scripts/Reco')
# From
from File import file_library as file_lib
### Perso ###


### Log ###
# logging.basicConfig(filename='/var/log/Script/file_lib.log', \
#                     format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', \
#                     level=logging.INFO)

#################################################################################
#                                                                               #
# Function: Reads from an xml file                                              #
# Parameters: - File name of the CSV (String)                                   #
#             - Nested directory specific to my script (Nested Dict)            #
# Return: Dict of Strings containing Hostnames as key and Ports as data         #
#                                                                               #
#################################################################################
def read_nmap_xml(file_name):
    ## Variables
    host_dict = {}

    # Open XML document using minidom parser
    DOMTree = xml.dom.minidom.parse(file_name)
    collection = DOMTree.documentElement

    # if collection.hasAttribute('scanner'):
    #     root_element = collection.getAttribute('scanner')
    #     print ('Root element : ' + root_element)

    # Get all the hosts in the collection
    hosts = collection.getElementsByTagName("host")

    ## Print hostnames of all hosts ##
    for host in hosts:
        # Parents
        hostnames_tag = host.getElementsByTagName('hostnames')
        ports_tag = host.getElementsByTagName('ports')

        # Childs 1
        hostname_tag = hostnames_tag.item(0).getElementsByTagName('hostname') # item(0) because there is just one hostnames <tag> per host <tag>
        port_tag = ports_tag.item(0).getElementsByTagName('port') # item(0) because there is just one ports <tag> per host <tag>

        print(hostname_tag)

        if hostname_tag:
            # Child 2
            hostname = hostname_tag.item(0).getAttribute('name') # item(0) = hostname || item(1) = PTR hostname
            print(hostname)
            # Save hostame as key in a dict
            host_dict[hostname] = []

            ## Save ports as data in the dict ##
            for port in port_tag:
                portid = port.getAttribute('portid')
                host_dict[hostname].append(portid)
            ## Save ports as data in the dict ##

            host_dict[hostname] = ' || '.join(host_dict[hostname])
    ## Print hostnames and ports of all hosts ##

    # print(host_dict)

    return host_dict

#################################################################################
#                                                                               #
# Function: Reads from an xml file                                              #
# Parameters: - File name of the CSV (String)                                   #
#             - Nested directory specific to my script (Nested Dict)            #
# Return: Dict of Strings containing Hostnames as key and Ports as data         #
#                                                                               #
#################################################################################
def xml_to_csv(xml_file, csv_file):
    ## Variables
    # System
    timestr = time.strftime("%Y%m%d-%H%M%S")
    # CSV
    csv_delimiter = ','
    # File
    csv_rows = file_lib.read_csv(csv_file, csv_delimiter)
    xml_data = read_nmap_xml(xml_file)
    result_file = 'Result/csv_updated' + timestr + '.csv'

    # Finding match FQDN between CSV and XML
    for csv_row in csv_rows:
        for fqdn in xml_data:
            # If FQDN are the same replace the 'PORT' column from row to ports contained in row[fqdn]
            if csv_row[3] == fqdn:
                csv_row[12] = xml_data[fqdn]

    file_lib.write_to_csv(result_file, csv_rows)

    return 0


### Main ###
if __name__ == '__main__':
    ## Variables
    csv_file = 'Data/subdom_result.csv'
    xml_file = 'Data/nmap_critical_nov.xml'

    ## Main
    xml_to_csv(xml_file, csv_file)
























# Space
