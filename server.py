#!/usr/bin/python3

import os, socket, argparse, logging
from channel import ICMP_Channel_Server

# Initialize argument parsing
parser = argparse.ArgumentParser()
parser.add_argument("-b", "--bind", type=str, default="0.0.0.0", help="Bind to this IP")
parser.add_argument("-v", "--verbose", action='store_true', help="Increase output verbosity")
args = parser.parse_args()

# Initialize logging
logger = logging.getLogger(__name__)
logger.setLevel(args.verbose and logging.DEBUG or logging.INFO)
formatter = logging.Formatter('%(levelname)s: [CLIENT] %(message)s')
handler = logging.StreamHandler()
handler.setFormatter(formatter)
logger.addHandler(handler)

# Initialize ICMP channel
icmp = ICMP_Channel_Server(logger, args.bind)

# Step 1: Receive size of data
expected_size = int.from_bytes(icmp.receive_data(), "big")
logger.debug(f"Expecting {expected_size} bytes")

# Step 2: Receive data until expected size is reached
data = icmp.receive_data_size(expected_size)

# Step 3: Unpad data
data = icmp.unpad(data)

# Step 4: Decode data to recover original file
data = data.decode("utf-8")

logger.info(f"Received {len(data)} bytes: {data}")
icmp.close()
