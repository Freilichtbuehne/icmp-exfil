import socket, logging, struct, sys, time, base64
from logging import Logger

class Channel_Transport:
    class Base64:
        def __init__(self, encoding: str = 'utf-8'):
            self._encoding = encoding

        def encode(self, data: bytes) -> bytes:
            return base64.b64encode(data)

        def decode(self, data: bytes) -> str:
            return base64.b64decode(data).decode(self._encoding)

class ICMP_Channel:
    def __init__(self, logger: Logger):
        # Block size in bytes
        self._block_size = 32
        self._log = logger
        self._icmp_identifier = 1
        self._sequence_number = 0

    @property
    def block_size(self) -> int:
        return self._block_size

    @property
    def sequence_number(self) -> int:
        return self._sequence_number & 0xFFFF

    @property
    def sequence_number_next(self) -> int:
        self._sequence_number += 1
        return self._sequence_number & 0xFFFF

    @property
    def icmp_identifier(self) -> int:
        return self._icmp_identifier

    def set_transport(self, transport: any) -> None:
        assert hasattr(transport, 'encode') and hasattr(transport, 'decode'), "Transport must have encode and decode methods"
        self._transport = transport

    def set_icmp_identifier(self, identifier: int) -> None:
        assert 1 <= identifier <= 65535, "Identifier must be between 1 and 65535"
        self._icmp_identifier = identifier

    def pad(self, data: bytes, block_size: int) -> bytes:
        if len(data) == 0:
            return b'\x00' * block_size
        elif len(data) % block_size == 0:
            return data

        missing = block_size - (len(data) % block_size)
        return data + (b'\x00' * missing)

    def unpad(self, data: bytes) -> bytes:
        return data.rstrip(b'\x00')

    def __fragment(self, data: bytes, block_size: int) -> list:
        # pad data to a pultiple of the block_size
        data = self.pad(data, block_size)
        fragments = [data[i:i+block_size] for i in range(0, len(data), block_size)]
        return fragments

    def __checksum(self, paket: bytes):
        def calculate_checksum_part(data):
            _sum = 0
            for i in range(0, len(data), 2):
                # extract 16-bit-value from data
                word = (data[i] << 8) + data[i + 1]
                _sum += word
                # handle overflow
                _sum = (_sum & 0xFFFF) + (_sum >> 16)
            return _sum & 0xFFFF

        # padding with zeros if length is uneven
        if len(paket) % 2 != 0:
            paket += b'\x00'

        checksum = calculate_checksum_part(paket)
        checksum = ~checksum & 0xFFFF

        return struct.pack('!H', checksum)

    def close(self) -> None:
        if self._socket:
            self._socket.close()
            self._log.debug('Socket closed')

class ICMP_Channel_Client(ICMP_Channel):
    def __init__(self, logger: Logger):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
        logger.info('Socket initialized')
        super().__init__(logger)

    # TODO: return sequence number or id?
    def send_single_block(self, buffer: bytes, dst_ip: str) -> None:
        assert self._socket != None, "socket is None"

        header = struct.pack("!BBHHH",
            # https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages
            8, # Echo Request (8 Bit)
            0, # only 0 is allowed (8 Bit)
            0, # checksum initialized with 0 (16 Bit)
            self.icmp_identifier, # identifier (16 Bit)
            self.sequence_number_next  # sequence number (16 Bit)
        )
        checksum = self._ICMP_Channel__checksum(header + buffer)
        packet = header[:2] + checksum + header[4:] + buffer

        self._socket.sendto(packet, (socket.gethostbyname(dst_ip), 1))

    def data_size(self, data: bytes) -> int:
        blocks = self._ICMP_Channel__fragment(data, self._block_size)
        return sum([len(block) for block in blocks])

    def send_data(self, buffer: bytes, dst_ip: str, delay: int = 0) -> None:
        # Step 1: Apply transport encoding (if available)
        if hasattr(self, '_transport'):
            buffer = self._transport.encode(buffer)

        # Step 2: Calculate size of data to send (including padding)
        data_size = self.data_size(buffer)
        self._log.debug(f"Sending {data_size} bytes")

        # Step 3: Send size of data
        data_size = data_size.to_bytes(self._block_size, "big")
        size_block = self._ICMP_Channel__fragment(data_size, self._block_size)
        assert len(size_block) == 1, "Data size must fit into a single block"
        self.send_single_block(size_block[0], dst_ip)

        # Step 4: Fragment data
        blocks = self._ICMP_Channel__fragment(buffer, self._block_size)
        block_count = len(blocks)

        # Step 5: Send each block
        for i in range(block_count):
            self.send_single_block(blocks[i], dst_ip)
            self._log.info(f'Sent paket {i+1}/{block_count}')
            time.sleep(delay / 1000)


class ICMP_Channel_Server(ICMP_Channel):
    def __init__(self, logger: Logger, bind: str):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
        self._socket.bind((bind, 0))
        logger.debug('Socket initialized')
        super().__init__(logger)

    def receive_data_size(self, expected_size: int) -> bytes:
        received = bytes()
        while len(received) < expected_size:
            data = self.receive_data()
            if data == b'':
                self._log.warning('Timeout reached')
                break
            received += data

        # Unpad data
        received = self.unpad(received)

        # Apply transport decoding (if available)
        if hasattr(self, '_transport'):
            received = self._transport.decode(received)

        return received

    def receive_data(self, timeout: int = 1) -> bytes:
        assert timeout > 0, "Timeout must be > 0"

        self._socket.settimeout(timeout)
        last_run = 0
        while True:
            # Check if the socket is still open
            if self._socket is None: break
            # 1 second cooldown between each run
            if time.time() - last_run < timeout: continue

            try:
                # Receive data
                response, address = self._socket.recvfrom(1024)
                sequence_number = response[26] << 8 | response[27]
                identifier = response[24] << 8 | response[25]

                # Check if the packet has correct identifier and sequence number
                if identifier != self.icmp_identifier:
                    self._log.warning(f'Identifier mismatch: expected {self.icmp_identifier}, got {identifier}')
                    continue

                if sequence_number != self.sequence_number_next:
                    self._log.warning(f'Sequence number mismatch: expected {self.sequence_number_next}, got {sequence_number}')
                    continue

                self._log.debug(f'Received {len(response)} bytes from {address}: seq={sequence_number}, id={identifier}')
                last_run = time.time()

                # Build the response packet (Echo Reply)
                header = struct.pack("!BBHHH",
                    0 + 8, # Echo Reply (8 Bit)
                    0, # only 0 is allowed (8 Bit)
                    0, # checksum initialized with 0 (16 Bit)
                    self.icmp_identifier, # identifier (16 Bit)
                    self.sequence_number  # sequence number (16 Bit)
                )
                checksum = self._ICMP_Channel__checksum(header + response[8:])
                packet = header[:2] + checksum + header[4:] #+ response[8:]

                # Send the packet back to the client
                self._socket.sendto(packet, (socket.gethostbyname(address[0]), 1))
                self._log.debug(f'Sent Echo Reply to {address}')
                return response[28:]
            except socket.timeout:
                continue
            except KeyboardInterrupt:
                # Close the socket on keyboard interrupt
                self.close()
                return b''