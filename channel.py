import socket, logging, struct, sys, time
from logging import Logger

class ICMP_Channel:
    def __init__(self, logger: Logger):
        # Block size in bytes
        self._block_size = 32
        self._log = logger

    @property
    def block_size(self) -> int:
        return self._block_size

    def pad(self, data: bytes, block_size: int) -> bytes:
        if len(data) == 0:
            return b'\x00' * block_size
        elif len(data) % block_size == 0:
            return data

        missing = block_size - (len(data) % block_size)
        return data + (b'\x00' * missing)

    def unpad(self, data: bytes) -> bytes:
        return data.rstrip(b'\x00')

    def _fragment(self, data: bytes, block_size: int) -> list:
        # pad data to a pultiple of the block_size
        data = self.pad(data, block_size)
        fragments = [data[i:i+block_size] for i in range(0, len(data), block_size)]
        return fragments

    def _checksum(self, paket: bytes):
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
            self._log.info('Socket closed')

class ICMP_Channel_Client(ICMP_Channel):
    def __init__(self, logger: Logger):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
        logger.info('Socket initialized')
        super().__init__(logger)

    # TODO: return sequence number or id?
    # TODO: delay?
    def send_single_block(self, buffer: bytes, dst_ip: str) -> None:
        assert self._socket != None, "socket is None"
        # TODO: assert buffer size
        #assert len(buffer) == self._block_size, f"buffer size does not match {self._block_size} bytes, got {len(buffer)} bytes"

        # https://docs.python.org/3/library/struct.html
        header = struct.pack("!BBHHH",
            # https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages
            8, # Echo Request (8 Bit)
            0, # only 0 is allowed (8 Bit)
            0, # checksum initialized with 0 (16 Bit)
            0, # identifier TODO (16 Bit)
            0  # sequence number TODO (16 Bit)
        )
        checksum = self._checksum(header + buffer)
        packet = header[:2] + checksum + header[4:] + buffer

        self._socket.sendto(packet, (socket.gethostbyname(dst_ip), 1))

    def data_size(self, data: bytes) -> int:
        blocks = self._fragment(data, self._block_size)
        return sum([len(block) for block in blocks])

    def send_data(self, buffer: bytes, dst_ip: str, delay: int = 0) -> None:
        blocks = self._fragment(buffer, self._block_size)
        block_count = len(blocks)
        for i in range(block_count):
            # TODO: progress bar
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
                self._log.info('Timeout reached')
                break
            received += data
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
                response, address = self._socket.recvfrom(1024)
                self._log.info(f'Received {len(response)} bytes from {address}')
                last_run = time.time()
                # Echo Reply to the client
                header = struct.pack("!BBHHH",
                    0 + 8, # Echo Reply (8 Bit)
                    0, # only 0 is allowed (8 Bit)
                    0, # checksum initialized with 0 (16 Bit)
                    0, # identifier TODO (16 Bit)
                    0  # sequence number TODO (16 Bit)
                )
                checksum = self._checksum(header + response[8:])
                packet = header[:2] + checksum + header[4:] #+ response[8:]
                # send the packet back to the client
                self._socket.sendto(packet, (socket.gethostbyname(address[0]), 1))
                self._log.debug(f'Sent Echo Reply to {address}')
                return response[28:]
            except socket.timeout:
                continue
            except KeyboardInterrupt:
                # Close the socket on keyboard interrupt
                self.close()
                return b''