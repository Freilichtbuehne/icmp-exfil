import socket, logging, struct
from logging import Logger

class Channel:
    CLIENT = 0
    SERVER = 1

class ICMP_Channel:
    def _init_client(self) -> socket:
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))

    def _init_server(self) -> socket:
        raise NotImplementedError

    # TODO: inizialize with ip
    def __init__(self, mode: int, logger: Logger):
        # Block size in bytes
        self._block_size = 12
        self._mode = mode
        self._log = logger
        if mode == Channel.CLIENT:
            self._init_client()
        elif mod == Channel.SERVER:
            self._init_server()
        else:
            raise ValueError(f"Mode must be Channel.CLIENT or Channel.SERVER, got '{mode}'")
        self._log.info('Socket initialized')

    def _pad(self, data: bytes, block_size: int) -> bytes:
        if len(data) == 0:
            return b'\x00' * block_size
        elif len(data) % block_size == 0:
            return data

        missing = block_size - (len(data) % block_size)
        return data + (b'\x00' * missing)

    def _fragment(self, data: bytes, block_size: int) -> list:
        # pad data to a pultiple of the block_size
        data = self._pad(data, block_size)
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

    # TODO: return sequence number or id?
    # TODO: delay?
    def send_single_block(self, buffer: bytes, dst_ip: str) -> None:
        assert self._socket != None, "socket is None"
        assert len(buffer) == self._block_size, f"buffer size does not match {self._block_size} bytes, got {len(buffer)} bytes"

        # https://docs.python.org/3/library/struct.html
        header = header = struct.pack("!BBHHH",
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

    def send_data(self, buffer: bytes, dst_ip: str) -> None:
        blocks = self._fragment(buffer, self._block_size)
        block_count = len(blocks)
        for i in range(block_count):
            # TODO: progress bar
            self.send_single_block(blocks[i], dst_ip)
            self._log.info(f'Sent paket {i+1}/{block_count}')

    def close(self) -> None:
        if self._socket:
            self._socket.close()
            self._log.info('Socket closed')
