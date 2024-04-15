"""
Author: Steven Wells
Email: snw2535@rit.edu
Class: CSCI 351 - Data Communications and Networks
Professor: Bruce Hartpence
Program for reading packet headers from a file and computing checksums.
This program will only read TCP packets inside Wireshark K12 text files.
"""

import argparse

argparser = argparse.ArgumentParser(description="Read packet headers from a file and compute checksums")

argparser.add_argument('-f', '--filename', required=True, help="Name of the file to read packet headers from")

program_errors = {
    'tcp': "Not a TCP packet",
    'ip': "Not an IP packet",
    'K12': "Not a Wireshark K12 text file"
}

def nibbles_to_bytes(nibble_list:list[str]):
    return [str(str(nibble_list[i]) + str(nibble_list[i+1])) for i in range(0, len(nibble_list), 2)]
    
def mac_address_from_hex(mac_nibbles:list[str]):
    bytes = nibbles_to_bytes(mac_nibbles)
    return ':'.join([byte for byte in bytes if byte is not None])

def eth_type_from_hex(eth_type_nibbles:list[str]):
    bytes = nibbles_to_bytes(eth_type_nibbles)
    return '0x' + ''.join(bytes)

def ip_address_from_nibbles(ip_nibbles:list[str]):
    return '.'.join([str(int(byte, 16)) for byte in nibbles_to_bytes(ip_nibbles)])

def hex_to_decimal(hex_nibbles:list[str]):
    return int(''.join(hex_nibbles), 16)

def check_file_exists(filename):
    try:
        with open(filename, 'r') as file:
            return True
    except FileNotFoundError:
        return False
    
def do_wrap_around(checksum:int):
    new_checksum = checksum
    
    binary_repr = bin(new_checksum)[2:].zfill(16)
    if len(binary_repr) > 16:
        long_repr = binary_repr.zfill(20)
        leftmost_octet = long_repr[:4]
        
        adjusted = long_repr[4:]
        new_checksum = int(adjusted, 2) + int(leftmost_octet, 2)
        
    return new_checksum


class Field:
    name: str
    value_nibbles: list[str]
    binary: str
    decoded_value: str
    
    def __init__(self, name, value_nibbles=None, value_decoder=None, value_binary=None ):
        self.name = name
        self.value_nibbles = value_nibbles
        self.binary = value_binary
        
        if value_nibbles:
            self.decoded_value = value_decoder(value_nibbles) if value_decoder else ' '.join(nibbles_to_bytes(value_nibbles))
        elif value_binary and value_decoder:
            self.decoded_value = value_decoder(value_binary)
        else:
            raise ValueError("No value provided")
        
    def value_binary(self):
        if self.value_nibbles:
            return bin(int(''.join(self.value_nibbles), 16))[2:]
        
    def __str__(self):
        return self.name + ' - ' + self.decoded_value
    
    
class Layer:
    hex_nibbles: list[str]
    title: str
    fields: list[Field]
    data_nibbles: list[str]
    display_data:bool = True
    
    def __init__(self, hex_nibbles, title, fields, data_nibbles, display_data=False):
        self.hex_nibbles = hex_nibbles
        self.title = title
        self.fields = fields
        self.data_nibbles = data_nibbles
        self.display_data = display_data
        
    def __str__(self):
        return f'\n{self.title}-------------------------------------\n' \
            + '\n'.join([str(field) for field in self.fields]) + ('\nData - ' \
            + ' '.join(nibbles_to_bytes(self.data_nibbles)) if self.display_data else '')


class FrameProcessor:
    def process_eth_layer(hex_nibbles):
        destination_mac = Field("Destination MAC Address", hex_nibbles[:12], mac_address_from_hex)
        source_mac = Field("Source MAC Address", hex_nibbles[12:24], mac_address_from_hex)
        eth_type = Field("Type", hex_nibbles[24:28], eth_type_from_hex)
        
        if eth_type.decoded_value != '0x0800':
            raise ValueError(program_errors["ip"])
        
        fields = [destination_mac, source_mac, eth_type]
        
        data = hex_nibbles[28:]
        
        return Layer(hex_nibbles, "Ethernet", fields, data)
    
    def process_ip_layer(ip_nibbles):
        version = Field("Version/IHL", ip_nibbles[:1], lambda x: f'Version: {int("".join(x), 16)}')
        header_length = Field("Header Length", ip_nibbles[1:2], lambda x: f'{int("".join(x), 16) * 4} bytes')
        type_of_service = Field("Type of Service", ip_nibbles[2:4], lambda x: f'0x{str("".join(x)).rjust(2, "0")}')
        total_length = Field("Total Length", ip_nibbles[4:8], lambda x: str(int("".join(x), 16)))
        identification = Field("Identification", ip_nibbles[8:12], lambda x: f'0x{"".join(x)}')
        
        flags_and_offset_binary = bin(int(''.join(ip_nibbles[12:16]), 16))[2:].zfill(16)
        
        flags_binary = flags_and_offset_binary[:3]
        offset_binary = flags_and_offset_binary[3:]
        
        flags = Field("Flags", None, lambda x: f'0x{int(x, 2)}', flags_binary)
        offset = Field("Fragment Offset", None, lambda x: f'{int(x, 2)}', offset_binary)
        
        ttl = Field("TTL", ip_nibbles[16:18], lambda x: str(hex_to_decimal(x)))
        protocol = Field("Protocol", ip_nibbles[18:20], lambda x: str(hex_to_decimal(x)))
        checksum = Field("Header Checksum", ip_nibbles[20:24], lambda x: f'0x{"".join(x)}')
        source_ip = Field("Source IP Address", ip_nibbles[24:32], ip_address_from_nibbles)
        destination_ip = Field("Destination IP Address", ip_nibbles[32:40], ip_address_from_nibbles)
        
        if protocol.decoded_value != '6':
            raise ValueError(program_errors['tcp'])

        fields = [version, header_length, type_of_service, total_length, identification, flags, offset, ttl, protocol, checksum, source_ip, destination_ip]
        
        data = ip_nibbles[40:]  
        
        return Layer(ip_nibbles, "IP", fields, data)
    
    def process_tcp_layer(tcp_nibbles, ip_layer:Layer):
        source_port = Field("Source Port", tcp_nibbles[:4], lambda x: str(hex_to_decimal(x)))
        dest_port = Field("Destination Port", tcp_nibbles[4:8], lambda x: str(hex_to_decimal(x)))
        sequence_number = Field("Sequence Number", tcp_nibbles[8:16], lambda x: str(hex_to_decimal(x)))
        ack_number = Field("Acknowledgement Number", tcp_nibbles[16:24], lambda x: str(hex_to_decimal(x)))
        header_length = Field("Data Offset", tcp_nibbles[24:25], lambda x: f'{int("".join(x), 16) * 4} bytes')
        flags = Field("Flags", tcp_nibbles[25:28], lambda x: f'0x{"".join(x)}')
        window_size = Field("Window Size", tcp_nibbles[28:32], lambda x: str(hex_to_decimal(x)))
        checksum = Field("Checksum", tcp_nibbles[32:36], lambda x: f'0x{"".join(x)}')
        urgent_pointer = Field("Urgent Pointer", tcp_nibbles[36:40], lambda x: f'0x{"".join(x)}')
        
        ip_total_length = int(''.join(ip_layer.hex_nibbles[4:8]), 16)* 2
        ip_header_length = int(''.join(ip_layer.hex_nibbles[1:2]), 16) * 4 * 2
        tcp_header_end = int("".join(header_length.value_nibbles), 16) * 4 * 2
        
        tcp_data_end = (ip_total_length - ip_header_length)
        
        data = tcp_nibbles[tcp_header_end:tcp_data_end] 
        padding_nibbles = tcp_nibbles[tcp_data_end:]
        
        if padding_nibbles:
            tcp_nibbles = tcp_nibbles[:-len(padding_nibbles)]
        
        fields = [source_port, dest_port, sequence_number, ack_number, header_length, flags, window_size, checksum, urgent_pointer]
        
        return Layer(tcp_nibbles, "TCP", fields, data, display_data=True), padding_nibbles
    
    def process_packet_file(filename):
        with open(filename, 'r') as packet_file:
            # line with + and - signs
            plus_line = packet_file.readline()
            
            if plus_line != '+---------+---------------+----------+\n':
                raise ValueError(program_errors["K12"])

            # line with date info and connection type
            packet_file.readline()

            # line with hex info
            hex_line = packet_file.readline()

            hex_bytes = hex_line.split('|')
            
            hex_bytes:list[str] = [byte for byte in hex_bytes if len(byte) == 2]
            
            hex_nibbles = []
            
            for byte in hex_bytes:
                hex_nibbles.append(byte[0])
                hex_nibbles.append(byte[1])
            
            return hex_nibbles
        

class TcpFrame:
    hex_nibbles: list[str]
    layers: list[Layer]
    eth_trailer: list[str]
    padding_nibbles: list[str]
    
    def from_file(filename):
        hex_nibbles = FrameProcessor.process_packet_file(filename)
        return TcpFrame(hex_nibbles)
    
    def __init__(self, hex_nibbles):
        self.hex_nibbles = hex_nibbles
        
        eth_layer = FrameProcessor.process_eth_layer(hex_nibbles)
        
        ip_layer = FrameProcessor.process_ip_layer(eth_layer.data_nibbles)
        
        tcp_layer, padding_nibbles = FrameProcessor.process_tcp_layer(ip_layer.data_nibbles, ip_layer)
        
        self.layers = [eth_layer, ip_layer, tcp_layer]
        
        self.padding_nibbles = padding_nibbles
        
    def ip_checksum(self):
        ip_layer = self.layers[1]
        ip_header = ip_layer.hex_nibbles[:40]
        
        checksum = 0
        
        for i in range(0, len(ip_header), 4):
            if i == 20:
                continue
            nibble = ''.join(ip_header[i:i+4])
            checksum += int(nibble, 16)
            checksum = do_wrap_around(checksum)
            
        binary_repr = bin(checksum)[2:].zfill(16)
        
        return hex(int(''.join('1' if bit == '0' else '0' for bit in binary_repr), 2)).zfill(4)
    
    def tcp_checksum(self):
        ip_layer = self.layers[1]
        tcp_layer = self.layers[2]

        # Create the pseudo-header
        src_ip = ip_layer.hex_nibbles[24:32]
        dest_ip = ip_layer.hex_nibbles[32:40]
        reserved = ['0','0']
        protocol = ip_layer.hex_nibbles[18:20]
        tcp_length = list(hex(len(tcp_layer.hex_nibbles) // 2)[2:].zfill(4))

        pseudo_header = src_ip + dest_ip + reserved + protocol + tcp_length
    
        checksum = 0
        
        # Calculate the checksum for the pseudo-header
        for i in range(0, len(pseudo_header), 4):
            word = ''.join(pseudo_header[i:i+4])
            checksum += int(word, 16)
            checksum = do_wrap_around(checksum)

        tcp_segment = tcp_layer.hex_nibbles
        
        # Pad the TCP segment to be a multiple of 4
        if len(tcp_segment) % 4 != 0:
            add = ['0'] * (4 - len(tcp_segment) % 4)
            tcp_segment += add

        for i in range(0, len(tcp_segment), 4):
            if i == 32: # Skip the checksum field
                continue
            word = ''.join(tcp_segment[i:i+4])
            checksum += int(word, 16)
            checksum = do_wrap_around(checksum)

        binary_repr = bin(checksum)[2:].zfill(16)
        
        return hex(int(''.join('1' if bit == '0' else '0' for bit in binary_repr), 2)).zfill(4)

    def __str__(self):
        return '\n'.join([str(layer) for layer in self.layers])
    
    def __repr__(self) -> str:
        return self.__str__()


def main():
    filename = argparser.parse_args().filename
        
    if not filename:
        print("No filename provided")
        return
        
    if not check_file_exists(filename):
        print("File does not exist")
        return
    try:
        frame = TcpFrame.from_file(filename)
    except ValueError as e:
        if e.args[0] == program_errors['tcp']:
            print(f'This program can only be used with TCP packets. The provided packet is not a TCP packet.')
        elif e.args[0] == program_errors['ip']:
            print(f'This program can only be used with IP packets. The provided packet is not an IP packet.')
        elif e.args[0] == program_errors['K12']:
            print(f'This program can only be used with Wireshark K12 text files. The provided file is not a Wireshark K12 text file.')
        else:
            print(f'Error processing packet: {e}')
        return
    
    print(f'Information in packet from file {filename}:')
    
    print(f'{str(frame)}\n\n')
    
    print(f'Calculated IP Checksum: {frame.ip_checksum()}')
    print(f'Actual IP Checksum: 0x{"".join(frame.layers[1].hex_nibbles[20:24])}')
    
    print(f'Calculated TCP Checksum: {frame.tcp_checksum()}')
    print(f'Actual TCP Checksum: 0x{"".join(frame.layers[2].hex_nibbles[32:36])}')
    

if __name__ == "__main__":
    main()