"""
Program for reading packet headers from a file and computing checksums
"""

import argparse

argparser = argparse.ArgumentParser(description="Read packet headers from a file and compute checksums")

argparser.add_argument('-f', '--filename', required=True, help="Name of the file to read packet headers from")

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


class Field:
    name: str
    value_nibbles: list[str]
    value_binary: str
    decoded_value: str
    
    def __init__(self, name, value_nibbles=None, value_decoder=None, value_binary=None ):
        self.name = name
        self.value_nibbles = value_nibbles
        self.value_binary = value_binary
        
        if value_nibbles:
            self.decoded_value = value_decoder(value_nibbles) if value_decoder else ' '.join(nibbles_to_bytes(value_nibbles))
        elif value_binary and value_decoder:
            self.decoded_value = value_decoder(value_binary)
        else:
            raise ValueError("No value provided")
        
    def __str__(self):
        return self.name + ' - ' + self.decoded_value
    
class Layer:
    hex_nibbles: list[str]
    title: str
    fields: list[Field]
    data_nibbles: list[str]
    
    def __init__(self, hex_nibbles, title, fields, data_nibbles):
        self.hex_nibbles = hex_nibbles
        self.title = title
        self.fields = fields
        self.data_nibbles = data_nibbles
        
    def __str__(self):
        return f'{self.title}:\n' + '\n'.join([str(field) for field in self.fields]) + '\nData - ' + ' '.join(nibbles_to_bytes(self.data_nibbles))

class FrameProcessor:
    def process_eth_layer(hex_nibbles):
        destination_mac = Field("Destination MAC Address", hex_nibbles[:12], mac_address_from_hex)
        source_mac = Field("Source MAC Address", hex_nibbles[12:24], mac_address_from_hex)
        eth_type = Field("Type", hex_nibbles[24:28], eth_type_from_hex)
        # eth_trailer = Field("Trailer", hex_byte_array[14:])
        
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

        fields = [version, header_length, type_of_service, total_length, identification, flags, offset, ttl, protocol, checksum, source_ip, destination_ip]
        
        data = ip_nibbles[40:]  # Assuming no IP options; adjust if needed
        
        return Layer(ip_nibbles, "IP", fields, data)
    
    def process_tcp_layer(tcp_nibbles):
        source_port = Field("Source Port", tcp_nibbles[:4], lambda x: str(hex_to_decimal(x)))
        dest_port = Field("Destination Port", tcp_nibbles[4:8], lambda x: str(hex_to_decimal(x)))
        sequence_number = Field("Sequence Number", tcp_nibbles[8:16], lambda x: str(hex_to_decimal(x)))
        ack_number = Field("Acknowledgement Number", tcp_nibbles[16:24], lambda x: str(hex_to_decimal(x)))
        data_offset = Field("Data Offset", tcp_nibbles[24:25], lambda x: f'{int("".join(x), 16) * 4} bytes')
        flags = Field("Flags", tcp_nibbles[25:28], lambda x: f'0x{"".join(x)}')
        window_size = Field("Window Size", tcp_nibbles[28:32], lambda x: str(hex_to_decimal(x)))
        checksum = Field("Checksum", tcp_nibbles[32:36], lambda x: f'0x{"".join(x)}')
        urgent_pointer = Field("Urgent Pointer", tcp_nibbles[36:40], lambda x: f'0x{"".join(x)}')
        
        data = tcp_nibbles[40:]
        
        fields = [source_port, dest_port, sequence_number, ack_number, data_offset, flags, window_size, checksum, urgent_pointer]
        
        return Layer(tcp_nibbles, "TCP", fields, data)
    
    def process_packet_file(filename):
        with open(filename, 'r') as packet_file:
            # line with + and - signs
            packet_file.readline()

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
    
    def __init__(self, hex_nibbles):
        self.hex_nibbles = hex_nibbles
        
        eth_layer = FrameProcessor.process_eth_layer(hex_nibbles)
        
        ip_layer = FrameProcessor.process_ip_layer(eth_layer.data_nibbles)
        
        tcp_layer = FrameProcessor.process_tcp_layer(ip_layer.data_nibbles)
        
        self.layers = [eth_layer, ip_layer, tcp_layer]
        
    def __str__(self):
        return '\n'.join([str(layer) for layer in self.layers])
    
    def __repr__(self) -> str:
        return self.__str__()


def check_file_exists(filename):
    try:
        with open(filename, 'r') as file:
            return True
    except FileNotFoundError:
        return False


def main():
    filename = argparser.parse_args().filename
        
        
    if not filename:
        print("No filename provided")
        
    if not check_file_exists(filename):
        print("File does not exist")
        
    hex_nibbles = FrameProcessor.process_packet_file(filename)
    
    frame = TcpFrame(hex_nibbles)
    
    print(f'{str(frame)}')
    

if __name__ == "__main__":
    main()