"""
Program for reading packet headers from a file and computing checksums
"""

import argparse

argparser = argparse.ArgumentParser(description="Read packet headers from a file and compute checksums")

argparser.add_argument('-f', '--filename', required=True, help="Name of the file to read packet headers from")

def mac_address_from_hex(mac_hex:list[str]):
    return ':'.join([byte for byte in mac_hex if byte is not None])

def eth_type_from_hex(eth_type_hex:list[str]):
    return '0x' + ''.join(eth_type_hex)

class Field:
    name: str
    value_bytes: list[str]
    decoded_value: str
    
    def __init__(self, name, value, value_decoder=None, ):
        self.name = name
        self.value_bytes = value
        self.decoded_value = value_decoder(value) if value_decoder else ' '.join(value)
        
    def __str__(self):
        return self.name + ' - ' + self.decoded_value
    
class Layer:
    hex_bytes: list[str]
    title: str
    fields: list[Field]
    data_bytes: list[str]
    
    def __init__(self, hex_bytes, title, fields, data_bytes):
        self.hex_bytes = hex_bytes
        self.title = title
        self.fields = fields
        self.data_bytes = data_bytes
        
    def __str__(self):
        return f'{self.title}:\n' + '\n'.join([str(field) for field in self.fields]) + '\nData - ' + ' '.join(self.data_bytes)

class FrameProcessor:
    def process_eth_layer(hex_bytes):
        destination_mac = Field("Destination MAC Address", hex_bytes[:6], mac_address_from_hex)
        source_mac = Field("Source MAC Address", hex_bytes[6:12], mac_address_from_hex)
        eth_type = Field("Type", hex_bytes[12:14], eth_type_from_hex)
        # eth_trailer = Field("Trailer", hex_byte_array[14:])
        
        fields = [destination_mac, source_mac, eth_type]
        
        data = hex_bytes[14:]
        
        return Layer(hex_bytes, "Ethernet", fields, data)
    
    def process_packet_file(filename):
        with open(filename, 'r') as packet_file:
            # line with + and - signs
            packet_file.readline()

            # line with date info and connection type
            packet_file.readline()

            # line with hex info
            hex_line = packet_file.readline()

            hex_bytes = hex_line.split('|')
            
            hex_bytes = [byte for byte in hex_bytes if len(byte) == 2]
            
            return hex_bytes
        

class TcpFrame:
    hex_bytes: list[str]
    layers: list[Layer]
    
    def __init__(self, hex_bytes):
        self.hex_bytes = hex_bytes
        
        eth_layer = FrameProcessor.process_eth_layer(hex_bytes)
        
        self.layers = [eth_layer]
        
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
        
    hex_bytes = FrameProcessor.process_packet_file(filename)
    
    frame = TcpFrame(hex_bytes)
    
    print(f'{str(frame)}')
    

if __name__ == "__main__":
    main()