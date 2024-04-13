"""
Program for reading packet headers from a file and computing checksums
"""

import argparse

argparser = argparse.ArgumentParser(description="Read packet headers from a file and compute checksums")

argparser.add_argument('-f', '--filename', required=True, help="Name of the file to read packet headers from")

def byte_list_to_pairs(byte_list:list[str]):
    return [str(str(byte_list[i]) + str(byte_list[i+1])) for i in range(0, len(byte_list), 2)]
    
def mac_address_from_hex(mac_hex:list[str]):
    byte_pairs = byte_list_to_pairs(mac_hex)
    return ':'.join([byte for byte in byte_pairs if byte is not None])

def eth_type_from_hex(eth_type_hex:list[str]):
    byte_pairs = byte_list_to_pairs(eth_type_hex)
    return '0x' + ''.join(byte_pairs)


class Field:
    name: str
    value_bytes: list[str]
    decoded_value: str
    
    def __init__(self, name, value_bytes, value_decoder=None, ):
        self.name = name
        self.value_bytes = value_bytes
        self.decoded_value = value_decoder(value_bytes) if value_decoder else ' '.join(byte_list_to_pairs(value_bytes))
        
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
        return f'{self.title}:\n' + '\n'.join([str(field) for field in self.fields]) + '\nData - ' + ' '.join(byte_list_to_pairs(self.data_bytes))

class FrameProcessor:
    def process_eth_layer(hex_bytes):
        destination_mac = Field("Destination MAC Address", hex_bytes[:12], mac_address_from_hex)
        source_mac = Field("Source MAC Address", hex_bytes[12:24], mac_address_from_hex)
        eth_type = Field("Type", hex_bytes[24:28], eth_type_from_hex)
        # eth_trailer = Field("Trailer", hex_byte_array[14:])
        
        fields = [destination_mac, source_mac, eth_type]
        
        data = hex_bytes[28:]
        
        return Layer(hex_bytes, "Ethernet", fields, data)
    
    def process_packet_file(filename):
        with open(filename, 'r') as packet_file:
            # line with + and - signs
            packet_file.readline()

            # line with date info and connection type
            packet_file.readline()

            # line with hex info
            hex_line = packet_file.readline()

            hex_byte_pairs = hex_line.split('|')
            
            hex_byte_pairs:list[str] = [byte for byte in hex_byte_pairs if len(byte) == 2]
            
            hex_bytes = []
            
            for byte_pair in hex_byte_pairs:
                hex_bytes.append(byte_pair[0])
                hex_bytes.append(byte_pair[1])
            
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