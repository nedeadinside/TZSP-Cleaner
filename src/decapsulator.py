import os

from .tzsp import TZSP
from scapy.utils import PcapReader, wrpcap
from scapy.packet import bind_layers
from scapy.layers.inet import UDP

from typing import Optional


# Default TZSP port(37008) change if you need it
TZSP_PORT_DEFAULT = 0x9090
bind_layers(UDP, TZSP, sport=TZSP_PORT_DEFAULT)
bind_layers(UDP, TZSP, dport=TZSP_PORT_DEFAULT)


class TZSPDecapsulator:
    """
    A class for removing TZSP encapsulation from PCAP files.
    """

    def __init__(self, input_pcap: str, output_pcap: str, chunk_size: Optional[int] = None) -> None:
        """
        Initializes the TZSPDecapsulator with input and output file paths.

        Args:
            input_pcap (str): Path to input PCAP file
            output_pcap (str): Path to output PCAP file
            chunk_size (Optional[int]): Chunk size for splitting output files
        """
        self.input_pcap = input_pcap
        self.output_pcap = output_pcap
        self.chunk_size = chunk_size

    def remove_tzsp_encapsulation(self) -> None:
        """
        Removes TZSP encapsulation from packets and saves processed packets.
        Handles both chunked and single-file output modes.
        """
        processed_packets = []
        chunk_count = 0
        output_base = os.path.splitext(self.output_pcap)[0]

        with PcapReader(self.input_pcap) as pcap_reader:
            for i, pkt in enumerate(pcap_reader, 1):
                if TZSP in pkt:
                    encapsulated = pkt[TZSP].get_encapsulated_payload()
                    processed_packets.append(encapsulated if encapsulated else pkt)
                else:
                    processed_packets.append(pkt)

                if self.chunk_size and i % self.chunk_size == 0:
                    chunk_count += 1
                    wrpcap(f"{output_base}_part{chunk_count}.pcap", processed_packets)
                    processed_packets.clear()
                    
            if processed_packets:
                if self.chunk_size:
                    chunk_count += 1
                    wrpcap(f"{output_base}_part{chunk_count}.pcap", processed_packets)
                else:
                    wrpcap(self.output_pcap, processed_packets)

        if self.chunk_size:
            print(f"Decapsulated packets saved to {output_base}_part[1-{chunk_count}].pcap")
        else:
            print(f"Decapsulated packets saved to {self.output_pcap}")