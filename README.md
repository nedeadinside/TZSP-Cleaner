# TZSP Cleaner

TZSP Cleaner is a Python utility that removes [TaZmen Sniffer Protocol (TZSP)](http://en.wikipedia.org/wiki/TZSP) encapsulation from PCAP files. The script processes an input PCAP file by identifying packets with a TZSP layer and extracting the encapsulated payload when available. The resulting decapsulated packets are then saved into a new PCAP file. Optionally, the output may be divided into multiple files based on a specified chunk size.

This utility is useful for handling PCAP files collected from devices such as Mikrotik routers, which include TZSP encapsulation in the packet data when you using Packet Sniffer tool.

If you require live decapsulation of TZSP encapsulated traffic, you may consider using the [tzsp2pcap](https://github.com/thefloweringash/tzsp2pcap) tool.

## How It Works
1. The script processes each packet in the input PCAP file.
2. For packets containing a TZSP layer, it extracts the encapsulated payload.
3. Processed packets are saved to either a single output file or multiple files (if chunking is enabled).
4. The TZSP protocol is bound to UDP ports (0x9090) using Scapy, ensuring proper detection and processing.

## Usage

Run the script from the command line by executing the `main.py` module:
```bash
python main.py <input_pcap> <output_pcap> [--chunk-size CHUNK_SIZE]
```
Arguments
 - <input_pcap>: Path to the PCAP file containing packets with potential TZSP encapsulation.
 - <output_pcap>: Path where the decapsulated PCAP file (or files) will be saved.
 - --chunk-size: (Optional) An integer specifying the maximum number of packets per output file. 
    When this option is used, the script will save multiple files appended with _partN (e.g., output_part1.pcap, output_part2.pcap, etc.).

## Examples
Single File Output:
```bash
python main.py inputfile.pcap outputfile.pcap
```

Chunked Output (e.g., 100 packets per file):
```bash
python main.py inputfile.pcap outputfile.pcap --chunk-size 100
```

## Requirements
 - Python 3.x
 - [Scapy](https://scapy.net/)

Also you can check [Scapy GitHub](https://github.com/secdev/scapy)
