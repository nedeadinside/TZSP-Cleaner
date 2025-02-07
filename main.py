import argparse
from src.decapsulator import TZSPDecapsulator
            
def main():
    """Main function to handle command line execution."""
    parser = argparse.ArgumentParser(
        description="Remove TZSP encapsulation from PCAP files"
    )
    parser.add_argument("input_pcap", help="Path to input PCAP file")
    parser.add_argument("output_pcap", help="Path to output PCAP file")
    parser.add_argument("--chunk-size", type=int, required=False,
                      help="Split output into chunks of specified size")

    args = parser.parse_args()
    decapsulator = TZSPDecapsulator(args.input_pcap, args.output_pcap, args.chunk_size)
    decapsulator.remove_tzsp_encapsulation()

if __name__ == "__main__":
    main()
