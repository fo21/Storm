# Storm
This repository is for the application to the [Graduate Challenge 2024: Operation PACKET STORM](https://www.coretechsec.com/operation-packet-storm).

## Expected usage

`packet-storm.cpp` and `packet-storm.pcap` should be in the same folder. `packet-storm.cpp` will output the analysis results in `analysis-output.txt`.

## Build instructions

### Install libpcap

Before running the code, ensure you have the libpcap library installed. On a Linux system, you can install it with:

`sudo apt-get install libpcap-dev`

### Compiling and Running the Code

To compile the code, use the following command:

`g++ -o pcap_analysis pcap_analysis.cpp -lpcap`

Then run the compiled program:

`./pcap_analysis`
