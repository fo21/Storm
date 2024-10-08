# Storm
This repository is intended for the application to the Graduate Challenge 2024: Operation PACKET STORM. You can find more information at https://www.coretechsec.com/operation-packet-storm.

## Expected usage

Both `packet-storm.cpp` and `packet-storm.pcap` should be in the same folder. Running `packet-storm.cpp` will generate the analysis results in `analysis-output.txt`.

## Build instructions

### Install libpcap

Before running the code, make sure you have the libpcap library installed. On a Linux system, you can install it using the following command:

`sudo apt-get install libpcap-dev`

### Compiling and Running the Code

To compile the code, use the following command:

`g++ -o pcap_analysis packet-storm.cpp -lpcap`

Then, run the compiled program:

`./pcap_analysis`
