# Network Traffic Analysis in Data Centres
**Analysis and Visualization of network traffic from data centres based on trace.pcap file.**

#### In this repo we analyze network traffic in data centers based on trace in PCAP format and extract traffic characteristics in the form of distributions. Then we plot the results-distributions (e.g. CDF) of all extracted motion characteristics. For the implementation we use DPTK library.

### Briefly, the repo contains:

  • **(1) Extraction of flow characteristics in the form of distributions.** The following features are extracted at the flow level:
      - Flow size (bytes)
      - Flow duration (sec)
  
  • **(2) Header-based choices.** The packets are grouped into streams based on the following header fields:
      - Sender's IP address
      - Receiver's IP address
      - Sender's port number
      - Receiver's port number
      - Protocol (TCP or UDP)
  
  • **(3) Extraction of packet size distribution.** We plot the packet size distribution which is extracted from all flows available in the .pcap file.
  
  • **(4) Categorization of the traffic.** We categorize the traffic into (a) TCP, (b) UDP, (c) ICMP and (d) ARP in order to find the percentage of each packet with respect to the total traffic.

This repository was initially created to store my personal python code but also be available to others trying to build or understand something similar.
The code contained in this repo is made specifically for a "Computer Networks for Big Data" course of my MSc program.
