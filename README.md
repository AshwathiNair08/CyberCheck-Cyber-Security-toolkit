CyberCheck is a network security toolkit designed to streamline the workflow of
penetration testers by integrating a suite of essential tools within a single platform. These
tools include nsLookup, nmap, MTR, Traceroute, and an IP Location Grabber, among
others, offering a comprehensive solution for evaluating and safeguarding the Target of
Evaluation (ToE) against potential cyber threats.
Built using Python, CyberCheck operates seamlessly from the terminal on any operating
system, ensuring accessibility and ease of use for cybersecurity professionals. By
consolidating multiple functionalities into one toolkit, CyberCheck aims to enhance
efficiency in network mapping, reconnaissance, and vulnerability analysis, making it an
indispensable resource for securing networks against attackers.

Environment Configuration:

  ● System: Ubuntu 22.04, Python 3.12.3, Scapy 2.4.5.
  
  ● Hardware: Intel Core i7-11700K, 16 GB RAM.
  
  ● Network: Tested using actual network traffic using a home network.
  
Traffic Source:

  Historical Traffic: Captured via tcpdump and stored as pcap files for OS
  fingerprinting
  
Testing Adjustments:

  ● API Limitations: VirusTotal free API constrained analysis to small batches of 4-5
  domains at a time.
  
  ● Cached Results: Pre-recorded API responses were used to supplement real-time
  analysis for previously queried domains.
