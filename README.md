Dataplane Router

Gheorghe Marius Razvan 324 CA

The starting point for this project was Lab 4, focusing on IPv4 functionality.

I implemented the routing process, longest prefix match (LPM), ICMP protocol, and static ARP.

1. Routing Process:
I check if the IP checksum is correct to determine whether the packet is corrupted.
If the packet is intended for the router and is an echo request, it sends back an echo reply.
I search for the best route for the packet’s destination. If none is found, an ICMP "Destination Unreachable" message is sent.
The TTL is decremented, and if it reaches zero before being sent, I proceed with an ICMP "Time Exceeded" message.
Then, I update the MAC addresses (source and destination) and forward the packet.
2. Longest Prefix Match (LPM)
I use an efficient search algorithm with O(logn) complexity, specifically binary search. Before this, I sort the routing table to increase efficiency further.
3. ICMP
I swap the source and destination IP addresses of the packet.
I reset the TTL and set the total length of the packet to include both the IP and ICMP headers, then recalculate the IP header checksum.
I set the ICMP type (such as echo reply, etc.).
I swap the MAC addresses and send the packet back through the original interface.
