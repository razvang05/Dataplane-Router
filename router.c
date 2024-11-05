#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <linux/if_ether.h>


struct route_table_entry *rtable;
int rtable_len;

struct arp_table_entry *arp_table;
int arp_table_len;

int compare_func(const void *a, const void *b) {

    struct route_table_entry *entry1 = (struct route_table_entry *)a;
    struct route_table_entry *entry2 = (struct route_table_entry *)b;

    uint32_t aux1 = entry1->prefix & entry1->mask;
    uint32_t aux2 = entry2->prefix & entry2->mask;
    
    if (aux1 != aux2) {
        return aux1 - aux2;
        // compare by masks
    } else if (entry1->mask != entry2->mask) {
        return entry1->mask - entry2->mask;
    }

    return 0;
       

}
 
int binary_search_route_rec(int left, int right, uint32_t ip_dest) {

    if (left > right) {
        return -1;
    }

    int mid = left + (right - left) / 2;
    struct route_table_entry *current = &rtable[mid];
    uint32_t masked_ip_dest = ip_dest & current->mask;
    uint32_t masked_route_ip = current->prefix & current->mask;

    // check if destination ip address with the mask
    // matches with route prefix
    if (masked_ip_dest == masked_route_ip) {

        int route_index = binary_search_route_rec(mid + 1, right, ip_dest);
        if (route_index != -1) {
            return route_index;
        }
        return mid;
    } else if (masked_ip_dest < masked_route_ip) {
        return binary_search_route_rec(left, mid - 1, ip_dest);
    } else {
        return binary_search_route_rec(mid + 1, right, ip_dest);
    }
}
  
struct route_table_entry *get_best_route(uint32_t ip_dest) {

    int best_index = binary_search_route_rec(0, rtable_len, ip_dest);
    // if found best route return her address
    if (best_index != -1) {
        return &rtable[best_index];
    } else {
        return NULL;
    }
}

 
struct arp_table_entry *get_arp_entry(uint32_t ip_dest) {
    // search for an entry which corresponds to ip_dest
    for (int i = 0; i < arp_table_len; ++i) {
        if (arp_table[i].ip == ip_dest) {
            return &arp_table[i];
        }
    }

    return NULL;
}

void send_icmp_message(struct iphdr *ip_hdr, struct ether_header *eth_hdr,
                        int type, int code, int interface, char *buf) {

    // swap between source ip and destination ip
    uint32_t aux_ip = ip_hdr->saddr;
    ip_hdr->saddr = ip_hdr->daddr;
    ip_hdr->daddr = aux_ip;

    ip_hdr->ttl = 64;
    ip_hdr->protocol = IPPROTO_ICMP;
    // update length with the ip header and icmp header
    // above are also the 64 bits for them
    ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
    ip_hdr->check = 0;
    // update checksum with new data
    ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

    // find the position of icmp header after ip header
    struct icmphdr *icmp = (struct icmphdr *)(buf + sizeof(struct ether_header)
                                                + sizeof(struct iphdr));

    // set type for message unreachable, time exceeded and echo reply
    icmp->type = type;
    icmp->code = code;
    icmp->checksum = 0;
    // checksum for icmp
    icmp->checksum = htons(checksum((uint16_t *)icmp, sizeof(struct icmphdr)));

    // send the package back 
    // but not without change the address
    uint8_t aux_mac[ETH_ALEN];
    memcpy(aux_mac, eth_hdr->ether_shost, ETH_ALEN);
    memcpy(eth_hdr->ether_shost, eth_hdr->ether_dhost, ETH_ALEN);
    memcpy(eth_hdr->ether_dhost, aux_mac, ETH_ALEN);

    // Send the modified packet
    // with size of ethernet and ip
    uint16_t ip_tot_len = ntohs(ip_hdr->tot_len);
    send_to_link(interface, buf, sizeof(struct ether_header) + ip_tot_len);
}



static void ipv4_packet(struct ether_header *eth_hdr, uint32_t len,
                         uint32_t interface, char buf[MAX_PACKET_LEN]) {

    struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));


    if (checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)) != 0) {
			printf("Corrupted packet\n");
            return;
	}
    
    // check if receive message echo_request
    if (ip_hdr->daddr == inet_addr(get_interface_ip(interface))) {
            // respond with echo reply
            send_icmp_message(ip_hdr, eth_hdr, 0, 0, interface, buf);
            return;
    }

    // find best route 
	struct route_table_entry *best_route = get_best_route(ip_hdr->daddr);
	if (best_route == NULL) {
        // destination unreachable
        send_icmp_message(ip_hdr, eth_hdr, 3, 0, interface, buf);
        return;
	}

    if (ip_hdr->ttl <= 1) {
        // time exceeded
        send_icmp_message(ip_hdr, eth_hdr, 11, 0, interface, buf); 
        return;
    }

	ip_hdr->ttl -= 1;
	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

	struct arp_table_entry *dest_mac = get_arp_entry(best_route->next_hop);

    get_interface_mac(best_route->interface, eth_hdr->ether_shost);

	if (dest_mac == NULL) {
		printf("no_mac_entry\n");
        return;
    }
    // update the source and destination addresses
    // send the package
	memcpy(eth_hdr->ether_dhost, dest_mac->mac, ETH_ALEN);

	send_to_link(best_route->interface, buf, len);

}
 

int main(int argc, char *argv[]) {

	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

    rtable = malloc(sizeof(struct route_table_entry) *100000);
    DIE(rtable == NULL, "malloc failed");
 

    arp_table = malloc(sizeof(struct arp_table_entry) * 100000);
    DIE(arp_table == NULL, "malloc failed");

    rtable_len = read_rtable(argv[1], rtable);
    arp_table_len = parse_arp_table("arp_table.txt", arp_table);

    // sort table for lpm
    qsort(rtable, rtable_len, sizeof(struct route_table_entry), compare_func);


	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

        // ipv4
        if (eth_hdr->ether_type == ntohs(0x0800)) {
			ipv4_packet(eth_hdr, len, interface, buf);
		} else {
            continue;
        }

	}

    free(rtable);
    free(arp_table);
    return 0;
}
