#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>

/* Ethernet header */
struct ethheader {
  unsigned char  ether_dhost[6]; /* destination host address */
  unsigned char  ether_shost[6]; /* source host address */
  unsigned short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
};

/* IP Header */
struct ipheader {
    
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address
  struct  in_addr    iph_destip;   //Destination IP address
};

void got_packet(unsigned char *args, const struct pcap_pkthdr *header,
                              const unsigned char *packet)
{
    
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) {
     // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader)); 

    printf(" From: %s\n", inet_ntoa(ip->iph_sourceip));   
    printf(" To: %s\n", inet_ntoa(ip->iph_destip));    

    /* determine protocol */
    switch(ip->iph_protocol) {
                                     
        case IPPROTO_TCP:
            printf(" Protocol: TCP\n\n");
            return;
        case IPPROTO_UDP:
            printf(" Protocol: UDP\n\n");
            return;
        case IPPROTO_ICMP:
            printf(" Protocol: ICMP\n\n");
            return;
        default:
            printf(" Protocol: others\n\n");
            return;
    }
  }
}

int main()
{
    
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  // char filter_exp[] = "TCP";

  // ICMP packets between this host and 8.8.8.8
  // char filter_exp[] = "icmp and (src host 192.168.153.136 and dst host 8.8.8.8) or (src host 8.8.8.8 and dst host 192.168.153.136)"; 
  
  // TCP packets with dest port 10-100
  // char filter_exp[] = "tcp dst portrange 10-100";

  // sniff pass 
  char filter_exp[] = "tcp port 23";  

  
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name eth0
  handle = pcap_open_live("eth0", BUFSIZ, 0, 1000, errbuf);
  printf("listening on network card, ret: %p...\n", handle);

  // Step 2: Compile filter_exp into BPF psuedo-code
  printf("try to compile filter...\n");
  pcap_compile(handle, &fp, filter_exp, 0, net);
  printf("try to set filter...\n");
  pcap_setfilter(handle, &fp);

  // Step 3: Capture packets
  printf("start to sniff...\n");
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //Close the handle
  return 0;
}