#include <net/ethernet.h>
#include <netinet/in.h>

#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
#define SIZE_ETHERNET 14
#define SIZE_IP6 40
#define SIZE_UDP 20
#define SIZE_ICMP 28

// Some ICMP Types
#define	ICMP_ECHOREPLY		0
#define	ICMP_UNREACH		3
#define	ICMP_SOURCEQUENCH	4
#define	ICMP_ECHO		8
#define	ICMP_ROUTERSOLICIT	10
#define	ICMP_TSTAMP		13
#define	ICMP_TSTAMPREPLY	14
#define	ICMP_IREQ		15
#define	ICMP_IREQREPLY		16
#define	ICMP_MASKREQ		17
#define	ICMP_EXTENDED_ECHO_REQUEST	42
#define	ICMP_EXTENDED_ECHO_REPLY	43

struct ETHeader
{
  uint8_t ether_dhost[ETHER_ADDR_LEN];
  uint8_t ether_shost[ETHER_ADDR_LEN];
  uint16_t ether_type;
};

struct IPHeader
{
  uint8_t ip_vhl;
  uint8_t ip_tos;
  uint16_t ip_len;
  uint16_t ip_id;
  uint16_t ip_off;
  uint8_t ip_ttl;
  uint8_t ip_p;
  uint16_t ip_sum;
  struct in_addr ip_src;
  struct in_addr ip_dst;
};

struct IP6Header
{
  uint32_t ip6_flow;
  uint16_t ip6_plen;
  uint8_t ip6_nxt;
  uint8_t ip6_hlim;
  uint8_t ip6_src[16];
  uint8_t ip6_dst[16];
};


struct TCPHeader
{
  uint16_t th_sport;
  uint16_t th_dport;
  uint32_t th_seq;
  uint32_t th_ack;
  uint8_t th_offx2;
  uint8_t th_flags;
  uint16_t th_win;
  uint16_t th_sum;
  uint16_t th_urp;
};

struct UDPHeader
{
  uint16_t uh_sport;
  uint16_t uh_dport;
  uint16_t uh_ulen;
  uint16_t uh_sum;
};

struct ICMPHeader
{
  uint8_t icmp_type;
  uint8_t icmp_code;
  uint16_t icmp_cksum;

  union
  {
    uint8_t ih_pptr;
    uint8_t ih_gwaddr[4];

    struct ih_idseq
    {
      uint16_t icd_id;
      uint16_t icd_seq;
    } ih_idseq;

    struct ih_idseqx
    {
      uint16_t icdx_id;
      uint8_t icdx_seq;
      uint8_t icdx_info;
    } ih_idseqx;

    uint32_t ih_void;
  } icmp_hun;

  union
  {
    struct id_ts
    {
      uint32_t its_otime;
      uint32_t its_rtime;
      uint32_t its_ttime;
    } id_ts;

    struct id_ip
    {
      struct IPHeader idi_ip;
    } id_ip;

    uint32_t id_mask;
    uint8_t id_data[1];
  } icmp_dun;
};

const char* get_protocol_name(uint16_t protocol);

const char* get_ip_protocol_name(uint8_t protocol);

const char* get_icmp_name(uint8_t type);
