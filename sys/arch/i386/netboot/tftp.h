/* netboot
 *
 * $Log: tftp.h,v $
 * Revision 1.1  1993/07/08 16:04:13  brezak
 * Diskless boot prom code from Jim McKim (mckim@lerc.nasa.gov)
 *
 * Revision 1.2  1993/06/30  20:14:17  mckim
 * Added BOOTP support.
 *
 * Revision 1.1.1.1  1993/05/28  11:41:08  mckim
 * Initial version.
 *
 *
 * source in this file came from
 * the Mach ethernet boot written by Leendert van Doorn.
 *
 * Trivial File Transfer Protocol (see RFC 783)
 */

#define	SEGSIZE		512		/* data segment size */

/*
 * Packet types
 */
#define	TFTP_RRQ	01		/* read request */
#define	TFTP_WRQ	02		/* write request */
#define	TFTP_DATA	03		/* data packet */
#define	TFTP_ACK	04		/* acknowledgement */
#define	TFTP_ERROR	05		/* error code */

/*
 * TFTP header structure
 */
typedef struct {
  u_short	th_op;			/* packet type */
  union {
    u_short	tu_block;		/* block # */
    u_short	tu_code;		/* error code */
    char	tu_stuff[1];		/* request packet stuff */
    } th_u;
} tftphdr_t;

/* for ease of reference */
#define	th_block	th_u.tu_block
#define	th_code		th_u.tu_code
#define	th_stuff	th_u.tu_stuff
#define	th_data		th_stuff[2]
#define	th_msg		th_data

void SetTftpParms(ipaddr_t server, ipaddr_t gateway, char *file_name);
u_long Read(void *result, u_long nbytes);
u_long PhysRead(u_long addr, u_long nbytes);
void IpSend(packet_t *pkt, ipaddr_t dst, ipaddr_t gateway);
