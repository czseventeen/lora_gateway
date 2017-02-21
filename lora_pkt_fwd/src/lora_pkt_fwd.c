/*
 / _____)             _              | |
( (____  _____ ____ _| |_ _____  ____| |__
 \____ \| ___ |    (_   _) ___ |/ ___)  _ \
 _____) ) ____| | | || |_| ____( (___| | | |
(______/|_____)_|_|_| \__)_____)\____)_| |_|
  (C)2013 Semtech-Cycleo

Description:
    Configure Lora concentrator and forward packets to a server
    Use GPS for packet timestamping.
    Send a becon at a regular interval without server intervention

License: Revised BSD License, see LICENSE.TXT file include in the project
Maintainer: Michael Coracin
*/


/* -------------------------------------------------------------------------- */
/* --- DEPENDANCIES --------------------------------------------------------- */

/* fix an issue between POSIX and C99 */
#if __STDC_VERSION__ >= 199901L
    #define _XOPEN_SOURCE 600
#else
    #define _XOPEN_SOURCE 500
#endif

#include <stdint.h>         /* C99 types */
#include <stdbool.h>        /* bool type */
#include <stdio.h>          /* printf, fprintf, snprintf, fopen, fputs */

#include <string.h>         /* memset */
#include <signal.h>         /* sigaction */
#include <time.h>           /* time, clock_gettime, strftime, gmtime */
#include <sys/time.h>       /* timeval */
#include <unistd.h>         /* getopt, access */
#include <stdlib.h>         /* atoi, exit */
#include <errno.h>          /* error messages */
#include <math.h>           /* modf */
#include <assert.h>

#include <sys/socket.h>     /* socket specific definitions */
#include <netinet/in.h>     /* INET constants and stuff */
#include <arpa/inet.h>      /* IP address conversion stuff */
#include <netdb.h>          /* gai_strerror */
#include <stdint.h>             /* C99 types */
#include <stdio.h>              /* printf fprintf */
#include <stdlib.h>             /* malloc free */
#include <unistd.h>             /* lseek, close */
#include <fcntl.h>              /* open */
#include <string.h>             /* memset */
//Jay - added 4 .h below for serial 
#include <unistd.h>  /* UNIX standard function definitions */
#include <errno.h>   /* Error number definitions */
#include <termios.h> /* POSIX terminal control definitions */

#include <pthread.h>

#include "trace.h"
#include "jitqueue.h"
#include "timersync.h"
#include "parson.h"
#include "base64.h"
#include "loragw_hal.h"
#include "loragw_gps.h"
#include "loragw_aux.h"
#include "loragw_reg.h"


/* -------------------------------------------------------------------------- */
/* --- PRIVATE MACROS ------------------------------------------------------- */

#define ARRAY_SIZE(a)   (sizeof(a) / sizeof((a)[0]))
#define STRINGIFY(x)    #x
#define STR(x)          STRINGIFY(x)

/* -------------------------------------------------------------------------- */
/* --- PRIVATE CONSTANTS ---------------------------------------------------- */
//for serial communication:
#define SER_DEV_PATH "/dev/ttyACM8"
#define BAUDRATE B115200
#define CRTSCTS 020000000000
#define TRUE 1
#define FALSE 0
#define READ_ACCESS 0x00
#define WRITE_ACCESS 0x80
#define END_OF_PACKET 0xd
#define CMD_BYTE_INDEX 1
#define RXSTAT_BYTE_INDEX 4
#define MAX_NUM_OF_HEX_BYTES 350

//For debugging
#define DEBUG_MSG(str)
#define DEBUG_PRINTF(fmt , args...)
#define DEBUG_ARRAY(a,b,c)  for(a=0;a!=0;){}
#define CHECK_NULL(a)       if(a==NULL){return LGW_HAL_ERROR;}


#ifndef VERSION_STRING
  #define VERSION_STRING "undefined"
#endif

#define DEFAULT_SERVER      54.236.219.14 //demoserver.occamsmart.com   /* hostname also supported */
#define DEFAULT_PORT_UP     1700
#define DEFAULT_PORT_DW     1700
#define DEFAULT_KEEPALIVE   5           /* default time interval for downstream keep-alive packet */
#define DEFAULT_STAT        30          /* default time interval for statistics */
#define PUSH_TIMEOUT_MS     100
#define PULL_TIMEOUT_MS     200
#define GPS_REF_MAX_AGE     30          /* maximum admitted delay in seconds of GPS loss before considering latest GPS sync unusable */
#define FETCH_SLEEP_MS      10          /* nb of ms waited when a fetch return no packets */
#define BEACON_POLL_MS      50          /* time in ms between polling of beacon TX status */

#define PROTOCOL_VERSION    1           /* v1.3 */

#define XERR_INIT_AVG       128         /* nb of measurements the XTAL correction is averaged on as initial value */
#define XERR_FILT_COEF      256         /* coefficient for low-pass XTAL error tracking */

#define PKT_PUSH_DATA   0
#define PKT_PUSH_ACK    1
#define PKT_PULL_DATA   2
#define PKT_PULL_RESP   3
#define PKT_PULL_ACK    4
#define PKT_TX_ACK      5

#define NB_PKT_MAX      8 /* max number of packets per fetch/send cycle */

#define MIN_LORA_PREAMB 6 /* minimum Lora preamble length for this application */
#define STD_LORA_PREAMB 8
#define MIN_FSK_PREAMB  3 /* minimum FSK preamble length for this application */
#define STD_FSK_PREAMB  5

#define STATUS_SIZE     200
#define TX_BUFF_SIZE    ((540 * NB_PKT_MAX) + 30 + STATUS_SIZE)


/* -------------------------------------------------------------------------- */
/* --- PRIVATE VARIABLES (GLOBAL) ------------------------------------------- */
/*serial file descriptor*/
int _fd;

static bool serial_is_opened= false;

/*For serial communication*/
static uint8_t serial_start_cmd[6] = {0x23, 0x30, 0x00, 0x00, 0x53, 0x0d};
static uint8_t serial_stop_cmd[6]  = {0x23, 0x31, 0x00, 0x00, 0x54, 0x0d};
static uint8_t serial_getrxstat_cmd[6] = {0x23, 0x43, 0x00, 0x00, 0x66, 0x0d};
static uint8_t serial_reset_cmd[6] = {0x23, 0x51, 0x00, 0x00, 0x74, 0x0d};
static uint8_t serial_ACK_cmd[7] = {0x23, 0x33, 0x01, 0x00, 0x00, 0x57, 0x0d};
static uint8_t serial_TXSTAT_cmd[6]= {0x23, 0x39, 0x00, 0x00, 0x5C, 0x0d };

/* signal handling variables */
volatile bool exit_sig = false; /* 1 -> application terminates cleanly (shut down hardware, close open files, etc) */
volatile bool quit_sig = false; /* 1 -> application terminates without shutting down the hardware */

/* packets filtering configuration variables */
static bool fwd_valid_pkt = true; /* packets with PAYLOAD CRC OK are forwarded */
static bool fwd_error_pkt = false; /* packets with PAYLOAD CRC ERROR are NOT forwarded */
static bool fwd_nocrc_pkt = false; /* packets with NO PAYLOAD CRC are NOT forwarded */

/* network configuration variables */
static uint64_t lgwm = 0x0000000baba3c750; /* Lora gateway MAC address */
static char serv_addr[64] = STR(DEFAULT_SERVER); /* address of the server (host name or IPv4/IPv6) */
static char serv_port_up[8] = STR(DEFAULT_PORT_UP); /* server port for upstream traffic */
static char serv_port_down[8] = STR(DEFAULT_PORT_DW); /* server port for downstream traffic */
static int keepalive_time = DEFAULT_KEEPALIVE; /* send a PULL_DATA request every X seconds, negative = disabled */

/* statistics collection configuration variables */
static unsigned stat_interval = DEFAULT_STAT; /* time interval (in sec) at which statistics are collected and displayed */

/* gateway <-> MAC protocol variables */
static uint32_t net_mac_h; /* Most Significant Nibble, network order */
static uint32_t net_mac_l; /* Least Significant Nibble, network order */

/* network sockets */
static int sock_up; /* socket for upstream traffic */
static int sock_down; /* socket for downstream traffic */

/* network protocol variables */
static struct timeval push_timeout_half = {0, (PUSH_TIMEOUT_MS * 500)}; /* cut in half, critical for throughput */
static struct timeval pull_timeout = {0, (PULL_TIMEOUT_MS * 1000)}; /* non critical for throughput */

/* hardware access control and correction */
pthread_mutex_t mx_concent = PTHREAD_MUTEX_INITIALIZER; /* control access to the concentrator */
static pthread_mutex_t mx_xcorr = PTHREAD_MUTEX_INITIALIZER; /* control access to the XTAL correction */
static bool xtal_correct_ok = false; /* set true when XTAL correction is stable enough */
static double xtal_correct = 1.0;

/* GPS configuration and synchronization */
static char gps_tty_path[64] = "\0"; /* path of the TTY port GPS is connected on */
static int gps_tty_fd = -1; /* file descriptor of the GPS TTY port */
static bool gps_enabled = false; /* is GPS enabled on that gateway ? */

/* GPS time reference */
static pthread_mutex_t mx_timeref = PTHREAD_MUTEX_INITIALIZER; /* control access to GPS time reference */
static bool gps_ref_valid; /* is GPS reference acceptable (ie. not too old) */
static struct tref time_reference_gps; /* time reference used for UTC <-> timestamp conversion */

/* Reference coordinates, for broadcasting (beacon) */
static struct coord_s reference_coord;

/* Enable faking the GPS coordinates of the gateway */
static bool gps_fake_enable; /* enable the feature */

/* measurements to establish statistics */
static pthread_mutex_t mx_meas_up = PTHREAD_MUTEX_INITIALIZER; /* control access to the upstream measurements */
static uint32_t meas_nb_rx_rcv = 0; /* count packets received */
static uint32_t meas_nb_rx_ok = 0; /* count packets received with PAYLOAD CRC OK */
static uint32_t meas_nb_rx_bad = 0; /* count packets received with PAYLOAD CRC ERROR */
static uint32_t meas_nb_rx_nocrc = 0; /* count packets received with NO PAYLOAD CRC */
static uint32_t meas_up_pkt_fwd = 0; /* number of radio packet forwarded to the server */
static uint32_t meas_up_network_byte = 0; /* sum of UDP bytes sent for upstream traffic */
static uint32_t meas_up_payload_byte = 0; /* sum of radio payload bytes sent for upstream traffic */
static uint32_t meas_up_dgram_sent = 0; /* number of datagrams sent for upstream traffic */
static uint32_t meas_up_ack_rcv = 0; /* number of datagrams acknowledged for upstream traffic */

static pthread_mutex_t mx_meas_dw = PTHREAD_MUTEX_INITIALIZER; /* control access to the downstream measurements */
static uint32_t meas_dw_pull_sent = 0; /* number of PULL requests sent for downstream traffic */
static uint32_t meas_dw_ack_rcv = 0; /* number of PULL requests acknowledged for downstream traffic */
static uint32_t meas_dw_dgram_rcv = 0; /* count PULL response packets received for downstream traffic */
static uint32_t meas_dw_network_byte = 0; /* sum of UDP bytes sent for upstream traffic */
static uint32_t meas_dw_payload_byte = 0; /* sum of radio payload bytes sent for upstream traffic */
static uint32_t meas_nb_tx_ok = 0; /* count packets emitted successfully */
static uint32_t meas_nb_tx_fail = 0; /* count packets were TX failed for other reasons */
static uint32_t meas_nb_tx_requested = 0; /* count TX request from server (downlinks) */
static uint32_t meas_nb_tx_rejected_collision_packet = 0; /* count packets were TX request were rejected due to collision with another packet already programmed */
static uint32_t meas_nb_tx_rejected_collision_beacon = 0; /* count packets were TX request were rejected due to collision with a beacon already programmed */
static uint32_t meas_nb_tx_rejected_too_late = 0; /* count packets were TX request were rejected because it is too late to program it */
static uint32_t meas_nb_tx_rejected_too_early = 0; /* count packets were TX request were rejected because timestamp is too much in advance */
static uint32_t meas_nb_beacon_queued = 0; /* count beacon inserted in jit queue */
static uint32_t meas_nb_beacon_sent = 0; /* count beacon actually sent to concentrator */
static uint32_t meas_nb_beacon_rejected = 0; /* count beacon rejected for queuing */

static pthread_mutex_t mx_meas_gps = PTHREAD_MUTEX_INITIALIZER; /* control access to the GPS statistics */
static bool gps_coord_valid; /* could we get valid GPS coordinates ? */
static struct coord_s meas_gps_coord; /* GPS position of the gateway */
static struct coord_s meas_gps_err; /* GPS position of the gateway */

static pthread_mutex_t mx_stat_rep = PTHREAD_MUTEX_INITIALIZER; /* control access to the status report */
static bool report_ready = false; /* true when there is a new report to send to the server */
static char status_report[STATUS_SIZE]; /* status report as a JSON object */

/* beacon parameters */
static uint32_t beacon_period = 0; /* set beaconing period, must be a sub-multiple of 86400, the nb of sec in a day */
static uint32_t beacon_freq_hz = 0; /* TX beacon frequency, in Hz */

/* auto-quit function */
static uint32_t autoquit_threshold = 0; /* enable auto-quit after a number of non-acknowledged PULL_DATA (0 = disabled)*/

/* Just In Time TX scheduling */
static struct jit_queue_s jit_queue;

/* Gateway specificities */
static int8_t antenna_gain = 0;

/* TX capabilities */
static struct lgw_tx_gain_lut_s txlut; /* TX gain table */
static uint32_t tx_freq_min[LGW_RF_CHAIN_NB]; /* lowest frequency supported by TX chain */
static uint32_t tx_freq_max[LGW_RF_CHAIN_NB]; /* highest frequency supported by TX chain */

/* -------------------------------------------------------------------------- */
/* --- PRIVATE FUNCTIONS DECLARATION ---------------------------------------- */

static void sig_handler(int sigio);

//static int parse_SX1301_configuration(const char * conf_file);

//static int parse_gateway_configuration(const char * conf_file);

static uint16_t crc16(const uint8_t * data, unsigned size);

static uint8_t CRC_SUM(const uint8_t * data, unsigned size);
static double difftimespec(struct timespec end, struct timespec beginning);

/* threads */
void thread_up(void);
void thread_down(void);
void thread_gps(void);
void thread_valid(void);
void thread_jit(void);
void thread_timersync(void);
void thread_ack(void);
/* -------------------------------------------------------------------------- */
/* --- PRIVATE FUNCTIONS DEFINITION ----------------------------------------- */

static void sig_handler(int sigio) {
    if (sigio == SIGQUIT) {
        quit_sig = true;
    } else if ((sigio == SIGINT) || (sigio == SIGTERM)) {
        exit_sig = true;
    }
    return;
}

int to_hex_data(struct lgw_pkt_tx_s *pkt, uint8_t *hex_data){//TO-DO, make sure the code below is populating the original array
//	uint8_t hex_data[pkt->size+30];
//	&hex_data=&hex_output;
	hex_data[0]=0x23;
	hex_data[1]=0x32;
//compute length at last
//
// Channel Freq
	hex_data[4]=pkt->freq_hz & 0xFF;
	hex_data[5]=(pkt->freq_hz >> 8) & 0xFF;
	hex_data[6]=(pkt->freq_hz >> 16) &0xFF;
// TX mode 
	hex_data[7]=pkt->tx_mode;
//start time
	hex_data[8]=pkt->count_us & 0xFF;
	hex_data[9]=(pkt->count_us >> 8) & 0xFF;
	hex_data[10]=(pkt->count_us >> 16) & 0xFF;
	hex_data[11]=(pkt->count_us >> 24) & 0xFF;
// RF chain
	hex_data[12]=pkt->rf_chain;
//TX power
	hex_data[13]=pkt->rf_power;
//modulation type
	hex_data[14]=pkt->modulation;
//modulation bw
	hex_data[15]=pkt->bandwidth;
//data rate
	hex_data[16]=pkt->datarate & 0xFF;
	hex_data[17]=(pkt->datarate >> 8) & 0xFF;
	hex_data[18]=(pkt->datarate >> 16) & 0xFF;
	hex_data[19]=(pkt->datarate >> 24) & 0xFF;
//code rate
	hex_data[20]=pkt->coderate;
//inv polarity
	hex_data[21]=pkt->invert_pol;
//fsk freq deviation
	hex_data[22]=pkt->f_dev;
//preamble
	hex_data[23]=pkt->preamble;
//CRC IBM
	hex_data[24]=pkt->no_crc;
//No Header
	hex_data[25]=pkt->no_header;
//Payload Size
	hex_data[26]=pkt->size & 0xFF;
	hex_data[27]=(pkt->size >>8) & 0xFF;
//payload
	for(int i=0; i< pkt->size ; i++){
	hex_data[28+i]=pkt->payload[i];
	}
	hex_data[28+pkt->size]= CRC_SUM(hex_data, 27+pkt->size); // the CRC bit is the sum all of previous bytes in the hex_data array.
	hex_data[29+pkt->size]=0x0d;
	hex_data[2]= (pkt->size + 24) & 0xFF; 
	hex_data[3]= ((pkt->size + 24)>> 8) & 0xFF;

return pkt->size+30;
}

int write_to_serial(int fd, uint8_t *data, uint16_t size){
              if((write(fd, data , size)<0 )){
                      return LGW_HAL_ERROR; // TO-DO, need to check whether the write was sucessfull

              }
              return LGW_HAL_SUCCESS;
}



// -Jay this sets up the serial interface for canonical input mode.
int set_interface_attribs (int fd)
{
        struct termios oldtty,tty;
	//save setting to oldtty.
        if (tcgetattr (fd, &oldtty) <0)
        {
                printf("error %d from tcgetattr", errno);
                return -1;
        }
	//clear the struct for new port settings
	//bzero(&tty, sizeof(tty));

/*setup for Canonical input mode:*/
	tty.c_cflag = BAUDRATE | CS8 | CLOCAL | CREAD ;
	tty.c_cflag &= ~CRTSCTS; //disable hw control

	tty.c_iflag = IGNPAR ;//| ICRNL;
	//tty.c_iflag = ICRNL;// | ICRNL; //temporarily remove CR -> NL, see if that solves the issue; 
	/* raw output */
	tty.c_oflag = 0;
	/* enabled canonical input, disable all echo functionality and don't send signals to calling program*/
	tty.c_lflag = 0;//ICANON;
	/* clear the modem line and activate the settings for the port */
	tcflush(fd, TCIFLUSH);

	if(tcsetattr(fd,TCSANOW, &tty) <0 ){
	return -1;
	}
	return 0;
}

/* -Jay decode serial message into struct lgw_pkt_rx_s for later use*/

int decode_serial_message(struct lgw_pkt_rx_s *pkt_data, uint8_t buf_in[]){
    struct lgw_pkt_rx_s *p; /* pointer to the current structure in the struct array */
    uint32_t rec_pack_index;
    uint16_t payload_size=0;
   // printf("First 10bytes read was: ");
    //           for(int c=0; c < 10 ; c++){
     //           printf("0x%x ",buf_in[c]);
      //          }
//		printf("\n");
	p=pkt_data;
    if(buf_in[0]!= 0x23){
        printf("The packet received was not valid\n");
        return LGW_HAL_ERROR;
    }
    //check to see if this is a RXSTAT packet, if it is, check to see if it needs additional ACK, send ACK if needed.
    if(buf_in[1]==0x43){
	printf("this was a RXSTAT pkt, checking status,");
	if(buf_in[4]!=0x00){
		printf("there are still pkts require ACK, sending it,");
		int w=write_to_serial(_fd, serial_ACK_cmd, sizeof serial_ACK_cmd);
		if(w != LGW_HAL_SUCCESS ){
		MSG("Writing ACK in response to RXSTAT failed!\n");
		}
	}else{
		printf("----> RX Status is good\n");
	}
	
	return LGW_HAL_ERROR; // need to send error because else the read is going to return a value;
    }else if(buf_in[1]!=0x33){
        printf("this was not a receive packet, do not decode\n");
        return LGW_HAL_ERROR;
    }

    rec_pack_index=4;



    p->freq_hz = buf_in[rec_pack_index+1] ;
    p->freq_hz |= buf_in[rec_pack_index+2] << 8;
    p->freq_hz |= buf_in[rec_pack_index+3] << 16;
    p->freq_hz |= buf_in[rec_pack_index+4] << 24;
    //printf("p->freq_hz == %d\n", p->freq_hz);
    p->if_chain = buf_in[rec_pack_index+5];
    
    p->status = buf_in[rec_pack_index+6];
    
    p->count_us = buf_in[rec_pack_index+7] ;
    p->count_us |= buf_in[rec_pack_index+8] << 8;
    p->count_us |= buf_in[rec_pack_index+9] << 16;
    p->count_us |= buf_in[rec_pack_index+10] << 24;

    p->rf_chain = buf_in[rec_pack_index+11];
    p->modulation = buf_in[rec_pack_index+12] ;
    p->bandwidth = buf_in[rec_pack_index+13] ;
    p->datarate = buf_in[rec_pack_index+14] ;
    p->datarate |= buf_in[rec_pack_index+15] << 8;
    p->datarate |= buf_in[rec_pack_index+16] << 16;
    p->datarate |= buf_in[rec_pack_index+17] << 24;
    p->coderate = buf_in[rec_pack_index+18] ;

// Converting rssi/snr/snrmin/snrmax to float
    uint32_t rssi_h;
    uint32_t snr_h;
    uint32_t snr_min_h;
    uint32_t snr_max_h;

    rssi_h = buf_in[rec_pack_index+19] ;
    rssi_h = buf_in[rec_pack_index+20]<<8 ;
    rssi_h = buf_in[rec_pack_index+21]<<16 ;
    rssi_h = buf_in[rec_pack_index+22]<<24 ;
    p->rssi=*(float *)&rssi_h;

    snr_h = buf_in[rec_pack_index+23] ;
    snr_h = buf_in[rec_pack_index+24]<<8 ;
    snr_h = buf_in[rec_pack_index+25]<<16 ;
    snr_h = buf_in[rec_pack_index+26]<<24 ;
    p->snr = *(float *)&snr_h;

    snr_min_h = buf_in[rec_pack_index+27] ;
    snr_min_h |= buf_in[rec_pack_index+28]<<8 ;
    snr_min_h |= buf_in[rec_pack_index+29]<<16 ;
    snr_min_h |= buf_in[rec_pack_index+30]<<24 ;
    p->snr_min = *(float *)&snr_min_h;

    snr_max_h = buf_in[rec_pack_index+31] ;
    snr_max_h |= buf_in[rec_pack_index+32]<<8 ;
    snr_max_h |= buf_in[rec_pack_index+33]<<16 ;
    snr_max_h |= buf_in[rec_pack_index+34]<<24 ;
    p->snr_max = *(float *)&snr_max_h;

    p->crc = buf_in[rec_pack_index+35];
    p->crc |= buf_in[rec_pack_index+36] <<8;
    //printf("---------buf_in[37] is%x\n", buf_in[rec_pack_index+37]); 
    payload_size = buf_in[rec_pack_index+37] ;
    payload_size |= buf_in[rec_pack_index+38] <<8 ;
    //printf("-----(uint16_t)buf_in[37] is%d\n", (uint16_t)buf_in[rec_pack_index+37]);
    p->size=payload_size;
    unsigned siz=p->size;
//copy over all the payload data.
    memcpy((void *)p->payload, (void *)&buf_in[rec_pack_index+39], siz);
	//printf("p->payload now contains %s\n", p->payload);
	//printf("-----payload_size is %d\n", payload_size);
    //printf("-----p->size is %d\n", p->size);
    //printf("-----pkt_data->size is %d\n", pkt_data->size);
    printf("ENTIRE PACKET at DECODE: ");
    for(int i=0; i< 45+siz; i++){
	printf("0x%x ", buf_in[i]);
     }
	printf("\n");
	return 1;
} 

// Jay -- used to open serial port
int open_serial_port (void){	
	int fd=open(SER_DEV_PATH, O_RDWR | O_NOCTTY | O_NDELAY);
	if (fd < 0) {
		printf("Failed to open serial port\n");		
	}
    serial_is_opened=true;
	return fd;
}


void close_serial_port(int fd){
    serial_is_opened=false;
	close(fd);
}


//this method will perform a serial read and return the number of bytes read, and populate the serial data into the buff byte array passed in as parameter.
//everytime it read something, it will also send an ACK back to the module
int read_from_serial(int fd, uint8_t max_pkt, uint8_t * buff ){
    int pkt_len=0;
    int set_index;
    	/* check if the concentrator is running */
	if (serial_is_opened == false) {
		DEBUG_MSG("ERROR: Serial IS NOT opened, open the port BEFORE RECEIVING\n");
		return LGW_HAL_ERROR;
	}
    	/* check input variables */
	if (max_pkt <= 0) {
		DEBUG_PRINTF("ERROR: %d = INVALID MAX NUMBER OF PACKETS TO FETCH\n", max_pkt);
		return LGW_HAL_ERROR;
	}
    //this loop is going to continuously read the serial port as long as there are valid data. The loop will end when the max number of packets allowed are stored into the pkt_data[]]
		/* point to the proper struct in the struct array */
        	int last_available_index=0;
 	
        	int rdlen= read(fd, buff, sizeof buff);  // change size to max size allowed, should be 4+ 39 + 2
						 //56 + 2
		/* how many packets are in the RX buffer ? Break if zero */
		if (rdlen <= 0) {
			return 0; /* no more packets to fetch, exit out of FOR loop */
		}
	if(buff[0]!= 0x23){
		//not a valid packet, discard.
		printf("didn't recevie a valid packet\n");
		return 0;
	}
	
	//preliminary check, making sure a complete packet is in buff, if not, continue to read until a 	//complete packet is there.
	last_available_index=rdlen-1;
	if(last_available_index>=3){
                pkt_len  = buff[2];
                pkt_len |= buff[3]<< 8;
                pkt_len = pkt_len+4+2; //adding first 4 bytes containing starting byte, command and length byte, also the CRC , EOP byte.
        	set_index=0;
	} else {
		 pkt_len= sizeof buff;
		 set_index=1;
	}
	while(last_available_index < pkt_len-1){
		// containue to read until we read in the packet length byte. 
		rdlen=0;
		while(rdlen <= 0){
			rdlen = read(fd,(buff+last_available_index+1), sizeof buff);
		}
		printf(" * ");
		last_available_index+=rdlen;
	if(last_available_index>=3 && set_index==1){
		pkt_len  = buff[2];
		pkt_len |= buff[3]<< 8;
		pkt_len = pkt_len+4+2; //adding first 4 bytes containing starting byte, command and length byte, also the CRC , EOP byte.
		//printf("There are a total of %d bytes\n", pkt_len);
		set_index=0; 
		}	
	}


        //send ACK if it is a recevive packet, in order to receive the next packet
        if(buff[1]==0x33)
	write_to_serial(_fd, serial_ACK_cmd, sizeof serial_ACK_cmd);
    return last_available_index+1;   
    
}


static uint8_t CRC_SUM(const uint8_t * data, unsigned size){
	uint8_t crc=0x00;
	for(unsigned i=0; i< size; i++){
	crc+=data[i];	
	}
	return crc;
}

static uint16_t crc16(const uint8_t * data, unsigned size) {
    const uint16_t crc_poly = 0x1021;
    const uint16_t init_val = 0x0000;
    uint16_t x = init_val;
    unsigned i, j;

    if (data == NULL)  {
        return 0;
    }

    for (i=0; i<size; ++i) {
        x ^= (uint16_t)data[i] << 8;
        for (j=0; j<8; ++j) {
            x = (x & 0x8000) ? (x<<1) ^ crc_poly : (x<<1);
        }
    }

    return x;
}

static double difftimespec(struct timespec end, struct timespec beginning) {
    double x;

    x = 1E-9 * (double)(end.tv_nsec - beginning.tv_nsec);
    x += (double)(end.tv_sec - beginning.tv_sec);

    return x;
}

static int send_tx_ack(uint8_t token_h, uint8_t token_l, enum jit_error_e error) {
    uint8_t buff_ack[64]; /* buffer to give feedback to server */
    int buff_index;

    /* reset buffer */
    memset(&buff_ack, 0, sizeof buff_ack);

    /* Prepare downlink feedback to be sent to server */
    buff_ack[0] = PROTOCOL_VERSION;
    buff_ack[1] = token_h;
    buff_ack[2] = token_l;
    buff_ack[3] = PKT_TX_ACK;
    *(uint32_t *)(buff_ack + 4) = net_mac_h;
    *(uint32_t *)(buff_ack + 8) = net_mac_l;
    buff_index = 12; /* 12-byte header */

    /* Put no JSON string if there is nothing to report */
    if (error != JIT_ERROR_OK) {
        /* start of JSON structure */
        memcpy((void *)(buff_ack + buff_index), (void *)"{\"txpk_ack\":{", 13);
        buff_index += 13;
        /* set downlink error status in JSON structure */
        memcpy((void *)(buff_ack + buff_index), (void *)"\"error\":", 8);
        buff_index += 8;
        switch (error) {
            case JIT_ERROR_FULL:
            case JIT_ERROR_COLLISION_PACKET:
                memcpy((void *)(buff_ack + buff_index), (void *)"\"COLLISION_PACKET\"", 18);
                buff_index += 18;
                /* update stats */
                pthread_mutex_lock(&mx_meas_dw);
                meas_nb_tx_rejected_collision_packet += 1;
                pthread_mutex_unlock(&mx_meas_dw);
                break;
            case JIT_ERROR_TOO_LATE:
                memcpy((void *)(buff_ack + buff_index), (void *)"\"TOO_LATE\"", 10);
                buff_index += 10;
                /* update stats */
                pthread_mutex_lock(&mx_meas_dw);
                meas_nb_tx_rejected_too_late += 1;
                pthread_mutex_unlock(&mx_meas_dw);
                break;
            case JIT_ERROR_TOO_EARLY:
                memcpy((void *)(buff_ack + buff_index), (void *)"\"TOO_EARLY\"", 11);
                buff_index += 11;
                /* update stats */
                pthread_mutex_lock(&mx_meas_dw);
                meas_nb_tx_rejected_too_early += 1;
                pthread_mutex_unlock(&mx_meas_dw);
                break;
            case JIT_ERROR_COLLISION_BEACON:
                memcpy((void *)(buff_ack + buff_index), (void *)"\"COLLISION_BEACON\"", 18);
                buff_index += 18;
                /* update stats */
                pthread_mutex_lock(&mx_meas_dw);
                meas_nb_tx_rejected_collision_beacon += 1;
                pthread_mutex_unlock(&mx_meas_dw);
                break;
            case JIT_ERROR_TX_FREQ:
                memcpy((void *)(buff_ack + buff_index), (void *)"\"TX_FREQ\"", 9);
                buff_index += 9;
                break;
            case JIT_ERROR_TX_POWER:
                memcpy((void *)(buff_ack + buff_index), (void *)"\"TX_POWER\"", 10);
                buff_index += 10;
                break;
            case JIT_ERROR_GPS_UNLOCKED:
                memcpy((void *)(buff_ack + buff_index), (void *)"\"GPS_UNLOCKED\"", 14);
                buff_index += 14;
                break;
            default:
                memcpy((void *)(buff_ack + buff_index), (void *)"\"UNKNOWN\"", 9);
                buff_index += 9;
                break;
        }
        /* end of JSON structure */
        memcpy((void *)(buff_ack + buff_index), (void *)"}}", 2);
        buff_index += 2;
    }

    buff_ack[buff_index] = 0; /* add string terminator, for safety */

    /* send datagram to server */
    return send(sock_down, (void *)buff_ack, buff_index, 0);
}

/* -------------------------------------------------------------------------- */
/* --- MAIN FUNCTION -------------------------------------------------------- */

int main(void)
{
    struct sigaction sigact; /* SIGQUIT&SIGINT&SIGTERM signal handling */
    int i; /* loop variable and temporary variable for return value */
//    int x;

    /* configuration file related */
 //-Jay   char *global_cfg_path= "global_conf.json"; /* contain global (typ. network-wide) configuration */
 //-Jay   char *local_cfg_path = "local_conf.json"; /* contain node specific configuration, overwrite global parameters for parameters that are defined in both */
 //-Jay   char *debug_cfg_path = "debug_conf.json"; /* if present, all other configuration files are ignored */

    /* threads */
    pthread_t thrid_up;
    pthread_t thrid_down;
    pthread_t thrid_gps;
    pthread_t thrid_valid;
    pthread_t thrid_jit;
    pthread_t thrid_timersync;

    pthread_t thrid_ack;
    /* network socket creation */
    struct addrinfo hints;
    struct addrinfo *result; /* store result of getaddrinfo */
    struct addrinfo *q; /* pointer to move into *result data */
    char host_name[64];
    char port_name[64];

    /* variables to get local copies of measurements */
    uint32_t cp_nb_rx_rcv;
    uint32_t cp_nb_rx_ok;
    uint32_t cp_nb_rx_bad;
    uint32_t cp_nb_rx_nocrc;
    uint32_t cp_up_pkt_fwd;
    uint32_t cp_up_network_byte;
    uint32_t cp_up_payload_byte;
    uint32_t cp_up_dgram_sent;
    uint32_t cp_up_ack_rcv;
    uint32_t cp_dw_pull_sent;
    uint32_t cp_dw_ack_rcv;
    uint32_t cp_dw_dgram_rcv;
    uint32_t cp_dw_network_byte;
    uint32_t cp_dw_payload_byte;
    uint32_t cp_nb_tx_ok;
    uint32_t cp_nb_tx_fail;
    uint32_t cp_nb_tx_requested = 0;
    uint32_t cp_nb_tx_rejected_collision_packet = 0;
    uint32_t cp_nb_tx_rejected_collision_beacon = 0;
    uint32_t cp_nb_tx_rejected_too_late = 0;
    uint32_t cp_nb_tx_rejected_too_early = 0;
    uint32_t cp_nb_beacon_queued = 0;
    uint32_t cp_nb_beacon_sent = 0;
    uint32_t cp_nb_beacon_rejected = 0;

    /* GPS coordinates variables */
    bool coord_ok = false;
    struct coord_s cp_gps_coord = {0.0, 0.0, 0};

    /* statistics variable */
    time_t t;
    char stat_timestamp[24];
    float rx_ok_ratio;
    float rx_bad_ratio;
    float rx_nocrc_ratio;
    float up_ack_ratio;
    float dw_ack_ratio;

    /* display version informations */
    MSG("*** Beacon Packet Forwarder for Lora Gateway ***\nVersion: " VERSION_STRING "\n");
    MSG("*** Lora concentrator HAL library version info ***\n%s\n***\n", lgw_version_info());

    /* display host endianness */
    #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        MSG("INFO: Little endian host\n");
    #elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        MSG("INFO: Big endian host\n");
    #else
        MSG("INFO: Host endianness unknown\n");
    #endif

    /* load configuration files */
/* -- Jay commented out b/c no need to initialize this config
    if (access(debug_cfg_path, R_OK) == 0) { // if there is a debug conf, parse only the debug conf 
        MSG("INFO: found debug configuration file %s, parsing it\n", debug_cfg_path);
        MSG("INFO: other configuration files will be ignored\n"); 
        x = parse_SX1301_configuration(debug_cfg_path);
        if (x != 0) {
            exit(EXIT_FAILURE);
        }
        x = parse_gateway_configuration(debug_cfg_path);
        if (x != 0) {
            exit(EXIT_FAILURE);
        }
    } else if (access(global_cfg_path, R_OK) == 0) { // if there is a global conf, parse it and then try to parse local conf  
        MSG("INFO: found global configuration file %s, parsing it\n", global_cfg_path);
        x = parse_SX1301_configuration(global_cfg_path);
        if (x != 0) {
            exit(EXIT_FAILURE);
        }
        x = parse_gateway_configuration(global_cfg_path);
        if (x != 0) {
            exit(EXIT_FAILURE);
        }
        if (access(local_cfg_path, R_OK) == 0) {
            MSG("INFO: found local configuration file %s, parsing it\n", local_cfg_path);
            MSG("INFO: redefined parameters will overwrite global parameters\n");
            parse_SX1301_configuration(local_cfg_path);
            parse_gateway_configuration(local_cfg_path);
        }
    } else if (access(local_cfg_path, R_OK) == 0) { // if there is only a local conf, parse it and that's all 
        MSG("INFO: found local configuration file %s, parsing it\n", local_cfg_path);
        x = parse_SX1301_configuration(local_cfg_path);
        if (x != 0) {
            exit(EXIT_FAILURE);
        }
        x = parse_gateway_configuration(local_cfg_path);
        if (x != 0) {
            exit(EXIT_FAILURE);
        }
    } else {
        MSG("ERROR: [main] failed to find any configuration file named %s, %s OR %s\n", global_cfg_path, local_cfg_path, debug_cfg_path);
        exit(EXIT_FAILURE);
    }

*/

    /* Start GPS a.s.a.p., to allow it to lock */
/*    if (gps_tty_path[0] != '\0') { // do not try to open GPS device if no path set 
        i = lgw_gps_enable(gps_tty_path, "ubx7", 0, &gps_tty_fd); // HAL only supports u-blox 7 for now 
        if (i != LGW_GPS_SUCCESS) {
            printf("WARNING: [main] impossible to open %s for GPS sync (check permissions)\n", gps_tty_path);
            gps_enabled = false;
            gps_ref_valid = false;
        } else {
            printf("INFO: [main] TTY port %s open for GPS synchronization\n", gps_tty_path);
            gps_enabled = true;
            gps_ref_valid = false;
        }
    }
*/
    /* get timezone info */
    tzset();

    /* sanity check on configuration variables */
    // TODO

    /* process some of the configuration variables */
    net_mac_h = htonl((uint32_t)(0xFFFFFFFF & (lgwm>>32)));
    net_mac_l = htonl((uint32_t)(0xFFFFFFFF &  lgwm  ));

    /* prepare hints to open network sockets */
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; /* WA: Forcing IPv4 as AF_UNSPEC makes connection on localhost to fail */
    hints.ai_socktype = SOCK_DGRAM;

    /* look for server address w/ upstream port */
    i = getaddrinfo(serv_addr, serv_port_up, &hints, &result);
    if (i != 0) {
        MSG("ERROR: [up] getaddrinfo on address %s (PORT %s) returned %s\n", serv_addr, serv_port_up, gai_strerror(i));
        exit(EXIT_FAILURE);
    }

    /* try to open socket for upstream traffic */
    for (q=result; q!=NULL; q=q->ai_next) {
        sock_up = socket(q->ai_family, q->ai_socktype,q->ai_protocol);
        if (sock_up == -1) continue; /* try next field */
        else break; /* success, get out of loop */
    }
    if (q == NULL) {
        MSG("ERROR: [up] failed to open socket to any of server %s addresses (port %s)\n", serv_addr, serv_port_up);
        i = 1;
        for (q=result; q!=NULL; q=q->ai_next) {
            getnameinfo(q->ai_addr, q->ai_addrlen, host_name, sizeof host_name, port_name, sizeof port_name, NI_NUMERICHOST);
            MSG("INFO: [up] result %i host:%s service:%s\n", i, host_name, port_name);
            ++i;
        }
        exit(EXIT_FAILURE);
    }

    /* connect so we can send/receive packet with the server only */
    i = connect(sock_up, q->ai_addr, q->ai_addrlen);
    if (i != 0) {
        MSG("ERROR: [up] connect returned %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    freeaddrinfo(result);

    /* look for server address w/ downstream port */
    i = getaddrinfo(serv_addr, serv_port_down, &hints, &result);
    if (i != 0) {
        MSG("ERROR: [down] getaddrinfo on address %s (port %s) returned %s\n", serv_addr, serv_port_up, gai_strerror(i));
        exit(EXIT_FAILURE);
    }

    /* try to open socket for downstream traffic */
    for (q=result; q!=NULL; q=q->ai_next) {
        sock_down = socket(q->ai_family, q->ai_socktype,q->ai_protocol);
        if (sock_down == -1) continue; /* try next field */
        else break; /* success, get out of loop */
    }
    if (q == NULL) {
        MSG("ERROR: [down] failed to open socket to any of server %s addresses (port %s)\n", serv_addr, serv_port_up);
        i = 1;
        for (q=result; q!=NULL; q=q->ai_next) {
            getnameinfo(q->ai_addr, q->ai_addrlen, host_name, sizeof host_name, port_name, sizeof port_name, NI_NUMERICHOST);
            MSG("INFO: [down] result %i host:%s service:%s\n", i, host_name, port_name);
            ++i;
        }
        exit(EXIT_FAILURE);
    }

    /* connect so we can send/receive packet with the server only */
    i = connect(sock_down, q->ai_addr, q->ai_addrlen);
    if (i != 0) {
        MSG("ERROR: [down] connect returned %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    freeaddrinfo(result);


	/* open serial port*/
	_fd=open_serial_port(); //fd will now contain the file descriptor for later use
	if(set_interface_attribs(_fd)<0 ){
		printf("the serial attributes were not set correctly");
	}


   // i = lgw_start();   -Jay not starting this way.
    
	//first reset the device to clear all the queues
    	i=write_to_serial(_fd, serial_reset_cmd, sizeof serial_reset_cmd);
    if (i == LGW_HAL_SUCCESS) {
        MSG("INFO: [main] concentrator reset finished\n");
    } else {
        MSG("ERROR: [main] failed to reset the concentrator\n");
        exit(EXIT_FAILURE);
    }
    /* starting the concentrator */
/*
	i=write_to_serial(_fd, serial_start_cmd, sizeof serial_start_cmd);

    if (i == LGW_HAL_SUCCESS) {
        MSG("INFO: [main] concentrator started, packet can now be received\n");
    } else {
        MSG("ERROR: [main] failed to start the concentrator\n");
        exit(EXIT_FAILURE);
    }
*/
    /* spawn threads to manage upstream and downstream */
    i = pthread_create( &thrid_up, NULL, (void * (*)(void *))thread_up, NULL);
    if (i != 0) {
        MSG("ERROR: [main] impossible to create upstream thread\n");
        exit(EXIT_FAILURE);
    }
    i = pthread_create( &thrid_down, NULL, (void * (*)(void *))thread_down, NULL);
    if (i != 0) {
        MSG("ERROR: [main] impossible to create downstream thread\n");
        exit(EXIT_FAILURE);
    }
    i = pthread_create( &thrid_jit, NULL, (void * (*)(void *))thread_jit, NULL);
    if (i != 0) {
        MSG("ERROR: [main] impossible to create JIT thread\n");
        exit(EXIT_FAILURE);
    }
    i = pthread_create( &thrid_timersync, NULL, (void * (*)(void *))thread_timersync, NULL);
    if (i != 0) {
        MSG("ERROR: [main] impossible to create Timer Sync thread\n");
        exit(EXIT_FAILURE);
    }
/*    i = pthread_create( &thrid_ack, NULL, (void * (*)(void *))thread_ack, NULL);
    if (i != 0) {
        MSG("ERROR: [main] impossible to create ACK thread\n");
        exit(EXIT_FAILURE);
    }
*/
    /* spawn thread to manage GPS */
    if (gps_enabled == true) {
        i = pthread_create( &thrid_gps, NULL, (void * (*)(void *))thread_gps, NULL);
        if (i != 0) {
            MSG("ERROR: [main] impossible to create GPS thread\n");
            exit(EXIT_FAILURE);
        }
        i = pthread_create( &thrid_valid, NULL, (void * (*)(void *))thread_valid, NULL);
        if (i != 0) {
            MSG("ERROR: [main] impossible to create validation thread\n");
            exit(EXIT_FAILURE);
        }
    }

    /* configure signal handling */
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = 0;
    sigact.sa_handler = sig_handler;
    sigaction(SIGQUIT, &sigact, NULL); /* Ctrl-\ */
    sigaction(SIGINT, &sigact, NULL); /* Ctrl-C */
    sigaction(SIGTERM, &sigact, NULL); /* default "kill" command */

    /* main loop task : statistics collection */
    while (!exit_sig && !quit_sig) {
        /* wait for next reporting interval */
        wait_ms(1000 * stat_interval);

        /* get timestamp for statistics */
        t = time(NULL);
        strftime(stat_timestamp, sizeof stat_timestamp, "%F %T %Z", gmtime(&t));

        /* access upstream statistics, copy and reset them */
        pthread_mutex_lock(&mx_meas_up);
        cp_nb_rx_rcv       = meas_nb_rx_rcv;
        cp_nb_rx_ok        = meas_nb_rx_ok;
        cp_nb_rx_bad       = meas_nb_rx_bad;
        cp_nb_rx_nocrc     = meas_nb_rx_nocrc;
        cp_up_pkt_fwd      = meas_up_pkt_fwd;
        cp_up_network_byte = meas_up_network_byte;
        cp_up_payload_byte = meas_up_payload_byte;
        cp_up_dgram_sent   = meas_up_dgram_sent;
        cp_up_ack_rcv      = meas_up_ack_rcv;
        meas_nb_rx_rcv = 0;
        meas_nb_rx_ok = 0;
        meas_nb_rx_bad = 0;
        meas_nb_rx_nocrc = 0;
        meas_up_pkt_fwd = 0;
        meas_up_network_byte = 0;
        meas_up_payload_byte = 0;
        meas_up_dgram_sent = 0;
        meas_up_ack_rcv = 0;
        pthread_mutex_unlock(&mx_meas_up);
        if (cp_nb_rx_rcv > 0) {
            rx_ok_ratio = (float)cp_nb_rx_ok / (float)cp_nb_rx_rcv;
            rx_bad_ratio = (float)cp_nb_rx_bad / (float)cp_nb_rx_rcv;
            rx_nocrc_ratio = (float)cp_nb_rx_nocrc / (float)cp_nb_rx_rcv;
        } else {
            rx_ok_ratio = 0.0;
            rx_bad_ratio = 0.0;
            rx_nocrc_ratio = 0.0;
        }
        if (cp_up_dgram_sent > 0) {
            up_ack_ratio = (float)cp_up_ack_rcv / (float)cp_up_dgram_sent;
        } else {
            up_ack_ratio = 0.0;
        }

        /* access downstream statistics, copy and reset them */
        pthread_mutex_lock(&mx_meas_dw);
        cp_dw_pull_sent    =  meas_dw_pull_sent;
        cp_dw_ack_rcv      =  meas_dw_ack_rcv;
        cp_dw_dgram_rcv    =  meas_dw_dgram_rcv;
        cp_dw_network_byte =  meas_dw_network_byte;
        cp_dw_payload_byte =  meas_dw_payload_byte;
        cp_nb_tx_ok        =  meas_nb_tx_ok;
        cp_nb_tx_fail      =  meas_nb_tx_fail;
        cp_nb_tx_requested                 +=  meas_nb_tx_requested;
        cp_nb_tx_rejected_collision_packet +=  meas_nb_tx_rejected_collision_packet;
        cp_nb_tx_rejected_collision_beacon +=  meas_nb_tx_rejected_collision_beacon;
        cp_nb_tx_rejected_too_late         +=  meas_nb_tx_rejected_too_late;
        cp_nb_tx_rejected_too_early        +=  meas_nb_tx_rejected_too_early;
        cp_nb_beacon_queued   +=  meas_nb_beacon_queued;
        cp_nb_beacon_sent     +=  meas_nb_beacon_sent;
        cp_nb_beacon_rejected +=  meas_nb_beacon_rejected;
        meas_dw_pull_sent = 0;
        meas_dw_ack_rcv = 0;
        meas_dw_dgram_rcv = 0;
        meas_dw_network_byte = 0;
        meas_dw_payload_byte = 0;
        meas_nb_tx_ok = 0;
        meas_nb_tx_fail = 0;
        meas_nb_tx_requested = 0;
        meas_nb_tx_rejected_collision_packet = 0;
        meas_nb_tx_rejected_collision_beacon = 0;
        meas_nb_tx_rejected_too_late = 0;
        meas_nb_tx_rejected_too_early = 0;
        meas_nb_beacon_queued = 0;
        meas_nb_beacon_sent = 0;
        meas_nb_beacon_rejected = 0;
        pthread_mutex_unlock(&mx_meas_dw);
        if (cp_dw_pull_sent > 0) {
            dw_ack_ratio = (float)cp_dw_ack_rcv / (float)cp_dw_pull_sent;
        } else {
            dw_ack_ratio = 0.0;
        }

        /* access GPS statistics, copy them */
        if (gps_enabled == true) {
            pthread_mutex_lock(&mx_meas_gps);
            coord_ok = gps_coord_valid;
            cp_gps_coord = meas_gps_coord;
            pthread_mutex_unlock(&mx_meas_gps);
        }

        /* overwrite with reference coordinates if function is enabled */
        if (gps_fake_enable == true) {
            cp_gps_coord = reference_coord;
        }

        /* display a report */
        printf("\n##### %s #####\n", stat_timestamp);
        printf("### [UPSTREAM] ###\n");
        printf("# RF packets received by concentrator: %u\n", cp_nb_rx_rcv);
        printf("# CRC_OK: %.2f%%, CRC_FAIL: %.2f%%, NO_CRC: %.2f%%\n", 100.0 * rx_ok_ratio, 100.0 * rx_bad_ratio, 100.0 * rx_nocrc_ratio);
        printf("# RF packets forwarded: %u (%u bytes)\n", cp_up_pkt_fwd, cp_up_payload_byte);
        printf("# PUSH_DATA datagrams sent: %u (%u bytes)\n", cp_up_dgram_sent, cp_up_network_byte);
        printf("# PUSH_DATA acknowledged: %.2f%%\n", 100.0 * up_ack_ratio);
        printf("### [DOWNSTREAM] ###\n");
        printf("# PULL_DATA sent: %u (%.2f%% acknowledged)\n", cp_dw_pull_sent, 100.0 * dw_ack_ratio);
        printf("# PULL_RESP(onse) datagrams received: %u (%u bytes)\n", cp_dw_dgram_rcv, cp_dw_network_byte);
        printf("# RF packets sent to concentrator: %u (%u bytes)\n", (cp_nb_tx_ok+cp_nb_tx_fail), cp_dw_payload_byte);
        printf("# TX errors: %u\n", cp_nb_tx_fail);
        if (cp_nb_tx_requested != 0 ) {
            printf("# TX rejected (collision packet): %.2f%% (req:%u, rej:%u)\n", 100.0 * cp_nb_tx_rejected_collision_packet / cp_nb_tx_requested, cp_nb_tx_requested, cp_nb_tx_rejected_collision_packet);
            printf("# TX rejected (collision beacon): %.2f%% (req:%u, rej:%u)\n", 100.0 * cp_nb_tx_rejected_collision_beacon / cp_nb_tx_requested, cp_nb_tx_requested, cp_nb_tx_rejected_collision_beacon);
            printf("# TX rejected (too late): %.2f%% (req:%u, rej:%u)\n", 100.0 * cp_nb_tx_rejected_too_late / cp_nb_tx_requested, cp_nb_tx_requested, cp_nb_tx_rejected_too_late);
            printf("# TX rejected (too early): %.2f%% (req:%u, rej:%u)\n", 100.0 * cp_nb_tx_rejected_too_early / cp_nb_tx_requested, cp_nb_tx_requested, cp_nb_tx_rejected_too_early);
        }
        printf("# BEACON queued: %u\n", cp_nb_beacon_queued);
        printf("# BEACON sent so far: %u\n", cp_nb_beacon_sent);
        printf("# BEACON rejected: %u\n", cp_nb_beacon_rejected);
        printf("### [JIT] ###\n");
        jit_print_queue (&jit_queue, false, DEBUG_LOG);
        printf("### [GPS] ###\n");
        if (gps_enabled == true) {
            /* no need for mutex, display is not critical */
            if (gps_ref_valid == true) {
                printf("# Valid time reference (age: %li sec)\n", (long)difftime(time(NULL), time_reference_gps.systime));
            } else {
                printf("# Invalid time reference (age: %li sec)\n", (long)difftime(time(NULL), time_reference_gps.systime));
            }
            if (coord_ok == true) {
                printf("# GPS coordinates: latitude %.5f, longitude %.5f, altitude %i m\n", cp_gps_coord.lat, cp_gps_coord.lon, cp_gps_coord.alt);
            } else {
                printf("# no valid GPS coordinates available yet\n");
            }
        } else if (gps_fake_enable == true) {
            printf("# GPS *FAKE* coordinates: latitude %.5f, longitude %.5f, altitude %i m\n", cp_gps_coord.lat, cp_gps_coord.lon, cp_gps_coord.alt);
        } else {
            printf("# GPS sync is disabled\n");
        }
        printf("##### END #####\n");

        /* generate a JSON report (will be sent to server by upstream thread) */
        pthread_mutex_lock(&mx_stat_rep);
        if (((gps_enabled == true) && (coord_ok == true)) || (gps_fake_enable == true)) {
            snprintf(status_report, STATUS_SIZE, "\"stat\":{\"time\":\"%s\",\"lati\":%.5f,\"long\":%.5f,\"alti\":%i,\"rxnb\":%u,\"rxok\":%u,\"rxfw\":%u,\"ackr\":%.1f,\"dwnb\":%u,\"txnb\":%u}", stat_timestamp, cp_gps_coord.lat, cp_gps_coord.lon, cp_gps_coord.alt, cp_nb_rx_rcv, cp_nb_rx_ok, cp_up_pkt_fwd, 100.0 * up_ack_ratio, cp_dw_dgram_rcv, cp_nb_tx_ok);
        } else {
            snprintf(status_report, STATUS_SIZE, "\"stat\":{\"time\":\"%s\",\"rxnb\":%u,\"rxok\":%u,\"rxfw\":%u,\"ackr\":%.1f,\"dwnb\":%u,\"txnb\":%u}", stat_timestamp, cp_nb_rx_rcv, cp_nb_rx_ok, cp_up_pkt_fwd, 100.0 * up_ack_ratio, cp_dw_dgram_rcv, cp_nb_tx_ok);
        }
        report_ready = true;
        pthread_mutex_unlock(&mx_stat_rep);
    }

    /* wait for upstream thread to finish (1 fetch cycle max) */
    pthread_join(thrid_up, NULL);
    pthread_cancel(thrid_ack);
    pthread_cancel(thrid_down); /* don't wait for downstream thread */
    pthread_cancel(thrid_jit); /* don't wait for jit thread */
    pthread_cancel(thrid_timersync); /* don't wait for timer sync thread */
    if (gps_enabled == true) {
        pthread_cancel(thrid_gps); /* don't wait for GPS thread */
        pthread_cancel(thrid_valid); /* don't wait for validation thread */
    }

    /* if an exit signal was received, try to quit properly */
    if (exit_sig) {
        /* shut down network sockets */
        shutdown(sock_up, SHUT_RDWR);
        shutdown(sock_down, SHUT_RDWR);
        /* stop the hardware */
       // i = lgw_stop(); -Jay commented out replace with serial command
        i=write_to_serial(_fd, serial_stop_cmd, sizeof serial_stop_cmd);
        if (i == LGW_HAL_SUCCESS) {
            MSG("INFO: concentrator stopped successfully\n");
        } else {
            MSG("WARNING: failed to stop concentrator successfully\n");
        }
	//close_serial_port(_fd);
    }

    MSG("INFO: Exiting packet forwarder program\n");
    exit(EXIT_SUCCESS);
}

/* -------------------------------------------------------------------------- */
/* --- THREAD 1: RECEIVING PACKETS AND FORWARDING THEM ---------------------- */

void thread_up(void) {
    int i, j; /* loop variables */
    unsigned pkt_in_dgram; /* nb on Lora packet in the current datagram */

    /* allocate memory for packet fetching and processing */
    struct lgw_pkt_rx_s rxpkt[NB_PKT_MAX]; /* array containing inbound packets + metadata */
    uint8_t buff_recv[1024]={0};// this is used to store the incoming hex data from LGW
    struct lgw_pkt_rx_s *p; /* pointer on a RX packet */
    int nb_pkt;

    /* local copy of GPS time reference */
    bool ref_ok = false; /* determine if GPS time reference must be used or not */
    struct tref local_ref; /* time reference used for UTC <-> timestamp conversion */

    /* data buffers */
    uint8_t buff_up[TX_BUFF_SIZE]; /* buffer to compose the upstream packet */
    int buff_index;
    uint8_t buff_ack[32]; /* buffer to receive acknowledges */

    /* protocol variables */
    uint8_t token_h; /* random token for acknowledgement matching */
    uint8_t token_l; /* random token for acknowledgement matching */

    /* ping measurement variables */
    struct timespec send_time;
    struct timespec recv_time;

    /* GPS synchronization variables */
    struct timespec pkt_utc_time;
    struct tm * x; /* broken-up UTC time */

    /* report management variable */
    bool send_report = false;

    /* mote info variables */
    uint32_t mote_addr = 0;
    uint16_t mote_fcnt = 0;

    /* set upstream socket RX timeout */
    i = setsockopt(sock_up, SOL_SOCKET, SO_RCVTIMEO, (void *)&push_timeout_half, sizeof push_timeout_half);
    if (i != 0) {
        MSG("ERROR: [up] setsockopt returned %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* pre-fill the data buffer with fixed fields */
    buff_up[0] = PROTOCOL_VERSION;
    buff_up[3] = PKT_PUSH_DATA;
    *(uint32_t *)(buff_up + 4) = net_mac_h;
    *(uint32_t *)(buff_up + 8) = net_mac_l;

    while (!exit_sig && !quit_sig) {

        /* fetch packets */
        pthread_mutex_lock(&mx_concent);
 //       nb_pkt = lgw_receive(NB_PKT_MAX, rxpkt);   -Jay comment out replace with serial read
        
	nb_pkt = read_from_serial(_fd, NB_PKT_MAX, buff_recv);
	if(nb_pkt!=0) //if read no packets, do not decode message, just continue to read.
	nb_pkt = decode_serial_message(rxpkt, buff_recv);
        pthread_mutex_unlock(&mx_concent);
        if (nb_pkt == LGW_HAL_ERROR) {
            //MSG("ERROR: [up] failed packet fetch, exiting\n");
            //exit(EXIT_FAILURE);
            nb_pkt = 0;
	}

        /* check if there are status report to send */
        send_report = report_ready; /* copy the variable so it doesn't change mid-function */
        /* no mutex, we're only reading */

        /* wait a short time if no packets, nor status report */
        if ((nb_pkt == 0) && (send_report == false)) {
            wait_ms(FETCH_SLEEP_MS);
            continue;
        }

        /* get a copy of GPS time reference (avoid 1 mutex per packet) */
        if ((nb_pkt > 0) && (gps_enabled == true)) {
            pthread_mutex_lock(&mx_timeref);
            ref_ok = gps_ref_valid;
            local_ref = time_reference_gps;
            pthread_mutex_unlock(&mx_timeref);
        } else {
            ref_ok = false;
        }

        /* start composing datagram with the header */
        token_h = (uint8_t)rand(); /* random token */
        token_l = (uint8_t)rand(); /* random token */
        buff_up[1] = token_h;
        buff_up[2] = token_l;
        buff_index = 12; /* 12-byte header */

        /* start of JSON structure */
        memcpy((void *)(buff_up + buff_index), (void *)"{\"rxpk\":[", 9);
        buff_index += 9;

        /* serialize Lora packets metadata and payload */
        pkt_in_dgram = 0;
        for (i=0; i < nb_pkt; ++i) {
            p = &rxpkt[i];
            //printf("----------------p->size is%d\n", p->size );
            /* Get mote information from current packet (addr, fcnt) */
            /* FHDR - DevAddr */
	   // printf("p->payload[1]=%x\n",p->payload[1]);
            mote_addr  = p->payload[1];
           // printf("p->payload[2]=%x\n",p->payload[2]);
            mote_addr |= p->payload[2] << 8;
           // printf("p->payload[3]=%x\n",p->payload[3]);
            mote_addr |= p->payload[3] << 16;
            //printf("p->payload[4]=%x\n",p->payload[4]);

            mote_addr |= p->payload[4] << 24;
            /* FHDR - FCnt */
            mote_fcnt  = p->payload[6];
            mote_fcnt |= p->payload[7] << 8;

            /* basic packet filtering */
            pthread_mutex_lock(&mx_meas_up);
            meas_nb_rx_rcv += 1;
		//printf("p->status is %x\n", p->status);
            switch(p->status) {
                case STAT_CRC_OK:
                    meas_nb_rx_ok += 1;
                    printf( "\nINFO: Received pkt from mote: %08X (fcnt=%u)\n", mote_addr, mote_fcnt );
                    if (!fwd_valid_pkt) {
                        pthread_mutex_unlock(&mx_meas_up);
                        continue; /* skip that packet */
                    }
                    break;
                case STAT_CRC_BAD:
                    meas_nb_rx_bad += 1;
	            printf("\nINFO: stats is bad!\n");
                    if (!fwd_error_pkt) {
                        pthread_mutex_unlock(&mx_meas_up);
                        continue; /* skip that packet */
                    }
                    break;
                case STAT_NO_CRC:
                    meas_nb_rx_nocrc += 1;
	   	    printf("\n STAT_CRC_bad\n");
                    if (!fwd_nocrc_pkt) {
                        pthread_mutex_unlock(&mx_meas_up);
                        continue; /* skip that packet */
                    }
                    break;
                default:
                    MSG("WARNING: [up] received packet with unknown status %u (size %u, modulation %u, BW %u, DR %u, RSSI %.1f)\n", p->status, p->size, p->modulation, p->bandwidth, p->datarate, p->rssi);
                    pthread_mutex_unlock(&mx_meas_up);
                    continue; /* skip that packet */
                    // exit(EXIT_FAILURE);
            }
            meas_up_pkt_fwd += 1;
            meas_up_payload_byte += p->size;
            pthread_mutex_unlock(&mx_meas_up);

            /* Start of packet, add inter-packet separator if necessary */
            if (pkt_in_dgram == 0) {
                buff_up[buff_index] = '{';
                ++buff_index;
            } else {
                buff_up[buff_index] = ',';
                buff_up[buff_index+1] = '{';
                buff_index += 2;
            }

            /* RAW timestamp, 8-17 useful chars */
            j = snprintf((char *)(buff_up + buff_index), TX_BUFF_SIZE-buff_index, "\"tmst\":%u", p->count_us);
            if (j > 0) {
                buff_index += j;
            } else {
                MSG("ERROR: [up] snprintf failed line %u\n", (__LINE__ - 4));
                exit(EXIT_FAILURE);
            }

            /* Packet RX time (GPS based), 37 useful chars */
            if (ref_ok == true) {
                /* convert packet timestamp to UTC absolute time */
                j = lgw_cnt2utc(local_ref, p->count_us, &pkt_utc_time);
                if (j == LGW_GPS_SUCCESS) {
                    /* split the UNIX timestamp to its calendar components */
                    x = gmtime(&(pkt_utc_time.tv_sec));
                    j = snprintf((char *)(buff_up + buff_index), TX_BUFF_SIZE-buff_index, ",\"time\":\"%04i-%02i-%02iT%02i:%02i:%02i.%06liZ\"", (x->tm_year)+1900, (x->tm_mon)+1, x->tm_mday, x->tm_hour, x->tm_min, x->tm_sec, (pkt_utc_time.tv_nsec)/1000); /* ISO 8601 format */
                    if (j > 0) {
                        buff_index += j;
                    } else {
                        MSG("ERROR: [up] snprintf failed line %u\n", (__LINE__ - 4));
                        exit(EXIT_FAILURE);
                    }
                }
            }

            /* Packet concentrator channel, RF chain & RX frequency, 34-36 useful chars */
            j = snprintf((char *)(buff_up + buff_index), TX_BUFF_SIZE-buff_index, ",\"chan\":%1u,\"rfch\":%1u,\"freq\":%.6lf", p->if_chain, p->rf_chain, ((double)p->freq_hz / 1e6));
            if (j > 0) {
                buff_index += j;
            } else {
                MSG("ERROR: [up] snprintf failed line %u\n", (__LINE__ - 4));
                exit(EXIT_FAILURE);
            }

            /* Packet status, 9-10 useful chars */
            switch (p->status) {
                case STAT_CRC_OK:
                    memcpy((void *)(buff_up + buff_index), (void *)",\"stat\":1", 9);
                    buff_index += 9;
                    break;
                case STAT_CRC_BAD:
                    memcpy((void *)(buff_up + buff_index), (void *)",\"stat\":-1", 10);
                    buff_index += 10;
                    break;
                case STAT_NO_CRC:
                    memcpy((void *)(buff_up + buff_index), (void *)",\"stat\":0", 9);
                    buff_index += 9;
                    break;
                default:
                    MSG("ERROR: [up] received packet with unknown status:%4x\n", p->status);
                    memcpy((void *)(buff_up + buff_index), (void *)",\"stat\":?", 9);
                    buff_index += 9;
                    exit(EXIT_FAILURE);
            }

            /* Packet modulation, 13-14 useful chars */
            if (p->modulation == MOD_LORA) {
                memcpy((void *)(buff_up + buff_index), (void *)",\"modu\":\"LORA\"", 14);
                buff_index += 14;

                /* Lora datarate & bandwidth, 16-19 useful chars */
                switch (p->datarate) {
                    case DR_LORA_SF7:
                        memcpy((void *)(buff_up + buff_index), (void *)",\"datr\":\"SF7", 12);
                        buff_index += 12;
                        break;
                    case DR_LORA_SF8:
                        memcpy((void *)(buff_up + buff_index), (void *)",\"datr\":\"SF8", 12);
                        buff_index += 12;
                        break;
                    case DR_LORA_SF9:
                        memcpy((void *)(buff_up + buff_index), (void *)",\"datr\":\"SF9", 12);
                        buff_index += 12;
                        break;
                    case DR_LORA_SF10:
                        memcpy((void *)(buff_up + buff_index), (void *)",\"datr\":\"SF10", 13);
                        buff_index += 13;
                        break;
                    case DR_LORA_SF11:
                        memcpy((void *)(buff_up + buff_index), (void *)",\"datr\":\"SF11", 13);
                        buff_index += 13;
                        break;
                    case DR_LORA_SF12:
                        memcpy((void *)(buff_up + buff_index), (void *)",\"datr\":\"SF12", 13);
                        buff_index += 13;
                        break;
                    default:
                        MSG("ERROR: [up] lora packet with unknown datarate:%8x\n", p->datarate);
                        memcpy((void *)(buff_up + buff_index), (void *)",\"datr\":\"SF?", 12);
                        buff_index += 12;
                        exit(EXIT_FAILURE);
                }
                switch (p->bandwidth) {
                    case BW_125KHZ:
                        memcpy((void *)(buff_up + buff_index), (void *)"BW125\"", 6);
                        buff_index += 6;
                        break;
                    case BW_250KHZ:
                        memcpy((void *)(buff_up + buff_index), (void *)"BW250\"", 6);
                        buff_index += 6;
                        break;
                    case BW_500KHZ:
                        memcpy((void *)(buff_up + buff_index), (void *)"BW500\"", 6);
                        buff_index += 6;
                        break;
                    default:
                        MSG("ERROR: [up] lora packet with unknown bandwidth:%4x\n", p->bandwidth);
                        memcpy((void *)(buff_up + buff_index), (void *)"BW?\"", 4);
                        buff_index += 4;
                        exit(EXIT_FAILURE);
                }

                /* Packet ECC coding rate, 11-13 useful chars */
                switch (p->coderate) {
                    case CR_LORA_4_5:
                        memcpy((void *)(buff_up + buff_index), (void *)",\"codr\":\"4/5\"", 13);
                        buff_index += 13;
                        break;
                    case CR_LORA_4_6:
                        memcpy((void *)(buff_up + buff_index), (void *)",\"codr\":\"4/6\"", 13);
                        buff_index += 13;
                        break;
                    case CR_LORA_4_7:
                        memcpy((void *)(buff_up + buff_index), (void *)",\"codr\":\"4/7\"", 13);
                        buff_index += 13;
                        break;
                    case CR_LORA_4_8:
                        memcpy((void *)(buff_up + buff_index), (void *)",\"codr\":\"4/8\"", 13);
                        buff_index += 13;
                        break;
                    case 0: /* treat the CR0 case (mostly false sync) */
                        memcpy((void *)(buff_up + buff_index), (void *)",\"codr\":\"OFF\"", 13);
                        buff_index += 13;
                        break;
                    default:
                        MSG("ERROR: [up] lora packet with unknown coderate:%4x\n", p->coderate);
                        memcpy((void *)(buff_up + buff_index), (void *)",\"codr\":\"?\"", 11);
                        buff_index += 11;
                        exit(EXIT_FAILURE);
                }

                /* Lora SNR, 11-13 useful chars */
                j = snprintf((char *)(buff_up + buff_index), TX_BUFF_SIZE-buff_index, ",\"lsnr\":%.1f", p->snr);
                if (j > 0) {
                    buff_index += j;
                } else {
                    MSG("ERROR: [up] snprintf failed line %u\n", (__LINE__ - 4));
                    exit(EXIT_FAILURE);
                }
            } else if (p->modulation == MOD_FSK) {
                memcpy((void *)(buff_up + buff_index), (void *)",\"modu\":\"FSK\"", 13);
                buff_index += 13;

                /* FSK datarate, 11-14 useful chars */
                j = snprintf((char *)(buff_up + buff_index), TX_BUFF_SIZE-buff_index, ",\"datr\":%u", p->datarate);
                if (j > 0) {
                    buff_index += j;
                } else {
                    MSG("ERROR: [up] snprintf failed line %u\n", (__LINE__ - 4));
                    exit(EXIT_FAILURE);
                }
            } else {
                MSG("ERROR: [up] received packet with unknown modulation:%4x\n", p->modulation);
                exit(EXIT_FAILURE);
            }

            /* Packet RSSI, payload size, 18-23 useful chars */
            j = snprintf((char *)(buff_up + buff_index), TX_BUFF_SIZE-buff_index, ",\"rssi\":%.0f,\"size\":%u", p->rssi, p->size);
            if (j > 0) {
                buff_index += j;
            } else {
                MSG("ERROR: [up] snprintf failed line %u\n", (__LINE__ - 4));
                exit(EXIT_FAILURE);
            }

            /* Packet base64-encoded payload, 14-350 useful chars */
            memcpy((void *)(buff_up + buff_index), (void *)",\"data\":\"", 9);
            buff_index += 9;
            j = bin_to_b64(p->payload, p->size, (char *)(buff_up + buff_index), 341); /* 255 bytes = 340 chars in b64 + null char */
            if (j>=0) {
                buff_index += j;
            } else {
                MSG("ERROR: [up] bin_to_b64 failed line %u\n", (__LINE__ - 5));
                exit(EXIT_FAILURE);
            }
            buff_up[buff_index] = '"';
            ++buff_index;

            /* End of packet serialization */
            buff_up[buff_index] = '}';
            ++buff_index;
            ++pkt_in_dgram;
        }

        /* restart fetch sequence without sending empty JSON if all packets have been filtered out */
        if (pkt_in_dgram == 0) {
            if (send_report == true) {
                /* need to clean up the beginning of the payload */
                buff_index -= 8; /* removes "rxpk":[ */
            } else {
                /* all packet have been filtered out and no report, restart loop */
                continue;
            }
        } else {
            /* end of packet array */
            buff_up[buff_index] = ']';
            ++buff_index;
            /* add separator if needed */
            if (send_report == true) {
                buff_up[buff_index] = ',';
                ++buff_index;
            }
        }

        /* add status report if a new one is available */
        if (send_report == true) {
            pthread_mutex_lock(&mx_stat_rep);
            report_ready = false;
            j = snprintf((char *)(buff_up + buff_index), TX_BUFF_SIZE-buff_index, "%s", status_report);
            pthread_mutex_unlock(&mx_stat_rep);
            if (j > 0) {
                buff_index += j;
            } else {
                MSG("ERROR: [up] snprintf failed line %u\n", (__LINE__ - 5));
                exit(EXIT_FAILURE);
            }
        }

        /* end of JSON datagram payload */
        buff_up[buff_index] = '}';
        ++buff_index;
        buff_up[buff_index] = 0; /* add string terminator, for safety */
/*
	printf("HEADER: %02X\n", buff_up[0]);
        printf("HEADER: %02X\n", buff_up[1]);
        printf("HEADER: %02X\n", buff_up[2]);
        printf("HEADER: %02X\n", buff_up[3]);
        printf("HEADER: %02X\n", buff_up[4]);
        printf("HEADER: %02X\n", buff_up[5]);
        printf("HEADER: %02X\n", buff_up[6]);
        printf("HEADER: %02X\n", buff_up[7]);
        printf("HEADER: %02X\n", buff_up[8]);
        printf("HEADER: %02X\n", buff_up[9]);
        printf("HEADER: %02X\n", buff_up[10]);
        printf("HEADER: %02X\n", buff_up[11]);
        printf("HEADER: %02X\n", buff_up[12]);
*/

 
        printf("\nJSON up: %s\n", (char *)(buff_up + 12)); /* DEBUG: display JSON payload */
        /* send datagram to server */
        
        send(sock_up, (void *)buff_up, buff_index, 0);
        clock_gettime(CLOCK_MONOTONIC, &send_time);
        pthread_mutex_lock(&mx_meas_up);
        meas_up_dgram_sent += 1;
        meas_up_network_byte += buff_index;

        /* wait for acknowledge (in 2 times, to catch extra packets) */
        for (i=0; i<2; ++i) {
            j = recv(sock_up, (void *)buff_ack, sizeof buff_ack, 0);
            clock_gettime(CLOCK_MONOTONIC, &recv_time);
            if (j == -1) {
                if (errno == EAGAIN) { /* timeout */
                    continue;
                } else { /* server connection error */
                    break;
                    MSG("WARNING: Server connection error");
		}
            } else if ((j < 4) || (buff_ack[0] != PROTOCOL_VERSION) || (buff_ack[3] != PKT_PUSH_ACK)) {
                MSG("WARNING: [up] ignored invalid non-ACL packet\n");
                continue;
            } else if ((buff_ack[1] != token_h) || (buff_ack[2] != token_l)) {
                MSG("WARNING: [up] ignored out-of sync ACK packet\n");
                continue;
            } else {
                MSG("INFO: [up] PUSH_ACK received in %i ms\n", (int)(1000 * difftimespec(recv_time, send_time)));
                meas_up_ack_rcv += 1;
                break;
            }
        }
        pthread_mutex_unlock(&mx_meas_up);
    }
    MSG("\nINFO: End of upstream thread\n");
}

/* -------------------------------------------------------------------------- */
/* --- THREAD 2: POLLING SERVER AND ENQUEUING PACKETS IN JIT QUEUE ---------- */

void thread_down(void) {
    int i; /* loop variables */

    /* configuration and metadata for an outbound packet */
    struct lgw_pkt_tx_s txpkt;
    bool sent_immediate = false; /* option to sent the packet immediately */

    /* local timekeeping variables */
    struct timespec send_time; /* time of the pull request */
    struct timespec recv_time; /* time of return from recv socket call */

    /* data buffers */
    uint8_t buff_down[1000]; /* buffer to receive downstream packets */
    uint8_t buff_req[12]; /* buffer to compose pull requests */
    int msg_len;

    /* protocol variables */
    uint8_t token_h; /* random token for acknowledgement matching */
    uint8_t token_l; /* random token for acknowledgement matching */
    bool req_ack = false; /* keep track of whether PULL_DATA was acknowledged or not */

    /* JSON parsing variables */
    JSON_Value *root_val = NULL;
    JSON_Object *txpk_obj = NULL;
    JSON_Value *val = NULL; /* needed to detect the absence of some fields */
    const char *str; /* pointer to sub-strings in the JSON data */
    short x0, x1;
    short x2, x3, x4;
    double x5, x6;

    /* variables to send on UTC timestamp */
    struct tref local_ref; /* time reference used for UTC <-> timestamp conversion */
    struct tm utc_vector; /* for collecting the elements of the UTC time */
    struct timespec utc_tx; /* UTC time that needs to be converted to timestamp */

    /* beacon variables */
    struct lgw_pkt_tx_s beacon_pkt;
    uint8_t beacon_loop;
    time_t diff_beacon_time;
    struct timespec next_beacon_gps_time; /* gps time of next beacon packet */
    struct timespec last_beacon_gps_time; /* gps time of last enqueued beacon packet */
    int retry;

    /* beacon data fields, byte 0 is Least Significant Byte */
    uint8_t field_info = 0;
    int32_t field_latitude; /* 3 bytes, derived from reference latitude */
    int32_t field_longitude; /* 3 bytes, derived from reference longitude */
    uint16_t field_crc1, field_crc2;

    /* auto-quit variable */
    uint32_t autoquit_cnt = 0; /* count the number of PULL_DATA sent since the latest PULL_ACK */

    /* Just In Time downlink */
    struct timeval current_unix_time;
    struct timeval current_concentrator_time;
    enum jit_error_e jit_result = JIT_ERROR_OK;
    enum jit_pkt_type_e downlink_type;

    /* set downstream socket RX timeout */
    i = setsockopt(sock_down, SOL_SOCKET, SO_RCVTIMEO, (void *)&pull_timeout, sizeof pull_timeout);
    if (i != 0) {
        MSG("ERROR: [down] setsockopt returned %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* pre-fill the pull request buffer with fixed fields */
    buff_req[0] = PROTOCOL_VERSION;
    buff_req[3] = PKT_PULL_DATA;
    *(uint32_t *)(buff_req + 4) = net_mac_h;
    *(uint32_t *)(buff_req + 8) = net_mac_l;

    /* beacon variables initialization */
    last_beacon_gps_time.tv_sec = 0;
    last_beacon_gps_time.tv_nsec = 0;

    /* beacon packet parameters */
    beacon_pkt.tx_mode = ON_GPS; /* send on PPS pulse */
    beacon_pkt.rf_chain = 0; /* antenna A */
    beacon_pkt.rf_power = 14;
    beacon_pkt.modulation = MOD_LORA;
    beacon_pkt.bandwidth = BW_125KHZ;
    beacon_pkt.datarate = DR_LORA_SF9;
    beacon_pkt.coderate = CR_LORA_4_5;
    beacon_pkt.invert_pol = false;
    beacon_pkt.preamble = 10;
    beacon_pkt.no_crc = true;
    beacon_pkt.no_header = true;
    beacon_pkt.size = 17;

    /* fixed bacon fields (little endian) */
    beacon_pkt.payload[0] = 0x0; /* RFU */
    beacon_pkt.payload[1] = 0x0; /* RFU */
    /* 2-5 : time (variable) */
    /* 6-7 : crc1 (variable) */

    /* calculate the latitude and longitude that must be publicly reported */
    field_latitude = (int32_t)((reference_coord.lat / 90.0) * (double)(1<<23));
    if (field_latitude > (int32_t)0x007FFFFF) {
        field_latitude = (int32_t)0x007FFFFF; /* +90 N is represented as 89.99999 N */
    } else if (field_latitude < (int32_t)0xFF800000) {
        field_latitude = (int32_t)0xFF800000;
    }
    field_longitude = 0x00FFFFFF & (int32_t)((reference_coord.lon / 180.0) * (double)(1<<23)); /* +180 = -180 = 0x800000 */

    /* optional beacon fields */
    beacon_pkt.payload[ 8] = field_info;
    beacon_pkt.payload[ 9] = 0xFF &  field_latitude;
    beacon_pkt.payload[10] = 0xFF & (field_latitude >>  8);
    beacon_pkt.payload[11] = 0xFF & (field_latitude >> 16);
    beacon_pkt.payload[12] = 0xFF &  field_longitude;
    beacon_pkt.payload[13] = 0xFF & (field_longitude >>  8);
    beacon_pkt.payload[14] = 0xFF & (field_longitude >> 16);

    /* CRC of the optional beacon fileds */
    field_crc2 = crc16((beacon_pkt.payload + 8), 7);
    beacon_pkt.payload[15] = 0xFF &  field_crc2;
    beacon_pkt.payload[16] = 0xFF & (field_crc2 >>  8);

    /* JIT queue initialization */
    jit_queue_init(&jit_queue);

    while (!exit_sig && !quit_sig) {

        /* auto-quit if the threshold is crossed */
        if ((autoquit_threshold > 0) && (autoquit_cnt >= autoquit_threshold)) {
            exit_sig = true;
            MSG("INFO: [down] the last %u PULL_DATA were not ACKed, exiting application\n", autoquit_threshold);
            break;
        }

        /* generate random token for request */
        token_h = (uint8_t)rand(); /* random token */
        token_l = (uint8_t)rand(); /* random token */
        buff_req[1] = token_h;
        buff_req[2] = token_l;

        /* send PULL request and record time */
        send(sock_down, (void *)buff_req, sizeof buff_req, 0);
        clock_gettime(CLOCK_MONOTONIC, &send_time);
        pthread_mutex_lock(&mx_meas_dw);
        meas_dw_pull_sent += 1;
        pthread_mutex_unlock(&mx_meas_dw);
        req_ack = false;
        autoquit_cnt++;

        /* listen to packets and process them until a new PULL request must be sent */
        recv_time = send_time;
        while ((int)difftimespec(recv_time, send_time) < keepalive_time) {

            /* try to receive a datagram */
            msg_len = recv(sock_down, (void *)buff_down, (sizeof buff_down)-1, 0);
            clock_gettime(CLOCK_MONOTONIC, &recv_time);

            /* Pre-allocate beacon slots in JiT queue, to check downlink collisions */
            beacon_loop = JIT_NUM_BEACON_IN_QUEUE - jit_queue.num_beacon;
            retry = 0;
            while (beacon_loop && (beacon_period != 0)) {
                pthread_mutex_lock(&mx_timeref);
                /* Wait for GPS to be ready before inserting beacons in JiT queue */
                if ((gps_ref_valid == true) && (xtal_correct_ok == true)) {

                    /* compute GPS time for next beacon to come    */
                    /*   LoRaWAN: T = k*beacon_period + TBeaconDelay */
                    /*            with TBeaconDelay = [0:50ms]       */
                    if (last_beacon_gps_time.tv_sec == 0) {
                        /* if no beacon has been queued, get next slot from current UTC time */
                        diff_beacon_time = time_reference_gps.utc.tv_sec % ((time_t)beacon_period);
                        next_beacon_gps_time.tv_sec = time_reference_gps.utc.tv_sec +
                                                        ((time_t)beacon_period - diff_beacon_time);
                    } else {
                        /* if there is already a beacon, take it as reference */
                        next_beacon_gps_time.tv_sec = last_beacon_gps_time.tv_sec + beacon_period;
                    }
                    /* now we can add a beacon_period to the reference to get next beacon GPS time */
                    next_beacon_gps_time.tv_sec += (retry * beacon_period);
                    next_beacon_gps_time.tv_nsec = 0;

                    MSG_DEBUG(DEBUG_BEACON, "GPS-now : %s", ctime(&time_reference_gps.utc.tv_sec));
                    MSG_DEBUG(DEBUG_BEACON, "GPS-last: %s", ctime(&last_beacon_gps_time.tv_sec));
                    MSG_DEBUG(DEBUG_BEACON, "GPS-next: %s", ctime(&next_beacon_gps_time.tv_sec));

                    /* convert UTC time to concentrator time, and set packet counter for JiT trigger */
                    lgw_utc2cnt(time_reference_gps, next_beacon_gps_time, &(beacon_pkt.count_us));
                    pthread_mutex_unlock(&mx_timeref);

                    /* apply frequency correction to beacon TX frequency */
                    pthread_mutex_lock(&mx_xcorr);
                    beacon_pkt.freq_hz = (uint32_t)(xtal_correct * (double)beacon_freq_hz);
                    pthread_mutex_unlock(&mx_xcorr);

                    /* load time in beacon payload */
                    beacon_pkt.payload[2] = 0xFF &  next_beacon_gps_time.tv_sec;
                    beacon_pkt.payload[3] = 0xFF & (next_beacon_gps_time.tv_sec >>  8);
                    beacon_pkt.payload[4] = 0xFF & (next_beacon_gps_time.tv_sec >> 16);
                    beacon_pkt.payload[5] = 0xFF & (next_beacon_gps_time.tv_sec >> 24);

                    /* calculate CRC */
                    field_crc1 = crc16(beacon_pkt.payload, 6); /* CRC for the first 6 bytes */
                    beacon_pkt.payload[6] = 0xFF & field_crc1;
                    beacon_pkt.payload[7] = 0xFF & (field_crc1 >> 8);

                    /* Insert beacon packet in JiT queue */
                    gettimeofday(&current_unix_time, NULL);
                    get_concentrator_time(&current_concentrator_time, current_unix_time);
                    jit_result = jit_enqueue(&jit_queue, &current_concentrator_time, &beacon_pkt, JIT_PKT_TYPE_BEACON);
                    if (jit_result == JIT_ERROR_OK) {
                        /* update stats */
                        pthread_mutex_lock(&mx_meas_dw);
                        meas_nb_beacon_queued += 1;
                        pthread_mutex_unlock(&mx_meas_dw);

                        /* One more beacon in the queue */
                        beacon_loop--;
                        retry = 0;
                        last_beacon_gps_time.tv_sec = next_beacon_gps_time.tv_sec; /* keep this beacon time as reference for next one to be programmed */

                        /* display beacon payload */
                        MSG("--- Beacon queued (count_us=%u) - payload: ---\n", beacon_pkt.count_us);
                        for (i=0; i<beacon_pkt.size; ++i) {
                            MSG("0x%02X", beacon_pkt.payload[i]);
                            if (i%8 == 7) {
                                MSG("\n");
                            } else {
                                MSG(" - ");
                            }
                        }
                        if (i%8 != 0) {
                            MSG("\n");
                        }
                        MSG("--- end of payload ---\n");
                    } else {
                        /* update stats */
                        pthread_mutex_lock(&mx_meas_dw);
                        if (jit_result != JIT_ERROR_COLLISION_BEACON) {
                            meas_nb_beacon_rejected += 1;
                        }
                        pthread_mutex_unlock(&mx_meas_dw);
                        /* In case previous enqueue failed, we retry one period later until it succeeds */
                        /* Note: In case the GPS has been unlocked for a while, there can be lots of retries */
                        /*       to be done from last beacon time to a new valid one */
                        retry++;
                        MSG_DEBUG(DEBUG_BEACON, "--> beacon queuing retry=%d\n", retry);
                    }
                } else {
                    pthread_mutex_unlock(&mx_timeref);
                    break;
                }
            }

            /* if no network message was received, got back to listening sock_down socket */
            if (msg_len == -1) {
                //MSG("WARNING: [down] recv returned %s\n", strerror(errno)); /* too verbose */
                continue;
            }

            /* if the datagram does not respect protocol, just ignore it */
            if ((msg_len < 4) || (buff_down[0] != PROTOCOL_VERSION) || ((buff_down[3] != PKT_PULL_RESP) && (buff_down[3] != PKT_PULL_ACK))) {
                MSG("WARNING: [down] ignoring invalid packet len=%d, protocol_version=%d, id=%d\n",
                        msg_len, buff_down[0], buff_down[3]);
                continue;
            }

            /* if the datagram is an ACK, check token */
            if (buff_down[3] == PKT_PULL_ACK) {
                if ((buff_down[1] == token_h) && (buff_down[2] == token_l)) {
                    if (req_ack) {
                        MSG("INFO: [down] duplicate ACK received :)\n");
                    } else { /* if that packet was not already acknowledged */
                        req_ack = true;
                        autoquit_cnt = 0;
                        pthread_mutex_lock(&mx_meas_dw);
                        meas_dw_ack_rcv += 1;
                        pthread_mutex_unlock(&mx_meas_dw);
                        MSG("INFO: [down] PULL_ACK received in %i ms\n", (int)(1000 * difftimespec(recv_time, send_time)));
                    }
                } else { /* out-of-sync token */
                    MSG("INFO: [down] received out-of-sync ACK\n");
                }
                continue;
            }

            /* the datagram is a PULL_RESP */
            buff_down[msg_len] = 0; /* add string terminator, just to be safe */
            MSG("INFO: [down] PULL_RESP received  - token[%d:%d] :)\n", buff_down[1], buff_down[2]); /* very verbose */
            printf("\nJSON down: %s\n", (char *)(buff_down + 4)); /* DEBUG: display JSON payload */

            /* initialize TX struct and try to parse JSON */
            memset(&txpkt, 0, sizeof txpkt);
            root_val = json_parse_string_with_comments((const char *)(buff_down + 4)); /* JSON offset */
            if (root_val == NULL) {
                MSG("WARNING: [down] invalid JSON, TX aborted\n");
                continue;
            }

            /* look for JSON sub-object 'txpk' */
            txpk_obj = json_object_get_object(json_value_get_object(root_val), "txpk");
            if (txpk_obj == NULL) {
                MSG("WARNING: [down] no \"txpk\" object in JSON, TX aborted\n");
                json_value_free(root_val);
                continue;
            }

            /* Parse "immediate" tag, or target timestamp, or UTC time to be converted by GPS (mandatory) */
            i = json_object_get_boolean(txpk_obj,"imme"); /* can be 1 if true, 0 if false, or -1 if not a JSON boolean */
            if (i == 1) {
                /* TX procedure: send immediately */
                sent_immediate = true;
                downlink_type = JIT_PKT_TYPE_DOWNLINK_CLASS_C;
                MSG("INFO: [down] a packet will be sent in \"immediate\" mode\n");
            } else {
                sent_immediate = false;
                val = json_object_get_value(txpk_obj,"tmst");
                if (val != NULL) {
                    /* TX procedure: send on timestamp value */
                    txpkt.count_us = (uint32_t)json_value_get_number(val);

                    /* Concentrator timestamp is given, we consider it is a Class A downlink */
                    downlink_type = JIT_PKT_TYPE_DOWNLINK_CLASS_A;
                } else {
                    /* TX procedure: send on UTC time (converted to timestamp value) */
                    str = json_object_get_string(txpk_obj, "time");
                    if (str == NULL) {
                        MSG("WARNING: [down] no mandatory \"txpk.tmst\" or \"txpk.time\" objects in JSON, TX aborted\n");
                        json_value_free(root_val);
                        continue;
                    }
                    if (gps_enabled == true) {
                        pthread_mutex_lock(&mx_timeref);
                        if (gps_ref_valid == true) {
                            local_ref = time_reference_gps;
                            pthread_mutex_unlock(&mx_timeref);
                        } else {
                            pthread_mutex_unlock(&mx_timeref);
                            MSG("WARNING: [down] no valid GPS time reference yet, impossible to send packet on specific UTC time, TX aborted\n");
                            json_value_free(root_val);

                            /* send acknoledge datagram to server */
                            send_tx_ack(buff_down[1], buff_down[2], JIT_ERROR_GPS_UNLOCKED);
                            continue;
                        }
                    } else {
                        MSG("WARNING: [down] GPS disabled, impossible to send packet on specific UTC time, TX aborted\n");
                        json_value_free(root_val);

                        /* send acknoledge datagram to server */
                        send_tx_ack(buff_down[1], buff_down[2], JIT_ERROR_GPS_UNLOCKED);
                        continue;
                    }

                    i = sscanf (str, "%4hd-%2hd-%2hdT%2hd:%2hd:%9lf", &x0, &x1, &x2, &x3, &x4, &x5);
                    if (i != 6 ) {
                        MSG("WARNING: [down] \"txpk.time\" must follow ISO 8601 format, TX aborted\n");
                        json_value_free(root_val);
                        continue;
                    }
                    x5 = modf(x5, &x6); /* x6 get the integer part of x5, x5 the fractional part */
                    utc_vector.tm_year = x0 - 1900; /* years since 1900 */
                    utc_vector.tm_mon = x1 - 1; /* months since January */
                    utc_vector.tm_mday = x2; /* day of the month 1-31 */
                    utc_vector.tm_hour = x3; /* hours since midnight */
                    utc_vector.tm_min = x4; /* minutes after the hour */
                    utc_vector.tm_sec = (int)x6;
                    utc_tx.tv_sec = mktime(&utc_vector) - timezone;
                    utc_tx.tv_nsec = (long)(1e9 * x5);

                    /* transform UTC time to timestamp */
                    i = lgw_utc2cnt(local_ref, utc_tx, &(txpkt.count_us));
                    if (i != LGW_GPS_SUCCESS) {
                        MSG("WARNING: [down] could not convert UTC time to timestamp, TX aborted\n");
                        json_value_free(root_val);
                        continue;
                    } else {
                        MSG("INFO: [down] a packet will be sent on timestamp value %u (calculated from UTC time)\n", txpkt.count_us);
                    }

                    /* GPS timestamp is given, we consider it is a Class B downlink */
                    downlink_type = JIT_PKT_TYPE_DOWNLINK_CLASS_B;
                }
            }

            /* Parse "No CRC" flag (optional field) */
            val = json_object_get_value(txpk_obj,"ncrc");
            if (val != NULL) {
                txpkt.no_crc = (bool)json_value_get_boolean(val);
            }

            /* parse target frequency (mandatory) */
            val = json_object_get_value(txpk_obj,"freq");
            if (val == NULL) {
                MSG("WARNING: [down] no mandatory \"txpk.freq\" object in JSON, TX aborted\n");
                json_value_free(root_val);
                continue;
            }
            txpkt.freq_hz = (uint32_t)((double)(1.0e6) * json_value_get_number(val));

            /* parse RF chain used for TX (mandatory) */
            val = json_object_get_value(txpk_obj,"rfch");
            if (val == NULL) {
                MSG("WARNING: [down] no mandatory \"txpk.rfch\" object in JSON, TX aborted\n");
                json_value_free(root_val);
                continue;
            }
            txpkt.rf_chain = (uint8_t)json_value_get_number(val);

            /* parse TX power (optional field) */
            val = json_object_get_value(txpk_obj,"powe");
            if (val != NULL) {
                txpkt.rf_power = (int8_t)json_value_get_number(val) - antenna_gain;
            }

            /* Parse modulation (mandatory) */
            str = json_object_get_string(txpk_obj, "modu");
            if (str == NULL) {
                MSG("WARNING: [down] no mandatory \"txpk.modu\" object in JSON, TX aborted\n");
                json_value_free(root_val);
                continue;
            }
            if (strcmp(str, "LORA") == 0) {
                /* Lora modulation */
                txpkt.modulation = MOD_LORA;

                /* Parse Lora spreading-factor and modulation bandwidth (mandatory) */
                str = json_object_get_string(txpk_obj, "datr");
                if (str == NULL) {
                    MSG("WARNING: [down] no mandatory \"txpk.datr\" object in JSON, TX aborted\n");
                    json_value_free(root_val);
                    continue;
                }
                i = sscanf(str, "SF%2hdBW%3hd", &x0, &x1);
                if (i != 2) {
                    MSG("WARNING: [down] format error in \"txpk.datr\", TX aborted\n");
                    json_value_free(root_val);
                    continue;
                }
                switch (x0) {
                    case  7: txpkt.datarate = DR_LORA_SF7;  break;
                    case  8: txpkt.datarate = DR_LORA_SF8;  break;
                    case  9: txpkt.datarate = DR_LORA_SF9;  break;
                    case 10: txpkt.datarate = DR_LORA_SF10; break;
                    case 11: txpkt.datarate = DR_LORA_SF11; break;
                    case 12: txpkt.datarate = DR_LORA_SF12; break;
                    default:
                        MSG("WARNING: [down] format error in \"txpk.datr\", invalid SF, TX aborted\n");
                        json_value_free(root_val);
                        continue;
                }
                switch (x1) {
                    case 125: txpkt.bandwidth = BW_125KHZ; break;
                    case 250: txpkt.bandwidth = BW_250KHZ; break;
                    case 500: txpkt.bandwidth = BW_500KHZ; break;
                    default:
                        MSG("WARNING: [down] format error in \"txpk.datr\", invalid BW, TX aborted\n");
                        json_value_free(root_val);
                        continue;
                }

                /* Parse ECC coding rate (optional field) */
                str = json_object_get_string(txpk_obj, "codr");
                if (str == NULL) {
                    MSG("WARNING: [down] no mandatory \"txpk.codr\" object in json, TX aborted\n");
                    json_value_free(root_val);
                    continue;
                }
                if      (strcmp(str, "4/5") == 0) txpkt.coderate = CR_LORA_4_5;
                else if (strcmp(str, "4/6") == 0) txpkt.coderate = CR_LORA_4_6;
                else if (strcmp(str, "2/3") == 0) txpkt.coderate = CR_LORA_4_6;
                else if (strcmp(str, "4/7") == 0) txpkt.coderate = CR_LORA_4_7;
                else if (strcmp(str, "4/8") == 0) txpkt.coderate = CR_LORA_4_8;
                else if (strcmp(str, "1/2") == 0) txpkt.coderate = CR_LORA_4_8;
                else {
                    MSG("WARNING: [down] format error in \"txpk.codr\", TX aborted\n");
                    json_value_free(root_val);
                    continue;
                }

                /* Parse signal polarity switch (optional field) */
                val = json_object_get_value(txpk_obj,"ipol");
                if (val != NULL) {
                    txpkt.invert_pol = (bool)json_value_get_boolean(val);
                }

                /* parse Lora preamble length (optional field, optimum min value enforced) */
                val = json_object_get_value(txpk_obj,"prea");
                if (val != NULL) {
                    i = (int)json_value_get_number(val);
                    if (i >= MIN_LORA_PREAMB) {
                        txpkt.preamble = (uint16_t)i;
                    } else {
                        txpkt.preamble = (uint16_t)MIN_LORA_PREAMB;
                    }
                } else {
                    txpkt.preamble = (uint16_t)STD_LORA_PREAMB;
                }

            } else if (strcmp(str, "FSK") == 0) {
                /* FSK modulation */
                txpkt.modulation = MOD_FSK;

                /* parse FSK bitrate (mandatory) */
                val = json_object_get_value(txpk_obj,"datr");
                if (val == NULL) {
                    MSG("WARNING: [down] no mandatory \"txpk.datr\" object in JSON, TX aborted\n");
                    json_value_free(root_val);
                    continue;
                }
                txpkt.datarate = (uint32_t)(json_value_get_number(val));

                /* parse frequency deviation (mandatory) */
                val = json_object_get_value(txpk_obj,"fdev");
                if (val == NULL) {
                    MSG("WARNING: [down] no mandatory \"txpk.fdev\" object in JSON, TX aborted\n");
                    json_value_free(root_val);
                    continue;
                }
                txpkt.f_dev = (uint8_t)(json_value_get_number(val) / 1000.0); /* JSON value in Hz, txpkt.f_dev in kHz */

                /* parse FSK preamble length (optional field, optimum min value enforced) */
                val = json_object_get_value(txpk_obj,"prea");
                if (val != NULL) {
                    i = (int)json_value_get_number(val);
                    if (i >= MIN_FSK_PREAMB) {
                        txpkt.preamble = (uint16_t)i;
                    } else {
                        txpkt.preamble = (uint16_t)MIN_FSK_PREAMB;
                    }
                } else {
                    txpkt.preamble = (uint16_t)STD_FSK_PREAMB;
                }

            } else {
                MSG("WARNING: [down] invalid modulation in \"txpk.modu\", TX aborted\n");
                json_value_free(root_val);
                continue;
            }

            /* Parse payload length (mandatory) */
            val = json_object_get_value(txpk_obj,"size");
            if (val == NULL) {
                MSG("WARNING: [down] no mandatory \"txpk.size\" object in JSON, TX aborted\n");
                json_value_free(root_val);
                continue;
            }
            txpkt.size = (uint16_t)json_value_get_number(val);

            /* Parse payload data (mandatory) */
            str = json_object_get_string(txpk_obj, "data");
            if (str == NULL) {
                MSG("WARNING: [down] no mandatory \"txpk.data\" object in JSON, TX aborted\n");
                json_value_free(root_val);
                continue;
            }
            i = b64_to_bin(str, strlen(str), txpkt.payload, sizeof txpkt.payload);
            if (i != txpkt.size) {
                MSG("WARNING: [down] mismatch between .size and .data size once converter to binary\n");
            }

            /* free the JSON parse tree from memory */
            json_value_free(root_val);

            /* select TX mode */
            if (sent_immediate) {
                txpkt.tx_mode = IMMEDIATE;
            } else {
                txpkt.tx_mode = TIMESTAMPED;
            }

            /* record measurement data */
            pthread_mutex_lock(&mx_meas_dw);
            meas_dw_dgram_rcv += 1; /* count only datagrams with no JSON errors */
            meas_dw_network_byte += msg_len; /* meas_dw_network_byte */
            meas_dw_payload_byte += txpkt.size;
            pthread_mutex_unlock(&mx_meas_dw);

            /* check TX parameter before trying to queue packet */
            jit_result = JIT_ERROR_OK;
            if ((txpkt.freq_hz < tx_freq_min[txpkt.rf_chain]) || (txpkt.freq_hz > tx_freq_max[txpkt.rf_chain])) {
                jit_result = JIT_ERROR_TX_FREQ;
                MSG("ERROR: Packet REJECTED, unsupported frequency - %u (min:%u,max:%u)\n", txpkt.freq_hz, tx_freq_min[txpkt.rf_chain], tx_freq_max[txpkt.rf_chain]);
            }
            if (jit_result == JIT_ERROR_OK) {
                for (i=0; i<txlut.size; i++) {
                    if (txlut.lut[i].rf_power == txpkt.rf_power) {
                        /* this RF power is supported, we can continue */
                        break;
                    }
                }
                if (i == txlut.size) {
                    /* this RF power is not supported */
                    jit_result = JIT_ERROR_TX_POWER;
                    MSG("ERROR: Packet REJECTED, unsupported RF power for TX - %d\n", txpkt.rf_power);
                }
            }

            /* insert packet to be sent into JIT queue */
            if (jit_result == JIT_ERROR_OK) {
                gettimeofday(&current_unix_time, NULL);
                get_concentrator_time(&current_concentrator_time, current_unix_time);
                jit_result = jit_enqueue(&jit_queue, &current_concentrator_time, &txpkt, downlink_type);
                if (jit_result != JIT_ERROR_OK) {
                    printf("ERROR: Packet REJECTED (jit error=%d)\n", jit_result);
                }
                pthread_mutex_lock(&mx_meas_dw);
                meas_nb_tx_requested += 1;
                pthread_mutex_unlock(&mx_meas_dw);
            }

            /* Send acknoledge datagram to server */
            send_tx_ack(buff_down[1], buff_down[2], jit_result);
        }
    }
    MSG("\nINFO: End of downstream thread\n");
}

void print_tx_status(uint8_t tx_status) {
    switch (tx_status) {
        case TX_OFF:
            MSG("INFO: [jit] lgw_status returned TX_OFF\n");
            break;
        case TX_FREE:
            MSG("INFO: [jit] lgw_status returned TX_FREE\n");
            break;
        case TX_EMITTING:
            MSG("INFO: [jit] lgw_status returned TX_EMITTING\n");
            break;
        case TX_SCHEDULED:
            MSG("INFO: [jit] lgw_status returned TX_SCHEDULED\n");
            break;
        default:
            MSG("INFO: [jit] lgw_status returned UNKNOWN (%d)\n", tx_status);
            break;
    }
}


/* -------------------------------------------------------------------------- */
/* --- THREAD 3: CHECKING PACKETS TO BE SENT FROM JIT QUEUE AND SEND THEM --- */

void thread_jit(void) {
    int result = LGW_HAL_SUCCESS;
    struct lgw_pkt_tx_s pkt;
    int pkt_index = -1;
    struct timeval current_unix_time;
    struct timeval current_concentrator_time;
    enum jit_error_e jit_result;
    enum jit_pkt_type_e pkt_type;
    uint8_t tx_status;
    uint8_t txstat_pkt[MAX_NUM_OF_HEX_BYTES];
    int rdlen;
    while (!exit_sig && !quit_sig) {
        wait_ms(10);

        /* transfer data and metadata to the concentrator, and schedule TX */
        gettimeofday(&current_unix_time, NULL);
        get_concentrator_time(&current_concentrator_time, current_unix_time);
        jit_result = jit_peek(&jit_queue, &current_concentrator_time, &pkt_index);
        if (jit_result == JIT_ERROR_OK) {
            if (pkt_index > -1) {
                jit_result = jit_dequeue(&jit_queue, pkt_index, &pkt, &pkt_type);
                if (jit_result == JIT_ERROR_OK) {
                    /* update beacon stats */
                    if (pkt_type == JIT_PKT_TYPE_BEACON) {
                        pthread_mutex_lock(&mx_meas_dw);
                        meas_nb_beacon_sent += 1;
                        pthread_mutex_unlock(&mx_meas_dw);
                    }

                    /* check if concentrator is free for sending new packet */
                    //result = lgw_status(TX_STATUS, &tx_status);  // TO-DO here, need to implement the lgw_status function that returns what kind of state the concentrator is
                   pthread_mutex_lock(&mx_concent);
		   result=write_to_serial(_fd, serial_TXSTAT_cmd, sizeof serial_TXSTAT_cmd);
			rdlen=0;   
			while(rdlen==0){
				rdlen=read_from_serial(_fd, 1, txstat_pkt);		
		   	}
			if(rdlen>0 && txstat_pkt[1]==0x39){
			 //txstat completely read.
			  tx_status=txstat_pkt[4];
			result=LGW_HAL_SUCCESS;
			printf("Received TXSTAT packet: ");
			for(int x=0; x< 7; x++){
			printf("0x%x ", txstat_pkt[x]);
			}
			printf("\n");
			}else{
			  result=LGW_HAL_ERROR;
			}	
		   pthread_mutex_lock(&mx_concent); 

		    if (result == LGW_HAL_ERROR) {
                        MSG("WARNING: [jit] lgw_status failed\n");
                    } else {
                        if (tx_status == TX_EMITTING) {
                            MSG("ERROR: concentrator is currently emitting\n");
                            print_tx_status(tx_status);
                            continue;
                        } else if (tx_status == TX_SCHEDULED) {
                            MSG("WARNING: a downlink was already scheduled, overwritting it...\n");
                            print_tx_status(tx_status);
                        } else {
                            /* Nothing to do */
                        }
                    }

                    /* send packet to concentrator */
                    pthread_mutex_lock(&mx_concent); /* may have to wait for a fetch to finish */
                    //result = lgw_send(pkt);// TO-DO need to convert the struct pkt into hex bytes and write to serial port.
                    uint8_t byte_to_write[4 + 24 + 128 + 2];
		    int hex_size= 0;
		    hex_size=to_hex_data(&pkt, byte_to_write);
		    result=write_to_serial(_fd, byte_to_write, hex_size);
		    pthread_mutex_unlock(&mx_concent); /* free concentrator ASAP */
                    if (result == LGW_HAL_ERROR) {
                        pthread_mutex_lock(&mx_meas_dw);
                        meas_nb_tx_fail += 1;
                        pthread_mutex_unlock(&mx_meas_dw);
                        MSG("WARNING: [jit] lgw_send failed\n");
                        continue;
                    } else {
                        pthread_mutex_lock(&mx_meas_dw);
                        meas_nb_tx_ok += 1;
                        pthread_mutex_unlock(&mx_meas_dw);
                        MSG_DEBUG(DEBUG_PKT_FWD, "lgw_send done: count_us=%u\n", pkt.count_us);
                    }
                } else {
                    MSG("ERROR: jit_dequeue failed with %d\n", jit_result);
                }
            }
        } else if (jit_result == JIT_ERROR_EMPTY) {
            /* Do nothing, it can happen */
        } else {
            MSG("ERROR: jit_peek failed with %d\n", jit_result);
        }
    }
}

/* -------------------------------------------------------------------------- */
/* --- THREAD 4: PARSE GPS MESSAGE AND KEEP GATEWAY IN SYNC ----------------- */

void thread_gps(void) {
    int i;

    /* serial variables */
    char serial_buff[128]; /* buffer to receive GPS data */
    ssize_t nb_char;

    /* variables for PPM pulse GPS synchronization */
    enum gps_msg latest_msg; /* keep track of latest NMEA message parsed */
    struct timespec utc_time; /* UTC time associated with PPS pulse */
    uint32_t trig_tstamp; /* concentrator timestamp associated with PPM pulse */

    /* position variable */
    struct coord_s coord;
    struct coord_s gpserr;

    /* initialize some variables before loop */
    memset(serial_buff, 0, sizeof serial_buff);

    while (!exit_sig && !quit_sig) {
        /* blocking canonical read on serial port */
        nb_char = read(gps_tty_fd, serial_buff, sizeof(serial_buff)-1);
        if (nb_char <= 0) {
            MSG("WARNING: [gps] read() returned value <= 0\n");
            continue;
        } else {
            serial_buff[nb_char] = 0; /* add null terminator, just to be sure */
        }

        /* parse the received NMEA */
        latest_msg = lgw_parse_nmea(serial_buff, sizeof(serial_buff));

        if (latest_msg == NMEA_RMC) { /* trigger sync only on RMC frames */

            /* get UTC time for synchronization */
            i = lgw_gps_get(&utc_time, NULL, NULL);
            if (i != LGW_GPS_SUCCESS) {
                MSG("WARNING: [gps] could not get UTC time from GPS\n");
                continue;
            }

            /* get timestamp captured on PPM pulse  */
            pthread_mutex_lock(&mx_concent);
            i = lgw_get_trigcnt(&trig_tstamp);
            pthread_mutex_unlock(&mx_concent);
            if (i != LGW_HAL_SUCCESS) {
                MSG("WARNING: [gps] failed to read concentrator timestamp\n");
                continue;
            }

            /* try to update time reference with the new UTC & timestamp */
            pthread_mutex_lock(&mx_timeref);
            i = lgw_gps_sync(&time_reference_gps, trig_tstamp, utc_time);
            pthread_mutex_unlock(&mx_timeref);
            if (i != LGW_GPS_SUCCESS) {
                MSG("WARNING: [gps] GPS out of sync, keeping previous time reference\n");
                continue;
            }

            /* update gateway coordinates */
            i = lgw_gps_get(NULL, &coord, &gpserr);
            pthread_mutex_lock(&mx_meas_gps);
            if (i == LGW_GPS_SUCCESS) {
                gps_coord_valid = true;
                meas_gps_coord = coord;
                meas_gps_err = gpserr;
                // TODO: report other GPS statistics (typ. signal quality & integrity)
            } else {
                gps_coord_valid = false;
            }
            pthread_mutex_unlock(&mx_meas_gps);
        }
    }
    MSG("\nINFO: End of GPS thread\n");
}

/* -------------------------------------------------------------------------- */
/* --- THREAD 5: CHECK TIME REFERENCE AND CALCULATE XTAL CORRECTION --------- */

void thread_valid(void) {

    /* GPS reference validation variables */
    long gps_ref_age = 0;
    bool ref_valid_local = false;
    double xtal_err_cpy;

    /* variables for XTAL correction averaging */
    unsigned init_cpt = 0;
    double init_acc = 0.0;
    double x;

    /* correction debug */
    // FILE * log_file = NULL;
    // time_t now_time;
    // char log_name[64];

    /* initialization */
    // time(&now_time);
    // strftime(log_name,sizeof log_name,"xtal_err_%Y%m%dT%H%M%SZ.csv",localtime(&now_time));
    // log_file = fopen(log_name, "w");
    // setbuf(log_file, NULL);
    // fprintf(log_file,"\"xtal_correct\",\"XERR_INIT_AVG %u XERR_FILT_COEF %u\"\n", XERR_INIT_AVG, XERR_FILT_COEF); // DEBUG

    /* main loop task */
    while (!exit_sig && !quit_sig) {
        wait_ms(1000);

        /* calculate when the time reference was last updated */
        pthread_mutex_lock(&mx_timeref);
        gps_ref_age = (long)difftime(time(NULL), time_reference_gps.systime);
        if ((gps_ref_age >= 0) && (gps_ref_age <= GPS_REF_MAX_AGE)) {
            /* time ref is ok, validate and  */
            gps_ref_valid = true;
            ref_valid_local = true;
            xtal_err_cpy = time_reference_gps.xtal_err;
        } else {
            /* time ref is too old, invalidate */
            gps_ref_valid = false;
            ref_valid_local = false;
        }
        pthread_mutex_unlock(&mx_timeref);

        /* manage XTAL correction */
        if (ref_valid_local == false) {
            /* couldn't sync, or sync too old -> invalidate XTAL correction */
            pthread_mutex_lock(&mx_xcorr);
            xtal_correct_ok = false;
            xtal_correct = 1.0;
            pthread_mutex_unlock(&mx_xcorr);
            init_cpt = 0;
            init_acc = 0.0;
        } else {
            if (init_cpt < XERR_INIT_AVG) {
                /* initial accumulation */
                init_acc += xtal_err_cpy;
                ++init_cpt;
            } else if (init_cpt == XERR_INIT_AVG) {
                /* initial average calculation */
                pthread_mutex_lock(&mx_xcorr);
                xtal_correct = (double)(XERR_INIT_AVG) / init_acc;
                xtal_correct_ok = true;
                pthread_mutex_unlock(&mx_xcorr);
                ++init_cpt;
                // fprintf(log_file,"%.18lf,\"average\"\n", xtal_correct); // DEBUG
            } else {
                /* tracking with low-pass filter */
                x = 1 / xtal_err_cpy;
                pthread_mutex_lock(&mx_xcorr);
                xtal_correct = xtal_correct - xtal_correct/XERR_FILT_COEF + x/XERR_FILT_COEF;
                pthread_mutex_unlock(&mx_xcorr);
                // fprintf(log_file,"%.18lf,\"track\"\n", xtal_correct); // DEBUG
            }
        }
        // printf("Time ref: %s, XTAL correct: %s (%.15lf)\n", ref_valid_local?"valid":"invalid", xtal_correct_ok?"valid":"invalid", xtal_correct); // DEBUG
    }
    MSG("\nINFO: End of validation thread\n");
}

/* -------------------------------------------------------------------------------------- */
/* --- THREAD 6: CHECK IF PACKETS ARE AVAILABLE IN THE RECEIVE QUEUE THEN SEND ACK------- */

void thread_ack(void){
	

	while (!exit_sig && !quit_sig) {
	wait_ms(10000);
	if(serial_is_opened==TRUE){
	//send RXSTAT command
	//uint8_t buf[1024];
	//int rdlen=0;
	//uint8_t rxstat=0xff; 
	int i= write_to_serial(_fd, serial_getrxstat_cmd, sizeof serial_getrxstat_cmd);
	if(i != LGW_HAL_SUCCESS){
		MSG("Write get RXSTAT command failed\n");
	}
/*	//read from serial until the stat is read
	int recvd_rxstat=FALSE;
		
		rdlen=read_from_serial(_fd,buf,sizeof buf);
		if(buf[CMD_BYTE_INDEX] == 0x43){
			// store the rxstatus into a variable
			rxstat=buf[RXSTAT_BYTE_INDEX];
		}else{
			continue;
		}
		if(rxstat != 0x00){
		//if the buf is not 
		}
	
	
	//see if ACK is required 
	//Send ACK when necessary.

*/
	}
	}

}

/* --- EOF ------------------------------------------------------------------ */
