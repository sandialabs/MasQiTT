// Linux
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>	// debugging
#include <string.h>
#include <errno.h>

// MasQiTT
#include "masqlib.h"
#include "kms_msg.h"

// TLS support
#include "tls.h"

static int	verbose = 0;

static char	*_protoid = KMS_PROTO_ID;

extern void
KMS_pkt_dump(unsigned char *p, size_t len, char *hdr, int show);
extern void
KMS_pkt_dump_req(KMS_req_t *req, char *hdr);
extern void
KMS_pkt_dump_time(KMS_time_t *time, char *hdr);
extern void
KMS_pkt_dump_data(KMS_data_t *data, char *hdr);

void
usage(char *cmd, int exitval)
{
    fprintf(stderr,
	    "usage: %s [-s server] [-p port]\n"
	    "       %s -h\n\n"
	    "where:\n"
	    "    -s\tserver, name or IPv4/v6 address (default: localhost)\n"
	    "    -p\tserver port (default: %d)\n"
	    "    -v\tincrease verbosity\n"
	    "    -h\tthis help message\n",
	    cmd, cmd, MASQ_KMS_DFLT_PORT);
    exit(exitval);
}

static unsigned char	_send_buf[1024];
static size_t		_send_len;
static unsigned char	_recv_buf[8 * 1024];	// overkill

#define	EXP_THIS	0
#define	EXP_PREV	1

static char	_kms_server[80] = { 0 };
static int	_kms_port = 0;

static void
set_kms_server(char *server, int port)
{
    strncpy(_kms_server, server, sizeof(_kms_server));
    _kms_port = port;
    if (verbose) {
	printf("%s(%s, %d)\n", __FUNCTION__,
	       _kms_server, _kms_port); fflush(stdout);
    }
}

#define	_pem_file(x, t)	"certs/" x t ".pem"
#define	_cert_file(x)	_pem_file(x, "-crt")
#define	_key_file(x)	_pem_file(x, "-key")
static char	*_ca_file  = _pem_file("ca", "-crt");

struct {
    char	*client_id;
    char	*what;		// topic name or subscription
    char	*cert_file;
    char	*key_file;
} _clients[] = {
    // publishers
#define	PUB_TL	0
    { "TankLevel00037a1", "tank/level",
      _cert_file("TankLevel00037a1"), _key_file("TankLevel00037a1") },
#define	PUB_TT	1
    { "TankTemp000a0032", "tank/temp",
      _cert_file("TankTemp000a0032"), _key_file("TankTemp000a0032") },
#define	PUB_PT	2
    { "PumpTemp007c0480", "pump/temp",
      _cert_file("PumpTemp007c0480"), _key_file("PumpTemp007c0480") },
#define	PUB_XX	3
    { "RogueClient00001", "rogue",
      _cert_file("RogueClient00001"), _key_file("RogueClient00001") },
    // subscribers
#define	SUB_DP	4	// display panel
    { "Display999999997", "#",
      _cert_file("Display999999997"), _key_file("Display999999997") },
#define	SUB_PC	5	// pump controller
    { "PumpUnit00006177", "tank/level pump/temp",
      _cert_file("PumpUnit00006177"), _key_file("PumpUnit00006177") }
};
#define	NUM_CLIENTS	((sizeof(_clients)/sizeof(_clients[0])))

static char	*_msg_types[] = {
    NULL,
    "TIMEREQ", "TIMERESP",
    "PUBREQ",  "PUBRESP",
    "PRIVREQ", "PRIVRESP"
};

static void
send_to_kms(char *certfile, char *keyfile,
	    unsigned char *msg,   size_t len,
	    unsigned char **resp, size_t *resplen)
{
    WOLFSSL_CTX		*ctx    = NULL;
    WOLFSSL		*ssl    = NULL;
    int			sockfd  = -1;
    struct sockaddr_in	kms_inetaddr;
    int			ret     = 0;
    int			err     = 0;
    int			saverr  = 0;
    char		buffer[WOLFSSL_MAX_ERROR_SZ];
    int			sleepcount = 0;

    printf("%s(%s, %s, %lu)\n",
	   __FUNCTION__, _kms_server, _msg_types[msg[0]], len);
    fflush(stdout);

    if (0 == strlen(_kms_server)) {
	printf("call set_kms_server() before first call to %s()\n",
	       __FUNCTION__);
	exit(1);
    }

    if (len > sizeof(_send_buf)) {
	printf("%s: ERROR: too much data (%lu bytes vs. %lu avail)\n",
	       __FUNCTION__, len, sizeof(_send_buf)); fflush(stdout);
	return;
    }
    if ((NULL == msg) || (NULL == resp) || (NULL == resplen)) {
	printf("%s: NULL arg received\n", __FUNCTION__); fflush(stdout);
	return;
    }

    *resp = NULL;
    *resplen = 0;

    _send_len = len;
    memcpy((void *) _send_buf, (void *) msg, len);

    // here comes the TLS
    if (WOLFSSL_SUCCESS != (ret = wolfSSL_Init())) {
	printf("wolfSSL_Init() failed (%d)\n", ret); fflush(stdout);
	goto send_cleanup;
    }

    // create and initialize WOLFSSL_CTX
    if (NULL == (ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()))) {
	printf("wolfSSL_CTX_new() failed\n"); fflush(stdout);
	goto send_cleanup;
    }

    // load trusted certificates
    if (WOLFSSL_SUCCESS !=
	(ret = wolfSSL_CTX_load_verify_locations(ctx, _ca_file, 0))) {
	printf("%s: ERROR loading ca file \"%s\" (%d)\n",
	       __FUNCTION__, _ca_file, ret);
	fflush(stdout);
	goto send_cleanup;
    }

    // client certificate
    if (WOLFSSL_SUCCESS !=
	(ret = wolfSSL_CTX_use_certificate_file(ctx, certfile,
						WOLFSSL_FILETYPE_PEM))) {
	printf("%s: ERROR Can not load cert file \"%s\" (%d)\n",
	       __FUNCTION__, certfile, ret);
	fflush(stdout);
	goto send_cleanup;
    }

    // client key
    if (WOLFSSL_SUCCESS !=
	(ret = wolfSSL_CTX_use_PrivateKey_file(ctx, keyfile,
					       WOLFSSL_FILETYPE_PEM))) {
	printf("%s: ERROR Can not load key file \"%s\" (%d)\n",
	       __FUNCTION__, keyfile, ret);
	fflush(stdout);
	goto send_cleanup;
    }

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
	printf("socket() failed, errno = %s\n", strerror(errno)); fflush(stdout);
	goto send_cleanup;
    }

    // fill in KMS address
    memset(&kms_inetaddr, 0, sizeof(kms_inetaddr));
    kms_inetaddr.sin_family = AF_INET;
    if (! inet_pton(AF_INET, _kms_server,
		    (struct in_addr *) &kms_inetaddr.sin_addr)) {
	printf("net> Bad addr %s\n", _kms_server); fflush(stdout);
	goto send_cleanup;
    }
    kms_inetaddr.sin_port = htons(_kms_port);

    // connect to KMS, may take a couple of tries if KMS hasn't reset its socket
    do {
	if (connect(sockfd, (struct sockaddr *) &kms_inetaddr,
		    sizeof(kms_inetaddr)) == -1) {
	    saverr = errno;
	    if (ECONNREFUSED == saverr) {
		printf("connect() refused, napping\n"); fflush(stdout);
		sleepcount++;
		usleep(271828);
	    } else {
		printf("connect() failed, errno = %s\n", strerror(errno));
		fflush(stdout);
		goto send_cleanup;
	    }
	}
    } while ((ECONNREFUSED == saverr) && (sleepcount < 10));

    // create WOLFSSL object
    if (NULL == (ssl = wolfSSL_new(ctx))) {
	printf("wolfSSL_new() failed\n"); fflush(stdout);
	goto send_cleanup;
    }

    // attach wolfSSL to the socket
    if (wolfSSL_set_fd(ssl, sockfd) != WOLFSSL_SUCCESS) {
	printf("%s: ERROR wolfSSL_set_fd() failed\n", __FUNCTION__);
	fflush(stdout);
	goto send_cleanup;
    }

    // send the request
    //do {
    err = 0; /* reset error */
    ret = wolfSSL_write(ssl, msg, len);
    if (ret <= 0) {
	err = wolfSSL_get_error(ssl, 0);
	//}
	//} while (WC_PENDING_E == err);

	//if (ret != len) {
	printf("%s: SSL_write msg error %d, %s\n", __FUNCTION__, err,
	       wolfSSL_ERR_error_string(err, buffer)); fflush(stdout);
	goto send_cleanup;
    }

    // read the response
    //do {
    err = 0; /* reset error */
    ret = wolfSSL_read(ssl, _recv_buf, sizeof(_recv_buf));
    if (ret <= 0) {
	err = wolfSSL_get_error(ssl, 0);
	//}
	//} while (WC_PENDING_E == err);
    
	//if (ret <= 0) {
	printf("%s: SSL_read msg error %d, %s\n", __FUNCTION__, err,
	       wolfSSL_ERR_error_string(err, buffer)); fflush(stdout);
	goto send_cleanup;
    }

    *resp = _recv_buf;
    *resplen = ret;
    printf("%s() returning %ld bytes\n", __FUNCTION__, *resplen);
    fflush(stdout);
    
 send_cleanup:
    if (ssl) wolfSSL_free(ssl);
    if (ctx) wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    if (sockfd >= 0) close(sockfd);
}

static unsigned char	_req_buf[KMS_req_num_fields][MASQ_MAXTOPIC_LEN];
static unsigned char	_time_buf[KMS_time_num_fields][MASQ_EXPDATE_LEN+1];
static unsigned char	_data_buf[KMS_data_num_fields][1024];

int
main(int argc, char *argv[])
{
    int			opt;
    int			port = MASQ_KMS_DFLT_PORT;
    char		*server_arg = NULL;

    KMS_req_t		my_req;
    KMS_time_t		my_time;
    KMS_data_t		my_data;
    uint8_t		reason;
    int			i;
    int			rc;
    unsigned char	*resp;
    size_t		resp_len;
    char		*messagep;
    char		msgbuf[80];

    unsigned char	expdate[MASQ_EXPDATE_LEN+1] = { 0 };

    extern char		*optarg;
    extern int		optind;

    while (-1 != (opt = getopt(argc, argv, "s:p:vh"))) {
	
	switch (opt) {
	    
	case 's':
	    server_arg = optarg;
	    break;
	    
	case 'p':
	    // listening port
	    port = atoi(optarg);
	    break;

	case 'v':
	    verbose++;
	    break;
	    
	case 'h':
	case '?':
	    usage(argv[0], opt != 'h');
	}
    }

    set_kms_server((server_arg ? server_arg : "127.0.0.1"), port);
    wolfSSL_Init();

    printf("\n------------- TIMEREQ (pub)\n\n");

    // set up my packet structs
    for (i = 0; i < KMS_req_num_fields; i++) {
	my_req.req[i].ptr = NULL;
    }

    i = KMS_req_proto_id;
    my_req.req[i].ptr = _req_buf[i];
    strncpy(my_req.req[i].ptr, _protoid, sizeof(_req_buf[i]));
    i = KMS_req_client_id;
    my_req.req[i].ptr = _req_buf[i];
    strncpy(my_req.req[i].ptr, _clients[PUB_TL].client_id, sizeof(_req_buf[i]));

    KMS_pkt_dump_req(&my_req, "KMS_make_timereq");

    _send_len = sizeof(_send_buf);
    rc = KMS_make_timereq(&my_req, _send_buf, &_send_len);

    if (KMS_ERR_SUCCESS == rc) {
	KMS_pkt_dump(_send_buf, _send_len, "TIMEREQ packet", 1);
    } else {
	printf("Got error %s\n", KMS_error_string(rc));
    }

    send_to_kms(_clients[PUB_TL].cert_file, _clients[PUB_TL].key_file,
		_send_buf, _send_len, &resp, &resp_len);

    if (0 == resp_len) {
	printf("Error sending request\n");
    } else {
	if (verbose > 1) {
	    KMS_pkt_dump(resp, resp_len, "from KMS", 1);
	}
	for (i = 0; i < KMS_time_num_fields; i++) {
	    my_time.time[i].ptr = _time_buf[i];
	    my_time.time[i].len = sizeof(_time_buf[i]);
	}
	KMS_pkt_dump(resp, resp_len, "TIMERESP", 1);
	messagep = NULL;
	rc = KMS_parse_timeresp(resp, resp_len, &reason, &my_time, &messagep);

	msgbuf[0] = '\0';
	if (messagep) {
	    snprintf(msgbuf, sizeof(msgbuf), "     [%s]\n", messagep);
	}

	if (KMS_ERR_SUCCESS == rc) {
	    if (KMS_REASON_SUCCESS == reason) {
		KMS_pkt_dump_time(&my_time, "KMS_parse_timeresp");
		if (strlen(my_time.time[KMS_time_exp_date].ptr)) {
		    // save expdate for later
		    strncpy(expdate, my_time.time[KMS_time_exp_date].ptr,
			    sizeof(expdate));
		}
	    } else {
		printf("==== KMS_parse_timeresp\n> %s\n%s",
		       KMS_reason_string(reason), msgbuf);
	    }
	} else {
	    printf("Got error %s\n", KMS_error_string(rc));
	}
	fflush(stdout);

	if (messagep) free(messagep);
    }

    //return 0;
    printf("going on ...\n"); fflush(stdout);

    // set up my packet structs
    for (i = 0; i < KMS_req_num_fields; i++) {
	my_req.req[i].ptr = NULL;
    }

    printf("\n------------- TIMEREQ (sub)\n\n");

    i = KMS_req_proto_id;
    my_req.req[i].ptr = _req_buf[i];
    strncpy(my_req.req[i].ptr, _protoid, sizeof(_req_buf[i]));
    i = KMS_req_client_id;
    my_req.req[i].ptr = _req_buf[i];
    strncpy(my_req.req[i].ptr, _clients[SUB_DP].client_id, sizeof(_req_buf[i]));

    KMS_pkt_dump_req(&my_req, "KMS_make_timereq");

    _send_len = sizeof(_send_buf);
    rc = KMS_make_timereq(&my_req, _send_buf, &_send_len);

    if (KMS_ERR_SUCCESS == rc) {
	KMS_pkt_dump(_send_buf, _send_len, "TIMEREQ packet", 1);
    } else {
	printf("Got error %s\n", KMS_error_string(rc));
    }

    send_to_kms(_clients[SUB_DP].cert_file, _clients[SUB_DP].key_file,
		_send_buf, _send_len, &resp, &resp_len);

    if (0 == resp_len) {
	printf("Error sending request\n");
    } else {
	if (verbose > 1) {
	    KMS_pkt_dump(resp, resp_len, "from KMS", 1);
	}
	for (i = 0; i < KMS_time_num_fields; i++) {
	    my_time.time[i].ptr = _time_buf[i];
	    my_time.time[i].len = sizeof(_time_buf[i]);
	}
	KMS_pkt_dump(resp, resp_len, "TIMERESP", 1);
	messagep = NULL;
	rc = KMS_parse_timeresp(resp, resp_len, &reason, &my_time, &messagep);

	msgbuf[0] = '\0';
	if (messagep) {
	    snprintf(msgbuf, sizeof(msgbuf), "     [%s]\n", messagep);
	}

	if (KMS_ERR_SUCCESS == rc) {
	    if (KMS_REASON_SUCCESS == reason) {
		KMS_pkt_dump_time(&my_time, "KMS_parse_timeresp");
		if (strlen(my_time.time[KMS_time_exp_date].ptr)) {
		    // save expdate for later
		    strncpy(expdate, my_time.time[KMS_time_exp_date].ptr,
			    sizeof(expdate));
		}
	    } else {
		printf("==== KMS_parse_timeresp\n> %s\n%s",
		       KMS_reason_string(reason), msgbuf);
	    }
	} else {
	    printf("Got error %s\n", KMS_error_string(rc));
	}
	fflush(stdout);
    }

    // set up my packet structs
    for (i = 0; i < KMS_req_num_fields; i++) {
	my_req.req[i].ptr = NULL;
    }

    printf("\n------------- TIMEREQ (rogue)\n\n");

    i = KMS_req_proto_id;
    my_req.req[i].ptr = _req_buf[i];
    strncpy(my_req.req[i].ptr, _protoid, sizeof(_req_buf[i]));
    i = KMS_req_client_id;
    my_req.req[i].ptr = _req_buf[i];
    strncpy(my_req.req[i].ptr, _clients[PUB_XX].client_id, sizeof(_req_buf[i]));

    KMS_pkt_dump_req(&my_req, "KMS_make_timereq");

    _send_len = sizeof(_send_buf);
    rc = KMS_make_timereq(&my_req, _send_buf, &_send_len);

    if (KMS_ERR_SUCCESS == rc) {
	KMS_pkt_dump(_send_buf, _send_len, "TIMEREQ packet", 1);
    } else {
	printf("Got error %s\n", KMS_error_string(rc));
    }

    send_to_kms(_clients[PUB_XX].cert_file, _clients[PUB_XX].key_file,
		_send_buf, _send_len, &resp, &resp_len);

    if (0 == resp_len) {
	printf("Error sending request\n");
    } else {
	if (verbose > 1) {
	    KMS_pkt_dump(resp, resp_len, "from KMS", 1);
	}
	for (i = 0; i < KMS_time_num_fields; i++) {
	    my_time.time[i].ptr = _time_buf[i];
	    my_time.time[i].len = sizeof(_time_buf[i]);
	}
	KMS_pkt_dump(resp, resp_len, "TIMERESP", 1);
	messagep = NULL;
	rc = KMS_parse_timeresp(resp, resp_len, &reason, &my_time, &messagep);

	msgbuf[0] = '\0';
	if (messagep) {
	    snprintf(msgbuf, sizeof(msgbuf), "     [%s]\n", messagep);
	}

	if (KMS_ERR_SUCCESS == rc) {
	    if (KMS_REASON_SUCCESS == reason) {
		KMS_pkt_dump_time(&my_time, "KMS_parse_timeresp");
		if (strlen(my_time.time[KMS_time_exp_date].ptr)) {
		    // save expdate for later
		    strncpy(expdate, my_time.time[KMS_time_exp_date].ptr,
			    sizeof(expdate));
		}
	    } else {
		printf("==== KMS_parse_timeresp\n> %s\n%s",
		       KMS_reason_string(reason), msgbuf);
	    }
	} else {
	    printf("Got error %s\n", KMS_error_string(rc));
	}
	fflush(stdout);
	
	if (messagep) free(messagep);
    }

    printf("\n------------- PUBREQ\n\n");

    // set up my packet structs
    for (i = 0; i < KMS_req_num_fields; i++) {
	my_req.req[i].ptr = NULL;
    }

    i = KMS_req_proto_id;
    my_req.req[i].ptr = _req_buf[i];
    strncpy(my_req.req[i].ptr, _protoid, sizeof(_req_buf[i]));
    i = KMS_req_client_id;
    my_req.req[i].ptr = _req_buf[i];
    strncpy(my_req.req[i].ptr, _clients[PUB_TL].client_id, sizeof(_req_buf[i]));

    KMS_pkt_dump_req(&my_req, "KMS_make_pubreq");

    _send_len = sizeof(_send_buf);
    rc = KMS_make_pubreq(&my_req, _send_buf, &_send_len);

    if (KMS_ERR_SUCCESS == rc) {
	KMS_pkt_dump(_send_buf, _send_len, "PUBREQ packet", 1);
    } else {
	printf("Got error %s\n", KMS_error_string(rc));
    }

    send_to_kms(_clients[PUB_TL].cert_file, _clients[PUB_TL].key_file,
		_send_buf, _send_len, &resp, &resp_len);

    if (0 == resp_len) {
	printf("Error sending request\n");
    } else {
	if (verbose > 1) {
	    KMS_pkt_dump(resp, resp_len, "from KMS", 1);
	}
	for (i = 0; i < KMS_data_num_fields; i++) {
	    my_data.data[i].ptr = _data_buf[i];
	    my_data.data[i].len = sizeof(_data_buf[i]);
	}
	KMS_pkt_dump(resp, resp_len, "PUBRESP", 1);
	messagep = NULL;
	rc = KMS_parse_pubresp(resp, resp_len, &reason, &my_data, &messagep);

	msgbuf[0] = '\0';
	if (messagep) {
	    snprintf(msgbuf, sizeof(msgbuf), "     [%s]\n", messagep);
	}

	if (KMS_ERR_SUCCESS == rc) {
	    if (KMS_REASON_SUCCESS == reason) {
		KMS_pkt_dump_data(&my_data, "KMS_parse_pubresp");
	    } else {
		printf("==== KMS_parse_pubresp\n> %s\n%s",
		       KMS_reason_string(reason), msgbuf);
	    }
	} else {
	    printf("Got error %s\n", KMS_error_string(rc));
	}
	fflush(stdout);
	
	if (messagep) free(messagep);
    }

    printf("\n------------- PRIVREQ\n\n");

    // set up my packet structs
    for (i = 0; i < KMS_req_num_fields; i++) {
	my_req.req[i].ptr = NULL;
    }

    i = KMS_req_proto_id;
    my_req.req[i].ptr = _req_buf[i];
    strncpy(my_req.req[i].ptr, _protoid, sizeof(_req_buf[i]));
    i = KMS_req_client_id;
    my_req.req[i].ptr = _req_buf[i];
    strncpy(my_req.req[i].ptr, _clients[SUB_DP].client_id, sizeof(_req_buf[i]));
    i = KMS_req_other_id;
    my_req.req[i].ptr = _req_buf[i];
    strncpy(my_req.req[i].ptr, _clients[PUB_TT].client_id, sizeof(_req_buf[i]));
    i = KMS_req_exp_date;
    my_req.req[i].ptr = _req_buf[i];
    strncpy(my_req.req[i].ptr, expdate, sizeof(_req_buf[i]));
    i = KMS_req_topic_name;
    my_req.req[i].ptr = _req_buf[i];
    strncpy(my_req.req[i].ptr, _clients[PUB_TT].what, sizeof(_req_buf[i]));

    KMS_pkt_dump_req(&my_req, "KMS_make_privreq");

    _send_len = sizeof(_send_buf);
    rc = KMS_make_privreq(&my_req, _send_buf, &_send_len);

    if (KMS_ERR_SUCCESS == rc) {
	KMS_pkt_dump(_send_buf, _send_len, "PRIVREQ packet", 1);
    } else {
	printf("Got error %s\n", KMS_error_string(rc));
    }

    send_to_kms(_clients[PUB_TT].cert_file, _clients[PUB_TT].key_file,
		_send_buf, _send_len, &resp, &resp_len);

    if (0 == resp_len) {
	printf("Error sending request\n");
    } else {
	if (verbose > 1) {
	    KMS_pkt_dump(resp, resp_len, "from KMS", 1);
	}
	for (i = 0; i < KMS_data_num_fields; i++) {
	    my_data.data[i].ptr = _data_buf[i];
	    my_data.data[i].len = sizeof(_data_buf[i]);
	}
	KMS_pkt_dump(resp, resp_len, "PRIVRESP", 1);
	messagep = NULL;
	rc = KMS_parse_privresp(resp, resp_len, &reason, &my_data, &messagep);

	msgbuf[0] = '\0';
	if (messagep) {
	    snprintf(msgbuf, sizeof(msgbuf), "     [%s]\n", messagep);
	}

	if (KMS_ERR_SUCCESS == rc) {
	    if (KMS_REASON_SUCCESS == reason) {
		KMS_pkt_dump_data(&my_data, "KMS_parse_privresp");
	    } else {
		printf("==== KMS_parse_privresp\n> %s\n%s",
		       KMS_reason_string(reason), msgbuf);
	    }
	} else {
	    printf("Got error %s\n", KMS_error_string(rc));
	}
	fflush(stdout);

	if (messagep) free(messagep);
    }

    printf("\n------------- PRIVREQ x3\n\n");

    // set up my packet structs
    for (i = 0; i < KMS_req_num_fields; i++) {
	my_req.req[i].ptr = NULL;
    }

    i = KMS_req_proto_id;
    my_req.req[i].ptr = _req_buf[i];
    strncpy(my_req.req[i].ptr, _protoid, sizeof(_req_buf[i]));
    i = KMS_req_client_id;
    my_req.req[i].ptr = _req_buf[i];
    strncpy(my_req.req[i].ptr, _clients[SUB_DP].client_id, sizeof(_req_buf[i]));
    i = KMS_req_other_id;
    my_req.req[i].ptr = _req_buf[i];
    strncpy(my_req.req[i].ptr, _clients[PUB_TL].client_id, sizeof(_req_buf[i]));
    i = KMS_req_exp_date;
    my_req.req[i].ptr = _req_buf[i];
    strncpy(my_req.req[i].ptr, expdate, sizeof(_req_buf[i]));
    i = KMS_req_topic_name;
    my_req.req[i].ptr = _req_buf[i];
    strncpy(my_req.req[i].ptr, _clients[PUB_TL].what, sizeof(_req_buf[i]));

    KMS_pkt_dump_req(&my_req, "KMS_make_privreq");

    _send_len = sizeof(_send_buf);
    rc = KMS_make_privreq(&my_req, _send_buf, &_send_len);

    if (KMS_ERR_SUCCESS == rc) {
	KMS_pkt_dump(_send_buf, _send_len, "PRIVREQ packet", 1);
    } else {
	printf("Got error %s\n", KMS_error_string(rc));
    }

    send_to_kms(_clients[PUB_TL].cert_file, _clients[PUB_TL].key_file,
		_send_buf, _send_len, &resp, &resp_len);

    if (0 == resp_len) {
	printf("Error sending request\n");
    } else {
	if (verbose > 1) {
	    KMS_pkt_dump(resp, resp_len, "from KMS", 1);
	}
	for (i = 0; i < KMS_data_num_fields; i++) {
	    my_data.data[i].ptr = _data_buf[i];
	    my_data.data[i].len = sizeof(_data_buf[i]);
	}
	KMS_pkt_dump(resp, resp_len, "PRIVRESP", 1);
	messagep = NULL;
	rc = KMS_parse_privresp(resp, resp_len, &reason, &my_data, &messagep);

	msgbuf[0] = '\0';
	if (messagep) {
	    snprintf(msgbuf, sizeof(msgbuf), "     [%s]\n", messagep);
	}

	if (KMS_ERR_SUCCESS == rc) {
	    if (KMS_REASON_SUCCESS == reason) {
		KMS_pkt_dump_data(&my_data, "KMS_parse_privresp");
	    } else {
		printf("==== KMS_parse_privresp\n> %s\n%s",
		       KMS_reason_string(reason), msgbuf);
	    }
	} else {
	    printf("Got error %s\n", KMS_error_string(rc));
	}
	fflush(stdout);

	if (messagep) free(messagep);
    }

    i = KMS_req_other_id;
    strncpy(my_req.req[i].ptr, _clients[PUB_PT].client_id, sizeof(_req_buf[i]));
    i = KMS_req_topic_name;
    strncpy(my_req.req[i].ptr, _clients[PUB_PT].what, sizeof(_req_buf[i]));

    KMS_pkt_dump_req(&my_req, "KMS_make_privreq");

    _send_len = sizeof(_send_buf);
    rc = KMS_make_privreq(&my_req, _send_buf, &_send_len);

    if (KMS_ERR_SUCCESS == rc) {
	KMS_pkt_dump(_send_buf, _send_len, "PRIVREQ packet", 1);
    } else {
	printf("Got error %s\n", KMS_error_string(rc));
    }

    send_to_kms(_clients[PUB_PT].cert_file, _clients[PUB_PT].key_file,
		_send_buf, _send_len, &resp, &resp_len);

    if (0 == resp_len) {
	printf("Error sending request\n");
    } else {
	if (verbose > 1) {
	    KMS_pkt_dump(resp, resp_len, "from KMS", 1);
	}
	for (i = 0; i < KMS_data_num_fields; i++) {
	    my_data.data[i].ptr = _data_buf[i];
	    my_data.data[i].len = sizeof(_data_buf[i]);
	}
	KMS_pkt_dump(resp, resp_len, "PRIVRESP", 1);
	messagep = NULL;
	rc = KMS_parse_privresp(resp, resp_len, &reason, &my_data, &messagep);

	msgbuf[0] = '\0';
	if (messagep) {
	    snprintf(msgbuf, sizeof(msgbuf), "     [%s]\n", messagep);
	}

	if (KMS_ERR_SUCCESS == rc) {
	    if (KMS_REASON_SUCCESS == reason) {
		KMS_pkt_dump_data(&my_data, "KMS_parse_privresp");
	    } else {
		printf("==== KMS_parse_privresp\n> %s\n%s",
		       KMS_reason_string(reason), msgbuf);
	    }
	} else {
	    printf("Got error %s\n", KMS_error_string(rc));
	}
	fflush(stdout);
	
	if (messagep) free(messagep);
    }

    i = KMS_req_client_id;
    strncpy(my_req.req[i].ptr, _clients[SUB_PC].client_id, sizeof(_req_buf[i]));
    i = KMS_req_other_id;
    strncpy(my_req.req[i].ptr, _clients[PUB_XX].client_id, sizeof(_req_buf[i]));
    i = KMS_req_topic_name;
    strncpy(my_req.req[i].ptr, _clients[PUB_XX].what, sizeof(_req_buf[i]));

    KMS_pkt_dump_req(&my_req, "KMS_make_privreq");

    _send_len = sizeof(_send_buf);
    rc = KMS_make_privreq(&my_req, _send_buf, &_send_len);

    if (KMS_ERR_SUCCESS == rc) {
	KMS_pkt_dump(_send_buf, _send_len, "PRIVREQ packet", 1);
    } else {
	printf("Got error %s\n", KMS_error_string(rc));
    }

    send_to_kms(_clients[SUB_PC].cert_file, _clients[SUB_PC].key_file,
		_send_buf, _send_len, &resp, &resp_len);

    if (0 == resp_len) {
	printf("Error sending request\n");
    } else {
	if (verbose > 1) {
	    KMS_pkt_dump(resp, resp_len, "from KMS", 1);
	}
	for (i = 0; i < KMS_data_num_fields; i++) {
	    my_data.data[i].ptr = _data_buf[i];
	    my_data.data[i].len = sizeof(_data_buf[i]);
	}
	KMS_pkt_dump(resp, resp_len, "PRIVRESP", 1);
	messagep = NULL;
	rc = KMS_parse_privresp(resp, resp_len, &reason, &my_data, &messagep);

	msgbuf[0] = '\0';
	if (messagep) {
	    snprintf(msgbuf, sizeof(msgbuf), "     [%s]\n", messagep);
	}

	if (KMS_ERR_SUCCESS == rc) {
	    if (KMS_REASON_SUCCESS == reason) {
		KMS_pkt_dump_data(&my_data, "KMS_parse_privresp");
	    } else {
		printf("==== KMS_parse_privresp\n> %s\n%s",
		       KMS_reason_string(reason), msgbuf);
	    }
	} else {
	    printf("Got error %s\n", KMS_error_string(rc));
	}
	fflush(stdout);

	if (messagep) free(messagep);
    }

    printf("\n------------- Errors\n\n");

    return(0);
}
