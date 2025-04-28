/** @file
 *
 * See masq_crypto.h for general comments and documentation of funcion
 * calls.
 *
 * Would be nice:
 * - switch from ExpDate to NextExp at random time before ExpDate
 */

#include "crypto.h"
#include "kms_msg.h"
#include "kms_utils.h"
#include "api.h"

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>

#ifdef	ebug
#include <ctype.h>
char	*_kms  = "\033[1;93m\u27a4\033[m";
char	*_kmse = "\033[1;91m\u27a4\033[m";
char	*_tls  = "\033[1;93m\u271a\033[m ";
char	*_tlse = "\033[1;91m\u271a\033[m ";
#else
static char	*_tlse = "";
// a hack to avoid unused parameters warnings
#define	UNUSED(x)	(void)(x)
#endif

const char	*MASQ_proto_id = "1.0/1";

static void
crypto_state_free(void *state);

MASQ_status_t
MASQ_crypto_overhead(MASQ_mek_strategy_t strategy,
		     size_t *overhead_bytes,
		     size_t *mek_bytes)
{
    /*
     * If multiple crypto protocols are supported, a differentiation
     * may need to be made on the basis of the state->CryptoId.
     */
    MASQ_status_t	retv = MASQ_STATUS_SUCCESS;

    // DEBUG(s, 0, ("%s(%p)\n", __FUNCTION__, state));

    if (NULL == overhead_bytes) {
	return MASQ_ERR_INVAL;
    }

    switch (strategy) {
	
    case MASQ_key_ephemeral:
	*overhead_bytes = MASQ_PAYLOAD_LEN_EPH(0);
	if (NULL != mek_bytes) {
	    *mek_bytes = 0;
	}
	break;
	
    case MASQ_key_persistent_pkt:
    case MASQ_key_persistent_bytes:
    case MASQ_key_persistent_time:
    case MASQ_key_persistent_exp:
	if (NULL == mek_bytes) {
	    retv = MASQ_ERR_INVAL;
	} else {
	    *overhead_bytes = MASQ_PAYLOAD_LEN_PER(0);
	    *mek_bytes = MASQ_ENCAPS_KEY_LEN;
	}
	break;

    default:
	retv = MASQ_ERR_INVAL;
	break;
    }

    return retv;
}

void
MASQ_dump_crypto_parms(masq_crypto_parms *p, const char *hdr)
{
#ifdef	ebug
    if (NULL != hdr) {
	printf("---- %s\n", hdr);
    }
    if (NULL == p) {
	printf("NULL parms\n");
	return;
    }
    printf("-        t_name %s\n"
	   "-       t_value %p\n"
	   "-   t_value_len %d\n"
	   "-   t_client_id %s\n"
	   "-           seq %s\n"
	   "-       seq_len %lu\n"
	   "-      exp_date %s\n"
	   "-  exp_date_len %lu\n"
	   "-           mek %p\n"
	   "-       mek_len %lu\n"
	   "-       payload %p\n"
	   "-   payload_len %d\n",
	   (p->t_name ? p->t_name : "<NULL>"),
	   p->t_value,
	   (p->t_value_len ? (int) *p->t_value_len : -1),
	   (p->client_id ? p->client_id : "<NULL>"),
	   (p->seq ? p->seq : "<NULL>"),
	   p->seq_len,
	   (p->exp_date ? p->exp_date : "<NULL>"),
	   p->exp_date_len,
	   p->mek,
	   p->mek_len,
	   p->payload,
	   (p->payload_len ? (int) *p->payload_len : -1));
#else	// ebug
    UNUSED(p);
    UNUSED(hdr);
    return;
#endif
}

#ifdef	ebug
static const char *
role_to_str(MASQ_role_t role)
{
    char	*ret = "???";
    switch (role) {
#undef	_X
#define	_X(x)	case MASQ_role_ ## x: ret = #x; break
    _X(publisher);
    _X(subscriber);
    _X(both);
    _X(none);
#undef	_X
    }
    return ret;
}

static const char *
strat_to_str(MASQ_mek_strategy_t strat)
{
    char	*ret = "???";
    switch (strat) {
#undef	_X
#define	_X(x)	case MASQ_key_ ## x: ret = #x; break
    _X(none);
    _X(ephemeral);
    _X(persistent_pkt);
    _X(persistent_bytes);
    _X(persistent_time);
    _X(persistent_exp);
#undef	_X
    }
    return ret;
}
#endif	// ebug

void
MASQ_dump_topic(MASQ_topic_t *t, const char *hdr)
{
#ifdef	ebug
    if (NULL != hdr) {
	printf(":::: %s\n", hdr);
    }
    if (NULL == t) {
	return;
    }
    printf(": [topic] topic %s\n"
	   ":       new_seq %s\n"
	   ":   next_seqnum %8lx\n"
	   ":       mek_seq %s\n"
	   ": stored_packet %s\n",
	   t->topic,
	   (t->new_seq ? "\u273b YES \u273b" : "NO"),
	   t->next_seqnum,
	   t->mek_seq,
	   (t->stored_packet ? "\u21e9 YES \u21e9" : "\u00d7 NO \u00d7"));
    if (t->stored_packet) {
	MASQ_dump_properties(&t->user_props, NULL);
	MASQ_dump(t->payload, t->payload_len, NULL, ':', 1);
    }
#else	// ebug
    UNUSED(t);
    UNUSED(hdr);
    return;
#endif
}

void
MASQ_dump_topics(MASQ_topic_t *t, const char *hdr)
{
#ifdef	ebug
    MASQ_topic_t	*tp;
    if (NULL != hdr) {
	printf(":::: %s\n", hdr);
    }
    for (tp = t; NULL != tp; tp = tp->next) {
	MASQ_dump_topic(tp, NULL);
    }
#else	// ebug
    UNUSED(t);
    UNUSED(hdr);
    return;
#endif
}

void
MASQ_dump_mek(MASQ_KS_mek_t *mek, const char *hdr, int n)
{
#ifdef	ebug
    if (NULL != hdr) {
	printf("|||| %s\n", hdr);
    }

    if (NULL == mek) {
	return;
    }
    
    printf("| %02d %16s %*s %*s %*s %lu/%lu\n",
	   n, mek->topic,
	   MASQ_EXPDATE_LEN, mek->expdate,
	   MASQ_SEQNUM_LEN, mek->seqnum,
	   MASQ_CLIENTID_LEN, mek->clientid,
	   mek->tally, mek->max);
    MASQ_dump((void *) mek->mek, MASQ_AESKEY_LEN, NULL, '|', 1);
#else	// ebug
    UNUSED(mek);
    UNUSED(hdr);
    UNUSED(n);
    return;
#endif
}

void
MASQ_dump_meks(MASQ_KS_mek_t *mek, const char *hdr)
{
#ifdef	ebug
    MASQ_KS_mek_t *p;
    int	i;
    
    if (NULL != hdr) {
	printf("|||| %s\n", hdr);
    }
    
    for (p = mek, i = 0; NULL != p; p = p->next, i++) {
	MASQ_dump_mek(p, NULL, i);
    }
#else	// ebug
    UNUSED(mek);
    UNUSED(hdr);
    return;
#endif
}

void
MASQ_dump_properties(MASQ_user_properties_t *p, const char *hdr)
{
#ifdef	ebug
    int	n;
    
    if (NULL != hdr) {
	printf(".... %s\n", hdr);
    }
    if (NULL == p) {
	printf("NULL properties\n");
	return;
    }
    for (n = 0; n < p->num_props; n++) {
	printf(". %*s %s\n",
	       MASQ_MAX_PROP_NAME_LEN, p->prop[n].name, p->prop[n].value);
    }
#else	// ebug
    UNUSED(p);
    UNUSED(hdr);
    return;
#endif
}

void
MASQ_dump_state(masq_crypto_state *s, const char *hdr)
{
#ifdef	ebug
    if (NULL != hdr) {
	printf("---- %s\n", hdr);
    }
    if (NULL == s) {
	printf("NULL state\n");
	return;
    }
    printf("- [state]  role %s\n"
	   "-       protoid %s\n"
	   "-      clientid %s\n"
	   "-       expdate %s\n"
	   "-       nextexp %s\n"
	   "-      need_exp %s\n"
	   "-         strat %s\n"
	   "-     strat_max %lu\n"
	   "-           kms %s\n",
	   role_to_str(s->role),
	   s->protoid, s->clientid,
	   s->expdate, s->nextexp,
	   (s->need_exp ? "\u273b YES \u273b" : "NO"),
	   strat_to_str(s->strat), s->strat_max,
	   s->kms);
    MASQ_dump_topics(s->topicp, "Topics");
    MASQ_dump_meks(s->pub_mek, "Pub");
    MASQ_dump_meks(s->sub_mek, "Sub");
#else	// ebug
    UNUSED(s);
    UNUSED(hdr);
    return;
#endif
}

static unsigned char	_send_buf[4 * 1024];	// overkill
static size_t		_send_len;
static unsigned char	_recv_buf[4 * 1024];	// overkill

static MASQ_status_t
tls_ctx_init(void *state, char *ca_file, char *cert_file, char *key_file)
{
    masq_crypto_state	*s = (masq_crypto_state *) state;
    MASQ_status_t	ret = MASQ_STATUS_SUCCESS;

    DEBUG(s, 0, ("%s%s(%s, %s, %s)\n",
		 _tls, __FUNCTION__, ca_file, cert_file, key_file));

    if (NULL != s->tls_ctx) {
	// alread initialized
	DEBUG(s, 0, ("%s%s() already initialized, bailing\n",
		     _tls,__FUNCTION__));
	return ret;
    }

    wolfSSL_Init();

    // create and initialize WOLFSSL_CTX
    if (NULL == (s->tls_ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()))) {
	printf("%swolfSSL_CTX_new() failed\n", _tlse); fflush(stdout);
	ret = MASQ_ERR_TLS_INIT;
	goto tls_ctx_cleanup;
    }

    // load trusted certificates
    if (wolfSSL_CTX_load_verify_locations(s->tls_ctx, ca_file, 0) !=
	WOLFSSL_SUCCESS) {
	printf("%s%s: ERROR loading ca file (%s)\n",
	       _tlse, __FUNCTION__, ca_file);
	fflush(stdout);
	ret = MASQ_ERR_TLS_INIT;
	goto tls_ctx_cleanup;
    }

    // client certificate
    if (wolfSSL_CTX_use_certificate_file(s->tls_ctx, cert_file,
					 WOLFSSL_FILETYPE_PEM)
	!= WOLFSSL_SUCCESS) {
	printf("%sERROR: Can not load cert file %s\n", _tlse, cert_file);
	fflush(stdout);
	ret = MASQ_ERR_TLS_INIT;
	goto tls_ctx_cleanup;
    }

    // client key
    if (wolfSSL_CTX_use_PrivateKey_file(s->tls_ctx, key_file,
					WOLFSSL_FILETYPE_PEM)
	!= WOLFSSL_SUCCESS) {
	printf("%sERROR: Can not load key file %s\n", _tlse, key_file);
	fflush(stdout);
	ret = MASQ_ERR_TLS_INIT;
	goto tls_ctx_cleanup;
    }

    DEBUG(s, 0, ("%s%s() SUCCESS, returning\n", _tls, __FUNCTION__));
    return ret;
    
 tls_ctx_cleanup:
    DEBUG(s, 0, ("%s%s() FAILED, returning\n", _tlse, __FUNCTION__));
    if (s->tls_ctx) {
	wolfSSL_CTX_free(s->tls_ctx);
	s->tls_ctx = NULL;
    }
    wolfSSL_Cleanup();
    return ret;
}

/**
 * Send formatted packet to KMS.
 *
 * @param[in] s Crypto state.
 * @param[in] expect_another Hold connection open for another packet? Avoids
 *   having to negotiate a new TLS connection but should only be used when
 *   another packet is currently available. (Currently not supported)
 * @param[in] msg Pointer to message to send
 * @param[in] len Length of message to send
 * @param[out] resp Pointer to response message
 * @param[out] resplen Length of response message
 */
static void
send_to_kms(masq_crypto_state *s,
	    unsigned char *msg,   size_t len,
	    unsigned char **resp, size_t *resplen)
{
    int		sockfd = (-1);
    WOLFSSL	*ssl = NULL;
    int		ret     = 0;
    int		err     = 0;
    int		saverr  = 0;
    char	buffer[WOLFSSL_MAX_ERROR_SZ];
    int		sleepcount = 0;
    
    DEBUG(s, 0, ("%s(%ld bytes)\n", __FUNCTION__, len));
    
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

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
	printf("socket() failed, errno = %s\n", strerror(errno));
	fflush(stdout);
	return;
    }

#define	MAX_SLEEP	(10)
    // connect to KMS, may take a couple of tries if KMS hasn't reset its socket
    do {
	if (connect(sockfd, (struct sockaddr *) &s->kms_addr,
		    sizeof(s->kms_addr)) < 0) {
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
    } while ((ECONNREFUSED == saverr) && (sleepcount < MAX_SLEEP));

    if (sleepcount >= MAX_SLEEP) {
	printf("connect() failed, errno = %s\n", strerror(errno));
	printf("Bad KMS address/port or KMS not running\n");
	fflush(stdout);
	goto send_cleanup;
    }

    // create WOLFSSL object
    if (NULL == (ssl = wolfSSL_new(s->tls_ctx))) {
	printf("%swolfSSL_new() failed\n", _tlse); fflush(stdout);
	goto send_cleanup;
    }

    // attach wolfSSL to the socket
    if (wolfSSL_set_fd(ssl, sockfd) != WOLFSSL_SUCCESS) {
	printf("%sERROR: wolfSSL_set_fd() failed\n", _tlse); fflush(stdout);
	goto send_cleanup;
    }

#ifdef	ebug
    if (s->debug > 1) {
	char	sbuf[80];
	snprintf(sbuf, sizeof(sbuf), "%s() sending", __FUNCTION__);
	MASQ_dump(msg, len, sbuf, '>', 1);
    }
#endif
    
    // send the request
    err = 0;	// reset error
    DEBUG(s, 1, ("%s%s() calling wolfSSL_write(%ld)\n",
		 _tls, __FUNCTION__, len));
    ret = wolfSSL_write(ssl, msg, len);

    if (ret <= 0) {
	err = wolfSSL_get_error(ssl, 0);
	printf("%sSSL_write msg error %d, %s\n", _tlse, err,
	       wolfSSL_ERR_error_string(err, buffer)); fflush(stdout);
	goto send_cleanup;
    }

    // read the response
    err = 0;	// reset error
    DEBUG(s, 1, ("%s%s() calling wolfSSL_read()\n", _tls, __FUNCTION__));
    ret = wolfSSL_read(ssl, _recv_buf, sizeof(_recv_buf));
    if (ret <= 0) {
	err = wolfSSL_get_error(ssl, 0);
	printf("%sSSL_read msg error %d, %s\n", _tlse, err,
	       wolfSSL_ERR_error_string(err, buffer)); fflush(stdout);
	goto send_cleanup;
#ifdef	ebug
    } else if (s->debug > 1) {
	char	sbuf[80];
	snprintf(sbuf, sizeof(sbuf), "%s() received", __FUNCTION__);
	MASQ_dump(_recv_buf, ret, sbuf, '<', 1);
#endif
    }

    *resp = _recv_buf;
    *resplen = ret;
    
 send_cleanup:
    if (ssl) wolfSSL_free(ssl);
    if (sockfd >= 0) close(sockfd);
}

#define	DUMP_WID	(16)

void
MASQ_dump(unsigned char *p, size_t len, char *hdr, char prefix, int show)
{
#ifdef	ebug
    size_t	i;
    char	*sep = "";
    char	pre = (prefix ? prefix : '~');
    char	buf[DUMP_WID+1];
    
    if (NULL != hdr) {
	printf("%c%c%c%c %04lx  %s\n", pre, pre, pre, pre, len, hdr);
    }

    memset(buf, '\0', sizeof(buf));
    
    for (i = 0; i < len; i++) {
	if (0 == (i % DUMP_WID)) {
	    if (show) {
		if (i) {
		    printf("    |%s|", buf);
		    memset(buf, '\0', sizeof(buf));
		}
	    }
	    printf("%s%c %04lx ", sep, pre, i);
	    sep = "\n";
	} else if (0 == (i % (DUMP_WID/2))) {
	    printf(" ");
	}
	printf(" %02x", p[i]);
	buf[i % DUMP_WID] = (isprint(p[i]) ? p[i] : '.');
    }

    if (show) {
	if (len % DUMP_WID) {
	    // add alignment spaces
	    if ((len % DUMP_WID) <= (DUMP_WID / 2)) printf(" ");
	    for (i = len % DUMP_WID; i < DUMP_WID; i++) {
		printf("   ");
	    }
	}
	printf("    |%s|", buf);
    }

    printf("\n");
#else	// ebug
    UNUSED(p);
    UNUSED(len);
    UNUSED(hdr);
    UNUSED(prefix);
    return;
#endif
}

/**
 * Represent sequence number as binary. Used to set first four bytes of
 * and IV to signal the start of a new sequence.
 *
 * @param[out] p Pointer to receive binary data
 * @param[in] seq Sequence number as '\0'-terminated string
 */
static void
seq_to_binary(void *p, char *seq)
{
    int			i;
    char		buf[4];
    unsigned char	*cp = (unsigned char *) p;

    for (i = 0; i < 4; i++) {
	memcpy(buf, &seq[i*2], 2);
	buf[2] = '\0';
	cp[i] = (unsigned char) strtol(buf, NULL, 16);
    }
}

/**
 * Compare IV to sequence number to see if it signals the start of a
 * new sequence.
 *
 * @param[in] iv Initialization Vector
 * @param[in] seq Sequence number as '\0'-terminated string
 * @return 1 if new sequence, else 0
 */
static int
iv_is_new_seq(unsigned char *iv, char *seq)
{
    unsigned char	sbuf[4];
    seq_to_binary((void *) sbuf, seq);
    return ! memcmp((void *) iv, (void *) sbuf, sizeof(sbuf));
}

/**
 * Return the next sequence number for the given Topic.
 *
 * @param[in] t Topic.
 * @param[in] seq_num Pointer to storage for sequence number.
 * @param[in] seq_num_len Length of storage available at @p seq_num.
 */
static int
next_seqnum(MASQ_topic_t *t,
	    char *seq_num, size_t seq_num_len)
{
    if ((NULL == seq_num) || (seq_num_len < MASQ_SEQNUM_LEN + 1)) {
	return 0;
    }
    
    // note: this relies on underlying compiler gracefully handling
    // 0xffffffff -> 0 rollover
    snprintf(seq_num, seq_num_len, "%0*lx", MASQ_SEQNUM_LEN, t->next_seqnum++);
    
    return 1;
}

/**
 * Retrieve expiration dates from KMS. (KMS TIMEREQ)
 *
 * @param[in] s Crypto state.
 * @param[out] cur_time Buffer to hold '\0'-terminated current time/date.
 *    Assumes size of at least MASQ_EXPDATE_LEN + 1.
 * @param[out] exp_date Buffer to hold '\0'-terminated expiration date.
 *    Assumes size of at least MASQ_EXPDATE_LEN + 1.
 * @param[out] next_exp Buffer to hold next '\0'-terminated expiration date.
 *    Assumes size of at least MASQ_EXPDATE_LEN + 1.
 * @return 1 on success, 0 if problems communicating with KMS
 */
static int
get_time(masq_crypto_state *s,
	 char *cur_time,
	 char *exp_date,
	 char *next_exp)
{
    KMS_req_t		my_req;
    KMS_time_t		my_time;
    uint8_t		reason;
    int			i;
    int			rc;
    unsigned char	*resp;
    size_t		resp_len;
    unsigned char	req_buf[KMS_req_num_fields][MASQ_MAXTOPIC_LEN];
    unsigned char	time_buf[KMS_time_num_fields][MASQ_EXPDATE_LEN+1];

    DEBUG(s, 0, ("%s %s(%p, %s)\n", _kms, __FUNCTION__, s, s->clientid));

    if ((NULL == cur_time) || (NULL == exp_date) || (NULL == next_exp)) {
	return 0;
    }
    cur_time[0] = exp_date[0] = next_exp[0] = '\0';
    
    // set up my packet structs
    for (i = 0; i < KMS_req_num_fields; i++) {
	my_req.req[i].ptr = NULL;
    }
    i = KMS_req_proto_id;
    my_req.req[i].ptr = req_buf[i];
    strncpy(my_req.req[i].ptr, KMS_PROTO_ID, sizeof(req_buf[i]));
    i = KMS_req_client_id;
    my_req.req[i].ptr = req_buf[i];
    strncpy(my_req.req[i].ptr, s->clientid, sizeof(req_buf[i]));
    
    for (i = 0; i < KMS_time_num_fields; i++) {
	my_time.time[i].ptr = time_buf[i];
	my_time.time[i].len = sizeof(time_buf[i]);
    }

    // create TIMEREQ packet
    _send_len = sizeof(_send_buf);
    if (KMS_ERR_SUCCESS !=
	(rc = KMS_make_timereq(&my_req, _send_buf, &_send_len))) {
	DEBUG(s, 0, ("%s %s() KMS_make_timereq() failed\n",
		     _kmse, __FUNCTION__));
	return 0;
    }

    DEBUG(s, 0, ("%s %s() calling send_to_kms\n", _kms, __FUNCTION__));
    // send packet, wait for response
    send_to_kms(s, _send_buf, _send_len, &resp, &resp_len);
    
    if (0 == resp_len) {
	// no data returned
	DEBUG(s, 0, ("%s %s() no data returned\n", _kmse, __FUNCTION__));
	return 0;
    }

    // parse TIMERESP packet
    if (KMS_ERR_SUCCESS !=
	(rc = KMS_parse_timeresp(resp, resp_len, &reason, &my_time, NULL))) {
	DEBUG(s, 0, ("%s %s() KMS_parse_timeresp() failed\n",
		     _kmse, __FUNCTION__));
	return 0;
    }
    if (KMS_REASON_SUCCESS != reason) {
	DEBUG(s, 0, ("%s %s() KMS_parse_timeresp() returned %s\n",
		     _kmse, __FUNCTION__, KMS_reason_string(reason)));
	return 0;
    }

    // return times
    if (strlen(my_time.time[KMS_time_cur].ptr)) {
	strncpy(cur_time, my_time.time[KMS_time_cur].ptr,
		MASQ_EXPDATE_LEN + 1);
    }
    if (strlen(my_time.time[KMS_time_exp_date].ptr)) {
	strncpy(exp_date, my_time.time[KMS_time_exp_date].ptr,
		MASQ_EXPDATE_LEN + 1);
    }
    if (strlen(my_time.time[KMS_time_next_exp].ptr)) {
	strncpy(next_exp, my_time.time[KMS_time_next_exp].ptr,
		MASQ_EXPDATE_LEN + 1);
    }
    return 1;
}

/**
 * Retrieve public parameters from KMS. (KMS PUBREQ)
 *
 * Pointers returned in @p r, @p t, and @p v must be free()d when available.
 *
 * @param[in] s Crypto state.
 * @param[out] r R public parameter
 * @param[out] rlen Length of R public parameter
 * @param[out] t T public parameter
 * @param[out] tlen Length of T public parameter
 * @param[out] v V public parameter
 * @param[out] vlen Length of V public parameter
 * @return 1 on success, 0 if problems communicating with KMS
 */
static int
get_public(masq_crypto_state *s,
	   void **r, size_t *rlen,
	   void **t, size_t *tlen,
	   void **v, size_t *vlen)
{
    KMS_req_t		my_req;
    KMS_data_t		my_data = { 0 };
    uint8_t		reason;
    int			i;
    int			rc;
    unsigned char	*resp;
    size_t		resp_len;
    unsigned char	req_buf[KMS_req_num_fields][MASQ_MAXTOPIC_LEN];

    DEBUG(s, 0, ("%s %s(%p)\n", _kms, __FUNCTION__, s));

    if ((NULL == r) || (NULL == rlen) ||
	(NULL == t) || (NULL == tlen) ||
	(NULL == v) || (NULL == vlen)) {
	return 0;
    }

    // if these are non-NULL it means we are replacing them
    // if they are NULL free() won't care
    free(*r);
    free(*t);
    free(*v);
    *r = *t = *v = NULL;
    *rlen = *tlen = *vlen = 0;
    
    // set up my packet structs
    for (i = 0; i < KMS_req_num_fields; i++) {
	my_req.req[i].ptr = NULL;
    }
    i = KMS_req_proto_id;
    my_req.req[i].ptr = req_buf[i];
    strncpy(my_req.req[i].ptr, KMS_PROTO_ID, sizeof(req_buf[i]));
    i = KMS_req_client_id;
    my_req.req[i].ptr = req_buf[i];
    strncpy(my_req.req[i].ptr, s->clientid, sizeof(req_buf[i]));
    
    // create PUBREQ packet
    _send_len = sizeof(_send_buf);
    if (KMS_ERR_SUCCESS !=
	(rc = KMS_make_pubreq(&my_req, _send_buf, &_send_len))) {
	DEBUG(s, 0, ("%s %s() KMS_make_pubreq() failed\n",
		     _kmse, __FUNCTION__));
	return 0;
    }

    DEBUG(s, 0, ("%s %s() calling send_to_kms\n", _kms, __FUNCTION__));
    // send packet, wait for response
    send_to_kms(s, _send_buf, _send_len, &resp, &resp_len);
    
    if (0 == resp_len) {
	DEBUG(s, 0, ("%s %s() no data returned\n", _kmse, __FUNCTION__));
	// no data returned
	return 0;
    }

    // parse TIMERESP packet
    if (KMS_ERR_SUCCESS !=
	(rc = KMS_parse_pubresp(resp, resp_len, &reason, &my_data, NULL))) {
	DEBUG(s, 0, ("%s %s() KMS_parse_pubresp() failed\n",
		     _kmse, __FUNCTION__));
	return 0;
    }
    if (KMS_REASON_SUCCESS != reason) {
	DEBUG(s, 0, ("%s %s() KMS_parse_timeresp() returned %s\n",
		     _kmse, __FUNCTION__, KMS_reason_string(reason)));
	return 0;
    }
    if (3 != my_data.num) {
	DEBUG(s, 0, ("%s %s() my_data.num = %d, should be 3\n",
		     _kmse, __FUNCTION__, my_data.num));
	return 0;
    }
    // my_data.data[i].ptr points into resp buffer, calloc() copy for caller
    *rlen = my_data.data[0].len;
    if (NULL == (*r = calloc(1, *rlen))) {
	*rlen = 0;
	return 0;
    }
    memcpy(*r, my_data.data[0].ptr, *rlen);
    *tlen = my_data.data[1].len;
    if (NULL == (*t = calloc(1, *tlen))) {
	free(*r); *r = NULL; *rlen = 0;
	*tlen = 0;
	return 0;
    }
    memcpy(*t, my_data.data[1].ptr, *tlen);
    *vlen = my_data.data[2].len;
    if (NULL == (*v = calloc(1, *vlen))) {
	free(*r); *r = NULL; *rlen = 0;
	free(*t); *t = NULL; *tlen = 0;
	*vlen = 0;
	return 0;
    }
    memcpy(*v, my_data.data[2].ptr, *vlen);

    return 1;
}

/**
 * Retrieve private key from KMS. (KMS PRIVREQ)
 *
 * @param[in] s Crypto state.
 * @param[in] client_id Client ID of Publisher ('\0'-terminated).
 * @param[in] topic Topic Name ('\0'-terminated).
 * @param[in] expdate Expiration date ('\0'-terminated).
 * @param[out] mekp Pointer to key cache entry pointer.
 * @return 1 on success, 0 if problems communicating with KMS
 */
static int
get_private(masq_crypto_state *s,
	    char *client_id,
	    char *topic,
	    char *expdate,
	    MASQ_KS_mek_t **mekp)
{
    MASQ_KS_mek_t	*p;
    KMS_req_t		my_req;
    KMS_data_t		my_data = { 0 };
    uint8_t		reason;
    int			i;
    int			rc;
    unsigned char	*resp;
    size_t		resp_len;
    unsigned char	req_buf[KMS_req_num_fields][MASQ_MAXTOPIC_LEN];

    /////
    ///// Look for PUK in crypto_state before pestering the KMS
    /////

    DEBUG(s, 0, ("%s %s(%p, %s, %s, %s)\n", _kms, __FUNCTION__, s,
		 client_id, topic, expdate));

    if (NULL !=
	(p = MASQ_KS_find_mek(s->sub_mek, topic, expdate, NULL, client_id))) {
	if (2 == p->puk.num) {
	    *mekp = p;
	    return 1;
	}
    }

    // set up my packet structs
    for (i = 0; i < KMS_req_num_fields; i++) {
	my_req.req[i].ptr = NULL;
    }

    i = KMS_req_proto_id;
    my_req.req[i].ptr = req_buf[i];
    strncpy(my_req.req[i].ptr, KMS_PROTO_ID, sizeof(req_buf[i]));
    i = KMS_req_client_id;
    my_req.req[i].ptr = req_buf[i];
    strncpy(my_req.req[i].ptr, s->clientid, sizeof(req_buf[i]));
    i = KMS_req_other_id;
    my_req.req[i].ptr = req_buf[i];
    strncpy(my_req.req[i].ptr, client_id, sizeof(req_buf[i]));
    i = KMS_req_exp_date;
    my_req.req[i].ptr = req_buf[i];
    strncpy(my_req.req[i].ptr, expdate, sizeof(req_buf[i]));
    i = KMS_req_topic_name;
    my_req.req[i].ptr = req_buf[i];
    strncpy(my_req.req[i].ptr, topic, sizeof(req_buf[i]));

    // create PRIVREQ packet
    _send_len = sizeof(_send_buf);
    if (KMS_ERR_SUCCESS !=
	(rc = KMS_make_privreq(&my_req, _send_buf, &_send_len))) {
	DEBUG(s, 0, ("%s %s() KMS_make_privreq() failed\n",
		     _kmse, __FUNCTION__));
	return 0;
    }

    DEBUG(s, 0, ("%s %s() calling send_to_kms\n", _kms, __FUNCTION__));
    // send packet, wait for response
    send_to_kms(s, _send_buf, _send_len, &resp, &resp_len);
    if (0 == resp_len) {
	// no data returned
	DEBUG(s, 0, ("%s %s() no data returned\n", _kmse, __FUNCTION__));
	return 0;
    }

    // parse PRIVRESP packet
    if (KMS_ERR_SUCCESS !=
	(rc = KMS_parse_privresp(resp, resp_len, &reason, &my_data, NULL))) {
	DEBUG(s, 0, ("%s %s() KMS_parse_privresp() failed\n",
		     _kmse, __FUNCTION__));
	return 0;
    }
    if (KMS_REASON_SUCCESS != reason) {
	DEBUG(s, 0, ("%s %s() KMS_parse_timeresp() returned %s\n",
		     _kmse, __FUNCTION__, KMS_reason_string(reason)));
	return 0;
    }
    
    if (2 != my_data.num) {
	DEBUG(s, 0, ("%s %s() my_data.num = %d, should be 2\n",
		     _kmse, __FUNCTION__, my_data.num));
	return 0;
    }
    
    // store PUK
    p = MASQ_KS_new(&s->sub_mek,
		    topic,
		    expdate,
		    NULL,	// seqnum
		    client_id,
		    MASQ_key_none, 0,
		    &my_data,
		    NULL, 0);	// mek
    *mekp = p;
    
    return (NULL != p);
}

/**
 * Set up MASQ crypto routines
 *
 */
MASQ_status_t
MASQ_crypto_init(const char *protoid,
		 MASQ_role_t role,
		 char *clientid,
		 MASQ_mek_strategy_t strategy,
		 unsigned long int strat_val,
		 char *kms_host,
		 int kms_port,
		 char *ca_file,
		 char *cert_file,
		 char *key_file,
#ifdef	ebug
		 int debug,
#endif
		 void **state)
{
    masq_crypto_state	*s;
    int			valid_role = 0;
    char		curbuf[MASQ_EXPDATE_LEN+1];
    char		*host = kms_host ? kms_host : "127.0.0.1";
    int			port = kms_port ? kms_port : MASQ_KMS_DFLT_PORT;
#ifdef	ebug
    char		addrbuf[32];
#endif
    int			i;
    MASQ_status_t	ret;

#ifdef	ebug
    if (debug) {
	printf("%s(%s, %s, %s, %s, %lu, %s, %d",
	       __FUNCTION__, protoid, role_to_str(role), clientid,
	       strat_to_str(strategy), strat_val, kms_host, kms_port);
	printf(", %s, %s, %s", ca_file, cert_file, key_file);
	printf(", %d)\n", debug);
    }
#endif

    if ((NULL == protoid) || (MASQ_PROTOID_LEN < strlen(protoid))) {
	return MASQ_ERR_INVAL;
    }
    if ((strlen(protoid) != strlen(MASQ_proto_id)) ||
	(strcmp(protoid, MASQ_proto_id))) {
	return MASQ_ERR_BAD_PROTOID;
    }
    if ((NULL == clientid) || (MASQ_CLIENTID_LEN != strlen(clientid))) {
	return MASQ_ERR_INVAL;
    }
    
    if (NULL == (s = calloc(1, sizeof(masq_crypto_state)))) {
	*state = NULL;
	return MASQ_ERR_NOMEM;
    }

#ifdef	ebug
    s->debug = debug;
#endif
    DEBUG(s, 0, ("%s() state = %p\n", __FUNCTION__, s));

    strncpy(s->protoid,  protoid,  sizeof(s->protoid));
    strncpy(s->clientid, clientid, sizeof(s->clientid));

    // fill in KMS address
    memset(&s->kms_addr, 0, sizeof(s->kms_addr));
    s->kms_addr.sin_family = AF_INET;
    if (! inet_pton(AF_INET, host, (struct in_addr *) &s->kms_addr.sin_addr)) {
	DEBUG(s, 0, ("%s() Bad addr %s\n", __FUNCTION__, host));
    }
    s->kms_addr.sin_port = htons(port);
    DEBUG(s, 0, ("%s %s() using KMS addr %s:%d\n", _kms, __FUNCTION__,
		 inet_ntop(AF_INET, &s->kms_addr.sin_addr,
		       addrbuf, sizeof(addrbuf)),
		 ntohs(s->kms_addr.sin_port)));

    // initialize TLS context
    if (MASQ_STATUS_SUCCESS !=
	(ret = tls_ctx_init(s, ca_file, cert_file, key_file))) {
	return ret;
    }
    
    if (MASQ_STATUS_SUCCESS != (ret = MC_crypto_init(protoid))) {
	return ret;
    }

    if ((MASQ_role_subscriber == role) || (MASQ_role_both == role)) {
	// handle subscriber side first so we don't wipe out publisher
	// data if role == both
	valid_role = 1;
	s->role = role;
	s->expdate[0] = s->nextexp[0] = '\0';
	s->need_exp = 0;
	s->strat = MASQ_key_none;
	s->strat_max = 0;
	s->pub_params.num = 0;
	for (i = 0; i < KMS_data_num_fields; i++) {
	    s->pub_params.data[i].ptr = NULL;
	    s->pub_params.data[0].len = 0;
	}
    }

    if ((MASQ_role_publisher == role) || (MASQ_role_both == role)) {
	// handle publisher side
	valid_role = 1;
	s->role = role;
	if (! get_time(s, curbuf, s->expdate, s->nextexp)) {
	    // do something?
	}
	s->need_exp = 1;
	s->strat = strategy;
	s->strat_max = 0;	// may not care about this
	
	switch (strategy) {
	case MASQ_key_ephemeral:
	case MASQ_key_persistent_exp:
	    // we're cool, values above work fine
	    break;
	case MASQ_key_persistent_pkt:
	case MASQ_key_persistent_bytes:
	    // care about strat_max in these cases
	    s->strat_max = strat_val;
	    break;
	case MASQ_key_persistent_time:
	    // strat_max used for interval time
	    // strat_cur used for expiration time
	    s->strat_max = strat_val;
	    break;
	default:
	    // default strategy if something weird is asked for
	    //// return MASQ_ERR_INVAL instead?
	    s->strat = MASQ_key_persistent_exp;
	    break;
	}

	DEBUG(s, 0, ("%s() calling get_public()\n", __FUNCTION__));
	
	if (! get_public(s,
			 &s->pub_params.data[0].ptr,	// R
			 &s->pub_params.data[0].len,
			 &s->pub_params.data[1].ptr,	// T
			 &s->pub_params.data[1].len,
			 &s->pub_params.data[2].ptr,	// V
			 &s->pub_params.data[2].len)) {
	    valid_role = 0;
	}
	s->pub_params.num = 3;				// maybe not needed?
    }

    if (! valid_role) {
	crypto_state_free((void *) s);
	return MASQ_ERR_INVAL_ROLE;
    }
    s->topicp = NULL;
    s->pub_mek = s->sub_mek = NULL;

    *state = (void *) s;
    return MASQ_STATUS_SUCCESS;
}

// use this to treat _rand_extra as a circular buffer rather than starting
// at the beginning every time
static size_t	_rbias = 0;
static unsigned char	_rand_extra[MASQ_HASH_LEN] = { 0 };

#ifdef	ebug
unsigned char *
MASQ_get_rand_extra(void)
{
    return _rand_extra;
}
#endif

void
MASQ_crypto_add_entropy(unsigned char *data, size_t data_len)
{
    void		*ctx;

    if ((NULL == data) || (0 == data_len)) {
	return;
    }

    //#ifdef	ebug
    //MASQ_dump(data, data_len, "Entropy input", '@', 1);
    //#endif

    // add this to what may already be there
    ctx = MASQ_hash_init(_rand_extra, sizeof(_rand_extra));
    MASQ_hash_add(ctx, data, data_len, _rand_extra, sizeof(_rand_extra));
    _rbias = 0;	// might as well reset this

    //#ifdef	ebug
    //MASQ_dump(_rand_extra, sizeof(_rand_extra), "Extra", '@', 1);
    //#endif
}

static int delete_topic(MASQ_topic_t **head, MASQ_topic_t *topic);

static void
crypto_state_free(void *state)
{
    masq_crypto_state	*s = (masq_crypto_state *) state;
    int	i;
    
    if (NULL == state) {
#ifdef	ebug
	printf("%s(%p)\n", __FUNCTION__, state);
#endif
	return;
    }
    DEBUG(s, 0, ("%s(%p)\n", __FUNCTION__, state));
    while (NULL != s->topicp) {
	DEBUG(s, 0, ("    top delete(%s %s %08lx)\n", s->topicp->topic,
		     s->topicp->mek_seq, s->topicp->next_seqnum));
	delete_topic(&s->topicp, s->topicp);
    }
    while (NULL != s->pub_mek) {
	DEBUG(s, 0, ("    pub delete(%s %s %s)\n", s->pub_mek->topic,
		     s->pub_mek->expdate, s->pub_mek->seqnum));
	MASQ_KS_delete(&s->pub_mek, s->pub_mek);
    }
    while (NULL != s->sub_mek) {
	DEBUG(s, 0, ("    sub delete(%s %s %s)\n", s->sub_mek->topic,
		     s->sub_mek->expdate, s->sub_mek->seqnum));
	MASQ_KS_delete(&s->sub_mek, s->sub_mek);
    }
    for (i = 0; i < KMS_data_num_fields; i++) {
	if (NULL != s->pub_params.data[i].ptr) {
	    DEBUG(s, 0, ("    params delete(%d)\n", i));
	    free(s->pub_params.data[i].ptr);
	}
    }
    if (NULL != s->tls_ctx) {
	DEBUG(s, 0, ("%stls_ctx free()\n", _tls));
	wolfSSL_CTX_free(s->tls_ctx);
    }
    memset(state, 0xcc, sizeof(masq_crypto_state));
    free(state);
}

void
MASQ_crypto_close(void *state)
{
    DEBUG(((masq_crypto_state *) state), 0, ("%s(%p)\n", __FUNCTION__, state));
    
    crypto_state_free(state);
    wolfSSL_Cleanup();
    MC_crypto_close();
}

int
MASQ_rand_bytes(unsigned char *buf, size_t len)
{
    size_t	i;

    MC_rand_bytes(buf, len);

    // mix in accumlated entropy
    for (i = 0; i < len; i++) {
	buf[i] ^= _rand_extra[(_rbias + i) % sizeof(_rand_extra)];
    }
    _rbias = (_rbias + len) % sizeof(_rand_extra);

    return 1;
}

static const char	*_alpha =
    "0123456789"
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

#define	ALPHA_LEN	(62)

int
MASQ_rand_clientid(unsigned char *buf, size_t len)
{
    uint64_t		rand;
    size_t		i, n;
    char		*cp = buf;

    if ((NULL == buf) || (len < (MASQ_CLIENTID_LEN + 1))) {
	return 0;
    }
    
    for (i = n = 0; i < MASQ_CLIENTID_LEN; i++) {
	if (0 == n) {
	    MASQ_rand_bytes((unsigned char *) &rand, sizeof(rand));
	    n = sizeof(rand);	// this undershoots number of available bits
	}
	*cp++ = _alpha[rand % ALPHA_LEN];
	rand /= ALPHA_LEN;
	n--;
    }
    *cp = '\0';
    
    return 1;
}

int
MASQ_hash(unsigned char *inbuf, size_t inlen,
	  unsigned char *outbuf, size_t outlen)
{
    // just a pass-through
    return MC_hash(inbuf, inlen, outbuf, outlen);
}

void *
MASQ_hash_init(unsigned char *inbuf, size_t inlen)
{
    // just a pass-through
    return MC_hash_init(inbuf, inlen);
}

int
MASQ_hash_add(void *ctx,
	      unsigned char *inbuf, size_t inlen,
	      unsigned char *outbuf, size_t outlen)
{
    // just a pass-through
    return MC_hash_add(ctx, inbuf, inlen, outbuf, outlen);
}

#ifdef	ebug
static void
MASQ_crypto_dump_keys(unsigned char *init,
		      char *seq,
		      unsigned char *mek)
{
    int	i;
    if ((NULL == init) || (NULL == mek)) {
	return;
    }
    printf("    \u2023 init ");
    for (i = 0; i < MASQ_AESKEY_LEN; i++) printf("%02x", init[i]);
    printf("\n  + \u2023 seq  %s\n  = \u2023 mek  ", seq);
    for (i = 0; i < MASQ_AESKEY_LEN; i++) printf("%02x", mek[i]);
    printf("\n");
}
#endif

void
MASQ_crypto_pkt_mek(unsigned char *init,
		    char *seqnum,
		    unsigned char *outbuf)
{
    void		*ctx;
    unsigned char	hash[MASQ_HASH_LEN];

    ctx = MASQ_hash_init(seqnum, MASQ_SEQNUM_LEN);
    MASQ_hash_add(ctx, init, MASQ_AESKEY_LEN, hash, sizeof(hash));
    memcpy((void *) outbuf, hash, MASQ_AESKEY_LEN);
    memset((void *) hash, 0, sizeof(hash));
#ifdef	ebug
    MASQ_crypto_dump_keys(init, seqnum, outbuf);
#endif
}

/**
 * Find a topic struct in the current state.
 *
 * @param[in] s Crypto state.
 * @param[in] topic Topic Name, '\0'-terminated.
 * @return Topic struct if found, else NULL
 */
static MASQ_topic_t *
get_topic(masq_crypto_state *s, char *topic)
{
    MASQ_topic_t	*ret;

    DEBUG(s, 0, ("%s(%p)\n", __FUNCTION__, s));

    for (ret = s->topicp; NULL != ret; ret = ret->next) {
	if (! strncmp(ret->topic, topic, sizeof(ret->topic))) {
	    break;
	}
    }
    return ret;
}

/**
 * Delete a topic
 *
 * @param[in,out] head Head of topic list, updated as needed
 * @param[in] topic Topic to delete
 * @return 1 if topic found and deleted, else 0
 */
static int
delete_topic(MASQ_topic_t **head,
	     MASQ_topic_t *topic)
{
    MASQ_topic_t	*p, *q;

    for (p = q = *head; NULL != p; q = p, p = p->next) {
	if (p == topic) {
	    if (q == *head) {
		*head = p->next;
	    } else {
		q->next = p->next;
	    }
	    memset((void *) p, 0x3c, sizeof(MASQ_topic_t));
	    free(p);
	    return 1;
	}
    }
    return 0;
}

MASQ_status_t
MASQ_get_topic_mek_seqnum(masq_crypto_state *s, char *topic,
			  char *seqnum, size_t seqnum_len)
{
    MASQ_topic_t	*t;
    if ((NULL == s) || (NULL == topic) || (NULL == seqnum) ||
	(seqnum_len < (MASQ_SEQNUM_LEN+1))) {
	return MASQ_ERR_INVAL;
    }

    DEBUG(s, 0, ("%s(%s)\n", __FUNCTION__, topic));

    t = get_topic(s, topic);
    if (NULL == t) {
	DEBUG(s, 0, ("%s() topic not found\n", __FUNCTION__));
	return MASQ_ERR_NOT_FOUND;
    }
    
    strncpy(seqnum, t->mek_seq, seqnum_len);
    DEBUG(s, 0, ("%s() returning %s\n", __FUNCTION__, seqnum));
    return MASQ_STATUS_SUCCESS;
}

int
MASQ_check_stored_packet(masq_crypto_state *s, char *topic,
			 MASQ_user_properties_t *user_props,
			 void **buffer, size_t *buffer_len)
{
    MASQ_topic_t	*t;
    if ((NULL == s) || (NULL == topic) || (NULL == user_props) ||
	(NULL == buffer) || (NULL == buffer_len)) {
	return 0;
    }
    t = get_topic(s, topic);
    if (NULL == t) {
	return 0;
    }
    if (! t->stored_packet) {
	return 0;
    }

    // return packet contents
    memcpy((void *) user_props, (void *) &t->user_props, sizeof(t->user_props));
    *buffer = t->payload;
    *buffer_len = t->payload_len;

    // clean out topic
    t->stored_packet = 0;
    memset((void *) &t->user_props, 0, sizeof(t->user_props));
    t->payload = NULL;
    t->payload_len = 0;

    return 1;
}

MASQ_status_t
MASQ_store_packet(masq_crypto_state *s, char *topic,
		  MASQ_user_properties_t *user_props,
		  void *buffer, size_t buffer_len)
{
    MASQ_topic_t	*t;
    int			n;
    if ((NULL == s) || (NULL == topic) || (NULL == user_props) ||
	(NULL == buffer)) {
	return MASQ_ERR_INVAL;
    }
    if (user_props->num_props > MASQ_MAX_PROPERTIES) {
	return MASQ_ERR_INVAL;
    }
    t = get_topic(s, topic);
    if (NULL == t) {
	return MASQ_ERR_NOT_FOUND;
    }
    
    t->stored_packet = 1;
    // store packet contents
    memset((void *) &t->user_props, 0, sizeof(t->user_props));
    for (n = 0; n < user_props->num_props; n++) {
	// clean copy from user
	strncpy(t->user_props.prop[n].name, user_props->prop[n].name,
		sizeof(t->user_props.prop[n].name));
	strncpy(t->user_props.prop[n].value, user_props->prop[n].value,
		sizeof(t->user_props.prop[n].value));
    }
    t->user_props.num_props = user_props->num_props;
    t->payload = buffer;
    t->payload_len = buffer_len;

    return MASQ_STATUS_SUCCESS;
}

/**
 * Allocate a new Topic and link it to the state.
 *
 * @param[in] s Crypto state.
 * @param[in] topic Topic Name, '\0'-terminated.
 * @param[out] t New topic struct.
 * @return MASQ_STATUS_SUCCESS on success, else error.
 */
static MASQ_status_t
new_topic(masq_crypto_state *s, char *topic, MASQ_topic_t **t)
{
    MASQ_topic_t	*ret = calloc(1, sizeof(MASQ_topic_t));
    unsigned int	seq;

    DEBUG(s, 0, ("%s(%p, %s)\n", __FUNCTION__, s, topic));
    if (NULL == ret) {
	DEBUG(s, 0, ("%s:%d returning ERR_NOMEM\n", __FUNCTION__, __LINE__));
	return MASQ_ERR_NOMEM;
    }

    if ((NULL == s) || (NULL == topic) || (NULL == t)) {
	DEBUG(s, 0, ("%s:%d returning ERR_INVAL\n", __FUNCTION__, __LINE__));
	return MASQ_ERR_INVAL;
    }

    // fill in what we can
    strncpy(ret->topic, topic, sizeof(ret->topic));
    ret->new_seq = ret->next_seqnum = 0;
    if ((MASQ_role_publisher == s->role) || (MASQ_role_both == s->role)) {
	if (MASQ_key_ephemeral == s->strat) {
	    ret->new_seq = 1;
	}
	MASQ_rand_bytes((unsigned char *) &seq, sizeof(seq));
	ret->next_seqnum = seq & 0xffffffff;
    }
    ret->mek_seq[0] = '\0';
    ret->stored_packet = 0;
    ret->payload = NULL;
    ret->payload_len = 0;
	
    // link it into the state
    ret->next = s->topicp;
    s->topicp = ret;
    *t = ret;

    return MASQ_STATUS_SUCCESS;
}

/**
 * Represent pub_params from crypto state as MIRACL octet for IBE code.
 *
 * @param[in] s Crypto state.
 * @return Pointer to static octet struct.
 */
static BB1_pubparams *
pub_params(masq_crypto_state *s)
{
    static octet		R, T, V;
    static BB1_pubparams	PP = { .R = &R, .T = &T, .V = &V };

    R.val = (char *) s->pub_params.data[0].ptr;
    R.len = R.max = (int) s->pub_params.data[0].len;
    T.val = (char *) s->pub_params.data[1].ptr;
    T.len = T.max = (int) s->pub_params.data[1].len;
    V.val = (char *) s->pub_params.data[2].ptr;
    V.len = V.max = (int) s->pub_params.data[2].len;

    return &PP;
}

#define	ID_LEN	(MASQ_CLIENTID_LEN + MASQ_EXPDATE_LEN + MASQ_MAXTOPIC_LEN + 3)

int
MASQ_pers_new_key(void *state, masq_crypto_parms *p)
{
    masq_crypto_state	*s = (masq_crypto_state *) state;
    MASQ_topic_t	*t;
    int			retv = 1;
    char		curbuf[MASQ_EXPDATE_LEN+1];
    char		id_buf[ID_LEN];
    octet		ID;
    MASQ_status_t	status;
    octet		*MEK = NULL;
    BB1_encaps		*ENC_KEY = NULL;

    MASQ_KS_mek_t	*mp;

    DEBUG(((masq_crypto_state *) state), 0, ("%s(%p)\n", __FUNCTION__, state));

    if ((NULL == state) || (NULL == p)
	|| (NULL == p->t_name) || (strlen(p->t_name) > MASQ_MAXTOPIC_LEN)
	// || (NULL == p->t_value)
	// || (NULL == p->t_value_len) || (*(p->t_value_len) > MASQ_MAXTOPIC_LEN)
	|| (NULL == p->client_id) || (strlen(p->client_id) != MASQ_CLIENTID_LEN)
	|| (NULL == p->seq) || (p->seq_len < MASQ_SEQNUM_LEN + 1)
	|| (NULL == p->exp_date) || (p->exp_date_len < MASQ_EXPDATE_LEN + 1)
	|| (NULL == p->mek) || (p->mek_len < MASQ_AESKEY_LEN)
	|| (NULL == p->payload) || (NULL == p->payload_len)
	|| (*(p->payload_len) < MASQ_ENCAPS_KEY_LEN)
	) {
	if (p->debug) {
	    DEBUG(((masq_crypto_state *) state), 0, ("%s: arg error\n",
						     __FUNCTION__));
	    MASQ_dump_crypto_parms(p, __FUNCTION__);
	}
	return 0;
    }

    if (NULL == (t = get_topic(s, p->t_name))) {
	if (MASQ_STATUS_SUCCESS != new_topic(s, p->t_name, &t)) {
	    DEBUG(s, 0, ("%s:%d returning 0\n", __FUNCTION__, __LINE__));
	    return 0;
	}
    }

    if (s->need_exp) {
	get_time(s, curbuf, s->expdate, s->nextexp);
	DEBUG(s, 0, ("%s:%d got time at %s\n", __FUNCTION__, __LINE__, curbuf));
	strncpy(p->exp_date, s->expdate, MASQ_EXPDATE_LEN+1);
	s->need_exp = 0;
    }
    
    snprintf(id_buf, sizeof(id_buf), "%s:%s:%s",
	     p->t_name, p->exp_date, p->client_id);
    DEBUG(s, 0, ("%s:%d [%s]\n", __FUNCTION__, __LINE__, id_buf));

    // set up BB1 params
    ID.val = id_buf;
    ID.len = ID.max = strlen(id_buf);
    MEK = OCT_new(BB1_AESKEYLEN);
    ENC_KEY = BB1_encaps_new(BBFS_BN254);
    if ((NULL == MEK) || (NULL == ENC_KEY)) {
	retv = 0;
	goto pers_new_out;
    }
    
    if (MASQ_STATUS_SUCCESS !=
	(status = BB1_encapsulate_key(pub_params(s), &ID, MEK, ENC_KEY))) {
	DEBUG(s, 0, ("%s:%d ret %s\n", __FUNCTION__, __LINE__,
		     MASQ_status_to_str(status)));
	retv = 0;
	goto pers_new_out;
    }

    // stash MEK for future use
    next_seqnum(t, p->seq, p->seq_len);
    strncpy(t->mek_seq, p->seq, p->seq_len);

    if (p->debug) {
	char	buf[80];
	snprintf(buf, sizeof(buf), "MASQ_pers_new_key mek for %s", t->mek_seq);
	MASQ_dump(MEK->val, MEK->len, buf, 0, 1);
    }

    mp = MASQ_KS_new(&s->pub_mek,
		     p->t_name,
		     p->exp_date,
		     p->seq,
		     NULL, // p->client_id,
		     s->strat, s->strat_max,
		     NULL,
		     MEK->val, MEK->len);
    if (NULL == mp) {
	retv = 0;
	goto pers_new_out;
    }
    // return MEK
    memcpy((void *) p->mek, (void *) MEK->val, (size_t) MEK->len);

    // build payload
    memcpy((void *) p->payload,
	   (void *) ENC_KEY->E0->val, (size_t) ENC_KEY->E0->len);
    memcpy((void *) &p->payload[ENC_KEY->E0->len],
	   (void *) ENC_KEY->E1->val, (size_t) ENC_KEY->E1->len);
    *(p->payload_len) = MASQ_ENCAPS_KEY_LEN;

 pers_new_out:
    BB1_encaps_free(ENC_KEY);
    OCT_free(MEK);

    return retv;
    
} // end MASQ_pers_new_key

int
MASQ_pers_recover_key(void *state,
		      masq_crypto_parms *p)
{
    masq_crypto_state	*s = (masq_crypto_state *) state;
    int			retv = 1;
    MASQ_status_t	status;
    octet		CT;
    char		id_buf[ID_LEN];
    octet		ID;
    octet		*MEK = NULL;
    BB1_puk		*PUK = NULL;

    MASQ_KS_mek_t	*mp;

    DEBUG(s, 0, ("%s(%p)\n", __FUNCTION__, state));

    if ((NULL == state) || (NULL == p)
	|| (NULL == p->t_name) || (strlen(p->t_name) > MASQ_MAXTOPIC_LEN)
	// || (NULL == p->t_value)
	// || (NULL == p->t_value_len) || (*(p->t_value_len) > MASQ_MAXTOPIC_LEN)
	|| (NULL == p->client_id) || (strlen(p->client_id) != MASQ_CLIENTID_LEN)
	|| (NULL == p->seq) // || (p->seq_len < MASQ_SEQNUM_LEN + 1)
	|| (NULL == p->exp_date) || (p->exp_date_len < MASQ_EXPDATE_LEN + 1)
	|| (NULL == p->payload) || (NULL == p->payload_len)
	|| (*(p->payload_len) < MASQ_ENCAPS_KEY_LEN)
	) {
	if (p->debug) {
	    DEBUG(((masq_crypto_state *) state), 0, ("%s: arg error\n",
						     __FUNCTION__));
	    MASQ_dump_crypto_parms(p, __FUNCTION__);
	}
	return 0;
    }

    // don't do extra math if we already have it
    if (NULL != (mp = MASQ_KS_find_mek(s->sub_mek,
				       p->t_name,
				       p->exp_date,
				       p->seq,
				       p->client_id))) {

	// return cached MEK
	if ((NULL != p->mek) && (sizeof(p->mek) <= p->mek_len)) {
	    memcpy((void *) p->mek, (void *) p->mek, sizeof(p->mek));
	}
	return 1;
    }

    // get_private will retrieve appropirate key cache entry or create one
    // as needed
    if (! get_private(s,
		      p->client_id,
		      p->t_name,
		      p->exp_date,
		      &mp)) {
	// ?
	DEBUG(s, 0, ("%s():%d get_private() failed\n", __FUNCTION__, __LINE__));
	return 0;
    }

    snprintf(id_buf, sizeof(id_buf), "%s:%s:%s",
	     p->t_name, p->exp_date, p->client_id);
    DEBUG(s, 0, ("%s:%d [%s]\n", __FUNCTION__, __LINE__, id_buf));

    // set up BB1 params
    ID.val = id_buf;
    ID.len = ID.max = (int) strlen(id_buf);
    CT.val = p->payload;
    CT.len = CT.max = (int) *p->payload_len;
    PUK = BB1_puk_new(BBFS_BN254);
    MEK = OCT_new(BB1_AESKEYLEN);
    if ((NULL == PUK) || (NULL == MEK)) {
	retv = 0;
	goto pers_rec_out;
    }
    // copy PUK from cache
    OCT_jbytes(PUK->K0M,
	       (char *) mp->puk.data[0].ptr, (int) mp->puk.data[0].len);
    OCT_jbytes(PUK->K1M,
	       (char *) mp->puk.data[1].ptr, (int) mp->puk.data[1].len);
    
    if (MASQ_STATUS_SUCCESS !=
	(status = BB1_decapsulate_key(PUK, &ID, &CT, MEK))) {
	DEBUG(s, 0, ("%s:%d ret %s\n", __FUNCTION__, __LINE__,
		     MASQ_status_to_str(status)));
	retv = 0;
	goto pers_rec_out;
    }

    // update key cache entry
    strncpy(mp->seqnum, p->seq, MASQ_SEQNUM_LEN+1);
    memcpy((void *) mp->mek, (void *) MEK->val, (size_t) MEK->len);

    // return MEK
    if ((NULL != p->mek) && (MEK->len <= p->mek_len)) {
	memcpy((void *) p->mek, (void *) MEK->val, (size_t) MEK->len);
    }

 pers_rec_out:
    BB1_puk_free(PUK);
    OCT_free(MEK);

    return retv;
    
} // end MASQ_pers_recover_key

int
MASQ_pers_encrypt(void *state, masq_crypto_parms *p)
{
    masq_crypto_state	*s = (masq_crypto_state *) state;
    MASQ_topic_t	*t;
    MC_aesgcm_params	ep;
    unsigned char	mek[MASQ_AESKEY_LEN];

    DEBUG(s, 0, ("%s(%p)\n", __FUNCTION__, state));

    if ((NULL == state) || (NULL == p)
	// || (NULL == p->t_name) || (strlen(p->t_name) > MASQ_MAXTOPIC_LEN)
	|| (NULL == p->t_value)
	|| (NULL == p->t_value_len) || (*(p->t_value_len) > MASQ_MAXTOPIC_LEN)
	//|| (NULL == p->client_id) || (strlen(p->client_id) != MASQ_CLIENTID_LEN)
	|| (NULL == p->seq) || (p->seq_len < MASQ_SEQNUM_LEN + 1)
	//|| (NULL == p->exp_date) || (p->exp_date_len < MASQ_EXPDATE_LEN + 1)
	//|| (NULL == p->pp_exp) || (p->pp_exp_len < MASQ_EXPDATE_LEN + 1)
	|| (NULL == p->mek) || (p->mek_len < MASQ_AESKEY_LEN)
	|| (NULL == p->payload) || (NULL == p->payload_len)
	|| (*(p->payload_len) < MASQ_PAYLOAD_LEN_PER(*(p->t_value_len)))
	) {
	if (p->debug) {
	    DEBUG(((masq_crypto_state *) state), 0, ("%s: arg error\n",
						     __FUNCTION__));
	    MASQ_dump_crypto_parms(p, __FUNCTION__);
	}
	return 0;
    }

    if (NULL == (t = get_topic(s, p->t_name))) {
	DEBUG(((masq_crypto_state *) state), 0, ("%s() bailing at %d\n",
						 __FUNCTION__, __LINE__ - 1));
	return 0;
    }

    next_seqnum(t, p->seq, p->seq_len);
    // combine MEK with seqnum
    MASQ_crypto_pkt_mek(p->mek, p->seq, mek);

    // encrypt Topic Value
    ep.key = mek; ep.key_len = MASQ_AESKEY_LEN;
    MASQ_rand_bytes(p->payload, MASQ_IV_LEN);
    if (t->new_seq) {
	seq_to_binary(p->payload, p->seq);
	t->new_seq = 0;
    }
    ep.iv  = p->payload; ep.iv_len = MASQ_IV_LEN;
    ep.hdr = (unsigned char *) p->seq; ep.hdr_len = MASQ_SEQNUM_LEN;
    ep.pt  = p->t_value; ep.pt_len = *(p->t_value_len);
    ep.ct  = &p->payload[MASQ_IV_LEN];
    ep.ct_len = ep.pt_len;
    ep.tag = &p->payload[MASQ_IV_LEN + ep.ct_len];
    ep.tag_len = MASQ_TAG_LEN;
    *(p->payload_len) = MASQ_PAYLOAD_LEN_PER(ep.pt_len);
    return MC_AESGCM_encrypt(&ep);
    
} // end MASQ_pers_encrypt

int
MASQ_pers_decrypt(void *state, masq_crypto_parms *p)
{
    MC_aesgcm_params	ep;
    unsigned char	mek[MASQ_AESKEY_LEN];

    DEBUG(((masq_crypto_state *) state), 0, ("%s(%p)\n", __FUNCTION__, state));

    if ((NULL == state) || (NULL == p)
	// || (NULL == p->t_name) || (strlen(p->t_name) > MASQ_MAXTOPIC_LEN)
	|| (NULL == p->t_value)
	|| (NULL == p->t_value_len) // || (*(p->t_value_len) > MASQ_MAXTOPIC_LEN)
	|| (NULL == p->client_id) || (strlen(p->client_id) != MASQ_CLIENTID_LEN)
	|| (NULL == p->seq) || (p->seq_len < MASQ_SEQNUM_LEN + 1)
	|| (NULL == p->exp_date) || (p->exp_date_len < MASQ_EXPDATE_LEN + 1)
	// || (NULL == p->pp_exp) || (p->pp_exp_len < MASQ_EXPDATE_LEN + 1)
	|| (NULL == p->mek) || (p->mek_len < MASQ_AESKEY_LEN)
	|| (NULL == p->payload) || (NULL == p->payload_len)
	|| (*(p->t_value_len) < MASQ_VALUE_LEN_PER(*(p->payload_len)))
	) {
	if (p->debug) {
	    DEBUG(((masq_crypto_state *) state), 0, ("%s: arg error\n",
						     __FUNCTION__));
	    MASQ_dump_crypto_parms(p, __FUNCTION__);
	}
	return 0;
    }

    if (iv_is_new_seq(p->payload, p->seq)) {
	DEBUG(((masq_crypto_state *) state), 0,
	      ("%s() -- NEW SEQUENCE\n", __FUNCTION__));
    }
    
    // combine MEK with seqnum
    MASQ_crypto_pkt_mek(p->mek, p->seq, mek);
    
    // decrypt Topic Value
    ep.key = mek; ep.key_len = MASQ_AESKEY_LEN;
    ep.iv  = p->payload; ep.iv_len = MASQ_IV_LEN;
    ep.hdr = (unsigned char *) p->seq; ep.hdr_len = MASQ_SEQNUM_LEN;
    ep.pt  = p->t_value; ep.pt_len = MASQ_VALUE_LEN_PER(*(p->payload_len));
    ep.ct  = &p->payload[MASQ_IV_LEN];
    ep.ct_len = ep.pt_len;
    ep.tag = &p->payload[MASQ_IV_LEN + ep.ct_len];
    ep.tag_len = MASQ_TAG_LEN;
    *(p->t_value_len) = ep.pt_len;
    return MC_AESGCM_decrypt(&ep);
    
} // end MASQ_pers_decrypt

int
MASQ_ephem_encrypt(void *state, masq_crypto_parms *p)
{
    masq_crypto_state	*s = (masq_crypto_state *) state;
    MASQ_status_t	status;
    MASQ_topic_t	*t;
    int			retv = 1;
    char		curbuf[MASQ_EXPDATE_LEN+1];
    char		id_buf[ID_LEN];
    octet		ID;
    octet		*MEK = NULL;
    BB1_encaps		*ENC_KEY = NULL;

    unsigned char	div[MASQ_IV_LEN];	//!< data encryption IV
    MC_aesgcm_params	ep;

    DEBUG(s, 0, ("%s(%p)\n", __FUNCTION__, state));

    if ((NULL == state) || (NULL == p)
	|| (NULL == p->t_name) || (strlen(p->t_name) > MASQ_MAXTOPIC_LEN)
	|| (NULL == p->t_value)
	|| (NULL == p->t_value_len) || (*(p->t_value_len) > MASQ_MAXTOPIC_LEN)
	|| (NULL == p->client_id) || (strlen(p->client_id) != MASQ_CLIENTID_LEN)
	|| (NULL == p->seq) || (p->seq_len < MASQ_SEQNUM_LEN + 1)
	|| (NULL == p->exp_date) || (p->exp_date_len < MASQ_EXPDATE_LEN + 1)
	// || (NULL == p->mek) || (p->mek_len < MASQ_AESKEY_LEN)
	|| (NULL == p->payload) || (NULL == p->payload_len)
	|| (*(p->payload_len) < MASQ_PAYLOAD_LEN_EPH(*(p->t_value_len)))
	) {
	if (p->debug) {
	    DEBUG(s, 0, ("%s: arg error\n", __FUNCTION__));
	    MASQ_dump_crypto_parms(p, __FUNCTION__);
	}
	return 0;
    }

    s = (masq_crypto_state *) state;
    
    if (NULL == (t = get_topic(s, p->t_name))) {
	if (MASQ_STATUS_SUCCESS != new_topic(s, p->t_name, &t)) {
	    DEBUG(s, 0, ("%s:%d returning 0\n", __FUNCTION__, __LINE__));
	    return 0;
	}
    }

    if (s->need_exp) {
	get_time(s, curbuf, s->expdate, s->nextexp);
	DEBUG(s, 0, ("%s:%d got time at %s\n", __FUNCTION__, __LINE__, curbuf));
	s->need_exp = 0;
    }
    strncpy(p->exp_date, s->expdate, MASQ_EXPDATE_LEN+1);
    
    snprintf(id_buf, sizeof(id_buf), "%s:%s:%s",
	     p->t_name, p->exp_date, p->client_id);
    DEBUG(s, 0, ("%s:%d [%s]\n", __FUNCTION__, __LINE__, id_buf));

    // set up BB1 params
    ID.val = id_buf;
    ID.len = ID.max = strlen(id_buf);
    MEK = OCT_new(BB1_AESKEYLEN);
    ENC_KEY = BB1_encaps_new(BBFS_BN254);
    if ((NULL == MEK) || (NULL == ENC_KEY)) {
	retv = 0;
	goto ephem_enc_out;
    }
    
    if (MASQ_STATUS_SUCCESS !=
	(status = BB1_encapsulate_key(pub_params(s), &ID, MEK, ENC_KEY))) {
	DEBUG(s, 0, ("%s:%d ret %s\n", __FUNCTION__, __LINE__,
		     MASQ_status_to_str(status)));
	retv = 0;
	goto ephem_enc_out;
    }

    MASQ_rand_bytes(div, sizeof(div));
    next_seqnum(t, p->seq, p->seq_len);
    if (t->new_seq) {
	MASQ_dump(div, sizeof(div), "new seq before", '$', 1);
	seq_to_binary(div, p->seq);
	MASQ_dump(div, sizeof(div), "new seq after", '$', 1);
	t->new_seq = 0;
    }

    // build payload
    memcpy((void *) p->payload,
	   (void *) ENC_KEY->E0->val, (size_t) ENC_KEY->E0->len);
    memcpy(&p->payload[ENC_KEY->E0->len],
	   (void *) ENC_KEY->E1->val, (size_t) ENC_KEY->E1->len);
    memcpy((void *) &p->payload[MASQ_ENCAPS_KEY_LEN],
	   (void *) div, MASQ_IV_LEN);
    
    // encrypt Topic Value
    ep.key = MEK->val; ep.key_len = (size_t) MEK->len;
    ep.iv  = div; ep.iv_len = MASQ_IV_LEN;
    ep.hdr = (unsigned char *) p->seq; ep.hdr_len = MASQ_SEQNUM_LEN;
    ep.pt  = p->t_value; ep.pt_len = *(p->t_value_len);
    ep.ct = &p->payload[MASQ_ENCAPS_KEY_LEN + MASQ_IV_LEN];
    ep.ct_len = ep.pt_len;
    ep.tag = &p->payload[MASQ_ENCAPS_KEY_LEN + MASQ_IV_LEN + ep.ct_len];
    ep.tag_len = MASQ_TAG_LEN;
    MC_AESGCM_encrypt(&ep);
    *(p->payload_len) = MASQ_PAYLOAD_LEN_EPH(ep.pt_len);

 ephem_enc_out:
    BB1_encaps_free(ENC_KEY);
    OCT_free(MEK);
    
    return retv;
    
} // end MASQ_ephem_encrypt

int
MASQ_ephem_decrypt(void *state, masq_crypto_parms *p)
{
    masq_crypto_state	*s = (masq_crypto_state *) state;
    MASQ_status_t	status;
    int			retv = 1;
    char		id_buf[ID_LEN];
    octet		ID;
    octet		CT;
    octet		*MEK = NULL;
    BB1_puk		*PUK = NULL;

    MASQ_KS_mek_t	*mp;
    MC_aesgcm_params	ep;

#ifdef	ebug
    DEBUG(s, 0, ("%s(%p)\n", __FUNCTION__, state));
#else
    UNUSED(s);
#endif

    if ((NULL == p)
	|| (NULL == p->t_name) || (strlen(p->t_name) > MASQ_MAXTOPIC_LEN)
	|| (NULL == p->t_value)
	|| (NULL == p->t_value_len) || (*(p->t_value_len) > MASQ_MAXTOPIC_LEN)
	|| (NULL == p->client_id) || (strlen(p->client_id) != MASQ_CLIENTID_LEN)
	|| (NULL == p->seq) // || (p->seq_len < MASQ_SEQNUM_LEN)
	|| (NULL == p->exp_date) || (p->exp_date_len < MASQ_EXPDATE_LEN)
	// || (NULL == p->mek) || (p->mek_len < MASQ_AESKEY_LEN)
	|| (NULL == p->payload) || (NULL == p->payload_len)
	|| (*(p->payload_len) < MASQ_VALUE_LEN_EPH(*(p->payload_len)))
	) {
	if (p->debug) {
	    DEBUG(((masq_crypto_state *) state), 0, ("%s:%d arg error\n",
						     __FUNCTION__, __LINE__-1));
	    MASQ_dump_crypto_parms(p, __FUNCTION__);
	}
	return 0;
    }

    if (! get_private(s,
		      p->client_id,
		      p->t_name,
		      p->exp_date,
		      &mp)) {
	// ?
	DEBUG(s, 0, ("%s():%d get_private() failed\n", __FUNCTION__, __LINE__));
	return 0;
    }

    snprintf(id_buf, sizeof(id_buf), "%s:%s:%s",
	     p->t_name, p->exp_date, p->client_id);
    DEBUG(s, 0, ("%s:%d [%s]\n", __FUNCTION__, __LINE__, id_buf));

    // set up BB1 params
    ID.val = id_buf;
    ID.len = ID.max = (int) strlen(id_buf);
    CT.val = p->payload;
    CT.len = CT.max = MASQ_ENCAPS_KEY_LEN;
    PUK = BB1_puk_new(BBFS_BN254);
    MEK = OCT_new(BB1_AESKEYLEN);
    if ((NULL == PUK) || (NULL == MEK)) {
	retv = 0;
	goto ephem_dec_out;
    }
    OCT_jbytes(PUK->K0M,
	       (char *) mp->puk.data[0].ptr, (int) mp->puk.data[0].len);
    OCT_jbytes(PUK->K1M,
	       (char *) mp->puk.data[1].ptr, (int) mp->puk.data[1].len);
    
    if (MASQ_STATUS_SUCCESS !=
	(status = BB1_decapsulate_key(PUK, &ID, &CT, MEK))) {
	DEBUG(s, 0, ("%s:%d ret %s\n", __FUNCTION__, __LINE__,
		     MASQ_status_to_str(status)));
	retv = 0;
	goto ephem_dec_out;
    }
    BB1_puk_free(PUK); PUK = NULL;

    if (iv_is_new_seq(&p->payload[MASQ_ENCAPS_KEY_LEN], p->seq)) {
	DEBUG(((masq_crypto_state *) state), 0,
	      ("%s() -- NEW SEQUENCE\n", __FUNCTION__));
    }

    // decrypt Topic Value
    ep.key = MEK->val; ep.key_len = (size_t) MEK->len;
    ep.iv  = &p->payload[MASQ_ENCAPS_KEY_LEN]; ep.iv_len = MASQ_IV_LEN;
    ep.hdr = (unsigned char *) p->seq; ep.hdr_len = MASQ_SEQNUM_LEN;
    ep.pt  = p->t_value; ep.pt_len = MASQ_VALUE_LEN_EPH(*(p->payload_len));
    ep.ct  = &p->payload[MASQ_ENCAPS_KEY_LEN + MASQ_IV_LEN];
    ep.ct_len = ep.pt_len;
    ep.tag = &p->payload[MASQ_ENCAPS_KEY_LEN + MASQ_IV_LEN + ep.ct_len];
    ep.tag_len = MASQ_TAG_LEN;
    MC_AESGCM_decrypt(&ep);
    *(p->t_value_len) = ep.pt_len;

 ephem_dec_out:
    BB1_puk_free(PUK); PUK = NULL;
    OCT_free(MEK);
    
    return retv;
    
} // end MASQ_ephem_decrypt
