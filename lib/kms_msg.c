/**
 * @file kms_msg.c
 * KMS packet parsing functions. See the detailed overview in @ref kms_msg.h.
 *
 * When the `Makefile` includes `-Debug` on the `CFLAGS_EXTRA` line, the
 * result is an executable that does a quick sanity check on each of the
 * calls exposed in @ref kms_packet.h.
 */

// Function calls are documented once in kms_packet.h to avoid duplication
// and drift. Doxygen helpfully includes them in this listing.

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "masqlib.h"
#include "kms_msg.h"
#include "kms_utils.h"

const char *
KMS_error_string(int error)
{
    static char	errbuf[80];
    switch (error) {
#undef	_X
#define	_X(x)	case KMS_ERR_ ## x: return #x
    _X(SUCCESS);
    _X(INVAL);
    _X(NOMEM);
    _X(NOSPACE);
    _X(CRYPTO);
    _X(MALFORMED_PACKET);
    _X(MALFORMED_UTF8);
    _X(PAYLOAD_SIZE);
    _X(WRONG_MSG_TYPE);
    _X(INTERNAL);
#undef	_X
    }
    snprintf(errbuf, sizeof(errbuf), "Unknown error (%d)", error);
    return errbuf;
}

const char *
KMS_reason_string(int reason_code)
{
    switch (reason_code) {
    case KMS_REASON_SUCCESS:
        return "Success";
    case KMS_REASON_ERR:
        return "Unspecified error";
    case KMS_REASON_PROTO_ERR:
        return "ProtoID not recognized/supported";
    case KMS_REASON_CLIENTID_ERR:
        return "ClientID not recognized by KMS";
    case KMS_REASON_OTHCLID_ERR:
        return "Other ClientID not recognized by KMS";
    case KMS_REASON_CLENT_AUTH_ERR:
        return "ClientID/TLS creds mismatch";
    case KMS_REASON_KEY_EXP_ERR:
        return "Expiration date not recognized";
    case KMS_REASON_PUB_AUTH_ERR:
        return "Publisher not authorized to publish Topic";
    case KMS_REASON_SUB_AUTH_ERR:
        return "Subscriber not authorized to receive Topic";
    case KMS_REASON_CLIENT_AUTH_ERR:
        return "Client not authorized";
    case KMS_REASON_UNAUTH_REQ_ERR:
        return "Policy prohibits this request from Client";
    }
    return "Unknown reason";
}

static void
clear_time(KMS_time_t *time)
{
    int	i;
    
    for (i = 0; i < KMS_time_num_fields; i++) {
	if (NULL == time->time[i].ptr) {
	    time->time[i].len = 0;
	} else {
	    memset((void *) time->time[i].ptr, 0, time->time[i].len);
	}
    }
}

static void
clear_data(KMS_data_t *data)
{
    int	i;
    
    for (i = 0; i < KMS_data_num_fields; i++) {
	if (NULL == data->data[i].ptr) {
	    data->data[i].len = 0;
	} else {
	    memset((void *) data->data[i].ptr, 0, data->data[i].len);
	}
    }
}

static void
clear_req(KMS_req_t *req)
{
    int	i;
    
    for (i = 0; i < KMS_req_num_fields; i++) {
	if (NULL == req->req[i].ptr) {
	    req->req[i].len = 0;
	} else {
	    memset((void *) req->req[i].ptr, 0, req->req[i].len);
	}
    }
}

/**
 * Utility function to simplify handling of KMS_data_t ptr fields
 *
 * @param[in/out] data Data struct to modify
 * @param[in] index Which field to modify
 * @param[in] ptr String to assign
 * @param[in] len Length of string
 * @return KMS_ERR_SUCCESS on success, else error
 */
static int
assign_data_ptr(KMS_data_t *data, int index, void *ptr, size_t len)
{
    if ((NULL == data) || (index >= KMS_data_num_fields)) {
	return KMS_ERR_INTERNAL;
    }
    if (NULL == data->data[index].ptr) {
	data->data[index].ptr = ptr;
    } else {
	if (data->data[index].len < len) {
	    return KMS_ERR_NOSPACE;
	}
	memcpy(data->data[index].ptr, ptr, len);
	free(ptr);
    }
    data->data[index].len = len;
    
    return KMS_ERR_SUCCESS;
}

/**
 * Utility function to simplify handling of KMS_req_t ptr fields
 *
 * @param[in/out] req Req struct to modify
 * @param[in] index Which field to modify
 * @param[in] ptr String to assign
 * @param[in] len Length of string
 * @return KMS_ERR_SUCCESS on success, else error
 */
static int
assign_req_ptr(KMS_req_t *req, int index, char *ptr, size_t len)
{
    if ((NULL == req) || (index >= KMS_req_num_fields)) {
	return KMS_ERR_INTERNAL;
    }
    if (NULL == req->req[index].ptr) {
	if (NULL == ptr) {
	    return KMS_ERR_INVAL;
	}
	req->req[index].ptr = ptr;
    } else {
	// packet routines add uncounted '\0' byte to end
	if ((req->req[index].len + 1) < len) {
	    return KMS_ERR_NOSPACE;
	}
	strncpy(req->req[index].ptr, ptr, len+1);
	free(ptr);
    }
    req->req[index].len = len;
    
    return KMS_ERR_SUCCESS;
}

/**
 * Utility function to simplify handling of KMS_time_t ptr fields
 *
 * @param[in/out] time Time struct to modify
 * @param[in] index Which field to modify
 * @param[in] ptr String to assign
 * @param[in] len Length of string
 * @return KMS_ERR_SUCCESS on success, else error
 */
static int
assign_time_ptr(KMS_time_t *time, int index, char *ptr, size_t len)
{
    if ((NULL == time) || (index >= KMS_time_num_fields)) {
	return KMS_ERR_INTERNAL;
    }
    if (NULL == time->time[index].ptr) {
	time->time[index].ptr = ptr;
    } else {
	// packet routines add uncounted '\0' byte to end
	if ((time->time[index].len + 1) < len) {
	    return KMS_ERR_NOSPACE;
	}
	strncpy(time->time[index].ptr, ptr, len+1);
	free(ptr);
    }
    time->time[index].len = len;
    
    return KMS_ERR_SUCCESS;
}

#define	check_rc(p)	if (KMS_ERR_SUCCESS != rc) { free(p); printf("%s:%d return %d\n", __FUNCTION__, __LINE__, rc); return (rc); }
#define	check_rc2(p)	if (KMS_ERR_SUCCESS != rc) { KMS_packet_cleanup(p); free(p); printf("%s:%d return %d\n", __FUNCTION__, __LINE__, rc); return (rc); }

/**
 * Common request making code.
 *
 * The KMS request messages are nearly identical, so write the heavy
 * lifting code just once.
 *
 * @param req[in] Packet type.
 * @param protoid[in] Protocol ID.
 * @param clientid[in] Client ID.
 * @param otherid[in] Other Client ID. PRIVREQ only.
 * @param expdate[in] Key expiration date. PRIVREQ only.
 * @param topic[in] Topic name. PRIVREQ only.
 * @param outbuf[out] Raw packet data written here.
 * @param buflen[in,out] Available data on input, length of packet on output
 * @return KMS_ERR_SUCCESS or error code.
 */
static int
make_req(int request,
	 const char *protoid,
	 const char *clientid,
	 const char *otherid,
	 const char *expdate,
	 const char *topic,
	 unsigned char *outbuf,
	 size_t *buflen)
{
    KMS_packet		*packet = NULL;
    size_t		packetlen;
    int			rc;

    switch (request) {
    case KMS_TIMEREQ:
    case KMS_PUBREQ:
	break;
    case KMS_PRIVREQ:
	if ((NULL == otherid) || (NULL == expdate) || (NULL == topic)) {
	    return KMS_ERR_INVAL;
	}
	break;
    default:
	return KMS_ERR_INVAL;
    }

    if ((NULL == protoid) || (NULL == clientid) ||
	(NULL == outbuf) || (NULL == buflen)) {
	return KMS_ERR_INVAL;
    }

    packetlen = 4 + (unsigned int) (strlen(protoid) + strlen(clientid));
    if (KMS_PRIVREQ == request) {
	packetlen += 6 + (unsigned int)
	    (strlen(otherid) + strlen(expdate) + strlen(topic));
    }

    packet = calloc(1, sizeof(KMS_packet));
    if (!packet) {
        return KMS_ERR_NOMEM;
    }

    packet->command = request;
    packet->remaining_length = packetlen;
    rc = KMS_packet_alloc(packet); check_rc(packet);

    /* Payload */
    rc = KMS_packet_write_string(packet, protoid, strlen(protoid));
    check_rc2(packet);
    rc = KMS_packet_write_string(packet, clientid, strlen(clientid));
    check_rc2(packet);
    if (KMS_PRIVREQ == request) {
	rc = KMS_packet_write_string(packet, otherid, strlen(otherid));
	check_rc2(packet);
	rc = KMS_packet_write_string(packet, expdate, strlen(expdate));
	check_rc2(packet);
	rc = KMS_packet_write_string(packet, topic, strlen(topic));
	check_rc2(packet);
    }

    if (*buflen < packet->packet_length) {
	KMS_packet_cleanup(packet); free(packet);
	return KMS_ERR_NOSPACE;
    }

    memcpy((void *) outbuf, (void *) packet->payload, packet->packet_length);
    *buflen = (size_t) packet->packet_length;
    KMS_packet_cleanup(packet); free(packet);
    
    return KMS_ERR_SUCCESS;
}

int
KMS_make_timereq(KMS_req_t *req, unsigned char *outbuf, size_t *buflen)
{
    return make_req(KMS_TIMEREQ,
		    req->req[KMS_req_proto_id].ptr,
		    req->req[KMS_req_client_id].ptr,
		    NULL, NULL,
		    NULL, outbuf, buflen);
}

int
KMS_make_pubreq(KMS_req_t *req, unsigned char *outbuf, size_t *buflen)
{
    return make_req(KMS_PUBREQ,
		    req->req[KMS_req_proto_id].ptr,
		    req->req[KMS_req_client_id].ptr,
		    NULL, NULL,
		    NULL, outbuf, buflen);
}

int
KMS_make_privreq(KMS_req_t *req, unsigned char *outbuf, size_t *buflen)
{
    return make_req(KMS_PRIVREQ,
		    req->req[KMS_req_proto_id].ptr,
		    req->req[KMS_req_client_id].ptr,
		    req->req[KMS_req_other_id].ptr,
		    req->req[KMS_req_exp_date].ptr,
		    req->req[KMS_req_topic_name].ptr,
		    outbuf, buflen);
}

/**
 * Common request parsing code.
 *
 * The KMS request messages are nearly identical, so write the heavy
 * lifting code just once.
 */
static int
parse_req(int request,
	  unsigned char *inbuf, size_t buflen,
	  KMS_req_t *req)
{
    KMS_packet		*packet = NULL;
    uint32_t		pkt_vbi;
    char		*strp;
    size_t		slen;
    int			rc;

    if ((NULL == inbuf) || (NULL == req)) {
	printf("%s KMS_ERR_INVAL %d\n", __FUNCTION__, __LINE__);
	return KMS_ERR_INVAL;
    }

    switch (request) {
    case KMS_TIMEREQ:
	if (KMS_TIMEREQ != inbuf[0]) {
	    return KMS_ERR_WRONG_MSG_TYPE;
	}
	break;
    case KMS_PUBREQ:
	if (KMS_PUBREQ != inbuf[0]) {
	    return KMS_ERR_WRONG_MSG_TYPE;
	}
	break;
    case KMS_PRIVREQ:
	if (KMS_PRIVREQ != inbuf[0]) {
	    return KMS_ERR_WRONG_MSG_TYPE;
	}
	break;
    default:
	printf("%s KMS_ERR_INVAL %d\n", __FUNCTION__, __LINE__);
	return KMS_ERR_INVAL;
    }

    clear_req(req);

    packet = calloc(1, sizeof(KMS_packet));
    if (!packet) {
        return KMS_ERR_NOMEM;
    }

    packet->command = inbuf[0];
    packet->pos = 1;
    packet->remaining_length = buflen;
    packet->packet_length = buflen;
    packet->payload = inbuf;

    rc = KMS_packet_read_varint(packet, &pkt_vbi, &packet->remaining_count);
    check_rc(packet);
    // don't care about this value, but now we're past the FH
    // *REQ packets have no VH, so on to the PL

#undef	_X
#define	_X(x)								\
    do {								\
	rc = KMS_packet_read_string(packet, &strp, &slen); check_rc(packet); \
	if (slen) rc = assign_req_ptr(req, KMS_req_ ## x, strp, slen);	\
	check_rc(packet);						\
    } while (0)

    _X(proto_id);
    _X(client_id);
    if (KMS_PRIVREQ == request) {
	_X(other_id);
	_X(exp_date);
	_X(topic_name);
    }
#undef	_X

    free(packet);
    
    return KMS_ERR_SUCCESS;
}

int
KMS_parse_timereq(unsigned char *inbuf, size_t buflen, KMS_req_t *req)
{
    return parse_req(KMS_TIMEREQ, inbuf, buflen, req);
}

int
KMS_parse_pubreq(unsigned char *inbuf, size_t buflen, KMS_req_t *req)
{
    return parse_req(KMS_PUBREQ, inbuf, buflen, req);
}

int
KMS_parse_privreq(unsigned char *inbuf, size_t buflen, KMS_req_t *req)
{
    return parse_req(KMS_PRIVREQ, inbuf, buflen, req);
}

/*
 * Unsuccesful KMS response messages are the same, so handle them all here.
 */
static int
make_resp_error(int request, int reason, char *message,
		unsigned char *outbuf, size_t *buflen)
{
    KMS_packet	*packet = calloc(1, sizeof(KMS_packet));
    uint32_t	packet_len = 0;
    uint32_t	vh_len = 0;
    int		rc;
    unsigned int	varbytes;

    if (NULL == packet) {
	return KMS_ERR_NOMEM;
    }

    if ((NULL != message) && strlen(message)) vh_len += 3 + strlen(message);
    varbytes = KMS_packet_varint_bytes(vh_len);
    packet_len = 1 +		// reason code
	varbytes + vh_len;		// rest of variable header
    
    packet->command = request;
    packet->remaining_length = packet_len;
    rc = KMS_packet_alloc(packet); check_rc(packet);

    // VH
    KMS_packet_write_byte(packet, reason);
    KMS_packet_write_varint(packet, vh_len);
    if ((NULL != message) && strlen(message)) {
	KMS_packet_write_byte(packet, KMS_PROP_MESSAGE);
	KMS_packet_write_string(packet, message, strlen(message));
    }

    if (*buflen < packet->packet_length) {
	KMS_packet_cleanup(packet); free(packet);
	return KMS_ERR_NOSPACE;
    }

    memcpy((void *) outbuf, (void *) packet->payload, packet->packet_length);
    *buflen = (size_t) packet->packet_length;
    KMS_packet_cleanup(packet); free(packet);
    
    return KMS_ERR_SUCCESS;
}

int
KMS_make_timeresp(int reason,
		  KMS_time_t *times,
		  char *message,
		  unsigned char *outbuf, size_t *buflen)
{
    KMS_packet	*packet = NULL;
    uint32_t	packet_len = 0;
    uint32_t	vh_len = 0;
    int		rc;
    unsigned int	varbytes;

    // convenience vars
    char	*timeofday, *expdate, *nextexp;

    if (KMS_REASON_SUCCESS != reason) {
	return(make_resp_error(KMS_TIMERESP, reason, message, outbuf, buflen));
    }
	
    if ((NULL == times) || (NULL == times->time[KMS_time_cur].ptr) ||
	(NULL == outbuf) || (NULL == buflen)) {
	return KMS_ERR_INVAL;
    }
    packet = calloc(1, sizeof(KMS_packet));
    if (NULL == packet) {
	return KMS_ERR_NOMEM;
    }
    packet->command = KMS_TIMERESP;

    timeofday = times->time[KMS_time_cur].ptr;
    expdate = times->time[KMS_time_exp_date].ptr;
    nextexp = times->time[KMS_time_next_exp].ptr;
    
    if ((NULL != expdate) && strlen(expdate)) vh_len += 3 + strlen(expdate);
    if ((NULL != nextexp) && strlen(nextexp)) vh_len += 3 + strlen(nextexp);
    if ((NULL != message) && strlen(message)) vh_len += 3 + strlen(message);
    varbytes = KMS_packet_varint_bytes(vh_len);
    packet_len = 1 +		// reason code
	varbytes + vh_len +		// rest of variable header
	2 + strlen(times->time[KMS_time_cur].ptr);	// payload
    packet->remaining_length = packet_len;
    rc = KMS_packet_alloc(packet); check_rc(packet);

    // VH
    KMS_packet_write_byte(packet, reason);
    KMS_packet_write_varint(packet, vh_len);
    if ((NULL != expdate) && strlen(expdate)) {
	KMS_packet_write_byte(packet, KMS_PROP_EXPIRATION_DATE);
	KMS_packet_write_string(packet, expdate, strlen(expdate));
    }
    if ((NULL != nextexp) && strlen(nextexp)) {
	KMS_packet_write_byte(packet, KMS_PROP_NEXT_EXP_DATE);
	KMS_packet_write_string(packet, nextexp, strlen(nextexp));
    }
    if ((NULL != message) && strlen(message)) {
	KMS_packet_write_byte(packet, KMS_PROP_MESSAGE);
	KMS_packet_write_string(packet, message, strlen(message));
    }

    // PL
    KMS_packet_write_string(packet, timeofday, strlen(timeofday));
	
    if (*buflen < packet->packet_length) {
	KMS_packet_cleanup(packet); free(packet);
	return KMS_ERR_NOSPACE;
    }

    memcpy((void *) outbuf, (void *) packet->payload, packet->packet_length);
    *buflen = (size_t) packet->packet_length;
    KMS_packet_cleanup(packet); free(packet);
    
    return KMS_ERR_SUCCESS;
}

int
KMS_make_pubresp(int reason,
		 KMS_data_t *data,
		 char *message,
		 unsigned char *outbuf, size_t *buflen)
{
    KMS_packet	*packet = NULL;
    uint32_t	packet_len = 0;
    uint32_t	vh_len = 0;
    uint32_t	pl_len = 0;
    int		rc;
    int		i;
    unsigned int	varbytes;

    if (KMS_REASON_SUCCESS != reason) {
	return(make_resp_error(KMS_PUBRESP, reason, message, outbuf, buflen));
    }
	
    if ((NULL == data) || (NULL == outbuf) || (NULL == buflen)) {
	return KMS_ERR_INVAL;
    }
    packet = calloc(1, sizeof(KMS_packet));
    if (NULL == packet) {
	return KMS_ERR_NOMEM;
    }
    packet->command = KMS_PUBRESP;

    // VH len
    if ((NULL != message) && strlen(message)) vh_len += 3 + strlen(message);
    varbytes = KMS_packet_varint_bytes(vh_len);

    // PL len
    for (i = 0; i < data->num; i++) {
	pl_len += (2 + data->data[i].len);
    }
    
    packet_len = 1 +		// reason code
	varbytes + vh_len +	// variable header
	pl_len;			// payload
    packet->remaining_length = packet_len;
    rc = KMS_packet_alloc(packet); check_rc(packet);

    // VH
    KMS_packet_write_byte(packet, reason);
    KMS_packet_write_varint(packet, vh_len);
    if ((NULL != message) && strlen(message)) {
	KMS_packet_write_byte(packet, KMS_PROP_MESSAGE);
	KMS_packet_write_string(packet, message, strlen(message));
    }

    // PL
    for (i = 0; i < data->num; i++) {
	KMS_packet_write_binary(packet, data->data[i].ptr, data->data[i].len);
    }
	
    if (*buflen < packet->packet_length) {
	KMS_packet_cleanup(packet); free(packet);
	return KMS_ERR_NOSPACE;
    }

    memcpy((void *) outbuf, (void *) packet->payload, packet->packet_length);
    *buflen = (size_t) packet->packet_length;
    KMS_packet_cleanup(packet); free(packet);
    
    return KMS_ERR_SUCCESS;
}

int
KMS_make_privresp(int reason,
		  KMS_data_t *data,
		  char *message,
		  unsigned char *outbuf, size_t *buflen)
{
    KMS_packet	*packet = NULL;
    uint32_t	packet_len = 0;
    uint32_t	vh_len = 0;
    uint32_t	pl_len = 0;
    int		rc;
    int		i;
    unsigned int	varbytes;

    if (KMS_REASON_SUCCESS != reason) {
	return(make_resp_error(KMS_PRIVRESP, reason, message, outbuf, buflen));
    }
	
    if ((NULL == data) || (NULL == outbuf) || (NULL == buflen)) {
	return KMS_ERR_INVAL;
    }
    packet = calloc(1, sizeof(KMS_packet));
    if (NULL == packet) {
	return KMS_ERR_NOMEM;
    }
    packet->command = KMS_PRIVRESP;

    // VH len
    if ((NULL != message) && strlen(message)) vh_len += 3 + strlen(message);
    varbytes = KMS_packet_varint_bytes(vh_len);

    // PL len
    for (i = 0; i < data->num; i++) {
	pl_len += (2 + data->data[i].len);
    }
    
    packet_len = 1 +		// reason code
	varbytes + vh_len +	// rest of variable header
	pl_len;			// payload
    packet->remaining_length = packet_len;
    rc = KMS_packet_alloc(packet); check_rc(packet);

    // VH
    KMS_packet_write_byte(packet, reason);
    KMS_packet_write_varint(packet, vh_len);
    if ((NULL != message) && strlen(message)) {
	KMS_packet_write_byte(packet, KMS_PROP_MESSAGE);
	KMS_packet_write_string(packet, message, strlen(message));
    }
    
    // PL
    for (i = 0; i < data->num; i++) {
	rc = KMS_packet_write_binary(packet, (uint8_t *) data->data[i].ptr,
				     data->data[i].len);
	check_rc2(packet);
    }
	
    if (*buflen < packet->packet_length) {
	KMS_packet_cleanup(packet); free(packet);
	return KMS_ERR_NOSPACE;
    }

    memcpy((void *) outbuf, (void *) packet->payload, packet->packet_length);
    *buflen = (size_t) packet->packet_length;
    KMS_packet_cleanup(packet); free(packet);
    
    return KMS_ERR_SUCCESS;
}

int
KMS_parse_timeresp(unsigned char *inbuf, size_t buflen,
		   uint8_t *reason, KMS_time_t *times,
		   char **message)
{
    KMS_packet	*packet = NULL;
    uint32_t	vh_pl_len;
    uint32_t	vh_len;
    int		rc;
    uint8_t	prop;
    char	*data;
    size_t	len;

    if ((NULL == inbuf) || (NULL == reason) || (NULL == times)) {
	printf("%s KMS_ERR_INVAL %d\n", __FUNCTION__, __LINE__);
	return KMS_ERR_INVAL;
    }

    if (KMS_TIMERESP != inbuf[0]) {
	return KMS_ERR_WRONG_MSG_TYPE;
    }

    clear_time(times);

    packet = calloc(1, sizeof(KMS_packet));
    if (!packet) {
        return KMS_ERR_NOMEM;
    }

    packet->command = inbuf[0];
    packet->pos = 1;
    packet->remaining_length = buflen;
    packet->packet_length = buflen;
    packet->payload = inbuf;

    rc = KMS_packet_read_varint(packet, &vh_pl_len, &packet->remaining_count);
    check_rc(packet);

    rc = KMS_packet_read_byte(packet, reason); check_rc(packet);

    rc = KMS_packet_read_varint(packet, &vh_len, NULL); check_rc(packet);
    
    while ((KMS_ERR_SUCCESS == rc) && (vh_len > 0)) {
	
	rc = KMS_packet_read_byte(packet, &prop); check_rc(packet);
	vh_len--;

	rc = KMS_packet_read_string(packet, &data, &len); check_rc(packet);
	
	switch (prop) {
	case KMS_PROP_EXPIRATION_DATE:
	    if ((KMS_REASON_SUCCESS != (*reason)) || (len > MASQ_EXPDATE_LEN)) {
		free(data);
		free(packet);
		return KMS_ERR_INVAL;
	    }
	    rc = assign_time_ptr(times, KMS_time_exp_date, data, len);
	    break;
	case KMS_PROP_NEXT_EXP_DATE:
	    if ((KMS_REASON_SUCCESS != (*reason)) || (len > MASQ_EXPDATE_LEN)) {
		free(data);
		free(packet);
		return KMS_ERR_INVAL;
	    }
	    rc = assign_time_ptr(times, KMS_time_next_exp, data, len);
	    break;
	case KMS_PROP_MESSAGE:
	    if (NULL == message) {
		free(data);
	    } else {
		*message = data;
	    }
	    break;
	default:
	    free(data);
	    free(packet);
	    return KMS_ERR_MALFORMED_PACKET;
	    break;
	}
	vh_len -= (2 + len);
    }
    check_rc(packet);
    
    if (KMS_REASON_SUCCESS != (*reason)) {
	free(packet);
	return KMS_ERR_SUCCESS;
    }

    rc = KMS_packet_read_string(packet, &data, &len); check_rc(packet);
    if (len > MASQ_EXPDATE_LEN) { free(data); return KMS_ERR_INVAL; }
    rc = assign_time_ptr(times, KMS_time_cur, data, len);
    free(packet);

    return rc;
}

int
KMS_parse_pubresp(unsigned char *inbuf, size_t buflen,
		  uint8_t *reason, KMS_data_t *data,
		   char **message)
{
    KMS_packet	*packet = NULL;
    uint32_t	pl_len;
    uint32_t	vh_len;
    int		rc;

    if ((NULL == inbuf) || (NULL == reason) || (NULL == data)) {
	printf("%s KMS_ERR_INVAL %d\n", __FUNCTION__, __LINE__);
	return KMS_ERR_INVAL;
    }

    if (KMS_PUBRESP != inbuf[0]) {
	return KMS_ERR_WRONG_MSG_TYPE;
    }

    packet = calloc(1, sizeof(KMS_packet));
    if (!packet) {
        return KMS_ERR_NOMEM;
    }

    packet->command = inbuf[0];
    packet->pos = 1;
    packet->remaining_length = buflen;
    packet->packet_length = buflen;
    packet->payload = inbuf;

    rc = KMS_packet_read_varint(packet, &pl_len, &packet->remaining_count);
    check_rc(packet);

    rc = KMS_packet_read_byte(packet, reason); check_rc(packet);
    pl_len--;
    
    rc = KMS_packet_read_varint(packet, &vh_len, NULL); check_rc(packet);
    pl_len -= (vh_len + 1);

    while ((KMS_ERR_SUCCESS == rc) && (vh_len > 0)) {
	
	uint8_t	prop;
	char	*dp;
	size_t	len;
	
	rc = KMS_packet_read_byte(packet, &prop); check_rc(packet);
	vh_len--;

	rc = KMS_packet_read_string(packet, &dp, &len); check_rc(packet);
	
	switch (prop) {
	case KMS_PROP_MESSAGE:
	    if (NULL == message) {
		free(dp);
	    } else {
		*message = dp;
	    }
	    break;
	default:
	    free(dp);
	    free(packet);
	    return KMS_ERR_MALFORMED_PACKET;
	    break;
	}
	vh_len -= (2 + len);
    }
    check_rc(packet);

    if (KMS_REASON_SUCCESS != (*reason)) {
	free(packet);
	return KMS_ERR_SUCCESS;
    }

    data->num = 0;
    while (pl_len > 0) {
	uint8_t	*dp;
	size_t	len;
	rc = KMS_packet_read_binary(packet, &dp, &len); check_rc(packet);
	rc = assign_data_ptr(data, data->num, (void *) dp, len);
	check_rc(packet);
	pl_len -= (2 + len);
	data->num++;
    }
    
    free(packet);

    return KMS_ERR_SUCCESS;
}

int
KMS_parse_privresp(unsigned char *inbuf, size_t buflen,
		   uint8_t *reason, KMS_data_t *data,
		   char **message)
{
    KMS_packet	*packet = NULL;
    uint32_t	pl_len;
    uint32_t	vh_len;
    int		rc;

    if ((NULL == inbuf) || (NULL == reason) || (NULL == data)) {
	printf("%s KMS_ERR_INVAL %d\n", __FUNCTION__, __LINE__);
	return KMS_ERR_INVAL;
    }

    if (KMS_PRIVRESP != inbuf[0]) {
	return KMS_ERR_WRONG_MSG_TYPE;
    }

    clear_data(data);

    packet = calloc(1, sizeof(KMS_packet));
    if (!packet) {
        return KMS_ERR_NOMEM;
    }

    packet->command = inbuf[0];
    packet->pos = 1;
    packet->remaining_length = buflen;
    packet->packet_length = buflen;
    packet->payload = inbuf;

    rc = KMS_packet_read_varint(packet, &pl_len, &packet->remaining_count);
    check_rc(packet);

    rc = KMS_packet_read_byte(packet, reason); check_rc(packet);
    pl_len--;

    rc = KMS_packet_read_varint(packet, &vh_len, NULL); check_rc(packet);
    pl_len -= (vh_len + 1);

    while ((KMS_ERR_SUCCESS == rc) && (vh_len > 0)) {
	
	uint8_t	prop;
	char	*dp;
	size_t	len;
	
	rc = KMS_packet_read_byte(packet, &prop); check_rc(packet);
	vh_len--;

	switch (prop) {
	case KMS_PROP_MESSAGE:
	    rc = KMS_packet_read_string(packet, &dp, &len); check_rc(packet);
	    if (NULL == message) {
		free(dp);
	    } else {
		*message = dp;
	    }
	    break;
	default:
	    free(dp);
	    free(packet);
	    return KMS_ERR_MALFORMED_PACKET;
	    break;
	}
	vh_len -= (2 + len);
    }
    check_rc(packet);

    if (KMS_REASON_SUCCESS != (*reason)) {
	// sucessfully read the unsucessful reason :-)
	free(packet);
	return KMS_ERR_SUCCESS;
    }

    data->num = 0;
    while (pl_len > 0) {
	uint8_t	*dp;
	size_t	len;
	rc = KMS_packet_read_binary(packet, &dp, &len); check_rc(packet);
	rc = assign_data_ptr(data, data->num, (void *) dp, len);
	check_rc(packet);
	pl_len -= (2 + len);
	data->num++;
    }
    
    free(packet);

    return KMS_ERR_SUCCESS;
}

#define	DUMP_WID	(16)

void
KMS_pkt_dump(unsigned char *p, size_t len, char *hdr, int show)
{
    size_t	i;
    char	*sep = "";
    char	buf[DUMP_WID+1];
    
    if (NULL != hdr) {
	printf("==== %04lx  %s\n", len, hdr);
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
	    printf("%s%04lx ", sep, i);
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
}

void
KMS_pkt_dump_req(KMS_req_t *req, char *hdr)
{
    if (NULL != hdr) {
	printf("==== %s\n", hdr);
    }

    if (NULL == req) return;
#undef	_X
#define	_X(l, x)					      \
    if ((NULL != req->req[x].ptr) && strlen(req->req[x].ptr)) \
	printf("  %s %s\n", l, req->req[x].ptr)

    _X("  protoid", KMS_req_proto_id);
    _X(" clientid", KMS_req_client_id);
    _X("  otherid", KMS_req_other_id);
    _X("  expdate", KMS_req_exp_date);
    _X("    topic", KMS_req_topic_name);
#undef	_X
}

void
KMS_pkt_dump_time(KMS_time_t *time, char *hdr)
{
    if (NULL != hdr) {
	printf("==== %s\n", hdr);
    }

    if (NULL == time) return;
#undef	_X
#define	_X(l, x)					      \
    if ((NULL != time->time[x].ptr) && strlen(time->time[x].ptr)) \
	printf("  %s %s\n", l, time->time[x].ptr)

    _X("  current", KMS_time_cur);
    _X(" exp_date", KMS_time_exp_date);
    _X(" next_exp", KMS_time_next_exp);
#undef	_X
}

void
KMS_pkt_dump_data(KMS_data_t *data, char *hdr)
{
    int		i;
    
    if (NULL != hdr) {
	printf("==== %s\n", hdr);
    }

    if (NULL == data) return;

    for (i = 0; i < data->num; i++) {
	printf("datum %d/%d\n", i, data->num);
	KMS_pkt_dump((unsigned char *) data->data[i].ptr,
		     data->data[i].len, NULL, 1);
    }
}

#ifdef	ebug

static char	_rprotoid[12];
static char	_clientid[MASQ_CLIENTID_LEN + 1];
static char	_otherid[MASQ_CLIENTID_LEN + 1];
static char	_expdate[MASQ_EXPDATE_LEN + 1];
static char	_topic[MASQ_MAXTOPIC_LEN + 1];

static void
reset_req(KMS_req_t *req)
{
#undef	_X
#define	_X(f, b)				\
    do {					\
	req->req[KMS_req_ ## f].ptr = b; \
	req->req[KMS_req_ ## f].len = sizeof(b);	\
    } while (0)
    _X(proto_id, _rprotoid);
    _X(client_id, _clientid);
    _X(other_id, _otherid);
    _X(exp_date, _expdate);
    _X(topic_name, _topic);
#undef	_X
}

struct {
    char	*client_id;
    char	*what;		// topic name or subscription
} _clients[] = {
    // publishers
#define	PUB_TL	0
    { "TankLevel00037a1", "tank/level" },
#define	PUB_TT	1
    { "TankTemp000a0032", "tank/temp" },
#define	PUB_RT	2
    { "TankTemp000a0032", "room/temp" },
#define	PUB_PT	3
    { "PumpTemp007c0480", "pump/temp" },
    // subscribers
#define	SUB_DP	4	// display panel
    { "Display999999997", "#" },
#define	SUB_PC	5	// pump controller
    { "PumpUnit00006177", "tank/level pump/temp" }
};
#define	NUM_CLIENTS	((sizeof(_clients)/sizeof(_clients[0])))
static char	*_protoid = "1.0/F";

static char *_dates[] = {
#define	DT_TOD	0
    "20231019T230357Z",
#define	DT_EXP	1
    "20231025T180000Z",
#define	DT_NEXP	2
    "20231125T180000Z",
};

int main(int argc, char *argv[])
{
    unsigned char	buf[1024];
    size_t		buflen;
    int			rc;
    int			i;
    KMS_req_t		myreq;
    KMS_time_t		mytime;
    KMS_data_t		mydata;
    KMS_data_t		outdata = { 0 };
    uint8_t		reason;

    char		curtime[MASQ_EXPDATE_LEN + 1];
    char		expdate[MASQ_EXPDATE_LEN + 1];
    char		nextexp[MASQ_EXPDATE_LEN + 1];
    KMS_time_t		outtime = {
	.time[KMS_time_cur] = { curtime, sizeof(curtime) },
	.time[KMS_time_exp_date] = { expdate, sizeof(expdate) },
	.time[KMS_time_next_exp] = { nextexp, sizeof(nextexp) },
    };

    KMS_req_t		outreq;

    srandom(13);

    printf("\n------------- TIMEREQ\n\n");

    buflen = sizeof(buf);
    myreq.req[KMS_req_proto_id].ptr = _protoid;
    myreq.req[KMS_req_client_id].ptr = _clients[PUB_PT].client_id;
    myreq.req[KMS_req_other_id].ptr = NULL;
    myreq.req[KMS_req_exp_date].ptr = NULL;
    myreq.req[KMS_req_topic_name].ptr = NULL;
    KMS_pkt_dump_req(&myreq, "KMS_make_timereq");
    rc = KMS_make_timereq(&myreq, buf, &buflen);

    if (KMS_ERR_SUCCESS == rc) {
	KMS_pkt_dump(buf, buflen, "TIMEREQ packet", 1);
    } else {
	printf("Got error %s\n", KMS_error_string(rc));
    }

    reset_req(&outreq);
    rc = KMS_parse_timereq(buf, buflen, &outreq);

    if (KMS_ERR_SUCCESS == rc) {
	KMS_pkt_dump_req(&outreq, "KMS_parse_timereq");
    } else {
	printf("Got error %s\n", KMS_error_string(rc));
    }

    printf("\n------------- TIMERESP\n\n");

    buflen = sizeof(buf);
    mytime.time[KMS_time_cur].ptr = _dates[DT_TOD];
    mytime.time[KMS_time_exp_date].ptr = _dates[DT_EXP];
    mytime.time[KMS_time_next_exp].ptr = _dates[DT_NEXP];
    KMS_pkt_dump_time(&mytime, "KMS_make_timeresp");
    rc = KMS_make_timeresp(KMS_REASON_SUCCESS, &mytime, NULL,
			   buf, &buflen);

    if (KMS_ERR_SUCCESS == rc) {
	KMS_pkt_dump(buf, buflen, "TIMERESP packet", 1);
    } else {
	printf("Got error %s\n", KMS_error_string(rc));
    }
    
    rc = KMS_parse_timeresp(buf, buflen, &reason, &outtime, NULL);

    if (KMS_ERR_SUCCESS == rc) {
	if (KMS_REASON_SUCCESS == reason) {
	    KMS_pkt_dump_time(&outtime, "KMS_parse_timeresp");
	} else {
	    printf("==== KMS_parse_timeresp\n> %s\n",
		   KMS_reason_string(reason));
	}
    } else {
	printf("Got error %s\n", KMS_error_string(rc));
    }
    
    buflen = sizeof(buf);
    rc = KMS_make_timeresp(KMS_REASON_CLIENTID_ERR,
			   NULL, NULL,
			   buf, &buflen);

    if (KMS_ERR_SUCCESS == rc) {
	KMS_pkt_dump(buf, buflen, "TIMERESP packet (w/ error)", 1);
    } else {
	printf("Got error %s\n", KMS_error_string(rc));
    }

    rc = KMS_parse_timeresp(buf, buflen, &reason, &outtime, NULL);

    if (KMS_ERR_SUCCESS == rc) {
	if (KMS_REASON_SUCCESS == reason) {
	    KMS_pkt_dump_time(&outtime, "KMS_parse_timeresp");
	} else {
	    printf("==== KMS_parse_timeresp\n> %s\n",
		   KMS_reason_string(reason));
	}
    } else {
	printf("Got error %s\n", KMS_error_string(rc));
    }
    
    printf("\n------------- PUBREQ\n\n");

    buflen = sizeof(buf);
    myreq.req[KMS_req_proto_id].ptr = _protoid;
    myreq.req[KMS_req_client_id].ptr = _clients[PUB_TT].client_id;
    myreq.req[KMS_req_other_id].ptr = NULL;
    myreq.req[KMS_req_exp_date].ptr = NULL;
    myreq.req[KMS_req_topic_name].ptr = NULL;
    KMS_pkt_dump_req(&myreq, "KMS_make_pubreq");
    rc = KMS_make_pubreq(&myreq, buf, &buflen);

    if (KMS_ERR_SUCCESS == rc) {
	KMS_pkt_dump(buf, buflen, "PUBREQ packet", 1);
    } else {
	printf("Got error %s\n", KMS_error_string(rc));
    }

    reset_req(&outreq);
    rc = KMS_parse_pubreq(buf, buflen, &outreq);

    if (KMS_ERR_SUCCESS == rc) {
	KMS_pkt_dump_req(&outreq, "KMS_parse_pubreq");
    } else {
	printf("Got error %s\n", KMS_error_string(rc));
    }

    printf("\n------------- PUBRESP\n\n");

    buflen = sizeof(buf);
    mydata.num = 2;
    mydata.data[0].ptr = (void *) "some random data";
    mydata.data[0].len = strlen(mydata.data[0].ptr);
    mydata.data[1].ptr = (void *) "other data here";
    mydata.data[1].len = strlen(mydata.data[1].ptr);
    rc = KMS_make_pubresp(KMS_REASON_SUCCESS,
			  &mydata,
			  NULL,
			  buf, &buflen);

    if (KMS_ERR_SUCCESS == rc) {
	KMS_pkt_dump(buf, buflen, "PUBRESP packet", 1);
    } else {
	printf("Got error %s\n", KMS_error_string(rc));
    }

    clear_data(&outdata);
    rc = KMS_parse_pubresp(buf, buflen, &reason, &outdata, NULL);

    if (KMS_ERR_SUCCESS == rc) {
	if (KMS_REASON_SUCCESS == reason) {
	    KMS_pkt_dump_data(&outdata, "KMS_parse_pubresp");
	    for (i = 0; i < outdata.num; i++) {
		free(outdata.data[i].ptr);
		outdata.data[i].ptr = NULL;
	    }
	} else {
	    printf("==== KMS_parse_pubresp\n> %s\n", KMS_reason_string(reason));
	}
    } else {
	printf("Got error %s\n", KMS_error_string(rc));
    }

    printf("\n------------- PRIVREQ\n\n");

    buflen = sizeof(buf);
    myreq.req[KMS_req_proto_id].ptr = _protoid;
    myreq.req[KMS_req_client_id].ptr = _clients[SUB_PC].client_id;
    myreq.req[KMS_req_other_id].ptr = _clients[PUB_TL].client_id;
    myreq.req[KMS_req_exp_date].ptr = _dates[DT_EXP];
    myreq.req[KMS_req_topic_name].ptr = "tank/level";
    KMS_pkt_dump_req(&myreq, "KMS_make_privreq");
    rc = KMS_make_privreq(&myreq, buf, &buflen);

    if (KMS_ERR_SUCCESS == rc) {
	KMS_pkt_dump(buf, buflen, "PRIVREQ packet", 1);
    } else {
	printf("Got error %s\n", KMS_error_string(rc));
    }

    reset_req(&outreq);
    rc = KMS_parse_privreq(buf, buflen, &outreq);

    if (KMS_ERR_SUCCESS == rc) {
	KMS_pkt_dump_req(&outreq, "KMS_parse_privreq");
    } else {
	printf("Got error %s\n", KMS_error_string(rc));
    }

    printf("\n------------- PRIVRESP\n\n");

#define	BLEN	128
    uint8_t	buf0[BLEN+1], buf1[BLEN+1];
    int32_t	r0, r1;
    buflen = sizeof(buf);
    mydata.num = 2;
    buf0[0] = buf1[0] = 0;
    for (i = 0; i < BLEN; i++) {
	if (0 == (i % 3)) { r0 = random(); r1 = random(); }
	buf0[i+1] = r0 % 0xff; r0 >>= 8;
	buf1[i+1] = r1 % 0xff; r1 >>= 8;
    }
    mydata.data[0].ptr = (void *) buf0;
    mydata.data[0].len = sizeof(buf0);
    mydata.data[1].ptr = (void *) buf1;
    mydata.data[1].len = sizeof(buf1);
    rc = KMS_make_privresp(KMS_REASON_SUCCESS,
			   &mydata,
			   NULL,
			   buf, &buflen);

    if (KMS_ERR_SUCCESS == rc) {
	KMS_pkt_dump(buf, buflen, "PRIVRESP packet", 1);
    } else {
	printf("Got error %s\n", KMS_error_string(rc));
    }

    outdata.data[0].ptr = (void *) buf0;
    outdata.data[0].len = sizeof(buf0);
    outdata.data[1].ptr = (void *) buf1;
    outdata.data[1].len = sizeof(buf1);
    rc = KMS_parse_privresp(buf, buflen, &reason, &outdata, NULL);

    if (KMS_ERR_SUCCESS == rc) {
	if (KMS_REASON_SUCCESS == reason) {
	    KMS_pkt_dump_data(&outdata, "KMS_parse_privresp");
	    for (i = 0; i < outdata.num; i++) {
		//free(outdata.data[i].ptr);
		outdata.data[i].ptr = NULL;
	    }
	} else {
	    printf("==== KMS_parse_privresp\n> %s\n",
		   KMS_reason_string(reason));
	}
    } else {
	printf("Got error %s\n", KMS_error_string(rc));
    }

    return(0);
}

#endif	// ebug
