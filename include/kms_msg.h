#ifndef	MASQ_KMS_MSG_H_INCLUDED
#define	MASQ_KMS_MSG_H_INCLUDED

/** @file

KMS packet parsing functions.
============================

Packet types
------------

There are six types of packets (messages) exchanged with the Key Management
Server (KMS):

- TIMEREQ / TIMERESP for Time of Day
- PUBREQ  / PUBRESP for IBE shared public parameters
- PRIVREQ / PRIVRESP for IBE private keys

For each type of packet, there are two functions provided, one to create a
packet of that type and one to parse a packet of that type. These will be
used either on behalf of a Client in the MasQiTT crypto library or by the
KMS itself as shown in the table below.

- TIMEREQ
  - KMS_make_timereq() called by Publisher, Subscriber
  - KMS_parse_timereq() called by KMS
- TIMERESP
  - KMS_make_timeresp() called by KMS
  - KMS_parse_timeresp() called by Publisher, Subscriber
- PUBREQ
  - KMS_make_pubreq() called by Publisher
  - KMS_parse_pubreq() called by KMS
- PUBRESP
  - KMS_make_pubresp() called by KMS
  - KMS_parse_pubresp() called by Publisher
- PRIVREQ
  - KMS_make_privreq() called by Subscriber
  - KMS_parse_privreq() called by KMS
- PRIVRESP
  - KMS_make_privresp() called by KMS
  - KMS_parse_privresp() called by Subscriber

It's possible that this code may be eventually split into two files, one
for Client use and the other for KMS use. For the time being everything
lives together.

Data structures
---------------

- KMS_req_t, KMS_time_t

  The KMS_req_t and KMS_time_t data types have similar structures in that
  each field is indexed by a corresponding enum value and described by
  a ptr and a len. When used as an input (the KMS_make_xxx() functions)
  the len fields are ignored. Each field with content should set ptr to
  point to a '\0'-terminated string; fields without data should either
  point to a zero-length string (ptr[0] == '\0') or be set to NULL.

  When used as an output (KMS_parse_xxx()) there are two options: 1) set
  ptr to point at a buffer to receive output (including the terminating
  '\0') and len to the length of that buffer or 2) set ptr to NULL, and
  a pointer to malloc()'d space will be returned. In both cases, len is
  set on output to the length of the string returned NOT including the
  terminating '\0'. In case 1), a KMS_ERR_NOSPACE error will be returned
  if the length of a field is too short to receive the data. In case 2),
  it is the caller's responsibility to free() the value in ptr after it
  is no longer needed.

- KMS_data_t

  KMS_data_t works the same way, except that ptr contains arbitrary binary
  data instead of a '\0'-terminated string. Here len is needed on input
  to specify how many bytes of ptr are relevant. When used as an output,
  ptr and len behave as described above for KMS_req_t and KMS_time_t.

Status messages
---------------

TIMERESP, PUBRESP, and PRIVRESP packets may contain an option status
message. If the caller wishes to receive a status message, it should set the
@p message parameter. If the packet contains a status message, it will be
returned in a malloc()'d '\0'-terminated string, and it is the caller's
responsibility to free() the memory. If no message is found in the packet,
@p message will be set to NULL. If @p message is NULL, no message is
returned.

*/

#include <stdint.h>
#include <sys/types.h>

/*
 *  Message types
 */
#define	KMS_TIMEREQ	0x1	//!< Time request message type
#define	KMS_TIMERESP	0x2	//!< Time response message type
#define	KMS_PUBREQ	0x3	//!< Public key info request message type
#define	KMS_PUBRESP	0x4	//!< Public key info response message type
#define	KMS_PRIVREQ	0x5	//!< Private key info request message type
#define	KMS_PRIVRESP	0x6	//!< Private key info response message type

/**
 * Error values returned by KMS message functions.
 */
enum KMS_error {
    KMS_ERR_SUCCESS = 0,	//!< Success
    KMS_ERR_INVAL,		//!< Invalid parameter or value
    KMS_ERR_NOMEM,		//!< Cannot alloc memory
    KMS_ERR_NOSPACE,		//!< Not enough space provided for output
    KMS_ERR_CRYPTO,		//!< Error returned by crypto routine
    KMS_ERR_MALFORMED_PACKET,	//!< Malformed packet
    KMS_ERR_MALFORMED_UTF8,	//!< Malformed UTF-8 code point(s)
    KMS_ERR_PAYLOAD_SIZE,	//!< Payload too large for a packet
    KMS_ERR_WRONG_MSG_TYPE,	//!< Parsing function does not handle this
    KMS_ERR_INTERNAL,		//!< Internal error, should not happen?
};

#define	KMS_ERROR_RESP_PKT_LEN	(4)

/**
 * String representation of KMS_error enum.
 *
 * @param[in] err Error code.
 * @return Printable string.
 */
extern const char *
KMS_error_string(int err);

/**
 * Reason codes returned in *RESP packets.
 */
enum KMS_reason {
    KMS_REASON_SUCCESS = 0,		//!< Success
    KMS_REASON_ERR = 0x80,		//!< Unspecified error
    KMS_REASON_PROTO_ERR = 0x81,	//!< ProtoID not recognized/supported
    KMS_REASON_CLIENTID_ERR = 0x82,	//!< ClientID not recognized by KMS
    KMS_REASON_OTHCLID_ERR = 0x83,	//!< Oth ClientID not recognized by KMS
    KMS_REASON_CLENT_AUTH_ERR = 0x84,	//!< ClientID/TLS creds mismatch
    KMS_REASON_KEY_EXP_ERR = 0x85,	//!< Expiration date not recognized
    KMS_REASON_PUB_AUTH_ERR = 0x90,	//!< Pub not authorized to publish Topic
    KMS_REASON_SUB_AUTH_ERR = 0x91,	//!< Sub not authorized to receive Topic
    KMS_REASON_CLIENT_AUTH_ERR = 0x92,	//!< Pub or Sub not authorized
    KMS_REASON_UNAUTH_REQ_ERR = 0x93,	//!< Policy prohibits req from Client
};

/** String representation of KMS_reason enum.
 *
 * @param[in] reason Reason code
 * @return Printable string
 */
extern const char *
KMS_reason_string(int reason_code);

/** Properties in KMS packet VH fields.
 */
enum KMS_property {
    KMS_PROP_EXPIRATION_DATE = 0x01,	//!< Current expiration date/time
    					// UTF-8 String: TIMERESP
    KMS_PROP_NEXT_EXP_DATE = 0x02,	//!< Next expiration date/time
    					// UTF-8 String: TIMERESP
    KMS_PROP_MESSAGE = 0xff,		//!< Optional debugging message
};

#define	KMS_data_num_fields	3
/**
 * Binary data structure.
 * 
 * Use this struture to pass binary data in (KMS_make_pubresp(),
 * KMS_make_privresp()) or receive binary data out (KMS_parse_pubresp()
 * KMS_parse_privresp()).
 */
typedef struct {
    int	num;		//!< Number of binary values in data[]
    struct {
	void	*ptr;	//!< Binary value
	size_t	len;	//!< Length of binary data
    } data[KMS_data_num_fields];
} KMS_data_t;

#define	KMS_PROTO_ID	"1.0/1"	//!< BB1 Crypto protocol ID

/**
 * Indices for @ref KMS_req_t `req` array.
 */
enum KMS_req_index {
    KMS_req_proto_id = 0,	//!< Protocol ID field index
    KMS_req_client_id,		//!< Client ID field index
    KMS_req_other_id,		//!< Other Client ID field index
    KMS_req_exp_date,		//!< Expiration date field index
    KMS_req_topic_name,		//!< Topic Name field index
    KMS_req_num_fields		//!< Number of @ref KMS_req_t fields
};

/**
 * Request data structure.
 *
 * Use this struture to pass request data in (KMS_make_timereq(),
 * KMS_make_pubreq(), KMS_make_privreq()) or receive request data out
 * (KMS_parse_timereq(), KMS_parse_pubreq() KMS_parse_privreq()).
 */
typedef struct {
    struct {
	char	*ptr;	//!< [in,out] NULL-terminated
	size_t	len;	//!< [in] not used, [out] available space in ptr
    } req[KMS_req_num_fields];
} KMS_req_t;

/**
 * Indices for @ref KMS_time_t `time` array.
 */
enum KMS_time_index {
    KMS_time_cur = 0,		//!< Current time field index
    KMS_time_exp_date,		//!< Expiration date field index
    KMS_time_next_exp,		//!< Next expiration date field index
    KMS_time_num_fields		//!< Number of @ref KMS_time_t fields
};

/**
 * Time data structure.
 *
 * Use this struture to pass date/time fields in (KMS_make_timeresp(),
 * KMS_make_pubresp()) or receive date/time fields out
 * (KMS_parse_timeresp(), KMS_parse_pubresp())
 */
typedef struct {
    struct {
	char	*ptr;	//!< [in,out] NULL-terminated
	size_t	len;	//!< [in] not used, [out] available space in ptr
    } time[KMS_time_num_fields];
} KMS_time_t;

/**** TIMEREQ ****/

/** Create TIMEREQ packet.
 *
 * @param[in] req Request fields (NULL-terminated)
 * @param[out] outbuf Raw packet data written here
 * @param[in,out] buflen Available data on input, length of packet on output
 * @return KMS_ERR_SUCCESS or error code.
 */
extern int
KMS_make_timereq(KMS_req_t *req, unsigned char *outbuf, size_t *buflen);

/** Parse TIMEREQ packet.
 *
 * @param[in] inbuf Raw packet data
 * @param[in] buflen Length of packet
 * @param[out] req Request fields (NULL-terminated strings in .buf fields, .len checked on input)
 * @return KMS_ERR_SUCCESS or error code.
 */
extern int
KMS_parse_timereq(unsigned char *inbuf, size_t buflen, KMS_req_t *req);

/**** TIMERESP ****/

/** Create TIMERESP packet.
 *
 * @param[in] reason Reason code
 * @param[in] times Properties for VH (NULL-terminated strings in .buf fields, .len ignored)
 * @param[in] message If non-NULL, '\0'-terminated status message to include in packet
 * @param[out] outbuf Raw packet data written here
 * @param[in,out] buflen Available data on input, length of packet on output
 * @return KMS_ERR_SUCCESS or error code.
 */
extern int
KMS_make_timeresp(int reason, KMS_time_t *times, char *message,
		  unsigned char *outbuf, size_t *buflen);

/** Parse TIMERESP packet.
 *
 * @param[in] inbuf Raw packet data
 * @param[in] buflen Length of packet
 * @param[out] reason Reason code
 * @param[out] times Properties from VH (NULL-terminated strings in .buf fields, .len checked on input)
 * @param[out] message Status message, if any (space must be free()d)
 * @return KMS_ERR_SUCCESS or error code.
 */
extern int
KMS_parse_timeresp(unsigned char *inbuf, size_t buflen,
		   uint8_t *reason, KMS_time_t *times,
		   char **message);

/**** PUBREQ ****/

/** Create PUBREQ packet.
 *
 * @param[in] req Request fields (NULL-terminated)
 * @param[out] outbuf Raw packet data written here
 * @param[in,out] buflen Available data on input, length of packet on output
 * @return KMS_ERR_SUCCESS or error code.
 */
extern int
KMS_make_pubreq(KMS_req_t *req, unsigned char *outbuf, size_t *buflen);

/** Parse PUBREQ packet.
 *
 * @param[in] inbuf Raw packet data
 * @param[in] buflen Length of packet
 * @param[out] req Request fields
 * @return KMS_ERR_SUCCESS or error code.
 */
extern int
KMS_parse_pubreq(unsigned char *inbuf, size_t buflen, KMS_req_t *req);

/**** PUBRESP ****/

/** Create PUBRESP packet.
 *
 * @param[in] reason Reason code
 * @param[in] data Binary values for packet payload
 * @param[in] message If non-NULL, '\0'-terminated status message to include in packet
 * @param[out] outbuf Raw packet data written here
 * @param[in,out] buflen Available data on input, length of packet on output
 * @return KMS_ERR_SUCCESS or error code.
 */
extern int
KMS_make_pubresp(int reason, KMS_data_t *data, char *message,
		 unsigned char *outbuf, size_t *buflen);

/** Parse PUBRESP packet.
 *
 * @param[in] inbuf Raw packet data
 * @param[in] buflen Length of packet
 * @param[out] reason Reason code
 * @param[out] data IBE public parameters (binary data in .buf fields, .len checked on input, set on output)
 * @param[out] message Status message, if any (space must be free()d)
 * @return KMS_ERR_SUCCESS or error code.
 */
extern int
KMS_parse_pubresp(unsigned char *inbuf, size_t buflen,
		  uint8_t *reason, KMS_data_t *data, char **message);

/**** PRIVREQ ****/

/** Create PRIVREQ packet.
 *
 * @param[in] req Request fields (NULL-terminated)
 * @param[out] outbuf Raw packet data written here
 * @param[in,out] buflen Available data on input, length of packet on output
 * @return KMS_ERR_SUCCESS or error code.
 */
extern int
KMS_make_privreq(KMS_req_t *req, unsigned char *outbuf, size_t *buflen);

/** Parse PUBREQ packet.
 *
 * @param[in] inbuf Raw packet data
 * @param[in] buflenc Length of packet
 * @param[out] req Request fields
 * @return KMS_ERR_SUCCESS or error code.
 */
extern int
KMS_parse_privreq(unsigned char *inbuf, size_t buflen, KMS_req_t *req);

/**** PRIVRESP ****/

/** Create PRIVRESP packet.
 *
 * @param[in] reason Reason code
 * @param[in] data Binary values for packet payload
 * @param[in] message If non-NULL, '\0'-terminated status message to include in packet
 * @param[out] outbuf Raw packet data written here
 * @param[in,out] buflen Available data on input, length of packet on output
 * @return KMS_ERR_SUCCESS or error code.
 */
extern int
KMS_make_privresp(int reason, KMS_data_t *data, char *message,
		  unsigned char *outbuf, size_t *buflen);

/** Parse PRIVRESP packet.
 *
 * @param[in] inbuf Raw packet data
 * @param[in] buflen Length of packet
 * @param[out] reason Reason code
 * @param[out] data IBE private key (binary data in .buf fields, .len checked on input, set on output)
 * @param[out] message Status message, if any (space must be free()d)
 * @return KMS_ERR_SUCCESS or error code.
 */
extern int
KMS_parse_privresp(unsigned char *inbuf, size_t buflen,
		   uint8_t *reason, KMS_data_t *data,
		   char **message);

/** Dump raw packet contents.
 *
 * @param[in] p Pointer to packet to dump
 * @param[in] len Length of packet
 * @param[in] hdr Header to print if non-NULL
 * @param[in] show Also show ASCII data?
 */
extern void
KMS_pkt_dump(unsigned char *p, size_t len, char *hdr, int show);

/** Dump KMS_req_t contents.
 *
 * @param[in] req Pointer to req structure
 * @param[in] hdr Header to print if non-NULL
 */
extern void
KMS_pkt_dump_req(KMS_req_t *req, char *hdr);

/** Dump KMS_time_t contents.
 *
 * @param[in] time Pointer to time structure
 * @param[in] hdr Header to print if non-NULL
 */
extern void
KMS_pkt_dump_time(KMS_time_t *time, char *hdr);

/** Dump KMS_data_t contents.
 *
 * @param[in] data Pointer to data structure
 * @param[in] hdr Header to print if non-NULL
 */
extern void
KMS_pkt_dump_data(KMS_data_t *data, char *hdr);

#endif	// MASQ_KMS_MSG_H_INCLUDED
