#ifndef	MASQ_CRYPTO_H_INCLUDED
#define	MASQ_CRYPTO_H_INCLUDED	1

/**
 * The routines in this file are the ones that the MasQiTT library shim
 * should call. If code needs to call a MASQ_*() function from a supporting
 * cryptographic primitives file [currently ibe.c], then some refactoring
 * may be in order.
 */

#include "masqlib.h"
#include "kms_msg.h"
#include "tls.h"
#include "ibe.h"

#ifdef	ebug
#define	DEBUG(s,n,x)				\
    do {					\
	if (s && (s->debug > n)) {		\
	    printf x; fflush(stdout); }		\
    } while (0)
#else
#define	DEBUG(s,n,x)
#endif

extern const char	*MASQ_proto_id;

#define	MASQ_AESKEY_LEN	BB1_AESKEYLEN
#define	MASQ_IV_LEN	BB1_IVLEN
#define	MASQ_TAG_LEN	BB1_TAGLEN
#define	MASQ_HASH_LEN	BB1_HASHLEN

/**
 * Topic-specific info.
 *
 * Sequence numbers are tracked separately from @ref MASQ_KS_mek_t as they
 * persist from Client startup to shutdown, during which time there may be
 * multiple persistent MEKs.
 *
 */
typedef struct MASQ_topic_s {
    struct MASQ_topic_s	*next;		//!< Singly-linked unordered list
    char	topic[MASQ_MAXTOPIC_LEN+1];	//!< Topic Name
    int				new_seq;	//!< non-0 if a new seqnum run
    unsigned long int		next_seqnum;	//!< Next packet sequence number
    char	mek_seq[MASQ_SEQNUM_LEN+1];	//!< Seqnum of current MEK
    int				stored_packet;	//!< Have a stored packet to follow a MEK packet
    MASQ_user_properties_t	user_props;	//!< Packet after a MEK packet
    unsigned char		*payload;	//!< Packet after a MEK packet
    size_t			payload_len;	//!< Packet after a MEK packet
} MASQ_topic_t;

#include "keys.h"

#define	MASQ_PAYLOAD_LEN_EPH(tv)	\
    (MASQ_ENCAPS_KEY_LEN + MASQ_IV_LEN + tv + MASQ_TAG_LEN)
#define	MASQ_VALUE_LEN_EPH(pl)	\
    ((pl) - MASQ_ENCAPS_KEY_LEN - MASQ_IV_LEN - MASQ_TAG_LEN)
#define	MASQ_PAYLOAD_LEN_PER(tv)	(MASQ_IV_LEN + tv + MASQ_TAG_LEN)
#define	MASQ_VALUE_LEN_PER(pl)	((pl) - MASQ_IV_LEN - MASQ_TAG_LEN)

/**
 * MasQiTT crypto per-Client internal state.
 *
 * This structure is intended ONLY for internal use by MasQiTT crypto
 * routines. A pointer to this structure is handled by callers as a
 * <tt>(void *)</tt> and should not be manipulated as the contents are
 * subject to change when the crypto library is updated.
 */
typedef struct {
    char	protoid[MASQ_PROTOID_LEN+1];	//!< Protocol Id to use
    MASQ_role_t	role;				//!< Client role(s)
    char	clientid[MASQ_CLIENTID_LEN+1];	//!< Client ID of this Client
    char	expdate[MASQ_EXPDATE_LEN+1];	//!< Expiration date
    char	nextexp[MASQ_EXPDATE_LEN+1];	//!< Next expiration date
    MASQ_topic_t		*topicp;	//!< Per-Topic information
    int				need_exp;	//!< Non-0 if need new exp dates
    unsigned long int		next_seqnum;	//!< Next packet sequence number
    MASQ_mek_strategy_t		strat;		//!< MEK strategy
    unsigned long int		strat_max;	//!< Value for pkt or bytes
    MASQ_KS_mek_t		*pub_mek;	//!< Publisher MEK/key store
    MASQ_KS_mek_t		*sub_mek;	//!< Subscriber MEK/key store
    KMS_data_t			pub_params;	//!< Shared public parameters
    char			kms[128];	//!< KMS host connection info
    struct sockaddr_in		kms_addr;	//!< KMS IP and port
    WOLFSSL_CTX			*tls_ctx;	//!< wolfSSL context
#ifdef	ebug
    int				debug;		//!< For unit testing use only
#endif	// ebug
} masq_crypto_state;

/**
 * Initialize the MasQiTT crypto library.
 *
 * @param[in] protoid Protocol ID
 * @param[in] role Publisher, Subscriber, or both
 * @param[in] clientid Client ID, '\0'-terminated
 * @param[in] strategy If a Publisher, how to handle MEK update strategy
 * @param[in] strat_val For persistent MEK strategy, threshold for new MEK
 * @param[in] kms_host Name or address of KMS host ('\0'-terminated string);
 *    if NULL, use "localost"
 * @param[in] kms_port TCP/IP port KMS listens on; if <= 0, use default
 * @param[in] ca_file File containing CA TLS certificate(s)
 * @param[in] cert_file File containing my TLS certificate
 * @param[in] key_file File containing my TLS private key
 * @param[out] state Pointer to masq_crypto_state
 * @return MASQ_STATUS_SUCCESS on sucess, else error/status code
 */
extern MASQ_status_t
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
		 void **state);

#ifdef	ebug
/**
 * Return pointer to entropy buffer for debugging.
 *
 * @return Pointer to entropy buffer, size is MASQ_HASH_LEN.
 */
extern unsigned char *
MASQ_get_rand_extra(void);
#endif

/**
 * Add extra data to state for additional key-generation entropy.
 *
 * The intent is for broker-controlled random(-ish) data to be added to the
 * crypto state and incorporated into the generation of Message Encryption
 * Keys.
 *
 * @param[in] data Data to add to state.
 * @param[in] data_len Length of data in @p data.
 */
extern void
MASQ_crypto_add_entropy(unsigned char *data, size_t data_len);

/**
 * Close down MasQiTT crypto library housekeeping.
 *
 * Best practice is to call this at the end of your program.
 *
 * @param[in] state Crypto state as returned by MASQ_crypto_init().
 */
extern void
MASQ_crypto_close(void *state);

/**
 * Get random data.
 *
 * The PRNG is seeded from /dev/random the first time this is called.
 *
 * @param[out] buf Storage for random data.
 * @param[in] len Length of output buffer.
 * @return 1 on sucess, 0 if an error occurs.
 */
extern int
MASQ_rand_bytes(unsigned char *buf, size_t len);

/**
 * Get random Client ID.
 *
 * Uses only MQTT-safe digits/letters.
 *
 * @param[out] buf Storage for Client Id, should include room for '\0'.
 * @param[in] len Length of output buffer.
 * @return 1 on sucess, 0 if an error occurs.
 */
extern int
MASQ_rand_clientid(unsigned char *buf, size_t len);

/**
 * Calculate a SHA256 hash value.
 *
 * @param[in] inbuf Data to hash.
 * @param[in] inlen Length of data to hash.
 * @param[out] outbuf Storage for hash value.
 * @param[in] outlen Length of buffer for hash value.
 * @return 1 on sucess, 0 if an error occurs
 */
extern int
MASQ_hash(unsigned char *inbuf, size_t inlen,
	  unsigned char *outbuf, size_t outlen);

/**
 * Initialize a SHA256 calculation. Use this an MASQ_hash_add()
 * if providing data to be hashed in multiple chunks.
 *
 * @param[in] inbuf If non-NULL, data to hash
 * @param[in] inlen Length of data to hash
 * @return Pointer to hash context, needed for MASQ_hash_add() or NULL on error
 */
extern void *
MASQ_hash_init(unsigned char *inbuf, size_t inlen);

/**
 * Continue or finalize a SHA256 hash calculation. Providing a pointer to
 * receive the hash value (@p outbuf) finalizes the hash and invalidates the
 * @p ctx.
 *
 * @param[in] ctx Hash context as provided by MASQ_hash_init()
 * @param[in] inbuf if non-NULL, data to add to hash
 * @param[in] inlen Length of data to hash
 * @param[out] outbuf If non-NULL, storage for hash value
 * @param[in] outlen Length of buffer for hash value
 * @return 1 on sucess, 0 if an error occurs
 */
extern int
MASQ_hash_add(void *ctx,
	      unsigned char *inbuf, size_t inlen,
	      unsigned char *outbuf, size_t outlen);

/**
 * Calculate a packet-specific traffic MEK.
 *
 * @param[in] init Initial MEK.
 * @param[in] seqnum Sequence number as found in the packet.
 * @param[out] outbuf Storage for traffic MEK. Must be at least MASQ_AESKEY_LEN bytes.
 * @return 1 on sucess, 0 if an error occurs
 */
extern void
MASQ_crypto_pkt_mek(unsigned char *init, char *seqnum, unsigned char *outbuf);

/**
 * Return current MEK sequence number for a Topic Name.
 *
 * @param[in] state Crypto state.
 * @param[in] topic Topic Name.
 * @param[out] seqnum Buffer for sequence number.
 * @param[in] seqnum_len Length of sequence number buffer.
 * @return MASQ_STATUS_SUCCESS on success, else error.
 */
extern MASQ_status_t
MASQ_get_topic_mek_seqnum(masq_crypto_state *s, char *topic,
			  char *seqnum, size_t seqnum_len);

/**
 * Check for stored packet and return if found.
 *
 * Clears stored packet status.
 *
 * @param[in] s Crypto state.
 * @param[in] topic Topic Name.
 * @param[out] user_props Caller-provided storage for user properties.
 * @param[out] buffer Pointer to data (caller's responsbility to free() this).
 * @param[out] buffer_len Length of buffer data.
 * @return 1 if stored packet was found (buffer, buffer_len, props filled in), else 0
 */
extern int
MASQ_check_stored_packet(masq_crypto_state *s, char *topic,
			 MASQ_user_properties_t *user_props,
			 void **buffer, size_t *buffer_len);

/**
 * Store a packet.
 *
 * @param[in] s Crypto state.
 * @param[in] topic Topic Name.
 * @param[in] user_props User properties.
 * @param[in] buffer Pointer to payload data.
 * @param[in] buffer_len Length of payload data.
 * @return MASQ_STATUS_SUCCESS on success, else error
 */
extern MASQ_status_t
MASQ_store_packet(masq_crypto_state *s, char *topic,
		  MASQ_user_properties_t *user_props,
		  void *buffer, size_t buffer_len);

/**
 * This structure is used to pass parameters to and from the MasQiTT
 * encryption and decryption routines. The individual routines below
 * indicate which fields are used and whether they are input, output, or
 * in/out parameters.
 *
 * Note that some *_len parameters are pointers so they can be updated. As
 * "in" parameters they indicate the number of bytes in the accompanying
 * parameter. As "in/out" parameters they indicate the number of bytes
 * available on input and on output are upated to indicated the number of
 * bytes used.
 */
typedef struct {
    char		*t_name;	//!< Topic Name, NULL-terminated
    unsigned char	*t_value;	//!< Topic Value, may be binary data
    size_t		*t_value_len;	//!< t_value buffer length
    char		*client_id;	//!< Client ID, NULL-terminated
    char		*seq;		//!< Sequence #, NULL-terminated
    size_t		seq_len;	//!< seq buffer length
    char		*exp_date;	//!< Key Exp date, NULL-terminated
    size_t		exp_date_len;	//!< exp_date buffer length
    unsigned char	*mek;		//!< Message Encryption Key
    size_t		mek_len;	//!< mek buffer length
    unsigned char	*payload;	//!< buffer for PUBLISH payload
					//   or encapsulated key
    size_t		*payload_len;	//!< payload length
    int			debug;		//!< for testing, do not use
} masq_crypto_parms;

/**
 * Ephemeral key encryption (encapsulated key + encrypted Topic Value).
 *
 * Parameters below refer to the individual fields in @p p.
 *
 * @param[in] t_name Topic Name
 * @param[in] t_value Topic Value
 * @param[in] t_value_len Length of Topic Value
 * @param[in] client_id Client ID (NULL-terminated)
 * @param[out] seq Sequence Number (NULL-terminated)
 * @param[in] seq_len Length of seq buffer
 * @param[out] exp_date Key expiration date (NULL-terminated)
 * @param[in] exp_date_len Length of exp_date buffer
 * @param mek (n/a)
 * @param mek_len (n/a)
 * @param[out] payload MQTT PUBLISH packet payload (encrypted Topic Value)
 * @param[in,out] payload_len Length of payload buffer, updated on output
 * @return 1 on sucess, 0 if an error occurs
 */
extern int
MASQ_ephem_encrypt(void *state, masq_crypto_parms *p);

/**
 * Ephemeral key decryption (encapsulated key + encrypted Topic Value).
 *
 * Parameters below refer to the individual fields in @p p.
 *
 * @param[in] t_name Topic Name
 * @param[out] t_value Decrypted Topic Value
 * @param[in,out] t_value_len Length of t_value buffer, updated on output
 * @param[in] client_id Client ID (NULL-terminated)
 * @param[in] seq Sequence Number (NULL-terminated)
 * @param seq_len (n/a)
 * @param[in] exp_date Key expiration date (NULL-terminated)
 * @param[in] exp_date_len Length of Expiration Date
 * @param mek (n/a)
 * @param mek_len (n/a)
 * @param[in] payload MQTT PUBLISH packet payload (encrypted Topic Value)
 * @param[in] payload_len Length of payload
 * @return 1 on sucess, 0 if an error occurs
 */
extern int
MASQ_ephem_decrypt(void *state, masq_crypto_parms *p);

/**
 * Persistent key protocol: create AES key.
 *
 * Parameters below refer to the individual fields in @p p.
 *
 * @param[in] t_name Topic Name
 * @param t_value (n/a)
 * @param t_value_len (n/a)
 * @param[in] client_id Client ID (NULL-terminated)
 * @param[out] seq Sequence Number (NULL-terminated)
 * @param[in] seq_len Length of seq buffer
 * @param[out] exp_date Key expiration date (NULL-terminated)
 * @param[in] exp_date_len Length of exp_date buffer
 * @param[out] mek Message encryption key
 * @param[in] mek_len Length of mek buffer
 * @param[out] payload MQTT PUBLISH packet payload (encapsulated MEK)
 * @param[in,out] payload_len Length of payload buffer, updated on output
 * @return 1 on sucess, 0 if an error occurs
 */
extern int
MASQ_pers_new_key(void *state, masq_crypto_parms *p);

/**
 * Persistent key protocol: recover AES key.
 *
 * Parameters below refer to the individual fields in @p p.
 *
 * @param[in] t_name Topic Name
 * @param t_value (n/a)
 * @param t_value_len (n/a)
 * @param[in] client_id Client ID (NULL-terminated)
 * @param[in] seq Sequence Number (NULL-terminated)
 * @param seq_len (n/a)
 * @param[in] exp_date Key expiration date (NULL-terminated)
 * @param[in] exp_date_len Length of Expiration Date
 * @param[out] mek Unencapsulated message encryption key
 * @param[in] mek_len Length of mek buffer
 * @param[in] payload MQTT PUBLISH packet payload (encapsulated MEK)
 * @param[in] payload_len Length of payload
 * @return 1 on sucess, 0 if an error occurs
 */
extern int
MASQ_pers_recover_key(void *state, masq_crypto_parms *p);

/**
 * Persistent key protocol: encrypt Topic Value.
 *
 * Parameters below refer to the individual fields in @p p.
 *
 * @param[in] t_name Topic Name
 * @param[in] t_value Topic Value
 * @param[in] t_value_len Length of Topic Value
 * @param client_id (n/a)
 * @param[out] seq Sequence Number (NULL-terminated)
 * @param[in] seq_len Length of seq buffer
 * @param exp_date (n/a)
 * @param exp_date_len (n/a)
 * @param[in] mek Message encryption key
 * @param[in] mek_len Length of message encryption key
 * @param[out] payload MQTT PUBLISH packet payload (encrypted Topic Value)
 * @param[in,out] payload_len Length of payload buffer, updated on output
 * @return 1 on sucess, 0 if an error occurs
 */
extern int
MASQ_pers_encrypt(void *state, masq_crypto_parms *p);

/**
 * Persistent key protocol: decrypt Topic Value.
 *
 * Parameters below refer to the individual fields in @p p.
 *
 * @param t_name (n/a)
 * @param[out] t_value Decrypted Topic Value
 * @param[in,out] t_value_len Length of t_value buffer, updated on output
 * @param client_id (n/a)
 * @param[in] seq (NULL-terminated)
 * @param seq_len (n/a)
 * @param exp_date (n/a)
 * @param exp_date_len (n/a)
 * @param[in] mek Message encryption key
 * @param[in] mek_len Length of message encryption key
 * @param[in] payload MQTT PUBLISH packet payload (encrypted Topic Value)
 * @param[in] payload_len Length of payload
 * @return 1 on sucess, 0 if an error occurs
 */
extern int
MASQ_pers_decrypt(void *state, masq_crypto_parms *p);

/**
 * Get overhead for encrypting Topic Values.
 *
 * This returns (in @p overhead_bytes) the number of additional bytes that
 * must be provided in a buffer to receive an encrypted Topic Value beyond
 * the number of bytes in the Topic Value itself. Conversely, a decrypted
 * Topic Value will be this many bytes shorter than its encrypted version.
 *
 * If a Publisher is using persistent MEKs, the @p mek_bytes parameter is
 * filled in with the number of bytes in a MEK-only payload. Before calling
 * MASQ_crypto_api_encrypt(), the caller should ensure the payload buffer is
 * sized to the maximum of @p mek_bytes and (length of Topic Value + @p
 * overhead_bytes).
 *
 * @param[in] strategy Crypto strategy.
 * @param[out] overhead_bytes Number of bytes added by encryption and reduced by decryption.
 * @param[out] mek_bytes Number of bytes in a MEK-only payload.
 * @return Success or error code.
 */
extern MASQ_status_t
MASQ_crypto_overhead(MASQ_mek_strategy_t strategy,
		     size_t *overhead_bytes,
		     size_t *mek_bytes);

// debugging stuff

/**
 * Debugging - Dump a single `MASQ_topic_t` structure.
 *
 * @param[in] t `MASQ_topic_t` structure to dump.
 * @param[in] hdr If non-NULL, text to print as a header.
 */
extern void
MASQ_dump_topic(MASQ_topic_t *t, const char *hdr);

/**
 * Debugging - Dump a linked list of `MASQ_topic_t` structures.
 *
 * @param[in] t Head of `MASQ_topic_t` structure list to dump.
 * @param[in] hdr If non-NULL, text to print as a header.
 */
extern void
MASQ_dump_topics(MASQ_topic_t *t, const char *hdr);

/**
 * Debugging - Dump a `masq_crypto_parms` structure.
 *
 * @param[in] p `masq_crypto_parms` structure to dump.
 * @param[in] hdr If non-NULL, text to print as a header.
 */
extern void
MASQ_dump_crypto_parms(masq_crypto_parms *p, const char *hdr);

/**
 * Debugging - Dump a single `MASQ_KS_mek_t` structure.
 *
 * @param[in] p `MASQ_KS_mek_t` structure to dump.
 * @param[in] hdr If non-NULL, text to print as a header.
 * @param[in] n Index value to print (not used in picking which struct to dump).
 */
extern void
MASQ_dump_mek(MASQ_KS_mek_t *mek, const char *hdr, int n);

/**
 * Debugging - Dump all `MASQ_KS_mek_t` structures in a list.
 *
 * @param[in] p Head of `MASQ_KS_mek_t` list to dump.
 * @param[in] hdr If non-NULL, text to print as a header.
 */
extern void
MASQ_dump_meks(MASQ_KS_mek_t *mek, const char *hdr);

/**
 * Debugging - Dump a `MASQ_user_properties_t` structure.
 *
 * @param[in] p `MASQ_user_properties_t` structure to dump.
 * @param[in] hdr If non-NULL, text to print as a header.
 */
extern void
MASQ_dump_properties(MASQ_user_properties_t *p, const char *hdr);

/**
 * Debugging - Dump a `MASQ_crypto_state` structure.
 *
 * @param[in] p `MASQ_crypto_state` structure to dump.
 * @param[in] hdr If non-NULL, text to print as a header.
 */
extern void
MASQ_dump_state(masq_crypto_state *s, const char *hdr);

/**
 * Debugging - Dump arbitrary data in the style of `hexdump -C`.
 *
 * @param[in] p Pointer to data to dump.
 * @param[in] len Length of data to dump.
 * @param[in] hdr If non-NULL, text to print as a header.
 * @param[in] prefix If non-zero, lines prefixed with this char (default: ~).
 * @param[in] show If non-zero, include ASCII representation on right.
 */
extern void
MASQ_dump(unsigned char *p, size_t len, char *hdr, char prefix, int show);

#endif	// MASQ_CRYPTO_H_INCLUDED
