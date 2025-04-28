#ifndef	MASQLIB_H_INCLUDED
#define	MASQLIB_H_INCLUDED

#define	MASQ_PROTOID_LEN	(16)	// excludes '\0'
#define	MASQ_SEQNUM_LEN		(8)	// excludes '\0'
#define	MASQ_CLIENTID_LEN	(16)	// excludes '\0'
#define	MASQ_EXPDATE_LEN	(16)	// excludes '\0'
#define	MASQ_MAXTOPIC_LEN	(128)	// arbitrary

/**
 * Client roles.
 */
typedef enum {
    MASQ_role_none = 0,			//!< Role not established
    MASQ_role_publisher,		//!< Client is a Publisher
    MASQ_role_subscriber,		//!< Client is a Subscriber
    MASQ_role_both,			//!< Client is Publisher and Subscriber
} MASQ_role_t;

typedef enum {
    MASQ_key_none = 0,			//!< I'm a Subscriber and don't gen keys
    MASQ_key_ephemeral,			//!< Use ephmeral keys
    MASQ_key_persistent_pkt,		//!< Use persistent key for X packets
    MASQ_key_persistent_bytes,		//!< Use persistent key for X bytes
    MASQ_key_persistent_time,		//!< Use persistent key for X seconds
    MASQ_key_persistent_exp,		//!< Use persistent key until exp date
} MASQ_mek_strategy_t;

#define	MASQ_MAX_PROPERTIES	(5)

#define	MASQ_MAX_PROP_NAME_LEN	(8)	//!< Max length of property Name
// revisit the following if ProtoID can be arbitrarily long
#if MASQ_CLIENTID_LEN >= MASQ_EXPDATE_LEN
#define	MASQ_MAX_PROP_VALUE_LEN	MASQ_CLIENTID_LEN //!< Max length of prop Value
#else
#define	MASQ_MAX_PROP_VALUE_LEN	MASQ_EXPDATE_LEN  //!< Max length of prop Value
#endif

/**
 * This struct is used for passing User Properties.
 *
 * Each Property is specified with a name and a value, both of which are
 * '\0'-terminated ASCII strings. Ordering should be preserved when
 * translating these to or from a PUBLISH packet.
 */
typedef struct {
    int		num_props;	//!< number of valid properties
    struct {
	char	name[MASQ_MAX_PROP_NAME_LEN+1];		//!< name of property
	char	value[MASQ_MAX_PROP_VALUE_LEN+1];	//!< value of property
    } prop[MASQ_MAX_PROPERTIES];
} MASQ_user_properties_t;

/* updates to MASQ_status_t should be reflected in api.c:MASQ_status_to_str() */
typedef enum {
    MASQ_STATUS_SUCCESS = 0,	//!< Success
    MASQ_STATUS_ANOTHER,	//!< call again for another packet
    MASQ_STATUS_KEY_MGMT,	//!< key management packet, no data
    MASQ_ERR_BAD_PROTOID,	//!< invalid or unsupported Protocol ID
    MASQ_ERR_INVAL,		//!< invalid parameter or value
    MASQ_ERR_INVAL_ROLE,	//!< invalid role for this operation
    MASQ_ERR_TLS_INIT,		//!< error initializing TLS subsystem
    MASQ_ERR_NO_KEY,		//!< cannot determine encryption key
    MASQ_ERR_DECRYPT,		//!< error on decryption (tag mismatch)
    MASQ_ERR_NOMEM,		//!< cannot alloc memory
    MASQ_ERR_NOSPACE,		//!< not enough space provided for output
    MASQ_ERR_MALFORMED_PACKET,	//!< malformed packet
    MASQ_ERR_MALFORMED_UTF8,	//!< malformed UTF-8 code point(s)
    MASQ_ERR_PAYLOAD_SIZE,	//!< payload too large for a packet
    MASQ_ERR_WRONG_MSG_TYPE,	//!< parsing function does not handle this
    MASQ_ERR_NOT_FOUND,		//!< an entry was not found
    MASQ_ERR_BAD_ENTRY,		//!< an entry was malformed/missing data
    MASQ_ERR_KMS,		//!< error communicating with KMS
    MASQ_ERR_MIRACL,		//!< error from MIRACL Core library
    MASQ_ERR_CRYPTO,		//!< error from crypto code, should not happen?
    MASQ_ERR_INTERNAL,		//!< internal error, should not happen?
} MASQ_status_t;

// 5/Secure, "MQTT" -> 6788 on keypad (0xddd4)
#define	MASQ_KMS_DFLT_PORT	(56788)

#endif	// MASQLIB_H_INCLUDED
