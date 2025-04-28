#ifndef	MASQITT_H_INCLUDED
#define	MASQITT_H_INCLUDED 1

#if defined(_MSC_VER) && _MSC_VER < 1900 && !defined(bool)
# define bool	char
# define true	1
# define false	0
#else
# include <stdbool.h>
#endif

#include <stddef.h>
#include <stdint.h>

#include "masqlib.h"
#include "mosquitto.h" /* For some mosquitto structs */

/* ======================================================================
 *
 * Section: Library version, init, and cleanup
 *
 * ====================================================================== */


struct userdata_callback {
    void	*userdata;	//!< The original user-provided callback data
    const char	*topic;		//!< mosquitto topic string
    void	*state;		//!< MasQiTT state for decrypting messages */
    int (*callback)(struct mosquitto *, void *, //!< The user-provided callback
		    const struct mosquitto_message *);
};

struct masqitt {
    struct mosquitto	*mosq;	//!< Internal mosquitto struct
    void		*state;	//!< Internal crypto state
    struct userdata_callback	cb_userdata;	//!< For storing callback info
    MASQ_role_t		role;	//!< Client role
    MASQ_mek_strategy_t	strategy;	//!< Pulisher key management strategy
    unsigned long int	strat_val;	//!< If using persistent MEK
};
typedef struct mqtt5__property	mosquitto_property;

/* ======================================================================
 *
 * Section: Client creation, destruction, and reinitialisation
 *
 * ====================================================================== */
/**
 * Create a new MasQiTT client instance.
 *
 * @param[in] masq_clientid String to use as the MasQiTT client id.
 * 	                '\0'-terminated. If NULL, a random client id
 * 	                will be generated. If id is NULL, clean_session must
 * 	                be true.
 * @param[in] mqtt_clientid Mosquitto (MQTT) client ID of caller,
 *   '\0'-terminated.
 * @param[in] clean_session set to true to instruct the broker to clean all
 *   messages and subscriptions on disconnect, false to instruct it to keep
 *   them. See the man page mqtt(7) for more details.  Note that a client
 *   will never discard its own outgoing messages on disconnect. Calling
 *   mosquitto_connect() or mosquitto_reconnect() will cause the messages to
 *   be resent.  Use <mosquitto_reinitialise> to reset a client to its
 *   original state.  Must be set to true if the id parameter is NULL.
 * @param[in] obj A user pointer that will be passed as an argument to any
 *   callbacks that are specified.
 * @param[in] role MASQ_role_publisher, MASQ_role_subscriber, or MASQ_role_both
 * @param[in] strategy If a Publisher, MEK encapsulation strategy to use;
 *    else MASQ_key_none.
 * @param strat_val If a Publisher and using persistent MEKs,
 *    threshold criteria for generating a new MEK.
 * @param[in] kms_host Name or address of KMS host ('\0'-terminated string);
 *    if NULL, use "localost"
 * @param[in] kms_port TCP/IP port KMS listens on; if <= 0, use default
 * @param[in] ca_file File containing CA TLS certificate(s)
 * @param[in] cert_file File containing my TLS certificate
 * @param[in] key_file File containing my TLS private key
#ifdef	ebug
 * @param[in] debug To enable or disable debug logging.
#endif
 * @return a pointer to an allocated struct masqitt on success, or NULL on
 *    failure.
 *  Interrogate errno to determine the cause for the failure:
 *  - ENOMEM on out of memory.
 *  - EINVAL on invalid input parameters.
 */
extern struct masqitt *
MASQ_new(const char *masq_clientid,
	 const char *mqtt_clientid,
	 bool clean_session,
	 void *obj,
	 MASQ_role_t role,
	 MASQ_mek_strategy_t strategy,
	 unsigned long int strat_val,
	 char *kms_host,
	 int kms_port,
	 char *ca_file,
	 char *cert_file,
	 char *key_file
#ifdef	ebug
	 , int debug
#endif
);

/**
 * Retrieve the internal Mosquitto instantiation of a MasQiTT client
 * instance.  This may be needed to call a Mosquitto API function that
 * MasQiTT does not provide.
 * 
 * This returns a pointer, NOT a copy of the struct mosquitto.
 * DO NOT free this pointer.
 *
 * @param[in] masq a struct masqitt pointer.
 * @return Pointer to internal struct mosquitto.
 */
extern struct mosquitto *
MASQ_get_mosquitto(const struct masqitt *masq);

/**
 * Retrieve the internal MasQiTT state of a MasQiTT client instance.
 * 
 * This returns a pointer, NOT a copy of the struct mosquitto.
 * DO NOT free this pointer.
 *
 * @param[in] masq a struct masqitt pointer.
 * @return Pointer to internal struct mosquitto.
 */
extern void *
MASQ_get_masqitt(const struct masqitt *masq);

/**
 * Free memory associated with a MasQiTT client instance.
 *
 * Parameters:
 * @param[in] masq a struct masqitt pointer to free.
 */
extern void
MASQ_destroy(struct masqitt *masq);

/**
 * Not yet implemented.
 */
extern MASQ_status_t
MASQ_reinitialise(struct masqitt *masq,
		  const char *id,
		  bool clean_session,
		  void *obj);

/**
 * Wrapper for MASQ_publish_v5().
 */
extern MASQ_status_t
MASQ_publish(struct masqitt *masq,
	     int *mid,
	     const char *topic,
	     int payloadlen,
	     const void *payload,
	     int qos,
	     bool retain);

/**
 * Publish a message on a given topic, with attached MQTT properties.
 * Uses MasQiTT to encrypt the payload using parameters provided to MASQ_new().
 *
 * Use e.g. mosquitto_property_add_string() and similar to create a list of
 * properties, then attach them to this publish. Properties need freeing with
 * mosquitto_property_free_all().
 *
 * MasQiTT requires MQTT v5 in order to use properties. The user does not
 * provide any properties for MasQiTT to perform crypto operations.  If the
 * MasQiTT instance @p masq is using user-provided properties, the
 * @p properties argument will be applied to the PUBLISH message.
 *
 * Set your client to use MQTT v5 immediately after it is created:
 *
 * mosquitto_int_option(mosq, MOSQ_OPT_PROTOCOL_VERSION, MQTT_PROTOCOL_V5);
 *
 * @param[in] masq a valid MasQiTT instance.
 * @param[in] mid pointer to an int. If not NULL, the function will set this
 *               to the message id of this particular message. This can be then
 *               used with the publish callback to determine when the message
 *               has been sent.
 *               Note that although the MQTT protocol doesn't use message ids
 *               for messages with QoS=0, libmosquitto assigns them message ids
 *               so they can be tracked with this parameter.
 * @param[in] topic null terminated string of the topic to publish to.
 * @param[in] payloadlen the size of the payload (bytes). Valid values are
 *               between 0 and 268,435,455.
 * @param[in] payload pointer to the data to send. If payloadlen > 0 this
 *               must be a valid memory location.
 * @param[in] qos integer value 0, 1, or 2 indicating the Quality of Service
 *               to be used for the message.
 * @param[in] retain set to true to make the message retained.
 * @param[in] properties a valid mosquitto_property list, or NULL.
 * @return Success or error code.
 *     MASQ_STATUS_SUCCESS on success.
 *     MASQ_ERR_INVAL if the input parameters were invalid, including invalid payloadlen.
 *     MASQ_ERR_NOMEM if an out of memory condition occurred.
 *     MASQ_ERR_INTERNAL if an error related to internal crypto operations occurred.
 */
extern MASQ_status_t
MASQ_publish_v5(struct masqitt *masq,
		int *mid,
		const char *topic,
		int payloadlen,
		const void *payload,
		int qos,
		bool retain,
		const mosquitto_property *properties);

/*
MASQ_status_t MASQ_subscribe_simple(
		struct mosquitto_message **messages,
		int msg_count,
		bool want_retained,
		const char *topic,
		int qos,
		const char *host,
		int port,
        const char *masq_clientid,
		const char *mqtt_clientid,
        MASQ_mek_strategy_t strategy,
        unsigned long int strat_val,
        char *kms_host,
        int kms_port,
		int keepalive,
		bool clean_session,
		const char *username,
		const char *password,
		const struct libmosquitto_will *will,
		const struct libmosquitto_tls *tls
#ifdef	ebug
		, int debug
#endif
);

MASQ_status_t MASQ_subscribe_callback(
		int (*callback)(struct mosquitto *, void *, const struct mosquitto_message *),
		void *userdata,
		const char *topic,
		int qos,
		const char *host,
		int port,
        const char *masq_clientid,
		const char *mqtt_clientid,
        MASQ_mek_strategy_t strategy,
        unsigned long int strat_val,
        char *kms_host,
        int kms_port,
		int keepalive,
		bool clean_session,
		const char *username,
		const char *password,
		const struct libmosquitto_will *will,
		const struct libmosquitto_tls *tls
#ifdef	ebug
		, int debug
#endif
);
*/

/**
 * Set the message callback. This is called when a message is received from the
 * broker and the required QoS flow has completed.
 *
 * It is valid to set this callback for all MQTT protocol versions. If it is
 * used with MQTT clients that use MQTT v3.1.1 or earlier, then the @p props
 * argument will always be NULL.
 *
 * @param[in] masq A valid MasQiTT instance.
 * @param[in] on_message A callback function in the following form: void
 *               callback(struct mosquitto *mosq, void *obj, const struct
 *               mosquitto_message *message)
 *
 * Callback Parameters:
 * - mosq: the mosquitto instance making the callback.
 * - obj: the user data provided in <MASQ_new>
 * - message: the message data. This variable and associated memory will be
 *            freed by the library after the callback completes. The client
 *            should make copies of any of the data it requires.
 * - props: list of MQTT 5 properties, or NULL
 *
 * See Also: mosquitto_message_copy()
 */
extern void
MASQ_message_v5_callback_set(struct masqitt *masq,
			     void (*on_message)(struct mosquitto *, void *,
						const struct mosquitto_message *,
						const mosquitto_property *props)
			     );

#endif /* MASQITT_H_INCLUDED */
