#include "masqitt.h"
#include "crypto.h"
#include "api.h"

#include <mosquitto.h>
#include "mqtt_protocol.h"	// For user property identifiers

#ifndef	MAX
#define MAX(a,b)				\
    ({ __typeof__ (a) _a = (a);			\
	__typeof__ (b) _b = (b);		\
	_a > _b ? _a : _b; })
#endif


/**
 * Initialize the MasQiTT library. For internal use only.
 *
 * Must be called before any other MasQiTT functions.
 *
 * This function is *not* thread safe because it calls the not-thread-safe
 * mosquitto_lib_init().
 *
 * @param[in] protoid Protocol ID
 * @param[in] role MASQ_role_publisher, MASQ_role_subscriber, or MASQ_role_both
 * @param[in] clientid MasQiTT Client ID of caller, '\0'-terminated.
 * @param[in] strategy If a Publisher, MEK encapsulation strategy to use;
 *    else MASQ_key_none.
 * @param strat_val If a Publisher and using persistent MEKs,
 *    threshold criteria for generating a new MEK.
 * @param[in] kms_host Name or address of KMS host ('\0'-terminated string);
 *    if NULL, use "localost"
 * @param[in] kms_port TCP/IP port KMS listens on; if <= 0, use default
#ifdef	ebug
 * @param[in] debug To enable or disable debug logging.
#endif
* @param[out] state Pointer to crypto state information, must be provided to other API calls.
* @return Success or error code.
 */
static MASQ_status_t
MASQ_lib_init(const char *protoid,
	      MASQ_role_t role,
	      char *clientid,
	      MASQ_mek_strategy_t strategy,
	      unsigned long int strat_val,
	      char *kms_host,
	      int kms_port,
	      char *ca_file,
	      char *cert_file,
	      char *key_file,
#ifdef  ebug
	      int debug,
#endif
	      void **state)
{
    int			ret = 0;
    MASQ_status_t	status;
    
    status = MASQ_crypto_api_init(protoid, role, clientid,
				  strategy, strat_val,
				  kms_host, kms_port,
				  ca_file, cert_file, key_file,
#ifdef	ebug
				  debug,
#endif
				  state);
    if (MASQ_STATUS_SUCCESS != status) {
        return status;
    }
    ret = mosquitto_lib_init();
    if (MOSQ_ERR_SUCCESS != ret) {
        MASQ_crypto_api_close(state);
        return MASQ_ERR_INTERNAL;
    }
    return MASQ_STATUS_SUCCESS;
}

struct masqitt *
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
	 )
{
    // On error, this returns NULL and sets errno.
    MASQ_status_t	status;
    struct masqitt	*masq = NULL;
    void		*state = NULL;
    struct mosquitto	*mosq = NULL;

    // This max length exists according to MQTT specs, but is never checked
    // in mosquitto.c
    if ((mqtt_clientid == NULL) ||
	(strlen(mqtt_clientid) > (MOSQ_MQTT_ID_MAX_LENGTH + 1))) {
        errno = EINVAL;
        return NULL;
    }

    if ((NULL == masq_clientid) ||
	(MASQ_CLIENTID_LEN != strlen(masq_clientid))) {
        errno = EINVAL;
        return NULL;
    }

    masq = malloc(sizeof(struct masqitt));
    if (NULL == masq) {
        errno = ENOMEM;
        return NULL;
    }

    status = MASQ_lib_init(MASQ_proto_id, role,
			   (char *) masq_clientid, strategy, strat_val,
			   kms_host, kms_port,
			   ca_file, cert_file, key_file,
#ifdef  ebug
			   debug,
#endif
			   &state);
    if (MASQ_STATUS_SUCCESS != status) {
        errno = EINVAL;
        goto err;
    }

    /* Setup for future callbacks */
    masq->cb_userdata.userdata = obj;
    masq->cb_userdata.callback = NULL; /* Callback will be set later */
    masq->cb_userdata.state = state;
    mosq = mosquitto_new(mqtt_clientid, clean_session, &(masq->cb_userdata));
    if (NULL == mosq) {
        errno = ENOMEM;
        goto err;
    }

    /* MasQiTT requires mosquitto v5 */
    mosquitto_int_option(mosq, MOSQ_OPT_PROTOCOL_VERSION, MQTT_PROTOCOL_V5);

    masq->mosq = mosq;
    masq->state = state;
    masq->role = role;
    masq->strategy = strategy;
    masq->strat_val = strat_val;
    return masq;
err:
    // Setting these pointers to NULL is consistent with how mosquitto deals
    // with important internal pointers
    if (NULL != mosq) {
        mosquitto_destroy(mosq);
        mosq = NULL;
    }
    if (NULL != state) {
        MASQ_crypto_api_close(state);
        state = NULL;
    }
    if (NULL != masq) {
        memset(&masq->cb_userdata, 0, sizeof(struct userdata_callback));
        free(masq);
        masq = NULL;
    }
    // Technically returns a status code (should always be success), but
    // this is already the err path.
    mosquitto_lib_cleanup();
    return NULL;
}

MASQ_status_t
MASQ_reinitialise(struct masqitt *masq, const char *id,
		  bool clean_session, void *obj)
{
    // Not yet implemented
    return MASQ_ERR_INTERNAL;
}

void
MASQ_destroy(struct masqitt *masq)
{
    if (NULL == masq) return;
    if (NULL != masq->mosq) {
        mosquitto_destroy(masq->mosq);
        masq->mosq = NULL;
    }
    if (NULL != masq->state) {
        MASQ_crypto_api_close(masq->state);
        masq->state = NULL;
    }
    free(masq);
    mosquitto_lib_cleanup();
}

MASQ_status_t
MASQ_publish(struct masqitt *masq, int *mid,
	     const char *topic, int payloadlen, const void *payload,
	     int qos, bool retain)
{
    return MASQ_publish_v5(masq, mid, topic, payloadlen, payload,
			   qos, retain, NULL);
}

MASQ_status_t MASQ_publish_v5(struct masqitt *masq, int *mid,
			      const char *topic,
			      int payloadlen, const void *payload,
			      int qos, bool retain,
			      const mosquitto_property *properties)
{
    int			ret = 0;
    MASQ_status_t	status;
    MASQ_user_properties_t	user_properties = { 0 };
    mosquitto_property		*merged_mosq_properties = NULL;

    unsigned char	*crypto_outbuf = NULL;
    size_t		payload_with_overhead_len = 0;
    size_t		max_crypto_outbuf_len = 0;
    size_t		overhead_bytes;
    size_t		mek_bytes;
    int			i;
    int			identifier = MQTT_PROP_USER_PROPERTY;

    // overhead_bytes is used in both ephemeral and persistent
    // mek_bytes can be used when using persistent keys and it has expired
    status = MASQ_crypto_api_overhead(masq->strategy,
				      &overhead_bytes,
				      &mek_bytes);
    if (MASQ_STATUS_SUCCESS != status) {
        goto err;
    }
    // Size check
    if ((payloadlen <= 0) || (payloadlen >= MQTT_MAX_PAYLOAD)) {
        status = MASQ_ERR_INVAL;
        goto err;
    }
    if ((payloadlen + overhead_bytes) > MQTT_MAX_PAYLOAD) {
        status = MASQ_ERR_INVAL;
        goto err;
    }
    // Choose the correct buffer size to allocate
    switch (masq->strategy) {
    case MASQ_key_ephemeral:
        payload_with_overhead_len = payloadlen + overhead_bytes;
        max_crypto_outbuf_len = payload_with_overhead_len;
	break;

    case MASQ_key_persistent_pkt:
    case MASQ_key_persistent_bytes:
    case MASQ_key_persistent_time:
    case MASQ_key_persistent_exp:
        payload_with_overhead_len = payloadlen + overhead_bytes;
        max_crypto_outbuf_len = MAX(payload_with_overhead_len, mek_bytes);
	break;

    default:
        // Error, should not publish if "none" strategy
        status = MASQ_ERR_INVAL;
        goto err;
	break;
    }
    crypto_outbuf = malloc(max_crypto_outbuf_len);
    if (NULL == crypto_outbuf) {
        status = MASQ_ERR_NOMEM;
        goto err;
    }
    memset(crypto_outbuf, 0, max_crypto_outbuf_len);
#ifdef ebug
    printf("%s: message before encrypt: \"", __func__);
    for (i = 0; i < payloadlen; i++) {
        char payload_byte = ((char *)(payload))[i];
        printf("%c", payload_byte);
    }
    printf("\"\n");
#endif
    status = MASQ_crypto_api_encrypt(masq->state,
				     (char *) topic,
				     (char *) payload,
				     payloadlen,
				     &user_properties,
				     crypto_outbuf,
				     &max_crypto_outbuf_len);

    /* If MASQ_STATUS_ANOTHER, the packet is MEK-only.
     * Send it as a publish packet with the Retain bit set (packet type
     * 0x31).
     * Then call encrypt again with same Topic Name to get the packet info
     * for encrypted Topic Value to send.
     */
    
    retain = 0;	/* override provided value */
    
    if (MASQ_STATUS_ANOTHER == status) {
	
        /* Convert MASQITT crypto properties for use with mosquitto API */
        /* The first call to mosquitto_property_add_string_pair will
         * allocate and make the first property the beginning of the linked
         * list. */
        for (i = 0; i < user_properties.num_props; i++) {
            ret = mosquitto_property_add_string_pair(&merged_mosq_properties,
						     identifier,
						     user_properties.prop[i].name,
						     user_properties.prop[i].value);
            if (MOSQ_ERR_SUCCESS != ret) {
                status = MASQ_ERR_INTERNAL;
                goto err;
            }
        }
        memset(&user_properties, 0, sizeof(MASQ_user_properties_t));
        
	retain = 1;	/* override provided value */
	
        ret = mosquitto_publish_v5(masq->mosq,
				   mid,
				   topic,
				   mek_bytes,
				   crypto_outbuf,
				   qos,
				   retain,
				   merged_mosq_properties);

	retain = 0;	/* override provided value */
	
        if (MOSQ_ERR_SUCCESS != ret) {
            status = MASQ_ERR_INTERNAL;
            goto err;
        }
	
        memset(crypto_outbuf, 0, max_crypto_outbuf_len);
        status = MASQ_crypto_api_encrypt(masq->state,
					 (char *) topic,
					 (char *) payload,
					 payloadlen,
					 &user_properties,
					 crypto_outbuf,
					 &payload_with_overhead_len);
        /* Cleanup mosq_properties, it will be used again for the next publish */
        if (NULL != merged_mosq_properties) {
            mosquitto_property_free_all(&merged_mosq_properties);
            merged_mosq_properties = NULL;
        }
    }
    
    if (MASQ_STATUS_SUCCESS != status) {
        /* This will return the status error from a MASQ encrypt operation */
        goto err;
    }

    /* Merge user-provided properties with MASQITT crypto properties
     * for use with mosquitto API */
    if (NULL != properties) {
        ret = mosquitto_property_copy_all(&merged_mosq_properties, properties);
        if (MOSQ_ERR_SUCCESS != ret) {
            status = MASQ_ERR_INTERNAL;
            goto err;
        }
    }

    /* The first call to mosquitto_property_add_string_pair will allocate
     * and make the first property the beginning of the linked list, if
     * *merged_mosq_properties is still NULL. */
    for (i = 0; i < user_properties.num_props; i++) {
        ret = mosquitto_property_add_string_pair(&merged_mosq_properties,
						 identifier,
						 user_properties.prop[i].name,
						 user_properties.prop[i].value);
        if (MOSQ_ERR_SUCCESS != ret) {
            status = MASQ_ERR_INTERNAL;
            goto err;
        }
    }
#ifdef ebug
    MASQ_dump(crypto_outbuf, payload_with_overhead_len,
	      "message after encrypt", '>', 1);
#endif
    
    ret = mosquitto_publish_v5(masq->mosq,
			       mid,
			       topic,
			       payload_with_overhead_len,
			       crypto_outbuf,
			       qos,
			       retain,
			       merged_mosq_properties);
    if (MOSQ_ERR_SUCCESS != ret) {
        status = MASQ_ERR_INTERNAL;
        goto err;
    }
    status = MASQ_STATUS_SUCCESS;
    
 err:
    if (NULL != crypto_outbuf) {
        memset(crypto_outbuf, 0, max_crypto_outbuf_len);
        free(crypto_outbuf);
        crypto_outbuf = NULL;
    }
    if (NULL != merged_mosq_properties) {
        mosquitto_property_free_all(&merged_mosq_properties);
        merged_mosq_properties = NULL;
    }
    memset(&user_properties, 0, sizeof(MASQ_user_properties_t));

    return status;
}

/*******************************
 * Callbacks and encypted packet parsing (decrypting topic values from
 * subscriptions)
 */

/**
 * Internal message callback. This is a wrapper for callbacks that are
 * registered using MASQ_message_v5_callback_set(). It is called when a
 * message is received from the broker and the required QoS flow has
 * completed.  This wrapper allows the MasQiTT-encrypted published payload
 * to be decrypted and the resulting decrypted message be passed to the
 * original callback. All of this is intented to be transparent to the
 * caller.
 *
 * MasQiTT can only be used for MQTT protocol version v5.
 *
 * @param[in] mosq A valid mosquitto instance.
 * @param[in] on_message A callback function in the following form:
 *               void callback(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message)
 *
 * Callback Parameters:
 * - mosq: the mosquitto instance making the callback.
 * - obj: the user data provided in <mosquitto_new>
 * - message: the message data. This variable and associated memory will be
 *            freed by the library after the callback completes. The client
 *            should make copies of any of the data it requires.
 *  - props: list of MQTT 5 properties, or NULL
 *
 * @return TBD.
 */
static int
on_message_callback(struct mosquitto *mosq,
		    void *obj,
		    const struct mosquitto_message *message,
		    const mosquitto_property *props)
{
    int		ret = 0;
    int		err = 1;	// Default to error = True
    int		rc;
    
    /* Retrieve callback struct that was set in "MASQ_new()" */
    struct userdata_callback	*userdata = (struct userdata_callback *) obj;
#ifdef ebug
    printf("MASQ %s\n", __func__);
#endif
    if (NULL == userdata) {
        /* Something terribly wrong happened if this is NULL */
        goto done;
    }
    
    /* Decrypt the message(s) */
    MASQ_status_t		status;
    MASQ_user_properties_t	masq_user_properties = { 0 };
    const mosquitto_property	*prop, *p;
    MASQ_mek_strategy_t		strategy = MASQ_key_none;

    unsigned char		*crypto_outbuf = NULL;
    size_t			crypto_outbuf_len = 0;
    size_t			overhead_bytes;
    size_t			mek_bytes;
    int				identifier = MQTT_PROP_USER_PROPERTY;
    char			*pub_protoid = NULL;
    char			*pub_seqnum = NULL;
    char			*pub_masq_clientid = NULL;
    char			*pub_masq_km_seq = NULL;
    char			*pub_params_exp = NULL;
    struct mosquitto_message	*new_message = NULL;
    
    /* Convert mosquitto_properties to MASQ_user_properties_t 
     * Also extract info we need to decrypt. */
    for (prop = props; prop != NULL; prop = mosquitto_property_next(prop)) {
	
        char	*tmp_name;
        char	*tmp_value;
	
        if ((masq_user_properties.num_props >= MASQ_MAX_PROPERTIES) ||
	    (masq_user_properties.num_props < 0)) {
            printf("%s: Too many MASQ properties", __func__);
            goto done;
        }
	
        /* Skip non-MQTT_PROP_USER_PROPERTY identifiers */
        p = mosquitto_property_read_string_pair(prop, identifier,
						&tmp_name,
						&tmp_value, 0);
        if (NULL == p) {
            continue;
	}
#ifdef ebug
        printf("%s: Parsing parameter %s\n", __func__, tmp_name);
#endif
        /* Obtain info about receipient needed for decrypting */
	
        /*
	 * Protocol ID — The Name is “SMQTT” and the Value is as described in
	 *   Appendix B.
	 * Sequence Number — The Name is “SeqNum” and the Value is an
	 *   eight-byte ASCII string representation of a four-byte unsigned
	 *   integer value in hexadecimal notation (“abcdef” and “ABCDEF”
	 *   characters are both acceptable) padded with leading zeros as
	 *   needed. See Section D.3 for information on Sequence Numbers.
	 * Client ID — The Name is “ClientID” and the Value is the Client Id
	 *  (see Section 3.2.1) of the Publisher.
	 * Public Parameters expiration date — The Name is “KeyExp” and the
	 *   Value is the expiration date as described in Section 6.2.4.
	 * Key management scheme — The Name is “KM” and the Value is one of
	 *   “Ephm”, “Pers”, or a sequence number as specified in Sections
	 *   5.4.1 and 5.4.2.
	 */
 
        if (strcmp(tmp_name, "SMQTT") == 0) {
            pub_protoid = strdup(tmp_value);
        } else if (strcmp(tmp_name, "SeqNum") == 0) {
            pub_seqnum = strdup(tmp_value);
        } else if (strcmp(tmp_name, "ClientId") == 0) {
            pub_masq_clientid = strdup(tmp_value);
        } else if (strcmp(tmp_name, "KM") == 0) {
            pub_masq_km_seq = strdup(tmp_value);
	    strategy = MASQ_crypto_api_mek_to_strat(tmp_value);
        } else if (strcmp(tmp_name, "KeyExp") == 0) {
            pub_params_exp = strdup(tmp_value);
        }
	
        /* Copy the contents */
        strncpy(masq_user_properties.prop[masq_user_properties.num_props].name,
		tmp_name, MASQ_MAX_PROP_NAME_LEN+1);
        strncpy(masq_user_properties.prop[masq_user_properties.num_props].value,
		tmp_value, MASQ_MAX_PROP_VALUE_LEN+1);
        masq_user_properties.num_props++;
        free(tmp_name);
        free(tmp_value);
    }
    
#ifdef ebug
    printf("%s: Received Pub ProtoID: %s\n", __func__, pub_protoid);
    printf("%s: Received Pub SeqNum: %s\n", __func__, pub_seqnum);
    printf("%s: Received Pub ClientID: %s\n", __func__, pub_masq_clientid);
    printf("%s: Received Pub KM Seq: %s\n", __func__, pub_masq_km_seq);
    printf("%s: Interpreted Pub KM Seq into strategy = %d\n", __func__, strategy);
    printf("%s: Received Pub ParamsExp: %s\n", __func__, pub_params_exp);
#endif

    // overhead_bytes is used in both ephemeral and persistent
    // mek_bytes can be used when using persistent keys and it has expired
    status = MASQ_crypto_api_overhead(strategy,
				      &overhead_bytes,
				      &mek_bytes);
    if (MASQ_STATUS_SUCCESS != status) {
        printf("%s: MASQ_crypto_api_overhead failed with status = %s\n",
	       __func__, MASQ_status_to_str(status));
        goto done;
    }

    // Choose the correct buffer size to allocate
    switch (strategy) {
    case MASQ_key_ephemeral:
        crypto_outbuf_len = overhead_bytes;
	break;
    case MASQ_key_persistent_pkt:
    case MASQ_key_persistent_bytes:
    case MASQ_key_persistent_time:
    case MASQ_key_persistent_exp:
        crypto_outbuf_len = MAX(overhead_bytes, mek_bytes);
	break;
    default:
        /* Should not publish if "none" strategy */
        printf("%s: Invalid strategy\n", __func__);
        goto done;
	break;
    }

    crypto_outbuf = malloc(crypto_outbuf_len);
    if (NULL == crypto_outbuf) {
        printf("%s: Malloc fail\n", __func__);
        goto done;
    }

#ifdef ebug
    MASQ_dump(message->payload, message->payloadlen,
	      "message before decrypt", '>', 1);
#endif
    status = MASQ_crypto_api_decrypt(userdata->state,
				     message->topic,
				     &masq_user_properties,
				     message->payload,
				     message->payloadlen,
				     crypto_outbuf,
				     &crypto_outbuf_len);
    
    if (MASQ_STATUS_KEY_MGMT == status) {
        /* If this function returns MASQ_STATUS_KEY_MGMT, this is a MEK-only
         * packet and the crypto library has recovered the persistent MEK
         * that will be used for decrypting subsequent packets. There is no
         * Topic Value returned in this case.
         *
         * Nothing for us to update here, the internal crypto library got
         * what it needed
         *
         * Return success code and skip the original callback
         */
        err = 0;
        goto done;
	
    } else if (MASQ_STATUS_SUCCESS != status) {
	
        printf("%s: MASQ_crypto_api_decrypt failed with status = %s\n",
	       __func__, MASQ_status_to_str(status));
        goto done;
    }

    /* Create a new struct mosquitto_message with the updated payload.
     * We cannot update the existing one because it is 'const' */
    new_message = malloc(sizeof(struct mosquitto_message));
    if (new_message == NULL) {
        printf("%s: Malloc fail\n", __func__);
        goto done;
    }
    
    /* Just in case mosquitto_message_copy fails, the length and pointers
       are all 0 before free attempt */
    memset(new_message, 0, sizeof(struct mosquitto_message));
    
    /* This does a deep copy including new memory allocations */
    rc = mosquitto_message_copy(new_message, message);
    if (rc) {
        printf("%s: mosquitto_message_copy failed with return code = %d\n",
	       __func__, rc);
        goto done;
    }
    
    /* Clear and free the existing copied payload, we are replacing it */
    memset(new_message->payload, 0, new_message->payloadlen);
    free(new_message->payload);
    new_message->payload = malloc(crypto_outbuf_len);
    if (new_message->payload == NULL) {
        printf("%s: Malloc fail\n", __func__);
        goto done;
    }
    
    memset(new_message->payload, 0, crypto_outbuf_len);
    memcpy(new_message->payload, crypto_outbuf, crypto_outbuf_len);
    new_message->payloadlen = crypto_outbuf_len;

    /* No return value, this is void */
    if (userdata->callback) {
        ret = userdata->callback(mosq, userdata->userdata, new_message);
    }
    err = 0;
done:
    if (NULL != new_message) {
        mosquitto_message_free(&new_message);
    }
    if (NULL != crypto_outbuf) free(crypto_outbuf);
    if (NULL != pub_protoid) free(pub_protoid);
    if (NULL != pub_seqnum) free(pub_seqnum);
    if (NULL != pub_masq_clientid) free(pub_masq_clientid);
    if (NULL != pub_masq_km_seq) free(pub_masq_km_seq);
    if (NULL != pub_params_exp) free(pub_params_exp);
    if (err) {
        printf("%s: mosquitto disconnecting due to error\n", __func__);
	mosquitto_disconnect(mosq);
    }
    return ret;
}

static void
on_message_callback_void(struct mosquitto *mosq, void *obj,
			 const struct mosquitto_message *message,
			 const mosquitto_property *props)
{
    (void) on_message_callback(mosq, obj, message, props);
}

void
MASQ_message_v5_callback_set(struct masqitt *masq,
			     void (*on_message)(struct mosquitto *, void *,
						const struct mosquitto_message *,
						const mosquitto_property *props))
{
#ifdef ebug
    printf("MASQ_message_v5_callback_set\n");
#endif
    masq->cb_userdata.callback = (int (*)(struct mosquitto *, void *,
					  const struct mosquitto_message *))
	on_message;
    mosquitto_message_v5_callback_set(masq->mosq, on_message_callback_void);
}

struct mosquitto *
MASQ_get_mosquitto(const struct masqitt *masq)
{
    return NULL != masq ? masq->mosq : NULL;
}

void *
MASQ_get_masqitt(const struct masqitt *masq)
{
    return NULL != masq ? masq->state : NULL;
}

/*
 * Unit Tests
 */
#ifdef UNIT_TESTS

int main(int argc, char *argv[])
{
    printf("masqitt_test\n");

    return 0;
}

#endif /* UNIT_TESTS */
