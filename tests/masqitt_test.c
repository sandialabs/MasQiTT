#include "masqitt.h"
#include "crypto.h"
#include "api.h"

#include <stddef.h>
#include <stdio.h>

#include <unistd.h> // for fork()
#include <sys/wait.h> // For waitpid()

// MASQ_proto_id from crypto.h
#define TEST_MASQ_V5 1

static volatile int sub_did_connect = 0;
static volatile int sub_received_message = 0;

static volatile int pub_did_connect = 0;
static volatile int pub_sent_publish = 0;

static const int USERDATA_SUBSCRIBER = 1;
static const int USERDATA_PUBLISHER = 2;

char *MASQ_STRATEGY_TO_STRING(MASQ_mek_strategy_t strat)
{

    if (strat == MASQ_key_none) {
        return "MASQ_key_none"; 			//!< I'm a Subscriber and don't gen keys
    } else if (strat == MASQ_key_ephemeral) {
        return "MASQ_key_ephemeral"; //!< Use ephmeral keys
    } else if (strat == MASQ_key_persistent_pkt) {
        return "MASQ_key_persistent_pkt"; //!< Use persistent key for X packets
    } else if (strat == MASQ_key_persistent_bytes) {
        return "MASQ_key_persistent_bytes"; //!< Use persistent key for X bytes
    } else if (strat == MASQ_key_persistent_time) {
        return "MASQ_key_persistent_time"; //!< Use persistent key for X seconds
    } else if (strat == MASQ_key_persistent_exp) {
        return "MASQ_key_persistent_exp"; //!< Use persistent key until exp date
    } else {
        return "Invalid MASQ MEK strategy provided!\n";
    }
}

#define	PUB_ID	"PumpTemp007c0480"
#define	SUB_ID	"Display999999997"

#define	pemfile(x, t)	"certs/" x t ".pem"
#define	certfile(x)	pemfile(x, "-crt")
#define	keyfile(x)	pemfile(x, "-key")

char		*clientid_pub  = PUB_ID;
char		*clientid_sub  = SUB_ID;
char		*ca_cert   = pemfile("ca", "-crt");
char		*pub_cert  = certfile(PUB_ID);
char		*pub_key   = keyfile(PUB_ID);
char		*sub_cert  = certfile(SUB_ID);
char		*sub_key   = keyfile(SUB_ID);

static void
check_files(void)
{
    char	*files[] = { ca_cert, pub_cert, pub_key, sub_cert, sub_key };
    int		i;
    int		err = 0;

    for (i = 0; i < (sizeof(files)/sizeof(files[0])); i++) {
	if (access((const char *) files[i], R_OK)) {
	    printf("can not find/read file: %s, bailing\n", files[i]);
	    err++;
	}
    }

    if (err) {
	exit(1);
    }
}

void on_message_v5_sub(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message, const mosquitto_property *props)
{
    int i;
    char payload_byte;
    printf("%s callback\n", __func__);
    if (message != NULL) {
        printf("%s: Received message with topic=\"%s\" and payload=\"", __func__, message->topic);
        for(i = 0; i < message->payloadlen; i++) {
            payload_byte = ((char *)message->payload)[i];
            printf("%c", payload_byte);
        }
        printf("\"\n");
    } else {
        printf("%s: ERR: Received NULL message\n", __func__);
    }
    /* If masqitt is working, the message should be decrypted */
    sub_received_message++;
}

/* the subscribe_callback interface uses an int return value instead of void */
int on_message_v5_simple_callback_sub(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message, const mosquitto_property *props)
{
    int i;
    char payload_byte;
    printf("%s callback\n", __func__);
    if (message != NULL) {
        printf("%s: Received message with topic=\"%s\" and payload=\"", __func__, message->topic);
        for(i = 0; i < message->payloadlen; i++) {
            payload_byte = ((char *)message->payload)[i];
            printf("%c", payload_byte);
        }
        printf("\"\n");
    } else {
        printf("%s: ERR: Received NULL message\n", __func__);
    }
    if (obj != NULL) {
        printf("%s: Received user data=\"%s\"\n", __func__, (char *)obj);
    } else {
        printf("%s: ERR: Received NULL userdata\n", __func__);
    }
    /* If masqitt is working, the message should be decrypted */
    sub_received_message++;
}

void on_publish_v5_pub(struct mosquitto *mosq, void *obj, int mid, int reason_code, const mosquitto_property *properties)
{
    printf("%s callback\n", __func__);
    pub_sent_publish = 1;
}

void on_connect_v5_sub(struct mosquitto *mosq, void *obj, int reason_code, int flags, const mosquitto_property *properties)
{
    printf("%s: callback\n", __func__);
    sub_did_connect = 1;
	if(reason_code) {
        printf("%s: Exiting with reason_code=%d\n", __func__, reason_code);
		exit(1);
	} else {
        struct userdata_callback *userdata_cb = (struct userdata_callback *) obj;
        int userdata = 0;
        if (userdata_cb) {
            if (userdata_cb->userdata) {
                userdata = *((int *)userdata_cb->userdata);
                printf("%s: userdata_cb->userdata = %x\n", __func__, userdata);
            }
            if (userdata == USERDATA_SUBSCRIBER) {
                printf("%s: Calling mosquitto_subscribe\n", __func__);
                mosquitto_subscribe(mosq, NULL, "tank/level", 0);
            }
        } else {
            printf("%s: No userdata\n", __func__);
        }
	}
}

void on_connect_v5_pub(struct mosquitto *mosq, void *obj, int reason_code, int flags, const mosquitto_property *properties)
{
    printf("%s callback\n", __func__);
    pub_did_connect = 1;
	if(reason_code) {
        printf("%s: Exiting with reason_code=%d\n", __func__, reason_code);
		exit(1);
	} else {
        struct userdata_callback *userdata_cb = (struct userdata_callback *) obj;
        int userdata = 0;
        if (userdata_cb) {
            if (userdata_cb->userdata) {
                userdata = *((int *)userdata_cb->userdata);
                printf("%s: userdata_cb->userdata = %x\n", __func__, userdata);
            }
            if (userdata == USERDATA_PUBLISHER) {
                printf("%s: Calling mosquitto_publish\n", __func__);
                int qos = 0;
                int sent_mid = -1; /* Just an id to keep track of which message is being published */
                mosquitto_publish(mosq, &sent_mid, "tank/level", strlen("message"), "message", qos, false);
            }
        } else {
            printf("%s: No userdata\n", __func__);
        }
	}
}

void MASQ_on_connect_v5_pub(struct mosquitto *mosq, void *obj, int reason_code, int flags, const mosquitto_property *properties)
{
    printf("%s callback\n", __func__);
    pub_did_connect = 1;
	if(reason_code) {
        printf("%s: Exiting with reason_code=%d\n", __func__, reason_code);
		exit(1);
	} else {
        struct userdata_callback *userdata_cb = (struct userdata_callback *) obj;
        int userdata = 0;
        if (userdata_cb) {
            if (userdata_cb->userdata) {
                userdata = *((int *)userdata_cb->userdata);
                printf("%s: userdata_cb->userdata = %x\n", __func__, userdata);
            }
            if (userdata == USERDATA_PUBLISHER) {
                printf("%s: got userdata for publisher!\n", __func__);
            }
        } else {
            printf("%s: No userdata\n", __func__);
        }
	}
}

void on_message_sub(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message)
{
    printf("%s callback\n", __func__);
    sub_received_message++;
}

void on_publish_pub(struct mosquitto *mosq, void *obj, int mid)
{
    printf("%s callback\n", __func__);
    pub_sent_publish = 1;
}

void on_connect_sub(struct mosquitto *mosq, void *obj, int reason_code)
{
    printf("%s callback\n", __func__);
    sub_did_connect = 1;
	if(reason_code) {
        printf("%s: Exiting with reason_code=%d\n", __func__, reason_code);
		exit(1);
	} else {
        int **i = (int **)obj;
        if (i && *i)
            printf("obj == %d\n", **i);
        if (i && *i && **i == USERDATA_SUBSCRIBER) {
            printf("mosquitto_subscribe in %s\n", __func__);
            mosquitto_subscribe(mosq, NULL, "tank/level", 0);
        }
	}
}

void on_connect_pub(struct mosquitto *mosq, void *obj, int reason_code)
{
    printf("%s callback\n", __func__);
    pub_did_connect = 1;
	if(reason_code) {
        printf("%s: Exiting with reason_code=%d\n", __func__, reason_code);
		exit(1);
	} else {
        int **i = (int **)obj;
        if (i && *i)
            printf("obj == %d\n", **i);
        if (i && *i && **i == USERDATA_PUBLISHER) {
            printf("Calling mosquitto_publish in %s\n", __func__);
            int qos = 0;
            int sent_mid = -1; /* Just an id to keep track of which message is being published */
            mosquitto_publish(mosq, &sent_mid, "tank/level", strlen("message"), "message", qos, false);
        }
	}
}

int mosquitto_API_test_sub(int do_api_v5,
			   char *kms_host, int kms_port,
			   char *ca_cert, char *sub_cert, char *sub_key)
{
    /* MASQ subscriber */
    struct masqitt *masq_sub = NULL;
    char *mqtt_id_sub = "subscriber 1";
    char *masq_id_sub = clientid_sub;
    MASQ_role_t role_sub = MASQ_role_subscriber;
    MASQ_mek_strategy_t strategy_sub = MASQ_key_none;
    unsigned long int strat_val_sub = 100;
    int clean_session_sub = 1;
    int callback_obj_sub = USERDATA_SUBSCRIBER;
    int ret = 0; /* Default to fail value */

#ifdef	ebug
    int debug = 1;
#endif

    masq_sub = MASQ_new(masq_id_sub, mqtt_id_sub,
			clean_session_sub, &callback_obj_sub,
                        role_sub, strategy_sub, strat_val_sub,
                        kms_host, kms_port,
			ca_cert, sub_cert, sub_key
#ifdef	ebug
			, debug
#endif
			);
    if (masq_sub == NULL) {
        printf("ERR: failed to allocate masq_sub\n");
        goto done;
    }

    if (do_api_v5) {
        mosquitto_int_option(masq_sub->mosq, MOSQ_OPT_PROTOCOL_VERSION, MQTT_PROTOCOL_V5);
        
        mosquitto_connect_v5_callback_set(masq_sub->mosq, on_connect_v5_sub);
        // mosquitto_message_callback_set(masq_sub->mosq, on_message_sub);
	    mosquitto_message_v5_callback_set(masq_sub->mosq, on_message_v5_sub);
    } else {
        mosquitto_connect_callback_set(masq_sub->mosq, on_connect_sub);
        mosquitto_message_callback_set(masq_sub->mosq, on_message_sub);
    }

    const char *host = "localhost";
    int port = 1883; // default port
    int keepalive = 60;

    // Start up mosquitto broker (use built "src/mosquitto")

    ret = mosquitto_connect(masq_sub->mosq, host, port, keepalive);
    if (ret) {
        printf("ERR: failed to connect sub to mosquitto client (ret code %d))\n", ret);
        goto done;
    }
    
    /* Loop until the subscriber receives the message published */
    printf("Starting to loop...\n");
    while (sub_received_message != 1) {
		ret = mosquitto_loop(masq_sub->mosq, 300, 1);
		if(ret) {
            printf("Error in subscriber mosquitto_loop (ret code %d)\n", ret);
			goto done;
		}
    }

    ret = 1;
done:
    MASQ_destroy(masq_sub);
    return ret;
}

int mosquitto_API_test_pub(int do_api_v5, MASQ_mek_strategy_t masq_key_strat,
                           char *kms_host, int kms_port,
			   char *ca_cert, char *pub_cert, char *pub_key)
{
    /* MASQ publisher */
    struct masqitt *masq_pub = NULL;
    char *mqtt_id_pub = "publisher 1";
    char *masq_id_pub = "8supYk69vxfwgqDg";
    MASQ_role_t role_pub = MASQ_role_publisher;
    unsigned long int strat_val_pub = 100;
    int clean_session_pub = 1;
    int callback_obj_pub = USERDATA_PUBLISHER;
    int ret = 0; /* Default to fail value */

#ifdef	ebug
    int debug = 1;
#endif

    if (masq_key_strat == MASQ_key_ephemeral) {
        strat_val_pub = 0; // Has no purpose for ephemeral key?
    } else if (masq_key_strat == MASQ_key_persistent_pkt) {
        strat_val_pub = 3; // Valid for X packets
    } else if (masq_key_strat == MASQ_key_persistent_bytes) {
        strat_val_pub = 50; // Valid for X bytes
    } else if (masq_key_strat == MASQ_key_persistent_time) {
        strat_val_pub = 10; // Valid for X seconds
    } else {
        printf("ERR: MASQ MEK strategy %s not supported in this test!\n", MASQ_STRATEGY_TO_STRING(masq_key_strat));
        goto done;
    }
    masq_pub = MASQ_new(masq_id_pub, mqtt_id_pub,
			clean_session_pub, &callback_obj_pub,
                        role_pub, masq_key_strat, strat_val_pub,
                        kms_host, kms_port,
			ca_cert, pub_cert, pub_key
#ifdef	ebug
			, debug
#endif
			);
    if (masq_pub == NULL) {
        printf("ERR: failed to allocate masq_pub\n");
        goto done;
    }

    if (do_api_v5) {
        mosquitto_int_option(masq_pub->mosq, MOSQ_OPT_PROTOCOL_VERSION, MQTT_PROTOCOL_V5);
        
        mosquitto_connect_v5_callback_set(masq_pub->mosq, on_connect_v5_pub);
        mosquitto_publish_v5_callback_set(masq_pub->mosq, on_publish_v5_pub);
    } else {
        mosquitto_connect_callback_set(masq_pub->mosq, on_connect_pub);
        mosquitto_publish_callback_set(masq_pub->mosq, on_publish_pub);
    }

    const char *host = "localhost";
    int port = 1883; // default port
    int keepalive = 60;

    // Start up mosquitto broker (use built "src/mosquitto")

    ret = mosquitto_connect(masq_pub->mosq, host, port, keepalive);
    if (ret) {
        printf("ERR: failed to connect pub to mosquitto client (ret code %d))\n", ret);
        goto done;
    }

    /* Loop until the subscriber receives the message published */
    printf("Starting to loop...\n");
    while (pub_sent_publish != 1) {
        ret = mosquitto_loop(masq_pub->mosq, 300, 1);
		if(ret) {
            printf("Error in publisher mosquitto_loop (ret code %d)\n", ret);
			goto done;
		}
    }

    ret = 1;
done:
    MASQ_destroy(masq_pub);
    return ret;
}


int MASQ_API_test_sub(int do_api_v5,
                      char *kms_host, int kms_port,
		      char *ca_cert, char *sub_cert, char *sub_key)
{
    /* MASQ subscriber */
    struct masqitt *masq_sub = NULL;
    char *mqtt_id_sub = "subscriber 1";
    // char *masq_id_sub = "ABCDEFGHIJKLMNOP";
    char *masq_id_sub = clientid_sub; // associated with d.pem for KMS
    MASQ_role_t role_sub = MASQ_role_subscriber;
    MASQ_mek_strategy_t strategy_sub = MASQ_key_none;
    unsigned long int strat_val_sub = 100;
    int clean_session_sub = 1;
    int callback_obj_sub = USERDATA_SUBSCRIBER;
    int ret = 0; /* Default to fail value */
    int rc;

#ifdef	ebug
    int debug = 1;
#endif

    masq_sub = MASQ_new(masq_id_sub, mqtt_id_sub,
			clean_session_sub, &callback_obj_sub,
                        role_sub, strategy_sub, strat_val_sub,
                        kms_host, kms_port,
			ca_cert, sub_cert, sub_key
#ifdef	ebug
			, debug
#endif
			);
    if (masq_sub == NULL) {
        printf("ERR: failed to allocate masq_sub\n");
        goto done;
    }

    if (do_api_v5) {
        mosquitto_int_option(masq_sub->mosq, MOSQ_OPT_PROTOCOL_VERSION,
			     MQTT_PROTOCOL_V5);
        
        mosquitto_connect_v5_callback_set(masq_sub->mosq, on_connect_v5_sub);
        // mosquitto_message_callback_set(masq_sub->mosq, on_message_sub);
	// mosquitto_message_v5_callback_set(masq_sub->mosq, on_message_v5_sub);
        MASQ_message_v5_callback_set(masq_sub, on_message_v5_sub);
    } else {
        /* Should not have non-v5 with MASQITT */
        printf("ERR: MASQITT should not be doing non-v5!\n");
        goto done;
    }

    const char *host = "localhost";
    int port = 1883; // default port
    int keepalive = 60;

    // Start up mosquitto broker (use built "src/mosquitto")

    rc = mosquitto_connect(masq_sub->mosq, host, port, keepalive);
    if (rc) {
        printf("ERR: failed to connect sub to mosquitto client (ret code %d))\n", rc);
        goto done;
    }

    printf("Waiting for subscriber to connect...\n");
    while (sub_did_connect != 1) {
		rc = mosquitto_loop(masq_sub->mosq, 300, 1);
		if(rc) {
            printf("Error in subscriber mosquitto_loop (ret code %d)\n", rc);
			goto done;
		}
    }

    /* Loop until the subscriber receives the message published */
    printf("Waiting for subscriber to receive message...\n");
    while (sub_received_message != 4) {
	rc = mosquitto_loop(masq_sub->mosq, 300, 1);
	if(rc) {
            printf("Error in subscriber mosquitto_loop (ret code %d)\n", rc);
	    goto done;
	}
    }

    ret = 1;
done:
    MASQ_destroy(masq_sub);
    return ret;
}

int MASQ_API_test_pub(int do_api_v5, MASQ_mek_strategy_t masq_key_strat,
                      char *kms_host, int kms_port,
		      char *ca_cert, char *pub_cert, char *pub_key)
{
    /* MASQ publisher */
    struct masqitt *masq_pub = NULL;
    char *mqtt_id_pub = "publisher 1";
    // char *masq_id_pub = "8supYk69vxfwgqDg";
    char *masq_id_pub = "TankLevel00037a1"; // associated with a.pem for KMS
    MASQ_role_t role_pub = MASQ_role_publisher;
    unsigned long int strat_val_pub = 3;
    int clean_session_pub = 1;
    int callback_obj_pub = USERDATA_PUBLISHER;
    MASQ_status_t status;
    int ret = 0; /* Default to fail value */
    int rc;

#ifdef	ebug
    int debug = 1;
#endif

    if (masq_key_strat == MASQ_key_ephemeral) {
        strat_val_pub = 0; // Has no purpose for ephemeral key?
    } else if (masq_key_strat == MASQ_key_persistent_pkt) {
        strat_val_pub = 3; // Valid for X packets
    } else if (masq_key_strat == MASQ_key_persistent_bytes) {
        strat_val_pub = 50; // Valid for X bytes
    } else if (masq_key_strat == MASQ_key_persistent_time) {
        strat_val_pub = 10; // Valid for X seconds
    } else {
        printf("ERR: MASQ MEK strategy %s not supported in this test!\n", MASQ_STRATEGY_TO_STRING(masq_key_strat));
        goto done;
    }

    masq_pub = MASQ_new(masq_id_pub, mqtt_id_pub,
			clean_session_pub, &callback_obj_pub,
                        role_pub, masq_key_strat, strat_val_pub,
                        kms_host, kms_port,
			ca_cert, pub_cert, pub_key
#ifdef	ebug
			, debug
#endif
			);
    if (masq_pub == NULL) {
        printf("ERR: failed to allocate masq_pub\n");
        goto done;
    }

    if (do_api_v5) {
        mosquitto_int_option(masq_pub->mosq, MOSQ_OPT_PROTOCOL_VERSION, MQTT_PROTOCOL_V5);
        
        mosquitto_connect_v5_callback_set(masq_pub->mosq, MASQ_on_connect_v5_pub);
        mosquitto_publish_v5_callback_set(masq_pub->mosq, on_publish_v5_pub);
    } else {
        /* Should not have non-v5 with MASQITT */
        printf("ERR: MASQITT should not be doing non-v5!\n");
        goto done;
    }

    const char *host = "localhost";
    int port = 1883; // default port
    int keepalive = 60;

    // Start up mosquitto broker (use built "src/mosquitto")

    rc = mosquitto_connect(masq_pub->mosq, host, port, keepalive);
    if (rc) {
        printf("ERR: failed to connect pub to mosquitto client (ret code %d))\n", rc);
        goto done;
    }

    printf("Waiting for publisher to connect...\n");
    while (pub_did_connect != 1) {
        rc = mosquitto_loop(masq_pub->mosq, 300, 1);
		if(rc) {
            printf("Error in publisher mosquitto_loop (ret code %d)\n", rc);
			goto done;
		}
    }

    mosquitto_property *pub_properties = NULL;
    char pub_message[64] = {0};
    int i;
    printf("%s: key expires every %ld packets/bytes/seconds\n", __func__, strat_val_pub);
    for (i = 0; i <= strat_val_pub + 1; i++) {
        pub_sent_publish = 0;
        snprintf(pub_message, 64, "%s %d", "pub message", i);

        status = MASQ_publish_v5(
            masq_pub,
            NULL,
            "tank/level",
            strlen(pub_message),
            pub_message,
            0,
            0,
            pub_properties);
        if (status != MASQ_STATUS_SUCCESS) {
            printf("ERR: Got non-success status %d\n", status);
            goto done;
        }
        /* Loop until the subscriber receives the message published */
        printf("Waiting for publisher to publish...\n");
        while (pub_sent_publish != 1) {
            rc = mosquitto_loop(masq_pub->mosq, 300, 1);
            if(rc) {
                printf("Error in publisher mosquitto_loop (ret code %d)\n", rc);
                goto done;
            }
        }
    }

    ret = 1;
done:
    MASQ_destroy(masq_pub);
    return ret;
}


int unit_tests(char *kms_host, int kms_port)
{
    struct masqitt *masq = NULL;
    char *mqtt_id_pub = "publisher 1";
    char *mqtt_id_sub = "subscriber 1";
    char masq_id_pub_invalid[256] = {0};
    char masq_id_sub_invalid[256] = {0};
    char *masq_id_pub_valid = "JgaciIX6EK9k79fi"; // associated with a.pem for KMS
    char *masq_id_sub_valid = "PH92zoxhL3qGPPqv"; // associated with d.pem for KMS
    MASQ_role_t role_pub = MASQ_role_publisher;
    MASQ_role_t role_sub = MASQ_role_subscriber;
    unsigned long int strat_val = 3;
    int clean_session = 1;
    int callback_obj = USERDATA_PUBLISHER;
    MASQ_status_t status;
    int ret = 0; /* Default to fail value */
    int rc;
    int test_idx = 0;
    MASQ_mek_strategy_t masq_key_strat = MASQ_key_persistent_pkt;
    mosquitto_property *pub_properties = NULL;
    char pub_message[64] = {0};
    int pub_message_len = sizeof(pub_message);
    const char *host = "localhost";
    int port = 1883; // default port
    int keepalive = 60;
#ifdef	ebug
	int debug = 1;
#endif

    // Unit Tests:
    // Check invalid inputs to MASQ_new()

    // 0: Invalid MasQiTT client ID - NULL
    masq = MASQ_new(NULL, mqtt_id_pub,
		    clean_session, &callback_obj,
		    role_pub, masq_key_strat, strat_val,
		    kms_host, kms_port,
		    ca_cert, pub_cert, pub_key
#ifdef	ebug
		    , debug
#endif
		    );
    if (masq != NULL) goto test_failed;
    test_idx++;

    char masq_id_pub_too_large[MASQ_CLIENTID_LEN + 1];
    memset(masq_id_pub_too_large, 'A', sizeof(masq_id_pub_too_large));
    // 1: Invalid MasQiTT client ID - too large
    masq = MASQ_new(masq_id_pub_too_large, mqtt_id_pub,
		    clean_session, &callback_obj,
		    role_pub, masq_key_strat, strat_val,
		    kms_host, kms_port,
		    ca_cert, pub_cert, pub_key
#ifdef	ebug
		    , debug
#endif
		    );
    if (masq != NULL) goto test_failed;
    test_idx++;

    // 2: Invalid MQTT client ID - NULL
    masq = MASQ_new(masq_id_pub_valid, NULL,
		    clean_session, &callback_obj,
		    role_pub, masq_key_strat, strat_val,
		    kms_host, kms_port,
		    ca_cert, pub_cert, pub_key
#ifdef	ebug
		    , debug
#endif
		    );
    if (masq != NULL) goto test_failed;
    test_idx++;

    // 3: Invalid MQTT client ID - too large
    char mqtt_id_pub_too_large[MOSQ_MQTT_ID_MAX_LENGTH + 1];
    memset(mqtt_id_pub_too_large, 'A', sizeof(mqtt_id_pub_too_large));
    masq = MASQ_new(masq_id_pub_valid, mqtt_id_pub_too_large,
		    clean_session, &callback_obj,
		    role_pub, masq_key_strat, strat_val,
		    kms_host, kms_port,
		    ca_cert, pub_cert, pub_key
#ifdef	ebug
		    , debug
#endif
		    );
    if (masq != NULL) goto test_failed;
    test_idx++;

    // 4: Invalid MASQ role
    MASQ_role_t invalid_role = -1;
    masq = MASQ_new(masq_id_pub_valid, mqtt_id_pub,
		    clean_session, &callback_obj,
		    invalid_role, masq_key_strat, strat_val,
		    kms_host, kms_port,
		    ca_cert, pub_cert, pub_key
#ifdef	ebug
		    , debug
#endif
		    );
    if (masq != NULL) goto test_failed;
    test_idx++;

    // 5: Invalid MASQ role
    invalid_role = 4;
    masq = MASQ_new(masq_id_pub_valid, mqtt_id_pub,
		    clean_session, &callback_obj,
		    invalid_role, masq_key_strat, strat_val,
		    kms_host, kms_port,
		    ca_cert, pub_cert, pub_key
#ifdef	ebug
		    , debug
#endif
		    );
    if (masq != NULL) goto test_failed;
    test_idx++;

    // 6: Invalid MASQ strategy
    MASQ_mek_strategy_t invalid_strat = -1;
    masq = MASQ_new(masq_id_pub_valid, mqtt_id_pub,
		    clean_session, &callback_obj,
		    role_pub, invalid_strat, strat_val,
		    kms_host, kms_port,
		    ca_cert, pub_cert, pub_key
#ifdef	ebug
		    , debug
#endif
		    );
    // This should not actually fail (currently), but sets a default instead
    if (masq == NULL) goto test_failed;
    MASQ_destroy(masq);
    test_idx++;

    // 7: Invalid MASQ strategy
    invalid_strat = 6;
    masq = MASQ_new(masq_id_pub_valid, mqtt_id_pub,
		    clean_session, &callback_obj,
		    role_pub, invalid_strat, strat_val,
		    kms_host, kms_port,
		    ca_cert, pub_cert, pub_key
#ifdef	ebug
		    , debug
#endif
		    );
    // This should not actually fail (currently), but sets a default instead
    if (masq == NULL) goto test_failed;
    MASQ_destroy(masq);
    test_idx++;

    // 8: MASQ role subscriber + a publisher strategy should not fail even
    // though the strategy is not used
    MASQ_mek_strategy_t strat = MASQ_key_persistent_pkt;
    masq = MASQ_new(masq_id_pub_valid, mqtt_id_pub,
		    clean_session, &callback_obj,
		    role_sub, strat, strat_val,
		    kms_host, kms_port,
		    ca_cert, pub_cert, pub_key
#ifdef	ebug
		    , debug
#endif
		    );
    // Should NOT fail.
    if (masq == NULL) goto test_failed;
    MASQ_destroy(masq);
    masq = NULL;
    test_idx++;

    // 9: Invalid kms host
    masq = MASQ_new(masq_id_pub_valid, mqtt_id_pub,
		    clean_session, &callback_obj,
		    role_pub, masq_key_strat, strat_val,
		    "254.254.254.254", kms_port,
		    ca_cert, pub_cert, pub_key
#ifdef	ebug
		    , debug
#endif
		    );
    // Should not fail but will timeout.
    if (masq == NULL) goto test_failed;
    MASQ_destroy(masq);
    test_idx++;

    goto skip;
    // 10: Invalid kms port
    masq = MASQ_new(masq_id_pub_valid, mqtt_id_pub,
		    clean_session, &callback_obj,
		    role_pub, masq_key_strat, strat_val,
		    kms_host, 80,
		    ca_cert, pub_cert, pub_key
#ifdef	ebug
		    , debug
#endif
		    );
    if (masq != NULL) goto test_failed;
    skip:
    test_idx++;

    // Check invalid inputs to MASQ_publish_v5()
    // 11: Payload length too large
    masq = MASQ_new(masq_id_pub_valid, mqtt_id_pub,
		    clean_session, &callback_obj,
                    role_pub, masq_key_strat, strat_val,
                    kms_host, kms_port,
                    ca_cert, pub_cert, pub_key
#ifdef	ebug
                    , debug
#endif
		    );
    ret = mosquitto_connect(masq->mosq, host, port, keepalive);
    if (ret) {
        printf("ERR: failed to connect sub to mosquitto client (ret code %d))\n", ret);
        goto test_failed;
    }

    pub_properties = NULL;
    snprintf(pub_message, pub_message_len, "%s", "test message");
    status = MASQ_publish_v5(
        masq,
        NULL,
        "tank/level",
        268435455U + 1, // MQTT_MAX_PAYLOAD,
        pub_message,
        0,
        0,
        pub_properties);
    MASQ_destroy(masq);
    if (status != MASQ_ERR_INVAL) goto test_failed;
    test_idx++;

    // 12: Payload length + overhead too large
    masq = MASQ_new(masq_id_pub_valid, mqtt_id_pub,
		    clean_session, &callback_obj,
                    role_pub, masq_key_strat, strat_val,
                    kms_host, kms_port,
                    ca_cert, pub_cert, pub_key
#ifdef	ebug
                    , debug
#endif
		    );
    ret = mosquitto_connect(masq->mosq, host, port, keepalive);
    if (ret) {
        printf("ERR: failed to connect sub to mosquitto client (ret code %d))\n", ret);
        goto test_failed;
    }
    pub_properties = NULL;
    snprintf(pub_message, pub_message_len, "%s", "test message");
    status = MASQ_publish_v5(
        masq,
        NULL,
        "tank/level",
        268435455U - MASQ_PAYLOAD_LEN_PER(0) + 1,
        pub_message,
        0,
        0,
        pub_properties);
    mosquitto_disconnect(masq->mosq);
    MASQ_destroy(masq);
    if (status != MASQ_ERR_INVAL) goto test_failed;
    test_idx++;

    // 13: Payload length is 0
    masq = MASQ_new(masq_id_pub_valid, mqtt_id_pub,
		    clean_session, &callback_obj,
                    role_pub, masq_key_strat, strat_val,
                    kms_host, kms_port,
                    ca_cert, pub_cert, pub_key
#ifdef	ebug
                    , debug
#endif
		    );
    ret = mosquitto_connect(masq->mosq, host, port, keepalive);
    if (ret) {
        printf("ERR: failed to connect pub to mosquitto client (ret code %d))\n", ret);
        goto test_failed;
    }
    pub_properties = NULL;
    snprintf(pub_message, pub_message_len, "%s", "test message");
    status = MASQ_publish_v5(
        masq,
        NULL,
        "tank/level",
        0,
        pub_message,
        0,
        0,
        pub_properties);
    mosquitto_disconnect(masq->mosq);
    MASQ_destroy(masq);
    if (status != MASQ_ERR_INVAL) goto test_failed;
    test_idx++;

    // 14: Payload length is negative
    masq = MASQ_new(masq_id_pub_valid, mqtt_id_pub,
		    clean_session, &callback_obj,
                    role_pub, masq_key_strat, strat_val,
                    kms_host, kms_port,
                    ca_cert, pub_cert, pub_key
#ifdef	ebug
                    , debug
#endif
		    );
    ret = mosquitto_connect(masq->mosq, host, port, keepalive);
    if (ret) {
        printf("ERR: failed to connect pub to mosquitto client (ret code %d))\n", ret);
        goto test_failed;
    }
    pub_properties = NULL;
    snprintf(pub_message, pub_message_len, "%s", "test message");
    status = MASQ_publish_v5(
        masq,
        NULL,
        "tank/level",
        -1,
        pub_message,
        0,
        0,
        pub_properties);
    mosquitto_disconnect(masq->mosq);
    MASQ_destroy(masq);
    if (status != MASQ_ERR_INVAL) goto test_failed;
    test_idx++;

    // Check invalid inputs to MASQ_message_v5_callback_set()
    // 15: Set NULL callback
    // Fork for subscriber and publisher
    pid_t pid;
    pid = fork();
    if (pid == -1) goto test_failed;
    // child process will be the publisher
    else if(pid == 0) {
        printf("\tPublisher child forked.\n");
        masq = MASQ_new(masq_id_pub_valid, mqtt_id_pub,
			clean_session, &callback_obj,
			role_pub, masq_key_strat, strat_val,
			kms_host, kms_port,
			ca_cert, pub_cert, pub_key
#ifdef	ebug
			, debug
#endif
			);
        mosquitto_int_option(masq->mosq, MOSQ_OPT_PROTOCOL_VERSION, MQTT_PROTOCOL_V5);        
        mosquitto_publish_v5_callback_set(masq->mosq, on_publish_v5_pub);
        ret = mosquitto_connect(masq->mosq, host, port, keepalive);
        if (ret) {
            printf("ERR: failed to connect pub to mosquitto client (ret code %d))\n", ret);
            goto test_failed;
        }
        printf("\tPublisher child: connected.\n");
        pub_properties = NULL;
        snprintf(pub_message, pub_message_len, "%s", "test message");
        status = MASQ_publish_v5(
            masq,
            NULL,
            "tank/level",
            strlen(pub_message),
            pub_message,
            0,
            0,
            pub_properties);
        printf("\tPublisher child: Waiting for publisher to publish...\n");
        while (pub_sent_publish != 1) {
            rc = mosquitto_loop(masq->mosq, 300, 1);
            if(rc) {
                printf("Error in publisher mosquitto_loop (ret code %d)\n", rc);
                goto test_failed;
            }
        }
        printf("\tPublisher child: published message.\n");
        sleep(2); // Allows the publish to "flush"
        MASQ_destroy(masq);
        printf("\tPublisher child: done.\n");
        exit(0);
    // parent process will be the subscriber
    } else {
        struct masqitt *masq_sub;
        masq_sub = MASQ_new(masq_id_sub_valid, mqtt_id_sub,
			    clean_session, &callback_obj,
			    role_sub, masq_key_strat, strat_val,
			    kms_host, kms_port,
			    ca_cert, sub_cert, sub_key
#ifdef	ebug
			    , debug
#endif
			    );
        MASQ_message_v5_callback_set(masq_sub, NULL); // Replace NULL with on_message_v5_sub to demonstrate a normal callback
        ret = mosquitto_connect(masq_sub->mosq, host, port, keepalive);
        if (ret) {
            printf("ERR: failed to connect sub to mosquitto client (ret code %d))\n", ret);
            goto test_failed;
        }
        rc = mosquitto_subscribe_v5(masq_sub->mosq, NULL, "tank/level", 0, 0, NULL);
        if(rc != MOSQ_ERR_SUCCESS){
            fprintf(stderr, "Error subscribing: %s\n", mosquitto_strerror(rc));
            mosquitto_disconnect(masq_sub->mosq);
        }
        printf("Waiting for subscriber to receive message...\n");
        while (1) {
            rc = mosquitto_loop(masq_sub->mosq, 300, 1);
            if(rc) {
                printf("Error in subscriber mosquitto_loop (ret code %d)\n", rc);
                goto test_failed;
            }
            // Wait for child process to finish.
            if (waitpid(-1, NULL, WNOHANG) != 0) {
                break;
            }
        }
        MASQ_destroy(masq_sub);
    }
    // No need to check an error case here. If it fails above,
    // it will likely segfault.
    test_idx++;

    // Check for when Subscriber has incorrect KMS credentials.
    // 16: Incorrect role - subscriber with role=publisher
    masq = MASQ_new(masq_id_sub_valid, mqtt_id_sub,
		    clean_session, &callback_obj,
		    role_pub, masq_key_strat, strat_val,
		    kms_host, kms_port,
		    ca_cert, sub_cert, sub_key
#ifdef	ebug
		    , debug
#endif
		    );
    if (masq != NULL) goto test_failed;
    test_idx++;

    // 17: Incorrect subscriber id
    memset(masq_id_sub_invalid, 'A', sizeof(MASQ_CLIENTID_LEN));
    masq = MASQ_new(masq_id_sub_invalid, mqtt_id_sub,
		    clean_session, &callback_obj,
		    role_sub, masq_key_strat, strat_val,
		    kms_host, kms_port,
		    ca_cert, sub_cert, sub_key
#ifdef	ebug
		    , debug
#endif
		    );
    if (masq != NULL) goto test_failed;
    test_idx++;
    // 18: Incorrect certificate
    test_idx++;

    // Check for when Publisher has incorrect KMS credentials.
    /*
        masq_id_pub_valid is associated with a.pem for KMS
            "JgaciIX6EK9k79fi"
        masq_id_sub_valid is associated with d.pem for KMS
            "PH92zoxhL3qGPPqv"
    */
    // 19: Incorrect role - publisher with role=subscriber
    masq = MASQ_new(masq_id_pub_valid, mqtt_id_pub,
		    clean_session, &callback_obj,
		    role_sub, masq_key_strat, strat_val,
		    kms_host, kms_port,
		    ca_cert, sub_cert, sub_key
#ifdef	ebug
		    , debug
#endif
		    );
    if (masq != NULL) goto test_failed;
    test_idx++;

    // 20: Incorrect publisher id
    memset(masq_id_pub_invalid, 'A', sizeof(MASQ_CLIENTID_LEN));
    masq = MASQ_new(masq_id_pub_invalid, mqtt_id_sub,
		    clean_session, &callback_obj,
		    role_pub, masq_key_strat, strat_val,
		    kms_host, kms_port,
		    ca_cert, pub_cert, pub_key
#ifdef	ebug
		    , debug
#endif
		    );
    if (masq != NULL) goto test_failed;
    test_idx++;
    // 21: Incorrect certificate
    test_idx++;


    // 22: A subscriber subscribes AFTER a publisher's MEK has been created
    // Fork for subscriber and publisher
    pid = fork();
    if (pid == -1) goto test_failed;
    // child process will be the publisher
    else if(pid == 0) {
        printf("\tPublisher child forked.\n");
        masq = MASQ_new(masq_id_pub_valid, mqtt_id_pub,
			clean_session, &callback_obj,
			role_pub, masq_key_strat, strat_val,
			kms_host, kms_port,
			ca_cert, pub_cert, pub_key
#ifdef	ebug
			, debug
#endif
			);
        mosquitto_int_option(masq->mosq, MOSQ_OPT_PROTOCOL_VERSION,
			     MQTT_PROTOCOL_V5);        
        mosquitto_publish_v5_callback_set(masq->mosq, on_publish_v5_pub);
        ret = mosquitto_connect(masq->mosq, host, port, keepalive);
        if (ret) {
            printf("ERR: failed to connect pub to mosquitto client (ret code %d))\n", ret);
            goto test_failed;
        }
        printf("\tPublisher child: connected.\n");
        pub_properties = NULL;
        snprintf(pub_message, pub_message_len, "%s", "message 1");
        status = MASQ_publish_v5(
            masq,
            NULL,
            "tank/level",
            strlen(pub_message),
            pub_message,
            0,
            0,
            pub_properties);
        printf("\tPublisher child: Waiting for publisher to publish...\n");
        while (pub_sent_publish != 1) {
            rc = mosquitto_loop(masq->mosq, 300, 1);
            if(rc) {
                printf("Error in publisher mosquitto_loop (ret code %d)\n", rc);
                goto test_failed;
            }
        }
        printf("\tPublisher child: published message 1.\n");
        printf("\tPublisher child: sleeping before next publish...\n");
        sleep(10); // Make sure we wait long enough for subscriber to subscribe
        snprintf(pub_message, pub_message_len, "%s", "message 2");
        status = MASQ_publish_v5(
            masq,
            NULL,
            "tank/level",
            strlen(pub_message),
            pub_message,
            0,
            0,
            pub_properties);
        printf("\tPublisher child: Waiting for publisher to publish...\n");
        while (pub_sent_publish != 1) {
            rc = mosquitto_loop(masq->mosq, 300, 1);
            if(rc) {
                printf("Error in publisher mosquitto_loop (ret code %d)\n", rc);
                goto test_failed;
            }
        }
        printf("\tPublisher child: published message 1.\n");
        sleep(2); // Allows the publish to "flush"
        MASQ_destroy(masq);
        printf("\tPublisher child: done.\n");
        exit(0);
    // parent process will be the subscriber
    } else {
        struct masqitt *masq_sub;
        masq_sub = MASQ_new(masq_id_sub_valid, mqtt_id_sub,
			    clean_session, &callback_obj,
			    role_sub, masq_key_strat, strat_val,
			    kms_host, kms_port,
			    ca_cert, sub_cert, sub_key
#ifdef	ebug
			    , debug
#endif
			    );
	// Replace NULL with on_message_v5_sub to demonstrate a normal callback
        MASQ_message_v5_callback_set(masq_sub, NULL);
        ret = mosquitto_connect(masq_sub->mosq, host, port, keepalive);
        if (ret) {
            printf("ERR: failed to connect sub to mosquitto client (ret code %d))\n", ret);
            goto test_failed;
        }
        sleep(5); // Wait until after the first publish has happened
        rc = mosquitto_subscribe_v5(masq_sub->mosq, NULL, "tank/level", 0, 0, NULL);
        if(rc != MOSQ_ERR_SUCCESS){
            fprintf(stderr, "Error subscribing: %s\n", mosquitto_strerror(rc));
            mosquitto_disconnect(masq_sub->mosq);
        }
        printf("Subscriber waiting to receive message...\n");
        while (1) {
            rc = mosquitto_loop(masq_sub->mosq, 300, 1);
            if(rc) {
                printf("Error in subscriber mosquitto_loop (ret code %d)\n", rc);
                goto test_failed;
            }
            // Wait for child process to finish.
            if (waitpid(-1, NULL, WNOHANG) != 0) {
                break;
            }
        }
        MASQ_destroy(masq_sub);
    }

    ret = 1;
test_failed:
    if (ret == 0) {
        printf("Failed test: %d\n", test_idx);
    };
    return ret;
}

int main(int argc, char *argv[])
{
    int ret = 0;
    int i;
    int do_unit_tests = 0;
    int do_pub = 0, do_sub = 0;
    int do_v5 = 1;
    int do_masq = 1;
    MASQ_mek_strategy_t masq_key_strat = MASQ_key_none;
    char *kms_host = NULL;
    int kms_port = 0;
    char USAGE[256] = {0};
    char USAGE2[] = "\t--unit-tests: run the unit tests only\n" \
                    "\t--subscriber: choose the subscriber role\n" \
                    "\t--publisher: choose the publisher role\n" \
                    "\t--key-per-pkt: persistent key strategy and use a new key every N packets\n" \
                    "\t--key-per-bytes: persistent key strategy and use a new key every N bytes\n" \
                    "\t--key-eph: use ephemerel keys instead of persistent keys\n" \
                    "\t--MASQ: Use MasQiTT instead of standard MOSQ. Default: true\n" \
                    "\t--v5: Use MOSQ protocol v5. Default: true\n" \
                    "\t--help: this help mesage\n" \
                    "\n";

    check_files();
    sprintf(USAGE, "Usage: %s [--unit-tests] [--subscriber | --publisher] [--key-per-pkt | --key-per-bytes | --key-eph] [--MASQ] [--v5] [--help]\n", argv[0]);

    printf("main\n");
    if (argc <= 1) {
        printf("%s\n", USAGE);
        printf("%s\n", USAGE2);
        return 0;
    }
    /* Check for help flag first */
    for(i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            printf("%s\n", USAGE);
            printf("%s\n", USAGE2);
            return 0;
        }
    }
    /* Parse arg flags */
    for(i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--unit-tests") == 0) {
            do_unit_tests = 1;
   	} else if (strcmp(argv[i], "--subscriber") == 0) {
            do_sub = 1;
        } else if (strcmp(argv[i], "--publisher") == 0) {
            do_pub = 1;
        } else if (strcmp(argv[i], "--v5") == 0) {
            do_v5 = 1;
        } else if (strcmp(argv[i], "--MASQ") == 0) {
            do_masq = 1;
        } else if (strcmp(argv[i], "--key-per-pkt") == 0) {
            masq_key_strat = MASQ_key_persistent_pkt;
        } else if (strcmp(argv[i], "--key-per-bytes") == 0) {
            masq_key_strat = MASQ_key_persistent_bytes;
        // } else if (strcmp(argv[i], "--key-per-time") == 0) {
        //     masq_key_strat = MASQ_key_persistent_time;
        // } else if (strcmp(argv[i], "--key-per-exp") == 0) {
        //     masq_key_strat = MASQ_key_persistent_exp;
        } else if (strcmp(argv[i], "--key-eph") == 0) {
            masq_key_strat = MASQ_key_ephemeral;
        }
    }

    if (!do_unit_tests) {
	if (do_sub == 1 && do_pub == 1) {
	    printf("ERR: Cannot be both a subscriber and publisher! Exiting test.\n");
	    return -1;
	}
	if (do_sub == 0 && do_pub == 0) {
	    printf("ERR: Must select subscriber or publisher role! Use --subscriber or --publisher. Exiting test.\n");
	    return -1;
	}
	if (masq_key_strat == MASQ_key_none && do_pub == 1) {
	    printf("ERR: Select a MASQ key strategy for the publisher! Exiting test.\n");
	    return -1;
	}
    }

    printf("Using protocol version %s\n", do_v5 ? "MQTTv5" : "MQTTv3");

    printf("Using %s\n", do_masq ? "MASQITT" : "standard mosquitto");

    if (do_unit_tests) {
	printf("Running unit tests\n");
        ret = unit_tests(kms_host, kms_port);
    } else if (do_sub) {
        printf("Subscriber mode\n");
        if (do_masq)
            ret = MASQ_API_test_sub(do_v5, kms_host, kms_port,
				    ca_cert, sub_cert, sub_key);
        else
            ret = mosquitto_API_test_sub(do_v5, kms_host, kms_port,
					 ca_cert, sub_cert, sub_key);
    } else if(do_pub) {
        printf("Publisher mode\n");
        if (do_masq)
            ret = MASQ_API_test_pub(do_v5, masq_key_strat,
				    kms_host, kms_port,
				    ca_cert, pub_cert, pub_key);
        else
            ret = mosquitto_API_test_pub(do_v5, masq_key_strat,
					 kms_host, kms_port,
					 ca_cert, pub_cert, pub_key);
    } else {
        printf("Invalid mode. Exiting.\n");
        return -1;
    }

    if (ret)
        printf("MASQ_API_test success!\n");
    else
        printf("MASQ_API_test fail!\n");

    return 0;
}
