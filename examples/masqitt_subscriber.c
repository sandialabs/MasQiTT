/*
 * This example shows how to write a client that subscribes to a topic and does
 * not do anything other than handle the messages that are received.
 *
 * This is a modified version of a Mosquitto example that uses MasQiTT.
 */

#include <masqitt.h>
#include <mosquitto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


/* Callback called when the client receives a CONNACK message from the broker. */
void on_connect(struct mosquitto *mosq, void *obj, int reason_code)
{
	int rc;
	/* Print out the connection result. mosquitto_connack_string() produces an
	 * appropriate string for MQTT v3.x clients, the equivalent for MQTT v5.0
	 * clients is mosquitto_reason_string().
	 */
	printf("on_connect: %s\n", mosquitto_connack_string(reason_code));
	if(reason_code != 0){
		/* If the connection fails for any reason, we don't want to keep on
		 * retrying in this example, so disconnect. Without this, the client
		 * will attempt to reconnect. */
		mosquitto_disconnect(mosq);
	}

	/* Making subscriptions in the on_connect() callback means that if the
	 * connection drops and is automatically resumed by the client, then the
	 * subscriptions will be recreated when the client reconnects. */
	rc = mosquitto_subscribe(mosq, NULL, "tank/level", 1);
	if(rc != MOSQ_ERR_SUCCESS){
		fprintf(stderr, "Error subscribing: %s\n", mosquitto_strerror(rc));
		/* We might as well disconnect if we were unable to subscribe */
		mosquitto_disconnect(mosq);
	}
}


/* Callback called when the broker sends a SUBACK in response to a SUBSCRIBE. */
void on_subscribe(struct mosquitto *mosq, void *obj, int mid, int qos_count, const int *granted_qos)
{
	int i;
	bool have_subscription = false;

	/* In this example we only subscribe to a single topic at once, but a
	 * SUBSCRIBE can contain many topics at once, so this is one way to check
	 * them all. */
	for(i=0; i<qos_count; i++){
		printf("on_subscribe: %d:granted qos = %d\n", i, granted_qos[i]);
		if(granted_qos[i] <= 2){
			have_subscription = true;
		}
	}
	if(have_subscription == false){
		/* The broker rejected all of our subscriptions, we know we only sent
		 * the one SUBSCRIBE, so there is no point remaining connected. */
		fprintf(stderr, "Error: All subscriptions rejected.\n");
		mosquitto_disconnect(mosq);
	}
}


/* Callback called when the client receives a message. */
void on_message(struct mosquitto *mosq, void *obj, const struct mosquitto_message *msg, const mosquitto_property *props)
{
	/* This blindly prints the payload, but the payload can be anything so take care. */
	printf("%s (qos %d): %s\n", msg->topic, msg->qos, (char *)msg->payload);
}


#define	PUB1_ID	"PumpTemp007c0480"
#define	PUB2_ID	"TankLevel00037a1"
#define	SUB_ID	"Display999999997"

#define	pemfile(x, t)	"../lib/test/" x t ".pem"
#define	certfile(x)	pemfile(x, "-crt")
#define	keyfile(x)	pemfile(x, "-key")

char		*ca_cert   = pemfile("ca", "-crt");

static char	*pub1_id   = PUB1_ID;
char		*pub1_cert = certfile(PUB1_ID);
char		*pub1_key  = keyfile(PUB1_ID);

static char	*pub2_id   = PUB2_ID;
char		*pub2_cert = certfile(PUB2_ID);
char		*pub2_key  = keyfile(PUB2_ID);

static char	*sub_id    = SUB_ID;
char		*sub_cert  = certfile(SUB_ID);
char		*sub_key   = keyfile(SUB_ID);

int
main(int argc, char *argv[])
{
    struct masqitt	*masq;
    struct mosquitto	*mosq;
    char		*mqtt_id = "subscriber 1";
    char		*masq_id = sub_id;
    MASQ_role_t		role = MASQ_role_subscriber;
    MASQ_mek_strategy_t	strategy = MASQ_key_none;
    unsigned long int	strat_val = 100;
    int			clean_session = 1;
    int			*callback_obj = NULL;
    int			ret = 0; /* Default to fail value */
    int			rc;
    char		*kms_host = NULL;	/* use default value */
    int			kms_port = 0;		/* use default value */

#ifdef	ebug
    int debug = 1;
#endif

    /* Create a new client instance.
     * id = NULL -> ask the broker to generate a client id for us
     * clean session = true -> the broker should remove old sessions when we
     * connect
     * obj = NULL -> we aren't passing any of our private data for callbacks
     */
    masq = MASQ_new(masq_id, mqtt_id, clean_session, callback_obj,
		    role, strategy, strat_val,
		    kms_host, kms_port,
		    ca_cert, sub_cert, sub_key
#ifdef	ebug
		    , debug
#endif
		    );

    if (NULL == masq) {
	fprintf(stderr, "Error: Out of memory.\n");
	return 1;
    }

    mosq = MASQ_get_mosquitto(masq);

    /* Configure callbacks. This should be done before connecting ideally. */
    mosquitto_connect_callback_set(mosq, on_connect);
    mosquitto_subscribe_callback_set(mosq, on_subscribe);
    MASQ_message_v5_callback_set(masq, on_message);

    /* Connect to localhost on port 1883 (default), with a keepalive of 60
     * seconds.  The `mosquitto` binary can be ran to be the broker which is
     * connected.  This call makes the socket connection only, it does not
     * complete the MQTT CONNECT/CONNACK flow, you should use
     * mosquitto_loop_start() or mosquitto_loop_forever() for processing net
     * traffic. */
    rc = mosquitto_connect(mosq, "localhost", 1883, 60);
    if (MOSQ_ERR_SUCCESS != rc) {
	mosquitto_destroy(mosq);
	fprintf(stderr, "Error: %s\n", mosquitto_strerror(rc));
	return 1;
    }

    /* Run the network loop in a blocking call. The only thing we do in this
     * example is to print incoming messages, so a blocking call here is fine.
     *
     * This call will continue forever, carrying automatic reconnections if
     * necessary, until the user calls mosquitto_disconnect().
     */
    mosquitto_loop_forever(mosq, -1, 1);

    mosq = NULL;
    MASQ_destroy(masq);
    
    return 0;
}

