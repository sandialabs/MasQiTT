/*
 * This example shows how to publish messages from outside of the Mosquitto network loop.
 */

#include <masqitt.h>
#include <api.h> /* For MASQ_status_to_str */
#include <mosquitto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


/* Callback called when the client receives a CONNACK message from the broker. */
void on_connect(struct mosquitto *mosq, void *obj, int reason_code)
{
	/* Print out the connection result. mosquitto_connack_string() produces an
	 * appropriate string for MQTT v3.x clients, the equivalent for MQTT v5.0
	 * clients is mosquitto_reason_string().
	 */
	printf("on_connect: %s\n", mosquitto_connack_string(reason_code));
	if(reason_code != 0) {
		/* If the connection fails for any reason, we don't want to keep on
		 * retrying in this example, so disconnect. Without this, the client
		 * will attempt to reconnect. */
		mosquitto_disconnect(mosq);
	}

	/* You may wish to set a flag here to indicate to your application that the
	 * client is now connected. */
}


/* Callback called when the client knows to the best of its abilities that a
 * PUBLISH has been successfully sent. For QoS 0 this means the message has
 * been completely written to the operating system. For QoS 1 this means we
 * have received a PUBACK from the broker. For QoS 2 this means we have
 * received a PUBCOMP from the broker. */
void on_publish(struct mosquitto *mosq, void *obj, int mid)
{
	printf("Message with mid %d has been published.\n", mid);
}


int get_temperature(void)
{
	sleep(1); /* Prevent a storm of messages - this pretend sensor works at 1Hz */
	return random() % 100;
}

/* This function pretends to read some data from a sensor and publish it.*/
void publish_sensor_data(struct masqitt *masq)
{
	char payload[20] = {0};
	int temp;
	int rc;
    MASQ_status_t status;
    int qos = 2;
    bool retain = false;

	/* Get our pretend data */
	temp = get_temperature();
	/* Print it to a string for easy human reading - payload format is highly
	 * application dependent. */
	snprintf(payload, sizeof(payload), "%d", temp);

	/* Publish the message
	 * mosq - our client instance
	 * *mid = NULL - we don't want to know what the message id for this message is
	 * topic = "example/temperature" - the topic on which this message will be published
	 * payloadlen = strlen(payload) - the length of our payload in bytes
	 * payload - the actual payload
	 * qos = 2 - publish with QoS 2 for this example
	 * retain = false - do not use the retained message feature for this message
	 */
    mosquitto_property *properties = NULL;
    printf("\tPublishing topic \"tank/level\": %s\n", payload);
    status = MASQ_publish_v5(masq, NULL, "tank/level", strlen(payload)+1, payload, qos, retain, properties);
	if(status != MASQ_STATUS_SUCCESS) {
		fprintf(stderr, "Error publishing: %s\n", MASQ_status_to_str(status));
	}
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
    char		*mqtt_id = "publisher 1";
    char		*masq_id = pub1_id;
    MASQ_role_t		role = MASQ_role_publisher;
    MASQ_mek_strategy_t	strategy = MASQ_key_persistent_pkt;
    unsigned long int	strat_val = 2; /* Send N packets before new keys */
    int			clean_session = 1;
    int			*callback_obj = NULL;
    int			ret = 0; /* Default to fail value */
    int			rc;
    char		*kms_host = NULL;	/* use default value */
    int			kms_port = 0;		/* use default value */

#ifdef	ebug
    int			debug = 1;
#endif

    /* Create a new client instance.
     * id = NULL -> ask the broker to generate a client id for us clean
     * session = true -> the broker should remove old sessions when we
     * connect
     * obj = NULL -> we aren't passing any of our private data for callbacks
     */
    masq = MASQ_new(masq_id, mqtt_id, clean_session, callback_obj,
		    role, strategy, strat_val,
		    kms_host, kms_port,
		    ca_cert, pub1_cert, pub1_key
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
    mosquitto_publish_callback_set(mosq, on_publish);

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

    /* Run the network loop in a background thread, this call returns
       quickly. */
    rc = mosquitto_loop_start(mosq);
    if (MOSQ_ERR_SUCCESS != rc) {
	mosquitto_destroy(mosq);
	fprintf(stderr, "Error: %s\n", mosquitto_strerror(rc));
	return 1;
    }

    /* At this point the client is connected to the network socket, but may
     * not have completed CONNECT/CONNACK.
     *
     * It is fairly safe to start queuing messages at this point, but if you
     * want to be really sure you should wait until after a successful call
     * to the connect callback.
     *
     * In this case we know it is 1 second before we start publishing.
     */
    int		num_publishes = 0;
    while (num_publishes < 25) {
	publish_sensor_data(masq);
        num_publishes++;
    }

    mosq = NULL;
    MASQ_destroy(masq);
    
    return 0;
}
