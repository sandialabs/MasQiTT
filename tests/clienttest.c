// Linux
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// MasQiTT
#include "masqlib.h"
#include "api.h"
#include "crypto.h"

#define	PUB1_ID	"TankTemp000a0032"
#define	PUB2_ID	"PumpTemp007c0480"
#define	SUB_ID	"PumpUnit00006177"

#define	pemfile(x, t)	"certs/" x t ".pem"
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

static void
check_files(void)
{
    char	*files[] = {
	ca_cert, pub1_cert, pub1_key, pub2_cert, pub2_key, sub_cert, sub_key
    };
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

static char	*_attn   = "\u27a4\u27a4\u27a4\u27a4";
static char	*_bad    = "\u2716";
static char	*_info   = "\u2726";

// doing these as #defines instead of char* for: _E "foo" _X
// error (red)
#define	_E	"\033[1;91m"
// warn (yellow)
#define	_W	"\033[1;93m"
// info (green)
#define	_I	"\033[1;92m"
// cmd (blue)
#define	_C	"\033[1;94m"
// masqitt (turquoise)
#define	_M	"\033[1;96m"
// restore
#define	_X	"\033[m"

static short	kms_port = 0;	// use default
static int	verbose = 0;

#define	BLEN	(4096)

static void
usage(char *cmd, int exitval)
{
    fprintf(stderr,
	    "usage: %s [-p port] [-v]\n"
	    "       %s -h\n\n"
	    "where:\n"
	    "    -p\tport to attach to (default: %d)\n"
	    "    -v\tincrease verbosity\n"
	    "    -h\tthis help message\n",
	    cmd, cmd, MASQ_KMS_DFLT_PORT);
    exit(exitval);
}

int
main(int argc, char *argv[])
{
    void		*p_state = NULL;	// publisher state
    void		*s_state = NULL;	// subscriber state
    MASQ_status_t	rc;
    unsigned char	p_buf[BLEN], p_buf2[BLEN];
    size_t		p_len = sizeof(p_buf), p_len2 = sizeof(p_buf2);
    unsigned char	s_buf[BLEN];
    size_t		s_len = MASQ_MAXTOPIC_LEN;
    char		topic_name[MASQ_MAXTOPIC_LEN];
    unsigned char	topic_value[MASQ_MAXTOPIC_LEN];	// arbitrary
    MASQ_user_properties_t	p_prop;

    int			opt;
    extern char		*optarg;
    extern int		optind;

    // parse command-line arguments
    while (-1 != (opt = getopt(argc, argv, "p:vh"))) {
	
	switch (opt) {
	    
	case 'p':
	    // listening port
	    kms_port = atoi(optarg);
	    break;

	case 'v':
	    verbose++;
	    break;
	    
	case 'h':
	case '?':
	    usage(argv[0], opt != 'h');
	}
    }

    check_files();
    extern char *_kms, *_kmse, *_tls, *_tlse;
    printf("Key\n"
	   "  %s%s Test info%s\n"
	   "  %s%s Test problem or failure%s\n"
	   "  %s /%s  KMS communication info (good/bad)\n"
	   "  %s/%s wolfSSL TLS lib calls (good/bad)\n",
	   _W, _info, _X, _E, _bad, _X, _kms, _kmse, _tls, _tlse);

    /*
     * Publisher using Ephemeral keys
     */
    printf("\n%s INITIALIZATION Ephemeral Publisher\n\n", _attn);

    rc = MASQ_crypto_api_init(MASQ_proto_id,
			      MASQ_role_publisher,
			      pub1_id,
			      MASQ_key_ephemeral,
			      0,	// stratval (N/A for ephemeral)
			      NULL,	// kms_host, use default
			      kms_port,	// kms_port, use default
			      ca_cert, pub1_cert, pub1_key,
#ifdef	ebug
			      1,	// debug
#endif
			      &p_state);
    printf("%s%s rc = %s%s\n", _W, _info, MASQ_status_to_str(rc), _X);

    if (MASQ_STATUS_SUCCESS != rc) {
	printf("%s%s Publisher init failed with %s%s\n", _E, _bad,
	       MASQ_status_to_str(rc), _X);
    } else {
	MASQ_dump_state((masq_crypto_state *) p_state, "Publisher state");
    }

    /*
     * Subscriber
     */
    printf("\n%s INITIALIZATION Subscriber\n\n", _attn);

    rc = MASQ_crypto_api_init(MASQ_proto_id,
			      MASQ_role_subscriber,
			      sub_id,
			      MASQ_key_none,	// take what comes along
			      0,	// stratval (N/A for subscriber)
			      NULL,	// kms_host, use default
			      kms_port,	// kms_port, use default
			      ca_cert, sub_cert, sub_key,
#ifdef	ebug
			      1,	// debug
#endif
			      &s_state);
    printf("%s%s rc = %s%s\n", _W, _info, MASQ_status_to_str(rc), _X);

    if (MASQ_STATUS_SUCCESS != rc) {
	printf("%s%s Subscriber init failed with %s%s\n", _E, _bad,
	       MASQ_status_to_str(rc), _X);
    } else {
	MASQ_dump_state((masq_crypto_state *) s_state, "Subscriber state");
    }

    /*
     * Encrypt Ephemeral
     */
    printf("\n%s ENCRYPT Ephemeral\n\n", _attn);

    strncpy(topic_name, "topic/name", sizeof(topic_name));
    strncpy(topic_value, "topic_value", sizeof(topic_value));
    rc = MASQ_crypto_api_encrypt(p_state,
				 topic_name,
				 topic_value,
				 strlen(topic_value),
				 &p_prop,
				 p_buf,
				 &p_len);
    printf("%s%s rc = %s%s\n", _W, _info, MASQ_status_to_str(rc), _X);

    if (MASQ_STATUS_SUCCESS != rc) {
	printf("%s%s Publisher encrypt failed at %d with %s%s\n", _E, _bad,
	       __LINE__-1, MASQ_status_to_str(rc), _X);
    } else {
	MASQ_dump_properties(&p_prop, "Publisher encrypt");
	MASQ_dump(p_buf, p_len, topic_value, '>', 1);
	printf("p_len = %lu\n", p_len);
    }

    /*
     * Decrypt Ephemeral
     */
    printf("\n%s DECRYPT Ephemeral\n\n", _attn);

    rc = MASQ_crypto_api_decrypt(s_state,
				 topic_name,
				 &p_prop,
				 p_buf,
				 p_len,
				 s_buf,
				 &s_len);
    printf("%s%s rc = %s%s\n", _W, _info, MASQ_status_to_str(rc), _X);

    if (MASQ_STATUS_SUCCESS != rc) {
	printf("%s%s Subscriber decrypt failed at %d with %s%s\n", _E, _bad,
	       __LINE__-1, MASQ_status_to_str(rc), _X);
    } else {
	MASQ_dump(s_buf, s_len, "Decrypted topic value", '<', 1);
    }

    printf("\n%s CLOSE Ephemeral Publisher\n\n", _attn);
    MASQ_dump_state((masq_crypto_state *) p_state, "Publisher state");
    printf("\n");
    MASQ_crypto_api_close(p_state);
    p_state = NULL;

    printf("\n%s INITIALIZATION Persistent Publisher\n\n", _attn);

    /*
     * Publisher using Persistent keys
     */
    rc = MASQ_crypto_api_init(MASQ_proto_id,
			      MASQ_role_publisher,
			      pub2_id,
			      MASQ_key_persistent_pkt,
			      4,	// stratval
			      NULL,	// kms_host, use default
			      kms_port,	// kms_port, use default
			      ca_cert, pub2_cert, pub2_key,
#ifdef	ebug
			      1,	// debug
#endif
			      &p_state);
    printf("%s%s rc = %s%s\n", _W, _info, MASQ_status_to_str(rc), _X);

    if (MASQ_STATUS_SUCCESS != rc) {
	printf("%s%s Publisher init failed with %s%s\n", _E, _bad,
	       MASQ_status_to_str(rc), _X);
    } else {
	MASQ_dump_state((masq_crypto_state *) p_state, "Publisher state");
    }
    
    printf("\n%s ENCRYPT Persistent\n\n", _attn);

    p_len = sizeof(p_buf);
    s_len = MASQ_MAXTOPIC_LEN;
    memset((void *) &p_prop, sizeof(p_prop), 0);

    strncpy(topic_name, "topic/name/other", sizeof(topic_name));
    strncpy(topic_value, "other_topic_value", sizeof(topic_value));
    rc = MASQ_crypto_api_encrypt(p_state,
				 topic_name,
				 topic_value,
				 strlen(topic_value),
				 &p_prop,
				 p_buf,
				 &p_len);
    printf("%s%s rc = %s%s\n", _W, _info, MASQ_status_to_str(rc), _X);

    if (MASQ_STATUS_ANOTHER != rc) {
	printf("%s%s Publisher encrypt failed at %d with %s%s\n", _E, _bad,
	       __LINE__-1, MASQ_status_to_str(rc), _X);
    } else {
	MASQ_dump_properties(&p_prop, "Publisher encrypt");
	MASQ_dump(p_buf, p_len, "Encapsulated MEK", '>', 1);
	printf("p_len = %lu\n", p_len);
    }

    printf("\n%s DECRYPT Persistent\n\n", _attn);

    rc = MASQ_crypto_api_decrypt(s_state,
				 topic_name,
				 &p_prop,
				 p_buf,
				 p_len,
				 s_buf,
				 &s_len);
    printf("%s%s rc = %s%s\n", _W, _info, MASQ_status_to_str(rc), _X);

    if (MASQ_STATUS_KEY_MGMT != rc) {
	printf("%s%s Subscriber decrypt failed at %d with %s%s\n", _E, _bad,
	       __LINE__-1, MASQ_status_to_str(rc), _X);
    }

    printf("\n%s ENCRYPT Persistent (again)\n\n", _attn);

    // using second Publisher buf to make sure we're not accidentally
    // processing stuff from MEK encapsulation
    p_len2 = sizeof(p_buf2);
    s_len = MASQ_MAXTOPIC_LEN;
    memset((void *) &p_prop, sizeof(p_prop), 0);

    strncpy(topic_name, "topic/name/other", sizeof(topic_name));
    strncpy(topic_value, "other_topic_value", sizeof(topic_value));
    rc = MASQ_crypto_api_encrypt(p_state,
				 topic_name,
				 topic_value,
				 strlen(topic_value),
				 &p_prop,
				 p_buf2,
				 &p_len2);
    printf("%s%s rc = %s%s\n", _W, _info, MASQ_status_to_str(rc), _X);

    if (MASQ_STATUS_SUCCESS != rc) {
	printf("%s%s Publisher encrypt failed at %d with %s%s\n", _E, _bad,
	       __LINE__-1, MASQ_status_to_str(rc), _X);
    } else {
	MASQ_dump_properties(&p_prop, "Publisher encrypt");
	MASQ_dump(p_buf2, p_len2, topic_value, '>', 1);
	printf("p_len2 = %lu\n", p_len2);
    }

    printf("\n%s DECRYPT Persistent (again)\n\n", _attn);

    rc = MASQ_crypto_api_decrypt(s_state,
				 topic_name,
				 &p_prop,
				 p_buf2,
				 p_len2,
				 s_buf,
				 &s_len);
    printf("%s%s rc = %s%s\n", _W, _info, MASQ_status_to_str(rc), _X);

    if (MASQ_STATUS_SUCCESS != rc) {
	printf("%s%s Subscriber decrypt failed at %d with %s%s\n", _E, _bad,
	       __LINE__-1, MASQ_status_to_str(rc), _X);
    } else {
	MASQ_dump(s_buf, s_len, "Decrypted topic value", '<', 1);
    }

    printf("\n%s ENCRYPT Persistent (3rd)\n\n", _attn);

    p_len = sizeof(p_buf);
    s_len = MASQ_MAXTOPIC_LEN;
    memset((void *) &p_prop, sizeof(p_prop), 0);

    strncpy(topic_name, "topic/name/other", sizeof(topic_name));
    strncpy(topic_value, "different_topic_value", sizeof(topic_value));
    rc = MASQ_crypto_api_encrypt(p_state,
				 topic_name,
				 topic_value,
				 strlen(topic_value),
				 &p_prop,
				 p_buf,
				 &p_len);
    printf("%s%s rc = %s%s\n", _W, _info, MASQ_status_to_str(rc), _X);

    if (MASQ_STATUS_SUCCESS != rc) {
	printf("%s%s Publisher encrypt failed at %d with %s%s\n", _E, _bad,
	       __LINE__-1, MASQ_status_to_str(rc), _X);
    } else {
	MASQ_dump_properties(&p_prop, "Publisher encrypt");
	MASQ_dump(p_buf, p_len, topic_value, '>', 1);
	printf("p_len = %lu\n", p_len);
    }

    printf("\n%s DECRYPT Persistent (3rd)\n\n", _attn);

    rc = MASQ_crypto_api_decrypt(s_state,
				 topic_name,
				 &p_prop,
				 p_buf,
				 p_len,
				 s_buf,
				 &s_len);
    printf("%s%s rc = %s%s\n", _W, _info, MASQ_status_to_str(rc), _X);

    if (MASQ_STATUS_SUCCESS != rc) {
	printf("%s%s Subscriber decrypt failed at %d with %s%s\n", _E, _bad,
	       __LINE__-1, MASQ_status_to_str(rc), _X);
    } else {
	MASQ_dump(s_buf, s_len, "Decrypted topic value", '<', 1);
    }

    printf("\n%s Cleanup\n\n", _attn);
    MASQ_dump_state((masq_crypto_state *) p_state, "Publisher state");
    printf("\n");
    MASQ_crypto_api_close(p_state);
    printf("\n");

    MASQ_dump_state((masq_crypto_state *) s_state, "Subscriber state");
    printf("\n");
    MASQ_crypto_api_close(s_state);

    return 0;
}
