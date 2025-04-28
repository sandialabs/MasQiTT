#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "masqlib.h"
#include "crypto.h"
#include "api.h"

typedef struct pkt_s {
    struct pkt_s		*next;
    char			*t_name;
    MASQ_user_properties_t	*up;
    unsigned char		*payload;
    size_t			payload_len;
    char			*expected;
} pkt_t;

static pkt_t	*_phead = NULL;
static pkt_t	*_ptail = NULL;
static int	_npkts = 0;

static void
add_pkt(char *t_name,
	MASQ_user_properties_t *up,
	unsigned char *payload,
	size_t payload_len,
	char *expected)
{
    pkt_t			*my_pkt;
    char			*my_t_name;
    MASQ_user_properties_t	*my_up;
    unsigned char		*my_payload;
    char			*my_expected;

    my_pkt = calloc(1, sizeof(pkt_t));
    my_t_name = calloc(1, strlen(t_name) + 1);
    my_up = calloc(1, sizeof(MASQ_user_properties_t));
    my_payload = calloc(1, payload_len);
    my_expected = calloc(1, strlen(expected) + 1);

    if ((NULL == my_pkt) || (NULL == my_t_name) ||
	(NULL == my_up) || (NULL == my_payload) || (NULL == my_expected)) {
	// in case any were successful
	free(my_pkt);
	free(my_t_name);
	free(my_up);
	free(my_payload);
	free(my_expected);
	printf("NOMEM!!!\n");
	return;
    }

    strcpy(my_t_name, t_name);
    memcpy((void *) my_up, (void *) up, sizeof(MASQ_user_properties_t));
    memcpy((void *) my_payload, (void *) payload, payload_len);
    strcpy(my_expected, expected);
    
    my_pkt->next = NULL;
    my_pkt->t_name = my_t_name;
    my_pkt->up = my_up;
    my_pkt->payload = my_payload;
    my_pkt->payload_len = payload_len;
    my_pkt->expected = my_expected;

    if (NULL == _phead) {
	_phead = _ptail = my_pkt;
    } else {
	_ptail->next = my_pkt;
	_ptail = my_pkt;
    }
    _npkts++;
}

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

#define	PUB_ID	"PumpTemp007c0480"
#define	SUB_ID	"Display999999997"

#define	pemfile(x, t)	"certs/" x t ".pem"
#define	certfile(x)	pemfile(x, "-crt")
#define	keyfile(x)	pemfile(x, "-key")

char		*ca_cert   = pemfile("ca", "-crt");

static char	*clientid_pub = PUB_ID;
char		*pub_cert = certfile(PUB_ID);
char		*pub_key  = keyfile(PUB_ID);

static char	*clientid_sub = SUB_ID;
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
	    printf("%scan not find/read file: %s, bailing%s\n",
		   _E, files[i], _X);
	    err++;
	}
    }

    if (err) {
	exit(1);
    }
}

int
main(int argc, char *argv[])
{
    int		i;
    void	*state;
    MASQ_status_t	ret;
    MASQ_user_properties_t	user_props;
    size_t		oh_len, mek_len;
    unsigned char	payload[MASQ_PAYLOAD_LEN_EPH(128)];
    size_t		payload_len = sizeof(payload);
    unsigned char	t_value[128];
    size_t		t_value_len = sizeof(t_value);
    unsigned char	extra[8];
    pkt_t	*pktp;
    unsigned char	*rand_extra;

    check_files();
    extern char *_kms, *_kmse, *_tls, *_tlse;
    printf("Key\n"
	   "  %sTest success%s\n"
	   "  %sTest problem or failure%s\n"
	   "  %s /%s  KMS communication info (good/bad)\n"
	   "  %s/%s wolfSSL TLS lib calls (good/bad)\n",
	   _I, _X, _E, _X, _kms, _kmse, _tls, _tlse);


    /*****
     ***** OVERHEAD CALCULATIONS
     *****/
    printf("\n>\n> MASQ_crypto_api_overhead\n>\n");
    MASQ_mek_strategy_t	strats[] = {
	MASQ_key_none,	MASQ_key_ephemeral, MASQ_key_persistent_pkt,
	MASQ_key_persistent_bytes, MASQ_key_persistent_time,
	MASQ_key_persistent_exp,
    };
    printf("%-16s %-14s over  mek\n%-16s %-14s ---- ----\n",
	   "strategy", "status", "--------", "------");
    for (i = 0; i < sizeof(strats)/sizeof(strats[0]); i++) {
	oh_len = mek_len = 0;
	ret = MASQ_crypto_api_overhead(strats[i], &oh_len, &mek_len);
	// expect all but first to succeed
	printf("%-16s %s%-14s%s %4lu %4lu\n", MASQ_strategy_to_str(strats[i]),
	       ((((0 == i) && (MASQ_ERR_INVAL == ret)) ||
		 (MASQ_STATUS_SUCCESS == ret)) ? _I : _E),
	       MASQ_status_to_str(ret), _X, oh_len, mek_len);
    }

    /*****
     ***** STRATEGY DETERMINATION
     *****/
    printf("\n>\n> MASQ_crypto_api_mek_to_strat\n>\n");
    struct {
	char			*str;	// input
	MASQ_mek_strategy_t	exp;	// expected strategy
    } mek_test[] = {
	{ .str = "Ephm", .exp = MASQ_key_ephemeral },
	{ .str = "Pers", .exp = MASQ_key_persistent_exp },
	{ .str = "ephm", .exp = MASQ_key_none },
	{ .str = "pers", .exp = MASQ_key_none },
	{ .str = "01234567", .exp = MASQ_key_persistent_exp },
	{ .str = "aAbBcCdD", .exp = MASQ_key_persistent_exp },
	{ .str = "1234567", .exp = MASQ_key_none },
	{ .str = "abcdefgh", .exp = MASQ_key_none },
	{ .str = "Hi, mom!", .exp = MASQ_key_none }
    };
    printf("%-8s %s\n%-8s %s\n",
	   "mek str", "strategy", "-------", "--------");
    for (i = 0; i < sizeof(mek_test)/sizeof(mek_test[0]); i++) {
	MASQ_mek_strategy_t ms = MASQ_crypto_api_mek_to_strat(mek_test[i].str);
	printf("%-8s %s%s%s\n", mek_test[i].str,
	       (ms == mek_test[i].exp ? _I : _E), MASQ_strategy_to_str(ms), _X);
    }

    /*****
     ***** EPHEMERAL CRYPTO
     *****/
    printf("\n>\n> MASQ_crypto_api_init\n>\n");
    ret = MASQ_crypto_api_init(MASQ_proto_id,
			       MASQ_role_publisher,
			       clientid_pub,
			       MASQ_key_ephemeral, 0,
			       NULL, 0,
			       ca_cert, pub_cert, pub_key,
#ifdef	ebug
			       1,
#endif
			       &state);
    if (MASQ_STATUS_SUCCESS != ret) {
	printf("%sUh, oh -- %s%s\n", _E, MASQ_status_to_str(ret), _X);
    } else {
	MASQ_dump_state((masq_crypto_state *) state, "Ephemeral init");
	MASQ_crypto_api_overhead(MASQ_key_ephemeral, &oh_len, NULL);
	printf("%lu bytes overhead\n", oh_len);
	printf("%sSTATUS_SUCCESS%s\n", _I, _X);
    }

    if (NULL == state) {
	printf("%sNULL state, bailing...\n%s", _E, _X);
	return 1;
    }

    printf("\n>\n> MASQ_crypto_api_add_entropy\n>\n");
    rand_extra = MASQ_get_rand_extra();
    MASQ_dump(rand_extra, MASQ_HASH_LEN, "Entropy before", '>', 0);
    MASQ_rand_bytes(extra, sizeof(extra));
    MASQ_dump(extra, sizeof(extra), "Extra", '>', 0);
    MASQ_crypto_api_add_entropy(extra, sizeof(extra));
    MASQ_dump(rand_extra, MASQ_HASH_LEN, "Entropy after", '>', 0);
    printf("%sAlways succeeds%s\n", _I, _X);
    
    printf("\n>\n> MASQ_crypto_api_encrypt\n>\n");
    ret = MASQ_crypto_api_encrypt(state,
				  "tank/level",
				  (unsigned char *) "85",
				  (size_t) 2,
				  &user_props,
				  payload,
				  &payload_len);
    if (MASQ_STATUS_SUCCESS != ret) {
	printf("%sUh, oh -- %s%s\n", _E, MASQ_status_to_str(ret), _X);
    } else {
	add_pkt("tank/level", &user_props, payload, payload_len, "85");
	MASQ_dump_state((masq_crypto_state *) state, NULL);
	MASQ_dump_properties(&user_props, "User Props");
	MASQ_dump(payload, payload_len, "85", '>', 1);
	printf("%sSTATUS_SUCCESS%s\n", _I, _X);
    }

    MASQ_crypto_api_close(state);

    /*****
     ***** PERSISTENT CRYPTO
     *****/
    printf("\n>\n> MASQ_crypto_api_init\n>\n");
    ret = MASQ_crypto_api_init(MASQ_proto_id,
			       MASQ_role_publisher,
			       clientid_pub,
			       MASQ_key_persistent_pkt, 100,
			       NULL, 0,
			       ca_cert, pub_cert, pub_key,
#ifdef	ebug
			       1,
#endif
			       &state);
    if (MASQ_STATUS_SUCCESS != ret) {
	printf("%sUh, oh -- %s%s\n", _E, MASQ_status_to_str(ret), _X);
    } else {
	MASQ_dump_state((masq_crypto_state *) state, "Persistent init");
	MASQ_crypto_api_overhead(MASQ_key_persistent_pkt, &oh_len, &mek_len);
	printf("%lu bytes overhead, %lu bytes for MEK\n", oh_len, mek_len);
	printf("%sSTATUS_SUCCESS%s\n", _I, _X);
    }

    printf("\n>\n> MASQ_crypto_api_add_entropy\n>\n");
    rand_extra = MASQ_get_rand_extra();
    MASQ_dump(rand_extra, MASQ_HASH_LEN, "Entropy before", '>', 0);
    MASQ_rand_bytes(extra, sizeof(extra));
    MASQ_dump(extra, sizeof(extra), "Extra", '>', 0);
    MASQ_crypto_api_add_entropy(extra, sizeof(extra));
    MASQ_dump(rand_extra, MASQ_HASH_LEN, "Entropy after", '>', 0);
    printf("%sAlways succeeds%s\n", _I, _X);
    
    printf("\n>\n> MASQ_crypto_api_encrypt 1\n>\n");
    payload_len = sizeof(payload);
    ret = MASQ_crypto_api_encrypt(state,
				  "tank/level",
				  (unsigned char *) "85",
				  (size_t) 2,
				  &user_props,
				  payload,
				  &payload_len);
    if (MASQ_STATUS_ANOTHER != ret) {
	printf("%sUh, oh -- %s%s\n", _E, MASQ_status_to_str(ret), _X);
    } else {
	add_pkt("tank/level", &user_props, payload, payload_len, "85");
	MASQ_dump_properties(&user_props, "MEK packet");
	MASQ_dump(payload, payload_len, "MEK", '>', 1);
	MASQ_dump_state((masq_crypto_state *) state,
			"Persistent enc w/ stored packet");
	printf("%sSTATUS_SUCCESS%s\n", _I, _X);
    }

    payload_len = sizeof(payload);
    printf("\n>\n> MASQ_crypto_api_encrypt 1a\n>\n");
    ret = MASQ_crypto_api_encrypt(state,
				  "tank/level",
				  (unsigned char *) "85",
				  (size_t) 2,
				  &user_props,
				  payload,
				  &payload_len);
    if (MASQ_STATUS_SUCCESS != ret) {
	printf("%sUh, oh -- %s%s\n", _E, MASQ_status_to_str(ret), _X);
    } else {
	add_pkt("tank/level", &user_props, payload, payload_len, "85");
	MASQ_dump_properties(&user_props, NULL);
	MASQ_dump(payload, payload_len, "85", '>', 1);
	MASQ_dump_state((masq_crypto_state *) state,
			"Persistent enc w/ stored packet");
	printf("%sSTATUS_SUCCESS%s\n", _I, _X);
    }

    static char *_lvls[] = { "80", "40", "7", "3.14159265358", "13" };
#define	NLVLS	(sizeof(_lvls)/sizeof(_lvls[0]))
    for (i = 0; i < NLVLS-1; i++) {
	printf("\n>\n> MASQ_crypto_api_encrypt 2.%d\n>\n", i);
	payload_len = sizeof(payload);
	ret = MASQ_crypto_api_encrypt(state,
				      "tank/level",
				      (unsigned char *) _lvls[i],
				      (size_t) strlen(_lvls[i]),
				      &user_props,
				      payload,
				      &payload_len);
	if (MASQ_STATUS_SUCCESS != ret) {
	    printf("%sUh, oh -- %s%s\n", _E, MASQ_status_to_str(ret), _X);
	} else {
	    add_pkt("tank/level", &user_props, payload, payload_len, _lvls[i]);
	    MASQ_dump_properties(&user_props, NULL);
	    MASQ_dump(payload, payload_len, _lvls[i], '>', 1);
	    printf("%sSTATUS_SUCCESS%s\n", _I, _X);
	}
    }

    static char *_tmps[] = { "83.1", "72", "98.6", "454" };
#define	NTMPS	(sizeof(_tmps)/sizeof(_tmps[0]))
    for (i = 0; i < NTMPS; i++) {
	payload_len = sizeof(payload);
	printf("\n>\n> MASQ_crypto_api_encrypt 3.%d\n>\n", i);
	ret = MASQ_crypto_api_encrypt(state,
				      "tank/temp",
				      (unsigned char *) _tmps[i],
				      (size_t) strlen(_tmps[i]),
				      &user_props,
				      payload,
				      &payload_len);
	if (MASQ_STATUS_ANOTHER == ret) {
	    add_pkt("tank/temp", &user_props, payload, payload_len, _tmps[i]);
	    MASQ_dump_properties(&user_props, "MEK packet");
	    MASQ_dump(payload, payload_len, "MEK", '>', 1);
	    MASQ_dump_state((masq_crypto_state *) state,
			    "Persistent enc w/ stored packet");
	    payload_len = sizeof(payload);
	    printf("\n>\n> MASQ_crypto_api_encrypt 3.%d a\n>\n", i);
	    ret = MASQ_crypto_api_encrypt(state,
					  "tank/temp",
					  (unsigned char *) _tmps[i],
					  (size_t) strlen(_tmps[i]),
					  &user_props,
					  payload,
					  &payload_len);
	    if (MASQ_STATUS_SUCCESS != ret) {
		printf("%sUh, oh -- %s%s\n", _E, MASQ_status_to_str(ret), _X);
	    } else {
		add_pkt("tank/temp", &user_props, payload, payload_len,
			_tmps[i]);
		MASQ_dump_properties(&user_props, NULL);
		MASQ_dump(payload, payload_len, _tmps[i], '>', 1);
		MASQ_dump_state((masq_crypto_state *) state,
				"Persistent enc w/ stored packet");
		printf("%sSTATUS_SUCCESS%s\n", _I, _X);
	    }
	} else if (MASQ_STATUS_SUCCESS != ret) {
	    printf("%sUh, oh -- %s%s\n", _E, MASQ_status_to_str(ret), _X);
	} else {
	    MASQ_dump_properties(&user_props, NULL);
	    MASQ_dump(payload, payload_len, _tmps[i], '>', 1);
	    printf("%sSTATUS_SUCCESS%s\n", _I, _X);
	}
    }

    i = NLVLS-1;
    printf("\n>\n> MASQ_crypto_api_encrypt 2.%d\n>\n", i);
    payload_len = sizeof(payload);
    ret = MASQ_crypto_api_encrypt(state,
				  "tank/level",
				  (unsigned char *) _lvls[i],
				  (size_t) strlen(_lvls[i]),
				  &user_props,
				  payload,
				  &payload_len);
    if (MASQ_STATUS_SUCCESS != ret) {
	printf("%sUh, oh -- %s%s\n", _E, MASQ_status_to_str(ret), _X);
    } else {
	add_pkt("tank/level", &user_props, payload, payload_len, _lvls[i]);
	MASQ_dump_properties(&user_props, NULL);
	MASQ_dump(payload, payload_len, _lvls[i], '>', 1);
	printf("%sSTATUS_SUCCESS%s\n", _I, _X);
    }
	
    MASQ_dump_state((masq_crypto_state *) state,
		    "After some persistent enc action");

    printf("\n>\n> Artificially induce MEK expiration\n>\n");
    ((masq_crypto_state *) state)->pub_mek->tally =
	((masq_crypto_state *) state)->pub_mek->max;
    MASQ_dump_meks(((masq_crypto_state *) state)->pub_mek, "forced expire");
    payload_len = sizeof(payload);
    ret = MASQ_crypto_api_encrypt(state,
				  ((masq_crypto_state *) state)->pub_mek->topic,
				  (unsigned char *) "????",
				  (size_t) 4,
				  &user_props,
				  payload,
				  &payload_len);
    if (MASQ_STATUS_ANOTHER != ret) {
	printf("%sUh, oh -- %s%s\n", _E, MASQ_status_to_str(ret), _X);
    } else {
	add_pkt(((masq_crypto_state *) state)->pub_mek->topic,
		&user_props, payload, payload_len, "????");
	MASQ_dump_properties(&user_props, "MEK packet");
	MASQ_dump(payload, payload_len, "MEK", '>', 1);
	MASQ_dump_state((masq_crypto_state *) state,
			"Persistent enc w/ stored packet");
	printf("%sSTATUS_SUCCESS%s\n", _I, _X);
    }
    
    payload_len = sizeof(payload);
    printf("\n>\n> MASQ_crypto_api_encrypt induced expiration\n>\n");
    ret = MASQ_crypto_api_encrypt(state,
				  ((masq_crypto_state *) state)->pub_mek->topic,
				  (unsigned char *) "????",
				  (size_t) 4,
				  &user_props,
				  payload,
				  &payload_len);
    if (MASQ_STATUS_SUCCESS != ret) {
	printf("%sUh, oh -- %s%s\n", _E, MASQ_status_to_str(ret), _X);
    } else {
	add_pkt(((masq_crypto_state *) state)->pub_mek->topic,
		&user_props, payload, payload_len, "????");
	MASQ_dump_properties(&user_props, NULL);
	MASQ_dump(payload, payload_len, "????", '>', 1);
	MASQ_dump_state((masq_crypto_state *) state,
			"Persistent enc w/ stored packet");
	printf("%sSTATUS_SUCCESS%s\n", _I, _X);
    }

    MASQ_crypto_api_close(state);

    printf("\n\n=============\n=============\n=============\n");
    printf("\n>\n> Properties\n>");

    for (pktp = _phead, i = 0; NULL != pktp; pktp = pktp->next, i++) {
	printf("\n%02d %s\n", i, pktp->t_name);
	MASQ_dump_properties(pktp->up, NULL);
	MASQ_dump(pktp->payload, pktp->payload_len, pktp->expected, '>', 1);
    }
    
    printf("\n=============\n=============\n=============\n");

    /*****
     ***** SUBSCRIBER
     *****/
    printf("\n>\n> MASQ_crypto_api_init\n>\n");
    ret = MASQ_crypto_api_init(MASQ_proto_id,
			       MASQ_role_subscriber,
			       clientid_sub,
			       MASQ_key_none, 0,
			       NULL, 0,
			       ca_cert, sub_cert, sub_key,
#ifdef	ebug
			       1,
#endif
			       &state);
    if (MASQ_STATUS_SUCCESS != ret) {
	printf("%sUh, oh -- %s%s\n", _E, MASQ_status_to_str(ret), _X);
    } else {
	MASQ_dump_state((masq_crypto_state *) state, "Subscriber init");
	printf("%sSTATUS_SUCCESS%s\n", _I, _X);
    }

    // decrypt the packets we created above
    for (pktp = _phead, i = 0; NULL != pktp; pktp = pktp->next, i++) {

	int	dump_state = 0;

	printf("\n%02d calling MASQ_crypto_api_decrypt()\n", i); fflush(stdout);
	t_value_len = sizeof(t_value);
	strcpy(t_value, "XXXXXXXX");
	ret = MASQ_crypto_api_decrypt(state,
				      pktp->t_name,
				      pktp->up,
				      pktp->payload,
				      pktp->payload_len,
				      t_value,
				      &t_value_len);

	printf("%s%02d %s%s\n",
	       (((MASQ_STATUS_SUCCESS == ret) || (MASQ_STATUS_KEY_MGMT == ret)) ?
		_I : _E), i, MASQ_status_to_str(ret), _X);
	
	switch (ret) {
	    
	case MASQ_STATUS_SUCCESS:
	    // all test Topic Values are strings
	    t_value[t_value_len] = '\0';
	    printf("%s%02d %s - %s%s\n", _I, i, pktp->t_name, t_value, _X);
	    dump_state = 1;
	    break;
	    
	case MASQ_STATUS_KEY_MGMT:
	    dump_state = 1;
	    break;
	    
	default:
	    printf("%s%02d !! OOPS !!%s\n", _E, i, _X);
	    break;
	}

	if (dump_state) {
	    printf("\n");
	    MASQ_dump_state((masq_crypto_state *) state, "Decrypt");
	}
    }
    
    MASQ_crypto_api_close(state);

    return 0;
}
