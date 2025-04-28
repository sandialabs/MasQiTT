#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "crypto.h"

unsigned char	iv[] = {
  0x5c, 0x14, 0x65, 0xbf, 0xe2, 0xc0, 0x52, 0xdd,
  0x5a, 0x3e, 0x22, 0xcf
};

unsigned char	key[] = {
  0x88, 0x05, 0x30, 0xf5, 0x27, 0xcc, 0x67, 0x9c,
  0x2a, 0xc4, 0x2f, 0xa0, 0x52, 0x04, 0x9b, 0x75
};

unsigned char	*hdr = (unsigned char *) "93062e28";

unsigned char	pt[] = {
  0xda, 0xca, 0x71, 0xb3, 0x09, 0x22, 0x80, 0x6c,
  0xfa, 0x0f, 0x40, 0xe2, 0x36, 0xdc, 0x88, 0xa6,
  0x3e, 0xc2, 0xe9, 0x07, 0xf0, 0xe0, 0x47, 0x4a,
  0xfd, 0x70, 0xcf, 0xd0, 0xea, 0xa6, 0x7a, 0xc8,
  0x10, 0x10, 0xe7, 0x6f, 0xf4
};

unsigned char	ct[sizeof(pt)];
unsigned char	pt2[sizeof(pt)];
unsigned char	pt3[sizeof(pt)];

unsigned char	tag[MASQ_TAG_LEN];

unsigned char	rand_buf[32];
char		clientid_buf[MASQ_CLIENTID_LEN + 1];

#define	PUB1_ID	"PumpTemp007c0480"
#define	PUB2_ID	"TankLevel00037a1"
#define	SUB_ID	"Display999999997"

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
	ca_cert,
	pub1_cert, pub1_key, pub2_cert, pub2_key,
	sub_cert, sub_key
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

static void
dump(unsigned char *p, size_t len, char *hdr)
{
    size_t	i;
    char	*sep = "";
    
    if (NULL != hdr) {
	printf("==== %04lx  %s\n", len, hdr);
    }

    for (i = 0; i < len; i++) {
	if (0 == (i % 16)) {
	    printf("%s%04lx ", sep, i);
	    sep = "\n";
	} else if (0 == (i % 8)) {
	    printf(" ");
	}
	printf(" %02x", p[i]);
    }
    printf("%s", sep);
}

int
main(int argc, char *argv[])
{
    int	retv;
    int	i;
    int	fail;
    MC_aesgcm_params	ep = {
	.key = key, .key_len = sizeof(key),
	.iv  = iv,  .iv_len  = sizeof(iv),
	.hdr = hdr, .hdr_len = sizeof(hdr),
	.pt  = pt,  .pt_len  = sizeof(pt),
	.ct  = ct,  .ct_len  = sizeof(ct),
	.tag = tag, .tag_len = sizeof(tag)
    };
    MC_aesgcm_params	dp = {
	.key = key, .key_len = sizeof(key),
	.iv  = iv,  .iv_len  = sizeof(iv),
	.hdr = hdr, .hdr_len = sizeof(hdr),
	.pt  = pt2, .pt_len  = sizeof(pt2),
	.ct  = ct,  .ct_len  = sizeof(ct),
	.tag = tag, .tag_len = sizeof(tag)
    };
    void	*pub_state_ephem = NULL;
    void	*pub_state_pers = NULL;
    void	*sub_state = NULL;

    check_files();
    extern char *_kms, *_kmse, *_tls, *_tlse;
    printf("Key\n"
	   "  %sTest success%s\n"
	   "  %sTest problem or failure%s\n"
	   "  %s /%s  KMS communication info (good/bad)\n"
	   "  %s/%s wolfSSL TLS lib calls (good/bad)\n",
	   _I, _X, _E, _X, _kms, _kmse, _tls, _tlse);

    printf("\ncalling MASQ_crypto_init()\n");
    // MASQ_rand_clientid(pub1_id, sizeof(pub1_id));
    if (MASQ_STATUS_SUCCESS !=
	MASQ_crypto_init(MASQ_proto_id,
			 MASQ_role_publisher, pub1_id,
			 MASQ_key_ephemeral, 0,
			 NULL, 0,
			 ca_cert, pub1_cert, pub1_key,
#ifdef	ebug
			 2,
#endif
			 &pub_state_ephem)) {
	printf("%sMASQ_crypto_init failed at %d%s\n", _E, __LINE__, _X);
    }
    if (MASQ_STATUS_SUCCESS !=
	MASQ_crypto_init(MASQ_proto_id,
			 MASQ_role_publisher, pub2_id,
			 MASQ_key_persistent_pkt, 5,
			 NULL, 0,
			 ca_cert, pub2_cert, pub2_key,
#ifdef	ebug
			 2,
#endif
			 &pub_state_pers)) {
	printf("%sMASQ_crypto_init failed at %d%s\n", _E, __LINE__, _X);
    }

    // MASQ_rand_clientid(sub_id, sizeof(sub_id));
    if (MASQ_STATUS_SUCCESS !=
	MASQ_crypto_init(MASQ_proto_id,
			 MASQ_role_subscriber, sub_id,
			 MASQ_key_none, 0,
			 NULL, 0,
			 ca_cert, sub_cert, sub_key,
#ifdef	ebug
			 2,
#endif
			 &sub_state)) {
	printf("%sMASQ_crypto_init failed at %d%s\n", _E, __LINE__, _X);
    }
    
    /*****
     ***** AES-GCM ENCRYPT/DECRYPT
     *****/
    dump(key, sizeof(key), "key");
    dump(iv, sizeof(iv), "iv");
    dump(hdr, sizeof(hdr), "hdr");
    dump(pt, sizeof(pt), "pt");

    printf("\n>\n> MC_AESGCM_encrypt\n>\n");
    retv = MC_AESGCM_encrypt(&ep);

    if (! retv) {
	printf("Uh, oh\n");
    } else {
	dump(ct, sizeof(ct), "ct");
	dump(tag, sizeof(tag), "tag");
    }
    
    printf("\n>\n> MC_AESGCM_decrypt\n>\n");
    retv = MC_AESGCM_decrypt(&dp);

    if (! retv) {
	printf("Uh, oh\n");
    } else {
	dump(pt2, sizeof(pt2), "pt2");
	if (memcmp((void *) pt, (void *) pt2, sizeof(pt))) {
	    printf("pt/pt2 mismatch\n");
	} else {
	    printf("%sSuccess!%s\n", _I, _X);
	}
    }
    
    printf("\n>\n> MC_AESGCM_decrypt fail\n>\n");
    dp.tag[0] ^= 0x80;
    dp.pt = pt3;
    explicit_bzero((void *) pt3, sizeof(pt3));
    retv = MC_AESGCM_decrypt(&dp);

    if (retv) {
	printf("%sUh, oh... failed to fail%s\n", _E, _X);
    } else {
	dump(pt3, sizeof(pt3), "pt3");
	if (memcmp((void *) pt, (void *) pt3, sizeof(pt))) {
	    printf("%spt/pt3 mismatch%s\n", _E, _X);
	} else {
	    printf("%sSuccess!%s\n", _I, _X);
	}
    }

    /*****
     ***** RANDOM
     *****/
    printf("\n>\n> MASQ_rand_bytes\n>\n");
    for (i = 0; i < 4; i++) {
	if (MASQ_rand_bytes(rand_buf, sizeof(rand_buf))) {
	    dump(rand_buf, sizeof(rand_buf), "rand");
	} else {
	    printf("%sMASQ_rand_bytes failed%s\n", _E, _X);
	}
    }

#define	HDR_MIN	(0)
#define	HDR_MAX	(16)
#define	PT_MIN	(16)
#define	PT_MAX	(32)
    unsigned char	rkey[MASQ_AESKEY_LEN];
    unsigned char	riv[MASQ_IV_LEN];
    unsigned char	rhdr[HDR_MAX];
    unsigned char	rpt[PT_MAX];
    unsigned char	rct[PT_MAX];
    unsigned char	rpt2[PT_MAX];
    unsigned char	rtag[MASQ_TAG_LEN];
    MC_aesgcm_params	rep = {
	.key = rkey, .key_len = sizeof(rkey),
	.iv  = riv,  .iv_len  = sizeof(riv),
	.hdr = rhdr, .hdr_len = sizeof(rhdr),
	.pt  = rpt,  .pt_len  = sizeof(rpt),
	.ct  = rct,  .ct_len  = sizeof(rct),
	.tag = rtag, .tag_len = sizeof(rtag)
    };
    MC_aesgcm_params	rdp = {
	.key = rkey, .key_len = sizeof(rkey),
	.iv  = riv,  .iv_len  = sizeof(riv),
	.hdr = rhdr, .hdr_len = sizeof(rhdr),
	.pt  = rpt2, .pt_len  = sizeof(rpt2),
	.ct  = rct,  .ct_len  = sizeof(rct),
	.tag = rtag, .tag_len = sizeof(rtag)
    };
    unsigned char	temp;
    size_t		ptlen;
    size_t		hdrlen;
    masq_crypto_parms	mcp;
    
#define	ED_ROUNDS	(1024)
    printf("\n>\n> encrypt/decrypt (%d rounds)\n>\n", ED_ROUNDS);
    for (i = fail = 0; i < ED_ROUNDS; i++) {
	
	MASQ_rand_bytes(rkey, sizeof(rkey));
	MASQ_rand_bytes(riv,  sizeof(riv));
	
	MASQ_rand_bytes(&temp, 1);
	hdrlen = HDR_MIN + (temp % (HDR_MAX - HDR_MIN + 1));
	MASQ_rand_bytes(rhdr, hdrlen);
	
	MASQ_rand_bytes(&temp, 1);
	ptlen = PT_MIN + (temp % (PT_MAX - PT_MIN + 1));
	MASQ_rand_bytes(rpt,  ptlen);

	rep.hdr_len = hdrlen;
	rep.pt_len = rep.ct_len = ptlen;
	if (! MC_AESGCM_encrypt(&rep)) {
	    if (! fail) {
		printf("%sMC_AESGCM_encrypt failed on round %d%s\n",
		       _E, i, _X);
	    }
	    fail++;
	    continue;
	}
	
	rdp.hdr_len = hdrlen;
	rdp.pt_len = rdp.ct_len = ptlen;
	if (! MC_AESGCM_decrypt(&rdp)) {
	    if (! fail) {
		printf("%sMC_AESGCM_decrypt failed on round %d%s\n",
		       _E, i, _X);
	    }
	    fail++;
	    continue;
	}
	
	if (memcmp((void *) rpt, (void *) rpt2, ptlen)) {
	    if (! fail) {
		printf("%spt/pt2 mismatch on round %d%s\n", _E, i, _X);
	    }
	    fail++;
	    continue;
	}

	if (i < 2) {
	    printf("-------- %d\n", i);
	    dump(rkey, sizeof(rkey), "key");
	    dump(riv,  sizeof(riv),  "iv");
	    dump(rhdr, hdrlen,       "hdr");
	    dump(rpt,  ptlen,        "pt");
	    dump(rct,  ptlen,        "ct");
	    dump(rtag, sizeof(rtag), "tag");
	    dump(rpt2, ptlen,        "pt2");
	}
    }
    if (fail) {
	printf("%s%d of %d iterations failed%s\n", _E, fail, ED_ROUNDS, _X);
    } else {
	printf("%sSuccess!%s\n", _I, _X);
    }

    /*****
     ***** HASH
     *****/
    printf("\n>\n> MASQ_hash\n>\n");
    char *kat = "tank/level:20240904T000000Z:TankLevel00037a1";
    unsigned char	katout[MASQ_HASH_LEN];
    unsigned char	katcmp[] = {
	0x7b, 0x1d, 0x02, 0x1a, 0x85, 0xc9, 0x3e, 0xfa,
	0x5e, 0xb8, 0xfc, 0xb9, 0x90, 0xe9, 0x29, 0x68,
	0x4b, 0x62, 0xe4, 0x1d, 0x01, 0x01, 0x9c, 0xdd,
	0xc6, 0xda, 0xd7, 0xbf, 0x6e, 0x14, 0x69, 0xb6
    };
    if (! MASQ_hash((unsigned char *) kat, strlen(kat),
		    katout, sizeof(katout))) {
	printf("%sMASQ_hash failed%s\n", _E, _X);
    } else {
	printf("==== %04lx  input\n%s\n", strlen(kat), kat);
	dump(katout, sizeof(katout), "hash");
	printf("MASQ_hash KAT %s\n",
	       (memcmp((void *) katout, (void *) katcmp, sizeof(katout)) ?
		_E "error" _X : _I "success" _X));
    }

    printf("\n>\n> MASQ_hash_init / MASQ_hash_add\n>\n");
    void	*ctx;
    ctx = MASQ_hash_init((unsigned char *) kat, strlen(kat) / 2);
    if (NULL == ctx) {
	printf("%sMASQ_hash_init failed%s\n", _E, _X);
    } else {
	if (! MASQ_hash_add(ctx, (unsigned char *) &kat[strlen(kat) / 2],
			    strlen(kat) - (strlen(kat) / 2),
			    katout, sizeof(katout))) {
	    printf("%sMASQ_hash_add failed%s\n", _E, _X);
	} else {
	    printf("==== %04lx  input\n%s\n", strlen(kat), kat);
	    dump(katout, sizeof(katout), "hash");
	    printf("MASQ_hash KAT %s\n",
		   (memcmp((void *) katout, (void *) katcmp, sizeof(katout)) ?
		    _E "error" _X : _I "success" _X));
	}
    }
    
    /*****
     ***** EPHEMERAL KEY CRYPTO
     *****/
    char	seq[MASQ_SEQNUM_LEN + 1];
    char	expdate[MASQ_EXPDATE_LEN + 1];
    unsigned char	payload[MASQ_PAYLOAD_LEN_EPH(MASQ_MAXTOPIC_LEN)];
    size_t	payload_len = sizeof(payload);
    size_t	t_value_len;

#define	TOPICVAL_TEST_VALUE	"85"
    mcp.t_name = "tank/level";
    mcp.t_value = (unsigned char *) TOPICVAL_TEST_VALUE;
    t_value_len = strlen((const char *) mcp.t_value);
    mcp.t_value_len = &t_value_len;
    mcp.client_id = pub1_id;
    mcp.seq = seq; mcp.seq_len = sizeof(seq);
    mcp.exp_date = expdate; mcp.exp_date_len = sizeof(expdate);
    mcp.payload = payload; mcp.payload_len = &payload_len;
    printf("\n>\n> MASQ_ephem_encrypt\n>\n");
    if (! MASQ_ephem_encrypt(pub_state_ephem, &mcp)) {
	printf("%sUh, oh%s\n", _E, _X);
    } else {
	printf("seq     %s\nexpdate %s\npayload %lu bytes\n",
	       seq, expdate, payload_len);
	dump(mcp.t_value, t_value_len, "topic value");
	dump(payload, payload_len, "payload");
    }
    if (! MASQ_ephem_encrypt(pub_state_ephem, &mcp)) {
	printf("%sUh, oh 2%s\n", _E, _X);
    } else {
	printf("seq     %s\nexpdate %s\npayload %lu bytes\n",
	       seq, expdate, payload_len);
	dump(mcp.t_value, t_value_len, "topic value");
	dump(payload, payload_len, "payload");
    }

    char	t_value[MASQ_MAXTOPIC_LEN];

    mcp.t_value = (unsigned char *) t_value;
    mcp.t_value_len = &t_value_len; t_value_len =
					MASQ_VALUE_LEN_EPH(payload_len);
    printf("\n>\n> MASQ_ephem_decrypt\n>\n");
    if (! MASQ_ephem_decrypt(sub_state, &mcp)) {
	printf("%sUh, oh%s\n", _E, _X);
    } else {
	dump(mcp.t_value, t_value_len, "topic value");
	if ((strlen(TOPICVAL_TEST_VALUE) != t_value_len) ||
	    strncmp(mcp.t_value, TOPICVAL_TEST_VALUE,
		    strlen(TOPICVAL_TEST_VALUE))) {
	    printf("Ephemeral key %sdecryption mismatch%s\n", _E, _X);
	} else {
	    printf("Ephemeral key crypto %ssuccess!%s\n", _I, _X);
	}
    }

    /*****
     ***** PERSISTENT KEY CRYPTO
     *****/
    unsigned char	mek[MASQ_AESKEY_LEN];
    unsigned char	mek2[MASQ_AESKEY_LEN];

    mcp.t_name = "tank/level";
    mcp.client_id = pub2_id;
    mcp.seq = seq; mcp.seq_len = sizeof(seq);
    mcp.exp_date = expdate; mcp.exp_date_len = sizeof(expdate);
    mcp.mek = mek; mcp.mek_len = sizeof(mek);
    mcp.payload = payload; mcp.payload_len = &payload_len;
#ifdef	ebug
    mcp.debug = 1;
#endif
    printf("\n>\n> MASQ_pers_new_key (%p)\n>\n", pub_state_pers);
    if (! MASQ_pers_new_key(pub_state_pers, &mcp)) {
	printf("%sUh, oh%s\n", _E, _X);
    } else {
	printf("seq     %s\nexpdate %s\npayload %lu bytes\n",
	       seq, expdate, payload_len);
	dump(mcp.mek, mcp.mek_len, "mek");
	dump(mcp.payload, payload_len, "payload (wrapped key)");
    }

    mcp.client_id = pub2_id;
    mcp.exp_date = expdate; mcp.exp_date_len = sizeof(expdate);
    mcp.mek = mek2; mcp.mek_len = sizeof(mek2);
    printf("\n>\n> MASQ_pers_recover_key\n>\n");
    if (! MASQ_pers_recover_key(sub_state, &mcp)) {
	printf("%sUh, oh%s\n", _E, _X);
    } else {
	dump(mcp.mek, mcp.mek_len, "mek");
    }
    if (memcmp((void *) mek, (void *) mek2, sizeof(mek))) {
	printf("%sMEK mismatch!%s\n", _E, _X);
    } else {
	printf("Persistent key MEK %ssuccess!%s\n", _I, _X);
    }

    mcp.client_id = pub2_id;
    mcp.t_value = (unsigned char *) TOPICVAL_TEST_VALUE;
    mcp.t_value_len = &t_value_len;
    t_value_len = strlen((const char *) mcp.t_value);
    payload_len = sizeof(payload);
    printf("\n>\n> MASQ_pers_encrypt\n>\n");
    if (! MASQ_pers_encrypt(pub_state_pers, &mcp)) {
	printf("%sUh, oh%s\n", _E, _X);
    } else {
	dump(mcp.payload, payload_len, "payload");
    }

    mcp.client_id = sub_id;
    mcp.t_value = (unsigned char *) t_value;
    t_value_len = MASQ_VALUE_LEN_PER(payload_len);

    printf("\n>\n> MASQ_pers_decrypt\n>\n");
    if (! MASQ_pers_decrypt(sub_state, &mcp)) {
	printf("%sUh, oh%s\n", _E, _X);
    } else {
	dump(mcp.t_value, t_value_len, "t_value");
	if (strncmp((char *) mcp.t_value, TOPICVAL_TEST_VALUE, t_value_len)) {
	    printf("%st_value mismatch [%*s] vs [85]%s\n",
		   _E, (int) t_value_len, mcp.t_value, _X);
	} else {
	    printf("%sSuccess!%s\n", _I, _X);
	}
    }

    /*****
     ***** BASE64
     *****/
    char		b64enc[MC_B64ENC_LEN(sizeof(key)) + 1];
    unsigned char	b64dec[sizeof(key)];
    size_t		b64dec_len;
    printf("\n>\n> MC_base64_encode w/ padding\n>\n");
    if (! MC_base64_encode(key, sizeof(key), b64enc, sizeof(b64enc), 1)) {
	printf("%sUh, oh%s\n", _E, _X);
    } else {
	dump(key, sizeof(key), "in");
	printf("[%s]\n", b64enc);
    }
    printf("\n>\n> MC_base64_decode\n>\n");
    b64dec_len = sizeof(b64dec);
    if (! MC_base64_decode(b64enc, strlen(b64enc), b64dec, &b64dec_len)) {
	printf("%sUh, oh%s\n", _E, _X);
    } else {
	dump(b64dec, b64dec_len, "out");
    }
    if (memcmp((void *) key, (void *) b64dec, b64dec_len)) {
	printf("%sData mismatch!%s\n", _E, _X);
    }

    printf("\n");
    printf("\n>\n> MC_base64_encode/decode w/out padding\n>\n");
    if (! MC_base64_encode(key, sizeof(key), b64enc, sizeof(b64enc), 0)) {
	printf("%sUh, oh%s\n", _E, _X);
    } else {
	dump(key, sizeof(key), "in");
	printf("[%s]\n", b64enc);
    }
    b64dec_len = sizeof(b64dec);
    if (! MC_base64_decode(b64enc, strlen(b64enc), b64dec, &b64dec_len)) {
	printf("%sUh, oh%s\n", _E, _X);
    } else {
	dump(b64dec, b64dec_len, "out");
    }
    if (memcmp((void *) key, (void *) b64dec, b64dec_len)) {
	printf("%sData mismatch!%s\n", _E, _X);
    }

    printf("\n>\n> MC_base64 %d round trips\n>\n", ED_ROUNDS);
    int	b64_good = 1;
#define	B64_MIN	(8)
#define	B64_MAX	(64)
    for (i = 0; i < ED_ROUNDS; i++) {
	unsigned short	temp;
	unsigned char	bin[B64_MAX];
	char		benc[MC_B64ENC_LEN(sizeof(bin)) + 1];
	unsigned char	bdec[B64_MAX];
	size_t		inlen, declen;
	
	MASQ_rand_bytes((unsigned char *) &temp, sizeof(temp));
	inlen = B64_MIN + (temp % (B64_MAX - B64_MIN + 1));
	MASQ_rand_bytes(bin, inlen);

	MC_base64_encode(bin, inlen, benc, sizeof(benc), (temp & 0x30));
	declen = B64_MAX;
	MC_base64_decode(benc, strlen(benc), bdec, &declen);
	if (memcmp((void *) bin, (void *) bdec, declen)) {
	    printf("%sbase64 failure on iteration %d%s\n", _E, i, _X);
	    b64_good = 0;
	    break;
	}
    }
    if (b64_good) {
	printf("%sSuccess!%s\n", _I, _X);
    }
    
    /*****
     ***** CLIENTID
     *****/
    char	*sep;
    for (i = 0; i < 64; i++) {
	if (! MASQ_rand_clientid(clientid_buf, sizeof(clientid_buf))) {
	    printf("rand_clientid failure on iteration %d\n", i);
	    break;
	}
	
	switch (i % 4) {
	case 0: sep = "\n"; break;
	default: sep = " "; break;
	}
	
	printf("%s%s", sep, clientid_buf);
    }
    printf("\n");
    
    printf("\ncalling MASQ_crypto_close()\n");
    MASQ_crypto_close(pub_state_ephem);
    MASQ_crypto_close(pub_state_pers);
    MASQ_crypto_close(sub_state);
    return retv;
}
