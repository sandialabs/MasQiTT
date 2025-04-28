#include <time.h>
#include <string.h>
#include <stdlib.h>

#include "crypto.h"

/** @file
 *
 * TODO:
 *
 * - Make sure right things happen when key expires
 *   - notice key expiration (exists, needs testing)
 *   - update state->expdate (exists, needs testing)
 *   - flush MEK cache as needed (a Subscriber needs to keep "slightly
 *     expired" entries in case of a late-arriving PUBLISH packet, so
 *     some heuristic is needed to know when it's safe to weed out
 *     entries that are no longer needed)
 *
 ********/

MASQ_status_t
MASQ_crypto_api_init(const char *protoid,
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
		     void **state)
{
#ifdef	ebug
    if (debug) {
	printf("%s()\n", __FUNCTION__);
    }
#endif

    return MASQ_crypto_init(protoid,
			    role,
			    clientid,
			    strategy,
			    strat_val,
			    kms_host,
			    kms_port,
			    ca_file,
			    cert_file,
			    key_file,
#ifdef	ebug
			    debug,
#endif
			    state);
}

void
MASQ_crypto_api_add_entropy(unsigned char *data, size_t data_len)
{
    return MASQ_crypto_add_entropy(data, data_len);
}

void
MASQ_crypto_api_close(void *state)
{
    DEBUG(((masq_crypto_state *) state), 0, ("%s(%p)\n", __FUNCTION__, state));

    MASQ_crypto_close(state);
}

/**
 * Signal any key expiration date updates that may be needed.
 *
 * This is used for Ephemeral MEK processing, the Persistent MEK counterpart
 * is MEK_expired().
 *
 * @param s Crypto state data
 */
static void
check_upd_exp_dates(masq_crypto_state *s)
{
    time_t	now = time((time_t *) 0);
    struct tm	tm, *tmp;
    char	nowstr[MASQ_EXPDATE_LEN+1];
    
    tmp = gmtime_r(&now, &tm);
    snprintf(nowstr, sizeof(nowstr), "%04d%02d%02dT%02d%02d%02dZ",
	     tmp->tm_year + 1900, tmp->tm_mon + 1, tmp->tm_mday,
	     tmp->tm_hour, tmp->tm_min, tmp->tm_sec);
    if (strcmp(s->expdate, nowstr) < 0) {
	// tell MASQ_pers_new_key() to update expiration fields
	s->need_exp = 1;
    }
}

/**
 * Determine if the current persistent MEK needs to be created or replaced,
 * based on MEK replacement strategy.
 *
 * Ephemeral MEK processing calls check_upd_exp_dates() instead.
 *
 * @param[in] s Crypto state data
 * @param[in] t_name Topic Name
 * @param[in] bytes Number of bytes in Topic Value
 * @param[out] mp MEK key pointer if found
 * @return 1 if MEK is expired, else 0
 */
static int
MEK_expired(masq_crypto_state *s,
	    char *t_name,
	    size_t t_value_len,
	    MASQ_KS_mek_t **mp)
{
    int		retv = 0;
    MASQ_KS_mek_t	*mek;
    time_t	now;
    struct tm	tm, *tmp;
    char	nowstr[MASQ_EXPDATE_LEN+1];
    char	mek_seqnum[MASQ_SEQNUM_LEN+1];

    DEBUG(s, 0, ("%s(%s)\n", __FUNCTION__, t_name));
    *mp = NULL;

    if (s->need_exp) {
	DEBUG(s, 0, ("%s() return 1 at line %d (need_exp set)\n",
		     __FUNCTION__, __LINE__ - 2));
	return 1;
    }

    // this routine called if Publisher and using persistent MEK
    if (MASQ_STATUS_SUCCESS !=
	MASQ_get_topic_mek_seqnum(s, t_name, mek_seqnum, sizeof(mek_seqnum))) {
	DEBUG(s, 0, ("%s() return 1 at line %d (Topic not found)\n",
		     __FUNCTION__, __LINE__ - 2));
	return 1;
    }
    mek = MASQ_KS_find_mek(s->pub_mek, t_name, s->expdate, mek_seqnum, NULL);
    if (NULL == mek) {
	DEBUG(s, 0, ("%s() return 1 at line %d (MEK not found)\n",
		     __FUNCTION__, __LINE__ - 3));
	return 1;
    }
    *mp = mek;
    
    switch (s->strat) {
	
    case MASQ_key_persistent_pkt:
	mek->tally++;
	if (mek->tally >= mek->max) {
	    DEBUG(s, 0, ("%s() return 1 at line %d (packet tally)\n",
			 __FUNCTION__, __LINE__ - 2));
	    mek->tally = 1;
	    retv = 1;
	}
	break;
	
    case MASQ_key_persistent_bytes:
	mek->tally += (unsigned long int) t_value_len;
	if (mek->tally > mek->max) {
	    DEBUG(s, 0, ("%s() return 1 at line %d (bytes tally)\n",
			 __FUNCTION__, __LINE__ - 2));
	    mek->tally = (unsigned long int) t_value_len;
	    retv = 1;
	}
	break;
	
    case MASQ_key_persistent_time:
	// strat_max used for interval time
	// strat_cur used for expiration time
	now = time((time_t *) 0);
	if ((unsigned long int) now > mek->tally) {
	    DEBUG(s, 0, ("%s() return 1 at line %d (time tally)\n",
			 __FUNCTION__, __LINE__ - 2));
	    mek->tally = ((unsigned long int) now) + mek->max;
	    retv = 1;
	}
	break;
	
    case MASQ_key_persistent_exp:
	now = time((time_t *) 0);
	tmp = gmtime_r(&now, &tm);
	snprintf(nowstr, sizeof(nowstr), "%04d%02d%02dT%02d%02d%02dZ",
		 tmp->tm_year + 1900, tmp->tm_mon + 1, tmp->tm_mday,
		 tmp->tm_hour, tmp->tm_min, tmp->tm_sec);
	if (strcmp(s->expdate, nowstr) < 0) {
	    DEBUG(s, 0, ("%s() return 1 at line %d (MEK expiration)\n",
			 __FUNCTION__, __LINE__ - 2));
	    // tell MASQ_pers_new_key() to update expiration fields
	    s->need_exp = 1;
	    retv = 1;
	}
	break;
    }
    
    return retv;
}

MASQ_status_t
MASQ_crypto_api_encrypt(void *state,
			char *topic_name,
			unsigned char *topic_value,
			size_t topic_value_len,
			MASQ_user_properties_t *up,
			unsigned char *outbuf,
			size_t *outbuf_len)
{
    masq_crypto_state	*s = (masq_crypto_state *) state;
    masq_crypto_parms	mcp;
    int			n;

    void		*buffer;
    size_t		buffer_len;
    MASQ_user_properties_t	user_props;

    MASQ_KS_mek_t	*mp;
    unsigned char	mek[MASQ_AESKEY_LEN];
    char		seqnum[MASQ_SEQNUM_LEN+1];
    char		seqnum2[MASQ_SEQNUM_LEN+1];

    MASQ_status_t	ret;
    
    DEBUG(s, 0, ("%s(%p, %s, %s)\n",
		 __FUNCTION__, state, topic_name, topic_value));

    if (NULL == s) {
	return MASQ_ERR_INVAL;
    }

    if (! ((MASQ_role_publisher == s->role) ||
	   (MASQ_role_both == s->role))) {
	return MASQ_ERR_INVAL_ROLE;
    }

    if ((NULL == topic_name) || (NULL == topic_value) ||
	(NULL == up) || (NULL == outbuf)) {
	return MASQ_ERR_INVAL;
    }

    if (MASQ_key_ephemeral == s->strat) {

	DEBUG(s, 0, ("%s:%d ephemeral MEK\n", __FUNCTION__, __LINE__));
	check_upd_exp_dates(s);

	mcp.t_name = topic_name;
	mcp.t_value = topic_value;
	mcp.t_value_len = &topic_value_len;
	mcp.client_id = s->clientid;
	mcp.seq = seqnum;
	mcp.seq_len = sizeof(seqnum);
	mcp.exp_date = s->expdate;
	mcp.exp_date_len = sizeof(s->expdate);
	mcp.payload = outbuf;
	mcp.payload_len = outbuf_len;
#ifdef	ebug
	mcp.debug = s->debug;
#endif

	if (! MASQ_ephem_encrypt((void *) s, &mcp)) {
	    DEBUG(s, 0, ("ERR_CRYPTO at %s:%d\n", __FUNCTION__, __LINE__));
	    return MASQ_ERR_CRYPTO;
	}

	n = 0;
#undef	_prop
#define	_prop(p,i,n,v)	do {						\
	    strncpy(p->prop[i].name,  n, sizeof(p->prop[i].name));	\
	    strncpy(p->prop[i].value, v, sizeof(p->prop[i].value));	\
	} while (0)
	_prop(up, n, "SMQTT", s->protoid);
	n++;
	_prop(up, n, "SeqNum", seqnum);
	n++;
	_prop(up, n, "ClientId", s->clientid);
	n++;
	_prop(up, n, "KeyExp", s->expdate);
	n++;
	_prop(up, n, "KM", "Ephm");
	n++;
	up->num_props = n;

	return MASQ_STATUS_SUCCESS;
    }

    // Persistent key strategy
    //
    if (MASQ_check_stored_packet(s, topic_name, &user_props,
				 &buffer, &buffer_len)) {

	DEBUG(s, 0, ("%s:%d found stored packet\n", __FUNCTION__, __LINE__));
	// return stored data to caller
	if (*outbuf_len < buffer_len) {
	    return MASQ_ERR_INVAL;
	}
	memcpy((void *) outbuf, buffer, buffer_len);
	free(buffer);
	*outbuf_len = buffer_len;
	    
	for (n = 0; n < user_props.num_props; n++) {
	    strncpy(up->prop[n].name, user_props.prop[n].name,
		    sizeof(up->prop[n].name));
	    strncpy(up->prop[n].value, user_props.prop[n].value,
		    sizeof(up->prop[n].value));
	}
	up->num_props = user_props.num_props;
	    
	return MASQ_STATUS_SUCCESS;
    }

    if (MEK_expired(s, topic_name, topic_value_len, &mp)) {
	// side-effect of calling MEK_expired is setting up mp
	// when not expired

	DEBUG(s, 0, ("!!!! %s:%d EXPIRED MEK\n", __FUNCTION__, __LINE__));
	MASQ_dump_state(s, "EXPIRED MEK");

	// generate MEK packet to return to caller
	mcp.t_name = topic_name;
	mcp.t_value = NULL;
	mcp.t_value_len = 0;
	mcp.client_id = s->clientid;
	mcp.seq = seqnum;
	mcp.seq_len = sizeof(seqnum);
	mcp.exp_date = s->expdate;
	mcp.exp_date_len = sizeof(s->expdate);
	mcp.mek = mek;
	mcp.mek_len = sizeof(mek);
	mcp.payload = outbuf;
	mcp.payload_len = outbuf_len;

	if (! MASQ_pers_new_key(state, &mcp)) {
	    DEBUG(s, 0, ("ERR_CRYPTO at %s:%d\n", __FUNCTION__, __LINE__));
	    return MASQ_ERR_CRYPTO;
	}

	// MASQ_pers_new_key adds new MEK to cache
	mp = MASQ_KS_find_mek(s->pub_mek, topic_name, s->expdate, NULL, NULL);

	if (NULL == mp) {
	    printf("!!!!!!!!!!!!!!!!!!!!!!!!!! ACK\n");
#if 0
	    DEBUG(s, 0, ("%s:%d sizeof(mek) = %lu\n", __FILE__, __LINE__ + 2,
			 *outbuf_len));
	    mp = MASQ_KS_new(&s->pub_mek,
			     topic_name,
			     s->expdate,
			     seqnum,
			     s->clientid,
			     s->strat,
			     s->strat_max,
			     outbuf, *outbuf_len);
	    MASQ_dump_mek(mp, "from MASQ_KS_new()", 0);
#endif
	}
	if (NULL != mp) {
	    // update MEK with fields that (may) have changed
	    strcpy(mp->expdate, s->expdate);
	    strcpy(mp->seqnum, seqnum);
	    memcpy((void *) mp->mek, mek, sizeof(mek));
	}

	MASQ_dump_meks(s->pub_mek, "updated MEK");
	
	n = 0;
	_prop(up, n, "SMQTT", s->protoid);
	n++;
	_prop(up, n, "SeqNum", seqnum);
	n++;
	_prop(up, n, "ClientId", s->clientid);
	n++;
	_prop(up, n, "KeyExp", s->expdate);
	n++;
	_prop(up, n, "KM", "Pers");
	n++;
	up->num_props = n;

	// generate data packet to store in back pocket
	buffer_len = MASQ_PAYLOAD_LEN_PER(topic_value_len);
	buffer = calloc(1, buffer_len);
	if (NULL == buffer) {
	    return MASQ_ERR_NOMEM;
	}
	//printf(">>>> buffer = %p, buffer_len = %lu\n", buffer, buffer_len);

	mcp.t_value = topic_value;
	mcp.t_value_len = &topic_value_len;
	mcp.seq = seqnum2;
	mcp.seq_len = sizeof(seqnum2);
	mcp.mek = mp->mek;

	mcp.payload = buffer;
	mcp.payload_len = &buffer_len;
	if (! MASQ_pers_encrypt((void *) s, &mcp)) {
	    DEBUG(s, 0, ("ERR_CRYPTO at %s:%d\n", __FUNCTION__, __LINE__));
	    return MASQ_ERR_CRYPTO;
	}
	MASQ_dump(buffer, buffer_len, "after MASQ_pers_encrypt()", '>', 1);

	MASQ_user_properties_t	*_up = &user_props;

	n = 0;
	_prop(_up, n, "SMQTT", s->protoid);
	n++;
	_prop(_up, n, "SeqNum", seqnum2);
	n++;
	_prop(_up, n, "ClientId", s->clientid);
	n++;
	_prop(_up, n, "KeyExp", s->expdate);
	n++;
	_prop(_up, n, "KM", seqnum);
	n++;
	_up->num_props = n;

	// return MEK packet with indication of second packet
	ret = MASQ_store_packet(s, topic_name, _up, buffer, buffer_len);
	return (MASQ_STATUS_SUCCESS == ret ? MASQ_STATUS_ANOTHER : ret);
	    
    }

    // Found a MEK to use
    //
    DEBUG(s, 0, ("%s:%d using established MEK\n", __FUNCTION__, __LINE__));
    MASQ_dump_mek(mp, "from MEK_expired()", 0);
    // generate data packet to return to caller
    mcp.t_name = topic_name;
    mcp.t_value = topic_value;
    mcp.t_value_len = &topic_value_len;
    mcp.seq = seqnum;
    mcp.seq_len = sizeof(seqnum);
    mcp.mek = mp->mek;
    mcp.mek_len = sizeof(mp->mek);
    mcp.payload = outbuf;
    mcp.payload_len = outbuf_len;

    if (! MASQ_pers_encrypt((void *) s, &mcp)) {
	DEBUG(s, 0, ("ERR_CRYPTO at %s:%d\n", __FUNCTION__, __LINE__));
	return MASQ_ERR_CRYPTO;
    }
	    
    n = 0;
    _prop(up, n, "SMQTT", s->protoid);
    n++;
    _prop(up, n, "SeqNum", seqnum);
    n++;
    _prop(up, n, "ClientId", s->clientid);
    n++;
    _prop(up, n, "KeyExp", s->expdate);
    n++;
    _prop(up, n, "KM", mp->seqnum);
    n++;
    up->num_props = n;
    return MASQ_STATUS_SUCCESS;
}

/**
 * Decryption type.
 */
typedef enum {
    MASQ_crypto_api_decrypt_none = 0,	//!< Decryption type not determined.
    MASQ_crypto_api_decrypt_ephem,	//!< Ephemeral key decryption.
    MASQ_crypto_api_decrypt_pers_mek,	//!< Persistent key MEK only.
    MASQ_crypto_api_decrypt_pers_data,	//!< Persistent key data decryption.
} MASQ_crypto_api_decrypt_t;

MASQ_status_t
MASQ_crypto_api_decrypt(void *state,
			char *topic_name,
			MASQ_user_properties_t *up,
			unsigned char *inbuf,
			size_t inbuf_len,
			unsigned char *topic_value,
			size_t *topic_value_len)
{
    masq_crypto_state	*s = (masq_crypto_state *) state;
    masq_crypto_parms	mcp;
    int			i;

    MASQ_crypto_api_decrypt_t	dec = MASQ_crypto_api_decrypt_none;
    size_t		t_value_len;
    size_t		pl_len = inbuf_len;
    char		mek_seqnum[MASQ_SEQNUM_LEN+1];
    unsigned char	mek[MASQ_AESKEY_LEN];
    MASQ_KS_mek_t	*mp;

    MASQ_status_t	retv = MASQ_STATUS_SUCCESS;

    DEBUG(s, 0, ("%s(%p, %s, %lu, %lu)\n", __FUNCTION__, state,
		 topic_name, inbuf_len, *topic_value_len));

    if (NULL == state) {
	return MASQ_ERR_INVAL;
    }

    if (! ((MASQ_role_subscriber == s->role) ||
	   (MASQ_role_both == s->role))) {
	return MASQ_ERR_INVAL_ROLE;
    }
    if ((NULL == topic_name) ||	(NULL == up) ||	(NULL == inbuf) ||
	(NULL == topic_value) || (NULL == topic_value_len)) {
	return MASQ_ERR_INVAL;
    }

    // fill in fields common among all decryption cases
    mcp.t_name = topic_name;
    mcp.t_value = topic_value;
    t_value_len = *topic_value_len;
    mcp.t_value_len = &t_value_len;
    mcp.payload = inbuf;
    mcp.payload_len = &pl_len;

    // parse user properties
    for (i = 0; i < up->num_props; i++) {
	
	if (! strncmp(up->prop[i].name, "ProtoId",
		      sizeof(up->prop[i].name))) {

	    if ((strlen(up->prop[i].value) != strlen(s->protoid)) ||
		(strcmp(up->prop[i].value, s->protoid))) {
		return MASQ_ERR_BAD_PROTOID;
	    }
	    
	} else if (! strncmp(up->prop[i].name, "SeqNum",
		      sizeof(up->prop[i].name))) {

	    mcp.seq = up->prop[i].value;
	    mcp.seq_len = sizeof(up->prop[i].value);
	    
	} else if (! strncmp(up->prop[i].name, "ClientId",
		      sizeof(up->prop[i].name))) {
	    
	    mcp.client_id = up->prop[i].value;
	    
	} else if (! strncmp(up->prop[i].name, "KeyExp",
		      sizeof(up->prop[i].name))) {
	    
	    mcp.exp_date = up->prop[i].value;
	    mcp.exp_date_len = sizeof(up->prop[i].value);
	    
	} else if (! strncmp(up->prop[i].name, "KM",
			     sizeof(up->prop[i].name))) {
	    
	    // determine key management scheme
	    if (! strncmp(up->prop[i].value, "Ephm",
			  sizeof(up->prop[i].value))) {
		
		// Ephemeral
		dec = MASQ_crypto_api_decrypt_ephem;
		
	    } else if (! strncmp(up->prop[i].value, "Pers",
			  sizeof(up->prop[i].value))) {
		
		// Persistent, MEK packet
		dec = MASQ_crypto_api_decrypt_pers_mek;
		
	    } else {
		
		// Persistent, data packet
		dec = MASQ_crypto_api_decrypt_pers_data;
		strncpy(mek_seqnum, up->prop[i].value, sizeof(mek_seqnum));
	    }
	}
    }

    switch (dec) {
	
    case MASQ_crypto_api_decrypt_ephem:
	// this is self-contained, so no need to dig around for more info
	mcp.mek = NULL;
	mcp.mek_len = 0;
	if (! MASQ_ephem_decrypt(state, &mcp)) {
	    DEBUG(s, 0, ("ERR_CRYPTO at %s:%d\n", __FUNCTION__, __LINE__));
	    retv = MASQ_ERR_CRYPTO;
	}
	break;
	
    case MASQ_crypto_api_decrypt_pers_mek:
	// stores MEK as a side effect
	mcp.mek = mek;
	mcp.mek_len = sizeof(mek);
	
	if (MASQ_pers_recover_key(state, &mcp)) {
	    retv = MASQ_STATUS_KEY_MGMT;
	} else {
	    DEBUG(s, 0, ("%s:%d MASQ_pers_recover_key() failed\n",
			 __FUNCTION__, __LINE__-1));
	    retv = MASQ_ERR_CRYPTO;
	}
	break;
	
    case MASQ_crypto_api_decrypt_pers_data:
	// get MEK
	mp = MASQ_KS_find_mek(s->sub_mek, topic_name,
			      mcp.exp_date, mek_seqnum,
			      mcp.client_id);
	if (NULL == mp) {
	    retv = MASQ_ERR_NO_KEY;
	    break;
	}
	
	mcp.mek = mp->mek;
	mcp.mek_len = sizeof(mek);
			      
	if (! MASQ_pers_decrypt(state, &mcp)) {
	    DEBUG(s, 0, ("ERR_CRYPTO at %s:%d\n", __FUNCTION__, __LINE__));
	    retv = MASQ_ERR_CRYPTO;
	}
	break;
	
    default:
	DEBUG(s, 0, ("%s() No/invalid KM User Property\n", __FUNCTION__));
	return MASQ_ERR_INVAL;
	break;
    }

    *topic_value_len = t_value_len;
    return retv;
}

MASQ_status_t
MASQ_crypto_api_overhead(MASQ_mek_strategy_t strategy,
			 size_t *overhead_bytes,
			 size_t *mek_bytes)
{
    return MASQ_crypto_overhead(strategy, overhead_bytes, mek_bytes);
}

MASQ_status_t
MASQ_crypto_api_get_strategy(void *state,
			     MASQ_mek_strategy_t *strategy)
{
    masq_crypto_state	*s = (masq_crypto_state *) state;

    if ((NULL == s) || (NULL == strategy)) {
	return MASQ_ERR_INVAL;
    }

    *strategy = s->strat;
    
    return MASQ_STATUS_SUCCESS;
}

MASQ_mek_strategy_t
MASQ_crypto_api_mek_to_strat(char *mek)
{
    int		m, h;
    char	*hex = "0123456789abcdefABCDEF";
    int		good;
    MASQ_mek_strategy_t	retv = MASQ_key_none;
    
    if (NULL == mek) {
	return retv;
    }
    
    if (! strcmp(mek, "Ephm")) {
	
	retv = MASQ_key_ephemeral;
	
    } else if (! strcmp(mek, "Pers")) {
	
	retv = MASQ_key_persistent_exp;	// any of the persistent values work
	
    } else if (MASQ_SEQNUM_LEN == strlen(mek)) {
	
	// ensure valid hex seqnum
	for (m = good = 0; m < MASQ_SEQNUM_LEN; m++) {
	    for (h = 0; h < strlen(hex); h++) {
		if (mek[m] == hex[h]) {
		    good++;
		    break;
		}
	    }
	}
	if (MASQ_SEQNUM_LEN == good) {
	    retv = MASQ_key_persistent_exp;	// any of the pers values work
	}
    }

    return retv;
}

const char *
MASQ_status_to_str(MASQ_status_t status)
{
    const char	*retv = "???";
    switch (status) {
#undef	_X
#define	_X(x)	case MASQ_ ## x: retv = # x; break
    _X(STATUS_SUCCESS);
    _X(STATUS_ANOTHER);
    _X(STATUS_KEY_MGMT);
    _X(ERR_BAD_PROTOID);
    _X(ERR_INVAL);
    _X(ERR_INVAL_ROLE);
    _X(ERR_TLS_INIT);
    _X(ERR_NO_KEY);
    _X(ERR_DECRYPT);
    _X(ERR_NOMEM);
    _X(ERR_NOSPACE);
    _X(ERR_MALFORMED_PACKET);
    _X(ERR_MALFORMED_UTF8);
    _X(ERR_PAYLOAD_SIZE);
    _X(ERR_WRONG_MSG_TYPE);
    _X(ERR_NOT_FOUND);
    _X(ERR_BAD_ENTRY);
    _X(ERR_KMS);
    _X(ERR_MIRACL);
    _X(ERR_CRYPTO);
    _X(ERR_INTERNAL);
#undef	_X
    }
    return retv;
}

const char *
MASQ_strategy_to_str(MASQ_mek_strategy_t strategy)
{
    const char	*retv = "???";
    switch (strategy) {
#undef	_X
#define	_X(x)	case MASQ_key_ ## x: retv = # x; break
    _X(none);
    _X(ephemeral);
    _X(persistent_pkt);
    _X(persistent_bytes);
    _X(persistent_time);
    _X(persistent_exp);
#undef	_X
    }
    return retv;
}
