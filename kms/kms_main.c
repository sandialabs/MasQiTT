/**
 * @file kms_main.c
 * MasQiTT Key Management Server.
 *
 * This KMS is functional for IBE/BB1 Crypto use.
 */

// Linux
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <time.h>
#include <signal.h>
#include <sys/types.h>
#include <pwd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <errno.h>

// MasQiTT
#include "kms_msg.h"
#include "kms_utils.h"
#include "crypto.h"
#include "cache.h"
#include "cfg.h"
#include "strings.h"

// TLS wiring
#include "tls.h"
#define	CA_DIR			"ca"
#define	CA_FILE			"ca-crt.pem"
#define	CERT_FILE		"kms-crt.pem"
#define	KEY_FILE		"kms-key.pem"

extern const char *
MASQ_status_to_str(MASQ_status_t status);

static int	verbose = 0;
static int	monochrome_mode = 0;
static int	daemon_mode = 0;
static int	_running = 1;

// expiration dates as time_t values
static KMS_exp_t	_exp;

//!< expiration dates as strings, separated from _exp for cache operations
static char	_exp_s[KMS_NUM_EXP][MASQ_EXPDATE_LEN + 1] = { { 0 }, { 0 } };
#define	KMS_EXPDATE	0
#define	KMS_NEXTEXP	1

static int	_alarm_interval = 30 * SEC_MINUTE;	//!< Alarm poll interval

typedef enum {
    cfg_bool,	//!< Config val is boolean.
    cfg_time,	//!< Config val is a time (duration) string.
    cfg_date,	//!< Config val is an absolute date/time string.
    cfg_string	//!< Config val is a string.
} cfg_t;

typedef struct {
    const char	*config;	//!< Name in config file if can be overridden.
    cfg_t	type;		//!< Boolean, time (as string), or string.
    union {
	int	bval;		//!< Boolean value.
	time_t	tval;		//!< Time-based value.
	const char *sval;	//!< String value.
    } v;			//!< Default value or from config file.
    time_t	next;		//!< Next time to do something if time-based.
} kms_cfg_t;

// forward reference
static void
precompute_keys(void);

/**
 * Default configuration options.
 */
static kms_cfg_t	_cfgval[] = {
#define	CFG_ALLOW_NC_CLIENTS	0
    { .config = "non_cache_clients", .type = cfg_bool,
      .v.bval = 0 },
#define	CFG_PUB_EPOCH	1
    { .config = "epoch", .type = cfg_date,
      .v.tval = 0, .next = 0 },
#define	CFG_PUB_EXPIRATION	2
    { .config = "expiry_interval", .type = cfg_time,
      .v.tval = 1 * SEC_DAY, .next = 0 },
#define	CFG_CACHE_EXPIRY	3
    { .config = "expire_cache_after", .type = cfg_time,
      .v.tval = 4 * SEC_HOUR, .next = 0 },
#define	CFG_DO_PRECOMPUTE	4
    { .config = "precompute_keys", .type = cfg_bool,
      .v.bval = 1 },
#define	CFG_PRECOMPUTE_KEYS	5
    { .config = "precompute_lead_time", .type = cfg_time,
      .v.tval = 2 * SEC_HOUR, .next = 0 },
#define	CFG_CACHE_SAVE	6
    { .config = "cache_save_interval", .type = cfg_time,
      .v.tval = 1 * SEC_HOUR, .next = 0 },
    /*
     * The following cannot be overridden via kms.cfg
     */
#define	CFG_CERT_DIR	7
    { .config = NULL, .type = cfg_string, .v.sval = CA_DIR },
#define	CFG_CA_CERT	8
    { .config = NULL, .type = cfg_string, .v.sval = CA_FILE },
#define	CFG_CERT	9
    { .config = NULL, .type = cfg_string, .v.sval = CERT_FILE },
#define	CFG_PRIV_KEY	10
    { .config = NULL, .type = cfg_string, .v.sval = KEY_FILE },
};
#define	NUM_CFGVALS	(sizeof(_cfgval)/sizeof(_cfgval[0]))

static char *
cfg_to_str(int cfg)
{
    char	*retv = "???";
#ifdef	_XS
#undef	_XS
#endif
#define	_XS(x)	case CFG_ ## x: retv = #x; break
    switch (cfg) {
    _XS(ALLOW_NC_CLIENTS);
    _XS(PUB_EXPIRATION);
    _XS(CACHE_EXPIRY);
    _XS(DO_PRECOMPUTE);
    _XS(PRECOMPUTE_KEYS);
    _XS(CACHE_SAVE);
    _XS(CERT_DIR);
    _XS(CA_CERT);
    _XS(CERT);
    _XS(PRIV_KEY);
    }
#undef	_XS
    return retv;
}

static KMS_shared_params_t	_params;	//!< Shared parameters
static KMS_client_t		*_head = NULL;	//!< Client cache

static char	*_M = "\033[38;2;0;173;208m";	// masqitt
static char	*_E = "\033[0;91m";	// error (red)
static char	*_W = "\033[0;93m";	// warn (yellow)
static char	*_I = "\033[0;92m";	// info (green)
static char	*_C = "\033[0;94m";	// cmd (blue)

//static char	*_B = "\033[5m";	// blink
//static char	*_b = "\033[25m";	// not blink
static char	*_X = "\033[m";		// restore

static void
do_monochrome(void)
{
    _E = _W = _I = _C = _M = _X = "";
}

/* forward references */
static void	get_config_options(void);
static void	add_clients_to_cache(KMS_client_t **head);

/*
 * Generate a string for verbose/debug printing.
 */
static char *
timestr(time_t t)
{
    struct tm	*tmp;
    static char	retbuf[32];

    tmp = gmtime(&t);
    snprintf(retbuf, sizeof(retbuf), "%02d/%02d/%02d %02d:%02d:%02d",
	     tmp->tm_year % 100, tmp->tm_mon + 1, tmp->tm_mday,
	     tmp->tm_hour, tmp->tm_min, tmp->tm_sec);
    return retbuf;
}

/**
 * Generate a string with the current GMT time for log printing.
 *
 * Like timestr() but with microseconds.
 */
static char *
timestamp(void)
{
    struct timeval	tv;
    struct tm		*tmp;
    static char		retbuf[32];

    if (! gettimeofday(&tv, NULL)) {
	tmp = gmtime(&tv.tv_sec);
	snprintf(retbuf, sizeof(retbuf), "%02d/%02d/%02d %02d:%02d:%02d.%06ld",
		 tmp->tm_year % 100, tmp->tm_mon + 1, tmp->tm_mday,
		 tmp->tm_hour, tmp->tm_min, tmp->tm_sec, tv.tv_usec);
    }
    return retbuf;
}

#define	tprintf(x)	do {			\
	printf("[%s] ", timestamp()); printf x; \
	fflush(stdout);				\
    } while (0)

/**
 * Add entropy to random number generation by sampling time-of-day and
 * processor clocks, both of which include microsecond values, so we can
 * glean a few bits of externally non-visible entropy from that.
 */
static void
kms_add_entropy(void)
{
    struct {
	// time of day
	struct timeval	tv;
	// process resource usage (includes struct timevals and other stats)
	struct rusage	ru;
    } in;

    if ((! gettimeofday(&in.tv, NULL)) && (! getrusage(RUSAGE_SELF, &in.ru))) {
	MASQ_crypto_add_entropy((unsigned char *) &in, sizeof(in));
    }
}

/**
 * KMS signal handler.
 *
 * Called as result of receiving a handled signal. Args are defined
 * by sigaction() system call.
 */
static void
handle_signal(int sig, siginfo_t *sig_info, void *vctxt)
{
    MASQ_status_t	rc;
    
    // don't care about params, but keep compiler from complaining...
    (void) sig_info; (void) vctxt;

    switch (sig) {

    case SIGHUP:
    case SIGINT:
	printf("\n");	// skip past displayed ^C
	tprintf(("KMS orderly shut down in progress\n"));
	_running = 0;
	break;

    case SIGUSR1:
	tprintf(("KMS received USR1 (saving cached data)\n"));
	cache_save(_head, &_exp, CACHE_FILE);
	break;

    case SIGUSR2:
	tprintf(("KMS received USR2 (re-reading config file)\n"));
	cfg_clear();
	rc = cfg_init(CONFIG_FILE);
	if (MASQ_STATUS_SUCCESS != (rc = cfg_init(CONFIG_FILE))) {
	    if (verbose) {
		printf("config_init ret %s\n", MASQ_status_to_str(rc));
	    }
	    exit(1);
	}
	get_config_options();
	add_clients_to_cache(&_head);
	break;

    default:
	fprintf(stderr, "%sUnhandled signal: %d%s\n", _W, sig, _X);
	break;
    }
}

static void
handle_alarm(int sig, siginfo_t *sig_info, void *vctxt);

/**
 * KMS alarm scheduler.
 *
 * Called at startup and after an alarm is handled. Search through scheduled
 * events, find the earliest, and set an alarm to expire at that time.
 */
static void
next_alarm(void)
{
    int		i;
    time_t	now = time((time_t *) 0);
    time_t	earliest = 0;
    int		what = -1;
    int		interval;

    alarm(0);	// cancel any pending alarms

    for (i = 0; i < NUM_CFGVALS; i++) {
	if ((cfg_time == _cfgval[i].type) && _cfgval[i].next) {
	    if (verbose > 1) {
		tprintf(("%s %s\n", timestr(_cfgval[i].next), cfg_to_str(i)));
	    }
	    if ((0 == earliest) || (_cfgval[i].next < earliest)) {
		earliest = _cfgval[i].next;
		what = i;
	    }
	}
    }

    if (earliest) {
	if (earliest <= now) {
	    // something else that needs handling?
	    // (this can pop up when a KMS has been running in a VM after the
	    // VM has been unpaused after a significant amount of time)
	    tprintf(("%s%s() handling another (paused VM?)%s\n",
		     _W, __FUNCTION__, _X));
	    handle_alarm(0, NULL, NULL);
	} else {
	    interval = ((int) earliest) - ((int) now);
	    if (interval <= 0) {
		// alarm(0) cancels alarm, so make sure that doesn't happen
		interval = 1;
	    }
	    alarm(interval);
	    if (verbose) {
		tprintf(("%s() %s%-15s%s at %s\n", __FUNCTION__,
			 _C, cfg_to_str(what), _X, timestr(earliest)));
	    } else {
		tprintf(("schedule %s%-15s%s at %s\n",
			 _C, cfg_to_str(what), _X, timestr(earliest)));
	    }
	}
    } else {
	tprintf(("%s%s() nothing to schedule????%s\n", _W, __FUNCTION__, _X));
    }
}

/**
 * KMS alarm handler.
 *
 * Called as result of receiving an alarm signal. Each recurring time-based
 * configuration value should be handled here. Args are defined by
 * sigaction() system call.
 *
 * - Compare current time against _cfgval[].next
 * - If time has passed, do something
 */
static void
handle_alarm(int sig, siginfo_t *sig_info, void *vctxt)
{
    int		i;
    time_t	now = time((time_t *) 0);
    (void) sig; (void) sig_info; (void) vctxt;	// not used

    for (i = 0; i < NUM_CFGVALS; i++) {
	if ((cfg_time == _cfgval[i].type) &&
	    _cfgval[i].next && (_cfgval[i].next <= now)) {

	    if (verbose) {
		tprintf(("%s() handling %s%s%s\n", __FUNCTION__,
			 _C, cfg_to_str(i), _X));
	    } else {
		tprintf(("time for %s%s%s\n", _C, cfg_to_str(i), _X));
	    }

	    // timer should set their own .next to the next time they should
	    // trigger, or set .next to 0 to avoid getting called over and
	    // over in a tight loop. it's okay to set some other timer's
	    // .next (as in the case of CFG_PUB_EXPIRATION) as those timers
	    // are deltas from that time.
	    
	    switch (i) {
		
	    case CFG_PUB_EXPIRATION:
		if (_cfgval[CFG_CACHE_EXPIRY].v.tval) {
		    // set timer to flush after current expiration
		    _cfgval[CFG_CACHE_EXPIRY].next =
			_cfgval[CFG_PUB_EXPIRATION].next +
			_cfgval[CFG_CACHE_EXPIRY].v.tval;
		    if (verbose) {
			tprintf(("%s() EXP_FLUSH next %s\n", __FUNCTION__,
				 timestr(_cfgval[CFG_CACHE_EXPIRY].next)));
		    }
		}
		
		// update public key expiration
		_cfgval[CFG_PUB_EXPIRATION].next +=
		    _cfgval[CFG_PUB_EXPIRATION].v.tval;
		_exp.expdate = _cfgval[CFG_PUB_EXPIRATION].next;
		cache_time_to_str(_exp.expdate, _exp_s[KMS_EXPDATE]);
		if (verbose) {
		    tprintf(("%s() PUB_EXPIRY next %s\n", __FUNCTION__,
			     timestr(_cfgval[CFG_PUB_EXPIRATION].next)));
		}

		// update next expiration
		_exp.nextexp = _cfgval[CFG_PUB_EXPIRATION].next +
		    _cfgval[CFG_PUB_EXPIRATION].v.tval;
		cache_time_to_str(_exp.nextexp, _exp_s[KMS_NEXTEXP]);

		if (_cfgval[CFG_DO_PRECOMPUTE].v.bval &&
		    _cfgval[CFG_PRECOMPUTE_KEYS].v.tval) {
		    // set timer to precompute before next expiration
		    _cfgval[CFG_PRECOMPUTE_KEYS].next =
			_cfgval[CFG_PUB_EXPIRATION].next -
			_cfgval[CFG_PRECOMPUTE_KEYS].v.tval;
		    if (verbose) {
			tprintf(("%s() PRECOMPUTE_KEYS next %s\n", __FUNCTION__,
				 timestr(_cfgval[CFG_PRECOMPUTE_KEYS].next)));
		    }
		}
		break;

	    case CFG_CACHE_EXPIRY:
		// flush outdated private keys
		// could call get_time() but don't need overhead of
		// seting expiration times
		char	my_nowbuf[MASQ_EXPDATE_LEN + 1];
		cache_time_to_str(time((time_t *) 0), my_nowbuf);
		cache_expire(_head, my_nowbuf);
		// .next set when key expiration set
		if (verbose) {
		    tprintf(("%s() clearing %s\n",
			     __FUNCTION__, cfg_to_str(i)));
		}
		_cfgval[i].next = 0;
		break;
		
	    case CFG_PRECOMPUTE_KEYS:
		// precompute private keys for next public expiration date
		precompute_keys();
		// .next set when key expiration set
		if (verbose) {
		    tprintf(("%s() clearing %s\n",
			     __FUNCTION__, cfg_to_str(i)));
		}
		_cfgval[i].next = 0;
		break;
		
	    case CFG_CACHE_SAVE:
		cache_save(_head, &_exp, CACHE_FILE);
		_cfgval[i].next += _cfgval[i].v.tval;
		if (verbose) {
		    tprintf(("%s() %s next %s\n", __FUNCTION__, cfg_to_str(i),
			     timestr(_cfgval[i].next)));
		}
		break;
		
	    default:
		if (verbose) {
		    tprintf(("%s() Unexpected config timer in slot %d\n",
			     __FUNCTION__, i));
		}
		_cfgval[i].next = 0;
		continue;
	    }
	}
    }

    // schedule next alarm
    next_alarm();
}

// forward reference
static void
get_privkey(KMS_req_t *req, int mark, KMS_data_t *data, int *reason);

/**
 * Iterate through current list of client private keys and for those in
 * current use create the key that will be valid after the current key
 * expires.
 */
static void
precompute_keys(void)
{
    KMS_client_t	*c;
    KMS_priv_t		*p;
    KMS_req_t		my_req = {
	.req = { { .ptr = NULL, .len = 0 },
		 { .ptr = NULL, .len = 0 },
		 { .ptr = NULL, .len = 0 },
		 { .ptr = NULL, .len = 0 },
		 { .ptr = NULL, .len = 0 } } };
    KMS_data_t		my_data = { 0 };
    int			reason;
    int			i;
    
    for (c = _head; NULL != c; c = c->next) {
	for (p = c->cache; NULL != p; p = p->next) {
	    if ((! strcmp(p->expdate, _exp_s[KMS_EXPDATE])) && p->used) {

		// only filling in fields that get_privkey() uses
		my_req.req[KMS_req_other_id].ptr = c->client_id;
		my_req.req[KMS_req_topic_name].ptr = p->topic;
		my_req.req[KMS_req_exp_date].ptr = _exp_s[KMS_NEXTEXP];

		// using get_privkey() to avoid code duplication, generates
		// key as side-effect
		get_privkey(&my_req, 0, &my_data, &reason);
		// don't care about returned key data
		for (i = 0; i < my_data.num; i++) {
		    free(my_data.data[i].ptr);
		}
		
		if (KMS_REASON_SUCCESS != reason) {
		    if (verbose) {
			printf("Could not precompute key for %s,%s,%s\n",
			       p->topic, _exp_s[KMS_NEXTEXP], c->client_id);
		    }
		}
	    }
	}
    }
}

/**
 * Read configuration options from the config file. These values override
 * the default (on startup) or current (if reloaded) configuration values.
 *
 * Note: the value for CFG_PUB_EXPIRATION must be at least one day given
 * the requirement the Publishers check expiration dates at least daily. A
 * shorter value would mean that Publishers could miss expiration dates.
 */
static void
get_config_options(void)
{
    int		i;
    int		ival;
    time_t	tval;
    const char	*sval;
    int		minval = -1;
    // time_t	now = time((time_t *) 0);

    for (i = 0; i < NUM_CFGVALS; i++) {
	
	if (NULL == _cfgval[i].config) {
	    // this configurable option cannot be overridden
	    continue;
	}
	
	switch (_cfgval[i].type) {
	    
	case cfg_bool:
	    if (MASQ_STATUS_SUCCESS ==
		cfg_get_bool(_cfgval[i].config, &ival)) {
		_cfgval[i].v.bval = ival;

		if (verbose) {
		    printf("%s() %s -> %s\n", __FUNCTION__, _cfgval[i].config,
			   (ival ? "true" : "false"));
		}
	    }
	    break;
	    
	case cfg_time:
	    if (MASQ_STATUS_SUCCESS ==
		cfg_get_field(_cfgval[i].config, &sval)) {
		
		ival = cfg_time_translate((char *) sval);

		// PUB_EXPIRY must be >= SEC_DAY
		if ((ival > 0) &&
		    ((CFG_PUB_EXPIRATION != i) || (ival >= SEC_DAY))) {
		    _cfgval[i].v.tval = ival;

		    if (verbose) {
			printf("%s() %s -> %d\n", __FUNCTION__,
			       _cfgval[i].config, ival);
		    }

		    if ((0 > minval) || (ival < minval)) {
			minval = ival;
		    }
		}
	    }
	    break;

	case cfg_date:
	    if (MASQ_STATUS_SUCCESS ==
		cfg_get_field(_cfgval[i].config, &sval)) {

		if (0 <= (tval = cfg_date_parse((char *) sval))) {
		    _cfgval[i].v.tval = tval;

		    if (verbose) {
			printf("%s() %s -> %ld (%s)\n", __FUNCTION__,
			       _cfgval[i].config, tval, sval);
		    }
		}
	    }
	    break;
	    
	case cfg_string:
	    if (MASQ_STATUS_SUCCESS ==
		cfg_get_field(_cfgval[i].config, &sval)) {
		
		_cfgval[i].v.sval = sval;

		if (verbose) {
		    printf("%s() %s -> %s\n", __FUNCTION__,
			   _cfgval[i].config, _cfgval[i].v.sval);
		}
	    }
	    break;
	}
    }

    if (minval > 0) {
	// set alarm to go off <= twice per shortest time period
	_alarm_interval = minval / 2;
    }
}

/**
 * Initialize/update cache with client info from config file.
 * 
 * - add config clients into cache if needed
 * - verify existing cached clients against role specified in config file
 * - if non_cache_clients config is false, remove clients that don't appear
     in config file
 */
static void
add_clients_to_cache(KMS_client_t **head)
{
    int			n = 0;
    MASQ_status_t	rc;
    KMS_client_info_t	clnt;
    cache_status_t	status;
    KMS_client_t	*cp;

    while (MASQ_STATUS_SUCCESS == (rc = cfg_get_client_n(n++, &clnt))) {
	if (NULL == (cp = cache_find_client(*head, (char *) clnt.client_id,
					    &status))) {
	    // add this client to the cache
	    if (verbose) {
		printf("adding %s to cache\n", clnt.client_id);
	    }
	    cache_new_client(head, (char *) clnt.client_id, clnt.role, &status);
	} else {
	    // verify role
	    if (verbose) {
		printf("found %s [%c] in cache\n",
		       cp->client_id, cache_role_to_char(cp->role));
	    }
	    if (clnt.role != cp->role) {
		printf("%s role mismatch! cache: %c, config: %c\n",
		       clnt.client_id,
		       cache_role_to_char(cp->role),
		       cache_role_to_char(clnt.role));
	    }
	}
    }

    if (MASQ_ERR_NOT_FOUND != rc) {
	printf("%s() got %s from cfg_get_client_n(%d)\n",
	       __FUNCTION__, MASQ_status_to_str(rc), (n - 1));
    }

    if (! _cfgval[CFG_ALLOW_NC_CLIENTS].v.bval) {
	// remove clients not found in the config file

	if (verbose) {
	    printf("%s() looking for rogue clients...\n", __FUNCTION__);
	}

	// record client ids from config
	int	num_clients = n;
	char	*known = (char *) calloc(1, num_clients * MASQ_CLIENTID_LEN);
	
	for (n = 0; n < num_clients; n++) {
	    cfg_get_client_n(n, &clnt);
	    memcpy((void *) &known[n * MASQ_CLIENTID_LEN],
		   (void *) clnt.client_id, MASQ_CLIENTID_LEN);
	}

	// iterate through cache
	KMS_client_t	*c;
	int		found;
	int		done = 0;

	while (! done) {

	    done = 1;
	    
	    for (c = *head; NULL != c; c = c->next) {
		found = 0;
		for (n = 0; n < num_clients; n++) {
		    if (0 == memcmp((void *) &known[n * MASQ_CLIENTID_LEN],
				    (void *) c->client_id, MASQ_CLIENTID_LEN)) {
			found = 1;
			break;
		    }
		}
		if (! found) {
		    printf("removing rogue client %s from cache\n",
			   c->client_id);
		    cache_free_client(head, c);
		    done = 0;	// start over at the beginning
		    break;
		}
	    }
	}
	
	free(known);
    }
}

static const char	*_protoid = KMS_PROTO_ID;

// sized for updated shared parameters, more than needed with fixed sparms
#define	HASHIN_LEN	\
    (MASQ_CLIENTID_LEN + (2 * MASQ_EXPDATE_LEN) + MASQ_MAXTOPIC_LEN + 3)

static int	_timers_started = 0;

static octet		_s1, _s2, _s3;
static BB1_pksk		_PKSK = { .s1 = &_s1, .s2 = &_s2, .s3 = &_s3 };
static int		_PKSK_init = 0;

/**
 * Convenience function to express private key server keys as octets.
 */
static BB1_pksk *
get_PKSK(void)
{
    if (! _PKSK_init) {

	_s1.val = (char *) _params.p[KMS_shared_s1].ptr;
	_s1.len = _s1.max = (int) _params.p[KMS_shared_s1].len;
	_s2.val = (char *) _params.p[KMS_shared_s2].ptr;
	_s2.len = _s2.max = (int) _params.p[KMS_shared_s2].len;
	_s3.val = (char *) _params.p[KMS_shared_s3].ptr;
	_s3.len = _s3.max = (int) _params.p[KMS_shared_s3].len;
	
	_PKSK_init = 1;
    }

    return &_PKSK;
}

static octet		_R, _T, _V;
static BB1_pubparams	_PP = { .R = &_R, .T = &_T, .V = &_V };
static int		_PP_init = 0;

/**
 * Convenience function to express public parameters as octets.
 */
static BB1_pubparams *
get_PP(void)
{
    if (! _PP_init) {

	_R.val = (char *) _params.p[KMS_shared_R].ptr;
	_R.len = _R.max = (int) _params.p[KMS_shared_R].len;
	_T.val = (char *) _params.p[KMS_shared_R].ptr;
	_T.len = _T.max = (int) _params.p[KMS_shared_T].len;
	_V.val = (char *) _params.p[KMS_shared_R].ptr;
	_V.len = _V.max = (int) _params.p[KMS_shared_V].len;
	
	_PP_init = 1;
    }

    return &_PP;
}

/**
 * Get current time. Has side-effect of updating _expdate/_nextexp as needed.
 *
 * @param[out] nowbuf Buffer for current time string.
 * @param[in] nowbuf_len Length of nowbuf.
 */
static void
get_time(char *nowbuf,
	 size_t nowbuf_len)
{
    time_t	now, then;
    char	my_nowbuf[MASQ_EXPDATE_LEN + 1];

    now = time((time_t *) 0);
    cache_time_to_str(now, my_nowbuf);

    if ((NULL != nowbuf) && (nowbuf_len > MASQ_EXPDATE_LEN)) {
	strcpy(nowbuf, my_nowbuf);
    }

    if ((MASQ_EXPDATE_LEN != strlen(_exp_s[KMS_EXPDATE])) ||
	(strcmp(_exp_s[KMS_EXPDATE], my_nowbuf) < 0)) {
	
	// first time called or need to generate/update both
	then = now + _cfgval[CFG_PUB_EXPIRATION].v.tval;
	then -= ((now - _cfgval[CFG_PUB_EPOCH].v.tval) %
		 _cfgval[CFG_PUB_EXPIRATION].v.tval);
	_exp.expdate = then;
	cache_time_to_str(_exp.expdate, _exp_s[KMS_EXPDATE]);
	
	then += _cfgval[CFG_PUB_EXPIRATION].v.tval;
	_exp.nextexp = then;
	cache_time_to_str(_exp.nextexp, _exp_s[KMS_NEXTEXP]);
    }

    if (! _timers_started) {
	
	_cfgval[CFG_PUB_EXPIRATION].next = _exp.expdate;
	if (verbose) {
	    tprintf(("%s() setting PUB_EXPIRY to %s\n", __FUNCTION__,
		     timestr(_cfgval[CFG_PUB_EXPIRATION].next)));
	}
	
	if (_cfgval[CFG_DO_PRECOMPUTE].v.bval &&
	    _cfgval[CFG_PRECOMPUTE_KEYS].v.tval) {
	    // set timer to precompute before next expiration
	    _cfgval[CFG_PRECOMPUTE_KEYS].next =
		_cfgval[CFG_PUB_EXPIRATION].next -
		_cfgval[CFG_PRECOMPUTE_KEYS].v.tval;
	    if (verbose) {
		tprintf(("%s() setting PRECOMPUTE_KEYS to %s\n", __FUNCTION__,
			 timestr(_cfgval[CFG_PRECOMPUTE_KEYS].next)));
	    }
	}
	
	_timers_started = 1;
    }
}

/**
 * Get private key according to values in request.
 *
 * Returns key from cache if found there, else determines the key and
 * adds it to the cache for future use.
 *
 * @param[in] req Request fields from PRIVREQ packet.
 * @param[in] mark Mark as used? Not set when precomputing keys.
 * @param[out] data Private key data. Note: ptr fields in data are
 *   calloc()ed and should be free()d when able.
 * @param[out] reason KMS reason code (KMS_REASON_SUCCESS or error).
 */
static void
get_privkey(KMS_req_t *req,
	    int mark,
	    KMS_data_t *data,
	    int *reason)
{
    KMS_client_t	*c;
    KMS_priv_t		*p;
    cache_status_t	status;
    KMS_data_t		my_data;
    int			i;

    char		id_buf[HASHIN_LEN];
    octet		ID;
    BB1_puk		*PUK = NULL;
    MASQ_status_t	rc;
    
    *reason = KMS_REASON_SUCCESS;

    if (NULL == (c = cache_find_client(_head,
				       req->req[KMS_req_other_id].ptr,
				       &status))) {

	if (_cfgval[CFG_ALLOW_NC_CLIENTS].v.bval) {

	    if (verbose > 1) {
		printf("cache_find_client(%s) not found, adding\n",
		       req->req[KMS_req_other_id].ptr);
	    }
	    // won't find a priv key, but need to add client so
	    // cache_find_privkey() doesn't fail
	    c = cache_new_client(&_head,
				 req->req[KMS_req_other_id].ptr,
				 MASQ_role_publisher,	// ??? provisional
				 &status);
	} else {
	    if (verbose > 1) {
		printf("cache_find_client(%s) not found, returning\n",
		       req->req[KMS_req_other_id].ptr);
	    }
	    data->num = 0;
	    *reason = KMS_REASON_CLIENTID_ERR;
	    return;
	}
    }

    // look for privkey in the cache
    if (NULL != (p = cache_find_privkey(_head,
					req->req[KMS_req_other_id].ptr,
					req->req[KMS_req_topic_name].ptr,
					req->req[KMS_req_exp_date].ptr,
					&status))) {
	if (verbose > 1) {
	    printf("cache_find_privkey(%s,%s,%s) found in cache\n",
		   req->req[KMS_req_other_id].ptr,
		   req->req[KMS_req_topic_name].ptr,
		   req->req[KMS_req_exp_date].ptr);
	}

	p->used = 1;
	data->num = p->key.num;
	for (i = 0; i < p->key.num; i++) {
	    data->data[i].len = p->key.data[i].len;
	    data->data[i].ptr = p->key.data[i].ptr;
	}

	return;
    }
    
    if (verbose > 1) {
	printf("cache_find_privkey(%s,%s,%s) not in cache\n",
	       req->req[KMS_req_other_id].ptr,
	       req->req[KMS_req_topic_name].ptr,
	       req->req[KMS_req_exp_date].ptr);
    }
	
    // determine privkey and add to the cache
    //
    snprintf(id_buf, sizeof(id_buf), "%s:%s:%s",
	     req->req[KMS_req_topic_name].ptr,
	     req->req[KMS_req_exp_date].ptr,
	     req->req[KMS_req_other_id].ptr);
    ID.val = id_buf;
    ID.len = ID.max = strlen(id_buf);
    if (NULL == (PUK = BB1_puk_new(BBFS_BN254))) {
	*reason = KMS_ERR_NOMEM;
	return;
    }

    if (MASQ_STATUS_SUCCESS !=
	(rc = BB1G_BN254_extract(get_PP(), get_PKSK(), &ID, PUK))) {
	tprintf(("%sBB1G_BN254_extract ret %s%s\n",
		 _E, MASQ_status_to_str(rc), _X));
	*reason = KMS_ERR_CRYPTO;
	return;
    }
	
    my_data.num = 2;
    my_data.data[0].ptr = (void *) calloc(1, PUK->K0M->len);
    my_data.data[1].ptr = (void *) calloc(1, PUK->K1M->len);
    if ((NULL == my_data.data[0].ptr) || (NULL == my_data.data[1].ptr)) {
	*reason = KMS_ERR_NOMEM;
	BB1_puk_free(PUK);
	return;
    }
    memcpy((void *) my_data.data[0].ptr,
	   (void *) PUK->K0M->val, (size_t) PUK->K0M->len);
    my_data.data[0].len = (int) PUK->K0M->len;
    
    memcpy((void *) my_data.data[1].ptr,
	   (void *) PUK->K1M->val, (size_t) PUK->K1M->len);
    my_data.data[1].len = (int) PUK->K1M->len;
    
    p = cache_new_privkey(_head,
			  req->req[KMS_req_other_id].ptr,
			  req->req[KMS_req_topic_name].ptr,
			  req->req[KMS_req_exp_date].ptr,
			  &my_data,
			  &status);

    p->used = mark ? 1 : 0;
    data->num = my_data.num;
    for (i = 0; i < my_data.num; i++) {
	data->data[i].len = my_data.data[i].len;
	data->data[i].ptr = my_data.data[i].ptr;
    }

    BB1_puk_free(PUK);
}

/**
 * Look up Client in cache and determine its role.
 *
 * @param[in] client_id Client ID of the Client in question.
 * @return role Client role, MASQ_role_none if not found in cache.
 */
static MASQ_role_t
get_role(char *client_id)
{
    KMS_client_t	*c;
    cache_status_t	status;

    if (NULL == (c = cache_find_client(_head, client_id, &status))) {

	if (verbose > 1) {
	    printf("%s(%s) not found\n", __FUNCTION__, client_id);
	}
	return MASQ_role_none;
    }

    return c->role;
}

static char	*_msg_types[] = {
    NULL,
    "TIMEREQ", "TIMERESP",
    "PUBREQ",  "PUBRESP",
    "PRIVREQ", "PRIVRESP"
};

/**
 * Create a response packet when reason is not KMS_REASON_SUCCESS.
 * Called by process_packet().
 *
 * @param[in] msg Mesage type, one of KMS_TIMERESP, KMS_PUBRESP, KMS_PRIVRESP.
 * @param[in] reason KMS reason.
 * @param[in] message Optional message ('\0'-terminated string).
 * @param[out] outbuf Buffer to receive response packet.
 * @param[in,out] outlen Available space in outbuf on input,
 *   space used on output.
 */
static void
make_error_packet(int msg, int reason, char *message,
		  void **outbuf, size_t *outlen)
{
    void	*obuf = NULL;
    size_t	olen =  KMS_ERROR_RESP_PKT_LEN;
    int		rc;

    tprintf(("send %s%s%s %s%s%s\n",
	     _E, _msg_types[msg], _X, _W, KMS_reason_string(reason), _X));
    if (verbose) {
	if (message) {
	    tprintf(("%s(%s, %s, [%s])\n", __FUNCTION__,
		     _msg_types[msg], KMS_reason_string(reason), message));
	} else {
	    tprintf(("%s(%s, %s)\n", __FUNCTION__,
		     _msg_types[msg], KMS_reason_string(reason)));
	}
    }

    *outbuf = NULL;
    *outlen = 0;
    if ((NULL != message) && strlen(message)) {
	olen += 3 + strlen(message);
    }

    obuf = calloc(1, olen);
    
    switch (msg) {
	
    case KMS_TIMERESP:
	if (KMS_ERR_SUCCESS != (rc = KMS_make_timeresp(reason, NULL, message,
						       obuf, &olen))) {
	    tprintf(("%s():%d %sKMS_make_timeresp() ret %s%s\n",
		     __FUNCTION__, __LINE__-2, _E, KMS_error_string(rc), _X));
	    free(obuf);
	    return;
	}
	break;
	
    case KMS_PUBRESP:
	if (KMS_ERR_SUCCESS != (rc = KMS_make_pubresp(reason, NULL, message,
						      obuf, &olen))) {
	    tprintf(("%s():%d %sKMS_make_pubresp() ret %s%s\n",
		     __FUNCTION__, __LINE__-2, _E, KMS_error_string(rc), _X));
	    free(obuf);
	    return;
	}
	break;
	
    case KMS_PRIVRESP:
	if (KMS_ERR_SUCCESS != (rc = KMS_make_privresp(reason, NULL, message,
						       obuf, &olen))) {
	    tprintf(("%s():%d %sKMS_make_privresp() ret %s%s\n",
		     __FUNCTION__, __LINE__-2, _E, KMS_error_string(rc), _X));
	    free(obuf);
	    return;
	}
	break;
    }
    
    *outbuf = obuf;
    *outlen = olen;
}

/**
 * Process a *REQ packet, the guts of KMS processing.
 *
 * @param[in] inbuf Received request data.
 * @param[in] inlen Length of received data.
 * @param[out] outbuf Response data to return to Client. Note: *outbuf is
 *   calloc()ed and should be free()d when able.
 * @param[in,out] outlen Available space in outbuf on input,
 *   space used on output.
 */
static void
process_packet(void *inbuf, size_t inlen,
	       void **outbuf, size_t *outlen)
{
    size_t	i;
    void	*obuf = NULL;
    size_t	olen;
    int		rc;
    MASQ_role_t	role;
    int		reason;

    KMS_req_t	kreq;
    KMS_time_t	ktime;
    KMS_data_t	kdata;
    int		parm_idx[KMS_data_num_fields] =
	{ KMS_shared_R, KMS_shared_T, KMS_shared_V };

    char	messagebuf[128] = { 0 };

    char	kreqbuf[KMS_req_num_fields][MASQ_MAXTOPIC_LEN];

    char	times[KMS_time_num_fields][MASQ_EXPDATE_LEN + 1];

    *outbuf = NULL;
    *outlen = 0;

    kms_add_entropy();	// builds up entropy for random number generation
    
    if (verbose) {
	printf("%s(%02x)\n", __FUNCTION__, ((unsigned char *) inbuf)[0]);
    }

    // initialze kreq to receive output
    memset((void *) kreqbuf, 0, sizeof(kreqbuf));
    for (i = 0; i < KMS_req_num_fields; i++) {
	kreq.req[i].ptr = (void *) &kreqbuf[i];
	kreq.req[i].len = sizeof(kreqbuf[i]);
    }
    
    switch (((unsigned char *) inbuf)[0]) {
	
    case KMS_TIMEREQ:
	
	if (KMS_ERR_SUCCESS !=
	    (rc = KMS_parse_timereq((unsigned char *) inbuf, inlen, &kreq))) {
	    // create error packet to return
	    if (verbose) {
		tprintf(("%4d %s%s%s\n", __LINE__+3,
			 _E, KMS_reason_string(KMS_REASON_ERR), _X));
	    }
	    make_error_packet(KMS_TIMERESP, KMS_REASON_ERR,
			      NULL, // message
			      outbuf, outlen);
	    return;
	}

	tprintf(("recv %sTIMEREQ%s %s\n", _I, _X,
		 kreq.req[KMS_req_client_id].ptr));

	if (verbose) {
	    KMS_pkt_dump_req(&kreq, "<KMS> KMS_TIMEREQ");
	}

	// check Proto ID
	if ((NULL == kreq.req[KMS_req_proto_id].ptr) ||
	    (strncmp(kreq.req[KMS_req_proto_id].ptr,
		     _protoid, strlen(_protoid) + 1))) {
	    if (verbose) {
		printf("[%s] != [%s] %lu\n",
		       kreq.req[KMS_req_proto_id].ptr, _protoid,
		       strlen(_protoid) + 1);
		tprintf(("%4d %s%s%s\n", __LINE__+3,
			 _E, KMS_reason_string(KMS_REASON_PROTO_ERR), _X));
	    }
	    make_error_packet(KMS_TIMERESP, KMS_REASON_PROTO_ERR,
			      NULL, // message
			      outbuf, outlen);
	    return;
	}

	// check Client ID
	if (MASQ_role_none ==
	    (role = get_role(kreq.req[KMS_req_client_id].ptr))) {
	    if (verbose) {
		tprintf(("%4d %s%s%s\n", __LINE__+3,
			 _E, KMS_reason_string(KMS_REASON_CLIENTID_ERR), _X));
	    }
	    make_error_packet(KMS_TIMERESP, KMS_REASON_CLIENTID_ERR,
			      "Who are you?", // message
			      outbuf, outlen);
	    return;
	}

	// initialize times struct
	for (i = 0; i < KMS_time_num_fields; i++) {
	    ktime.time[i].ptr = times[i];
	    ktime.time[i].len = 0;
	    times[i][0] = '\0';
	}
	
	// do stuff ...
	strcpy(messagebuf, "This is a timeresp packet");
	olen = (KMS_time_num_fields * (MASQ_EXPDATE_LEN + 3)) + 8;
	olen += strlen(messagebuf) + 3;
	obuf = calloc(1, olen);
	if (NULL == obuf) {
	    fprintf(stderr, "%s", _W);
	    perror("calloc");
	    fprintf(stderr, "%s", _X);
	    return;
	}

	get_time(times[KMS_time_cur], sizeof(times[KMS_time_cur]));
	if (MASQ_role_subscriber != role) {
	    strcpy(times[KMS_time_exp_date], _exp_s[KMS_EXPDATE]);
	    strcpy(times[KMS_time_next_exp], _exp_s[KMS_NEXTEXP]);
	}
	
	if (verbose) {
	    KMS_pkt_dump_time(&ktime, "<KMS> KMS_make_timeresp");
	} else {
	    tprintf(("send %sTIMERESP%s\n", _I, _X));
	}
	
	if (KMS_ERR_SUCCESS !=
	    (rc = KMS_make_timeresp(KMS_REASON_SUCCESS, &ktime,
				    messagebuf, // message
				    obuf, &olen))) {
	    if (verbose) {
		tprintf(("%4d %s%s%s\n", __LINE__+3,
			 _E, KMS_reason_string(KMS_REASON_PROTO_ERR), _X));
	    }
	    make_error_packet(KMS_TIMERESP, KMS_REASON_PROTO_ERR,
			      NULL, // message
			      outbuf, outlen);
	    return;
	}
	*outbuf = obuf;
	*outlen = olen;
	break;

    case KMS_PUBREQ:
	
	if (KMS_ERR_SUCCESS !=
	    (rc = KMS_parse_pubreq((unsigned char *) inbuf, inlen, &kreq))) {
	    if (verbose) {
		printf("dead at %d\n", __LINE__); fflush(stdout);
	    }
	    // create error packet to return
	    if (verbose) {
		tprintf(("%4d %s%s%s\n", __LINE__+3,
			 _E, KMS_reason_string(KMS_REASON_ERR), _X));
	    }
	    make_error_packet(KMS_PUBRESP, KMS_REASON_ERR,
			      NULL, // message
			      outbuf, outlen);
	    return;
	}

	tprintf(("recv %sPUBREQ%s %s\n", _I, _X,
		 kreq.req[KMS_req_client_id].ptr));
	
	if (verbose) {
	    KMS_pkt_dump_req(&kreq, "<KMS> KMS_PUBREQ");
	}

	// check Proto ID
	if ((NULL == kreq.req[KMS_req_proto_id].ptr) ||
	    (strncmp(kreq.req[KMS_req_proto_id].ptr,
		     _protoid, strlen(_protoid) + 1))) {
	    if (verbose) {
		printf("[%s] != [%s] %lu\n",
		       kreq.req[KMS_req_proto_id].ptr, _protoid,
		       strlen(_protoid) + 1);
	    }
	    if (verbose) {
		tprintf(("%4d %s%s%s\n", __LINE__+3,
			 _E, KMS_reason_string(KMS_REASON_PROTO_ERR), _X));
	    }
	    make_error_packet(KMS_PUBRESP, KMS_REASON_PROTO_ERR,
			      NULL, // message
			      outbuf, outlen);
	    return;
	}

	// check Client ID
	if (MASQ_role_none ==
	    (role = get_role(kreq.req[KMS_req_client_id].ptr))) {
	    if (verbose) {
		tprintf(("%4d %s%s%s\n", __LINE__+3,
			 _E, KMS_reason_string(KMS_REASON_CLIENTID_ERR), _X));
	    }
	    make_error_packet(KMS_PUBRESP, KMS_REASON_CLIENTID_ERR,
			      NULL, // message
			      outbuf, outlen);
	    return;
	}

	// check if requesting client is authorized to make
	// this request and/or how much information to return
	if (MASQ_role_subscriber == role) {
	    if (verbose) {
		tprintf(("%4d %s%s%s\n", __LINE__+3,
			 _E, KMS_reason_string(KMS_REASON_UNAUTH_REQ_ERR), _X));
	    }
	    make_error_packet(KMS_PUBRESP, KMS_REASON_UNAUTH_REQ_ERR,
			      NULL, // message
			      outbuf, outlen);
	    return;
	}
	
	olen = 0;
	// zero out times struct
	for (i = 0; i < KMS_time_num_fields; i++) {
	    ktime.time[i].ptr = times[i];
	    ktime.time[i].len = 0;
	    times[i][0] = '\0';
	}
	// return public parameters
	for (i = 0; i < KMS_data_num_fields; i++) {
	    kdata.data[i].ptr = _params.p[parm_idx[i]].ptr;
	    kdata.data[i].len = _params.p[parm_idx[i]].len;
	    olen += (kdata.data[i].len + 2);
	}
	kdata.num = i;

	strcpy(messagebuf, "This is a pubresp packet");
	olen += strlen(messagebuf) + 3;
	olen += 16;	// elbow room for packet overhead
	obuf = calloc(1, olen);
	if (NULL == obuf) {
	    fprintf(stderr, "%s", _W);
	    perror("calloc");
	    fprintf(stderr, "%s", _X);
	    return;
	}

	if (verbose) {
	    KMS_pkt_dump_data(&kdata, "<KMS> KMS_make_pubresp");
	} else {
	    tprintf(("send %sPUBRESP%s\n", _I, _X));
	}
	
	if (KMS_ERR_SUCCESS !=
	    KMS_make_pubresp(KMS_REASON_SUCCESS, &kdata,
			     messagebuf, // message
			     obuf, &olen)) {
	    free(obuf);
	    return;
	}
	
	*outbuf = obuf;
	*outlen = olen;
	break;

    case KMS_PRIVREQ:
	
	if (KMS_ERR_SUCCESS !=
	    (rc = KMS_parse_privreq((unsigned char *) inbuf, inlen, &kreq))) {
	    // create error packet to return
	    if (verbose) {
		tprintf(("%4d %s%s%s\n", __LINE__+3,
			 _E, KMS_reason_string(KMS_REASON_ERR), _X));
	    }
	    make_error_packet(KMS_PRIVRESP, KMS_REASON_ERR,
			      NULL, // message
			      outbuf, outlen);
	    return;
	}

	tprintf(("recv %sPRIVREQ%s %s %s\n", _I, _X,
		 kreq.req[KMS_req_client_id].ptr,
		 kreq.req[KMS_req_topic_name].ptr));
	    
	if (verbose) {
	    KMS_pkt_dump_req(&kreq, "<KMS> KMS_PRIVREQ");
	}

	// check Proto ID
	if ((NULL == kreq.req[KMS_req_proto_id].ptr) ||
	    (strncmp(kreq.req[KMS_req_proto_id].ptr,
		       KMS_PROTO_ID, sizeof(KMS_PROTO_ID)))) {
	    if (verbose) {
		tprintf(("%4d %s%s%s\n", __LINE__+3,
			 _E, KMS_reason_string(KMS_REASON_PROTO_ERR), _X));
	    }
	    make_error_packet(KMS_PRIVRESP, KMS_REASON_PROTO_ERR,
			      NULL, // message
			      outbuf, outlen);
	    return;
	}

	// check Client ID
	if (MASQ_role_none ==
	    (role = get_role(kreq.req[KMS_req_client_id].ptr))) {
	    if (verbose) {
		tprintf(("%4d %s%s%s\n", __LINE__+3,
			 _E, KMS_reason_string(KMS_REASON_CLIENTID_ERR), _X));
	    }
	    make_error_packet(KMS_PRIVRESP, KMS_REASON_CLIENTID_ERR,
			      "Who are you?", // message
			      outbuf, outlen);
	    return;
	}

	// check if requesting client is authorized to make this request
	if (MASQ_role_publisher == role) {
	    if (verbose) {
		tprintf(("%4d %s%s%s\n", __LINE__+3,
			 _E, KMS_reason_string(KMS_REASON_UNAUTH_REQ_ERR), _X));
	    }
	    make_error_packet(KMS_PRIVRESP, KMS_REASON_UNAUTH_REQ_ERR,
			      "Publishers prohibited", // message
			      outbuf, outlen);
	    return;
	}
	
	for (i = KMS_req_client_id; i < KMS_req_topic_name; i++) {
#if MASQ_CLIENTID_LEN != MASQ_EXPDATE_LEN
	    // the following takes advantage of the fact that
	    // MASQ_CLIENTID_LEN == MASQ_EXPDATE_LEN; if these change this
	    // will break
#error "Code needs updating!"
#endif
	    if ((NULL == kreq.req[i].ptr) ||
		(MASQ_CLIENTID_LEN != strlen(kreq.req[i].ptr))) {
		if (verbose) {
		    tprintf(("%4d %s%s%s\n", __LINE__+3,
			     _E, KMS_reason_string(KMS_REASON_ERR), _X));
		}
		make_error_packet(KMS_PRIVRESP, KMS_REASON_ERR,
				  NULL, // message
				  outbuf, outlen);
		return;
	    }
	}

	if (NULL == kreq.req[KMS_req_topic_name].ptr) {
	    if (verbose) {
		tprintf(("%4d %s%s%s\n", __LINE__+3,
			 _E, KMS_reason_string(KMS_REASON_ERR), _X));
	    }
	    make_error_packet(KMS_PRIVRESP, KMS_REASON_ERR,
			      NULL, // message
			      outbuf, outlen);
	    return;
	}

	// check for a cached private key value to avoid calculating it again
	get_privkey(&kreq, 1, &kdata, &reason);

	if (KMS_REASON_SUCCESS != reason) {
	    // invalid Client
	    if (verbose) {
		tprintf(("%4d %s%s%s\n", __LINE__+3,
			 _E, KMS_reason_string(reason), _X));
	    }
	    make_error_packet(KMS_PRIVRESP, reason,
			      "I don't know you", // message
			      outbuf, outlen);
	    return;
	}

	strcpy(messagebuf, "This is a privresp packet");
	olen = kdata.data[0].len + kdata.data[1].len + 4 /*Bin len*/ +
	    strlen(messagebuf) + (strlen(messagebuf) ? 3 : 0) +
	    16;	// elbow room for packet overhead
	obuf = calloc(1, olen);
	if (NULL == obuf) {
	    fprintf(stderr, "%s", _W);
	    perror("calloc");
	    fprintf(stderr, "%s", _X);
	    return;
	}

	if (verbose) {
	    KMS_pkt_dump_data(&kdata, "<KMS> KMS_make_privresp");
	} else {
	    tprintf(("send %sPRIVRESP%s\n", _I, _X));
	}

	if (KMS_ERR_SUCCESS !=
	    KMS_make_privresp(KMS_REASON_SUCCESS, &kdata,
			      messagebuf, // message
			      obuf, &olen)) {
	    free(obuf);
	    return;
	}
	
	*outbuf = obuf;
	*outlen = olen;
	break;

    default:
	tprintf(("Unrecognized packet type: %02x\n",
		 ((unsigned char *) inbuf)[0]));
	break;
    }
}

//*// static int	_poll_cnt = 0;
//*// static char	*_poll[] = {
//*//     "+", "X", "+", "X", "+", "X", "+", "X", "+", "X", "+", "X", // pattern
//*//     ".", "o", "O", "o", ".", "o", "O", "o", ".", "o", "O", "o", // ----
//*//     "-", "=", "-", "=", "-", "=", "-", "=", "-", "=", "-", "=", // ----
//*//     "|", ">", "\u2014", ">", "|", "<", "\u2014", "<", // ----
//*//     "|", ">", "\u2014", ">", "|", "<", "\u2014", "<",
//*//     "|", ">", "\u2014", ">", "|", "<", "\u2014", "<",
//*//     "|", ">", "|", "<", "|", ">", "|", "<", "|", ">", "|", "<", // ----
//*//     "\u2059", "\u205c", "\u2059", "\u205c", // ----
//*//     "\u2059", "\u205c", "\u2059", "\u205c",
//*//     "\u2059", "\u205c", "\u2059", "\u205c",
//*//     "\u2059", "\u2058", "\u2059", "\u2058", // ----
//*//     "\u2059", "\u2058", "\u2059", "\u2058",
//*//     "\u2059", "\u2058", "\u2059", "\u2058",
//*//     "\u205b", "\u2058", "\u205b", "\u2058", // ----
//*//     "\u205b", "\u2058", "\u205b", "\u2058",
//*//     "\u205b", "\u2058", "\u205b", "\u2058",
//*//     "A", ">", "V", "<", "A", ">", "V", "<", "A", ">", "V", "<", // ----
//*//     "V", ">", "A", "<", "V", ">", "A", "<", "V", ">", "A", "<", // ----
//*//     "b", "d", "q", "p", "b", "d", "q", "p", "b", "d", "q", "p", // ----
//*//     "\u2014", "\\","|", "/", // ----
//*//     "\u2014", "\\","|", "/",
//*//     "\u2014", "\\","|", "/",
//*//     "\u2014", "/","|", "\\", // ----
//*//     "\u2014", "/","|", "\\",
//*//     "\u2014", "/","|", "\\",
//*//     "\u2058", "\u205b", "\u2058", "\u2059", "\u205c", "\u2059", // ----
//*//     "\u2058", "\u205b", "\u2058", "\u2059", "\u205c", "\u2059",
//*//     "\u2058", "\u205b", "\u2058", "\u2059", "\u205c", "\u2059",
//*// };
//*// static int	_poll_sz = (sizeof(_poll)/sizeof(_poll[0]));

static unsigned char	_recv_buf[4 * 1024];	// overkill

char		*_kms_host = "127.0.0.1";	// localhost

#if 0
// https://github.com/wolfSSL/wolfssl-examples/tls/server-tls-verifycallback.c
static int
myVerifyCb(int preverify, WOLFSSL_X509_STORE_CTX *store)
{
    char		buffer[WOLFSSL_MAX_ERROR_SZ];
#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
    WOLFSSL_X509	*peer;
#if defined(SHOW_CERTS) && !defined(NO_FILESYSTEM)
    WOLFSSL_BIO		*bio = NULL;
    WOLFSSL_STACK	*sk = NULL;
    X509		*x509 = NULL;
    int			i = 0;
#endif
#endif
    (void)preverify;
    printf("preverify = %d\n", preverify);
    preverify = 1;

    /* Verify Callback Arguments:
     * preverify:           1=Verify Okay, 0=Failure
     * store->error:        Failure error code (0 indicates no failure)
     * store->current_cert: Current WOLFSSL_X509 object (only with OPENSSL_EXTRA)
     * store->error_depth:  Current Index
     * store->domain:       Subject CN as string (null term)
     * store->totalCerts:   Number of certs presented by peer
     * store->certs[i]:     A `WOLFSSL_BUFFER_INFO` with plain DER for each cert
     * store->store:        WOLFSSL_X509_STORE with CA cert chain
     * store->store->cm:    WOLFSSL_CERT_MANAGER
     * store->ex_data:      The WOLFSSL object pointer
     * store->discardSessionCerts: When set to non-zero value session certs
        will be discarded (only with SESSION_CERTS)
     */

    printf("In verification callback, error = %d, %s\n", store->error,
	   wolfSSL_ERR_error_string(store->error, buffer)); fflush(stdout);
#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
    peer = store->current_cert;
    if (peer) {
        char	*issuer =
	    wolfSSL_X509_NAME_oneline(wolfSSL_X509_get_issuer_name(peer),0,0);
        char	*subject =
	    wolfSSL_X509_NAME_oneline(wolfSSL_X509_get_subject_name(peer),0 0);
        printf("\tPeer's cert info:\n issuer : %s\n subject: %s\n",
	       issuer, subject);
        XFREE(subject, 0, DYNAMIC_TYPE_OPENSSL);
        XFREE(issuer,  0, DYNAMIC_TYPE_OPENSSL);
#if defined(SHOW_CERTS) && !defined(NO_FILESYSTEM)
	/* avoid printing duplicate certs */
        if (store->depth == 1) {
            /* retrieve x509 certs and display them on stdout */
            sk = wolfSSL_X509_STORE_GetCerts(store);

            for (i = 0; i < wolfSSL_sk_X509_num(sk); i++) {
                x509 = wolfSSL_sk_X509_value(sk, i);
                bio = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
                if (bio != NULL) {
                    wolfSSL_BIO_set_fp(bio, stdout, BIO_NOCLOSE);
                    wolfSSL_X509_print(bio, x509);
                    wolfSSL_BIO_free(bio);
                }
            }
            wolfSSL_sk_X509_free(sk);
        }
#endif
    } else {
        printf("\tPeer has no cert!\n"); fflush(stdout);
    }
#else
    printf("\tPeer certs: %d\n", store->totalCerts); fflush(stdout);
    //#ifdef SHOW_CERTS
    {
	int	i;
        for (i = 0; i < store->totalCerts; i++) {
            WOLFSSL_BUFFER_INFO* cert = &store->certs[i];
            printf("\t\tCert %d: Ptr %p, Len %u\n",
		   i, cert->buffer, cert->length); fflush(stdout);
        }
    }
    //#endif /* SHOW_CERTS */
#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */

    printf("\tSubject's domain name at %d is %s\n",
	   store->error_depth, store->domain); fflush(stdout);

    /* If error indicate we are overriding it for testing purposes */
    if (store->error != 0) {
        printf("\tAllowing failed certificate check, testing only "
	       "(shouldn't do this in production)\n"); fflush(stdout);
    }

    /* A non-zero return code indicates failure override */
    return preverify;
}
#endif

// global wolfSSL-related stuff
static int		_tls_init = 0;
static WOLFSSL_CTX	*_tls_ctx = NULL;
static int		_listenfd = (-1);

/**
 * Initialize wolfSSL and network socket.
 *
 * @param[in] addr KMS IP address to bind to.
 * @param[in] addr KMS TCP port to bind to.
 * @param[in] certfile KMS TLS certificate file.
 * @param[in] keyfile KMS TLS key file.
 * @param[in] cafile Trusted CA's certificate file.
 * @return 0 on success, else error.
 */
static int
initialize_tls(char *addr, int port,
	       char *certfile, char *keyfile, char *cafile)
{
    int			ret = 0;
    int			yes = 1;
    struct sockaddr_in	kms_inetaddr;

    if (_tls_init) {
	return 0;
    }

    tprintf(("%s(%s, %d)\n", __FUNCTION__, addr, port));

    wolfSSL_Init();

    // create and initialize WOLFSSL_CTX
    if (NULL == (_tls_ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method()))) {
	tprintf(("%snet> WOLFSSL_CTX creation failed%s\n", _E, _X));
	_running = 0;
	return 1;
    }

    // load trusted certificates
    if (WOLFSSL_SUCCESS !=
	(ret = wolfSSL_CTX_load_verify_locations(_tls_ctx, cafile, NULL))) {
	tprintf(("%sERROR: Can not load CA file %s (ret = %d)%s\n",
		 _E, cafile, ret, _X));
	_running = 0;
	goto init_errout;
    }

    // server certificate(s)
    if (WOLFSSL_SUCCESS !=
	(ret = wolfSSL_CTX_use_certificate_file(_tls_ctx,
						certfile,
						WOLFSSL_FILETYPE_PEM))) {
	tprintf(("%sERROR: Can not load cert file %s (ret = %d)%s\n",
		 _E, certfile, ret, _X));
	_running = 0;
	goto init_errout;
    }

    // server key
    if (WOLFSSL_SUCCESS !=
	(ret = wolfSSL_CTX_use_PrivateKey_file(_tls_ctx, keyfile,
					       WOLFSSL_FILETYPE_PEM))) {
	tprintf(("%sERROR: Can not load key file %s (ret = %d)%s\n",
		 _E, keyfile, ret, _X));
	_running = 0;
	goto init_errout;
    }

#if	0
    // require Client certificate and verify all peers
    wolfSSL_CTX_set_verify(_tls_ctx, WOLFSSL_VERIFY_PEER, myVerifyCb);
#endif

    _listenfd = socket(AF_INET, SOCK_STREAM, 0);

    if ((_listenfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
	tprintf(("%snet> socket creation failed, errno = %s%s\n",
		 _E, strerror(errno), _X));
	_running = 0;
	goto init_errout;
    }
#if 0
    if (fcntl(_listenfd, F_SETFL, O_NONBLOCK)) {
	tprintf(("%snet> fcntl(O_NONBLOCK) failed, errno = %s%s\n",
		 _E, strerror(errno), _X));
	_running = 0;
	goto init_errout;
    }
#endif
    if (setsockopt(_listenfd, SOL_SOCKET,
		   SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
	tprintf(("%snet> setsockopt(SO_REUSEADDR) failed, errno = %s%s\n",
		 _E, strerror(errno), _X));
	_running = 0;
	goto init_errout;
    }

    // might be overkill
    if (setsockopt(_listenfd, SOL_SOCKET, SO_REUSEPORT,
		   &yes, sizeof(yes)) < 0) {
	tprintf(("%snet> setsockopt(SO_REUSEPORT) failed, errno = %s%s\n",
		 _E, strerror(errno), _X));
	_running = 0;
	goto init_errout;
    }

    // fill in the server address
    memset(&kms_inetaddr, 0, sizeof(kms_inetaddr));
    kms_inetaddr.sin_family = AF_INET;
    if (! inet_pton(AF_INET, addr, (struct in_addr *) &kms_inetaddr.sin_addr)) {
	tprintf(("%snet> Bad addr %s%s\n", _E, addr, _X));
	_running = 0;
	goto init_errout;
    }
    kms_inetaddr.sin_port = htons(port);

    // bind the server socket to the port
    if (bind(_listenfd, (struct sockaddr *) &kms_inetaddr,
	     sizeof(kms_inetaddr)) == -1) {
	tprintf(("%snet> bind failed, errno = %s%s\n",
		 _E, strerror(errno), _X));
	_running = 0;
	goto init_errout;
    }

    // listen for new connection, allowing up to 16
    if (listen(_listenfd, 16) == -1) {
	tprintf(("%snet> listen failed, errno = %s%s\n",
		 _E, strerror(errno), _X));
	_running = 0;
	goto init_errout;
    }

    _tls_init = 1;
    return 0;
    
 init_errout:
    if (_tls_ctx) {
	wolfSSL_CTX_free(_tls_ctx);
	_tls_ctx = NULL;
    }
    if (_listenfd >= 0) {
	close(_listenfd);
	_listenfd = (-1);
    }
    wolfSSL_Cleanup();
    return 1;
}

/**
 * Handle KMS requests.
 */
static void
handle_request(void)
{
    void		*outbuf;
    size_t		outlen;
    int			n;

    int			ret = 0;
    WOLFSSL		*ssl = NULL;
    int			clientfd;
    struct sockaddr_in	client_inetaddr;
    socklen_t		client_len = sizeof(client_inetaddr);
    char		addrbuf[32];

    if (! _running) return;

    if (! _tls_init) {
	tprintf(("%snet> must call initialize_tls() before %s()%s\n",
		 _E, __FUNCTION__, _X));
	_running = 0;
	goto request_cleanup;
    }

    tprintf(("waiting for Client\n"));

    // accept client connections
    if ((clientfd = accept(_listenfd, (struct sockaddr *) &client_inetaddr,
			   (socklen_t *) &client_len)) == -1) {
	if (EINTR != errno) {
	    tprintf(("%snet> accept failed, errno = %s%s\n",
		     _E, strerror(errno), _X));
	    _running = 0;
	}
	goto request_cleanup;
    }
    
    tprintf(("%sconnection%s %s:%d\n", _I, _X,
	     inet_ntop(AF_INET, &client_inetaddr.sin_addr,
		       addrbuf, sizeof(addrbuf)),
	     ntohs(client_inetaddr.sin_port)));

    // create WOLFSSL object
    if (NULL == (ssl = wolfSSL_new(_tls_ctx))) {
	tprintf(("%sERROR: failed to create WOLFSSL object%s\n", _E, _X));
	_running = 0;
	goto request_cleanup;
    }

    // attach wolfSSL to the socket
    wolfSSL_set_fd(ssl, clientfd);

    // Usually end up here when KMS is shut down, so make a graceful exit
    // if (! _running) return;
    
    ret = wolfSSL_read(ssl, _recv_buf, sizeof(_recv_buf));

    if (0 == ret) {
	tprintf(("net> client closed connection\n"));
	goto request_cleanup;
    } else if (0 > ret) {
	tprintf(("%snet> wolfSSL_read error = %d%s\n",
		 _E, wolfSSL_get_error(ssl, ret), _X));
	goto request_cleanup;
    }

    n = ret;
    process_packet((void *) _recv_buf, n, &outbuf, &outlen);
 
    if (NULL == outbuf) {
	KMS_pkt_dump(_recv_buf, n, "<KMS> process_packet failure", 1);
 	tprintf(("%sprocess_packet() returned NULL, bailing%s\n", _E, _X));
 	goto request_cleanup;
    }

    ret = wolfSSL_write(ssl, outbuf, outlen);
    if (0 >= ret) {
	tprintf(("%snet> wolfSSL_write error = %d%s\n",
		 _E, wolfSSL_get_error(ssl, ret), _X));
	//err = wolfSSL_get_error(ssl, 0);
    }

 request_cleanup:
    if (ssl) wolfSSL_free(ssl);
    if (clientfd >= 0) close(clientfd);
}

/**
 * Look up the KMS home directory.
 *
 * @return Path of home directory.
 */
static char *
get_home(void)
{
    struct passwd	*pwp = getpwuid(geteuid());
    
    if (NULL == pwp) {
	fprintf(stderr, "%sError: can not find user info%s%s\n", _E, _X, _W);
	perror("getpwuid");
	fprintf(stderr, "%s", _X);
	exit(1);
    }
    
    return pwp->pw_dir;
}

/**
 * Determine name of CA certificate file.
 *
 * @param[in] home Home directory.
 * @return Full path to CA file.
 */
static char *
ca_file(char *home)
{
    static char			buf[256];

    snprintf(buf, sizeof(buf), "%s/%s/%s", home,
	     _cfgval[CFG_CERT_DIR].v.sval, _cfgval[CFG_CA_CERT].v.sval);

    return buf;
}

/**
 * Determine name of KMS certificate file.
 *
 * @param[in] home Home directory.
 * @return Full path to KMS certificate file.
 */
static char *
cert_file(char *home)
{
    static char	buf[256];

    snprintf(buf, sizeof(buf), "%s/%s/%s", home,
	     _cfgval[CFG_CERT_DIR].v.sval, _cfgval[CFG_CERT].v.sval);

    return buf;
}

/**
 * Determine name of KMS key file.
 *
 * @param[in] home Home directory.
 * @return Full path to KMS key file.
 */
static char *
key_file(char *home)
{
    static char	buf[256];

    snprintf(buf, sizeof(buf), "%s/%s/%s", home,
	     _cfgval[CFG_CERT_DIR].v.sval, _cfgval[CFG_PRIV_KEY].v.sval);

    return buf;
}

/**
 * Save the KMS process ID to a file. This file is used to avoid having
 * multiple instances of KMS running and by `kms_ctrl` to interact with the
 * KMS. Calling this function has the side effect of changing the current
 * directory to `~kms` and initializing TLS parameters.
 *
 * @param[in] force In case of an existing PID file, return error if not set.
 * @return 1 on sucess, 0 on error.
 */
static int
save_pid(int force)
{
    int		fd;
    int		flags = O_RDWR|O_CREAT;
    pid_t	pid;
    char	*home = get_home();

    if (verbose) {
	printf("Changing directory to %s\n", home);
    }

    if (chdir(home)) {
	fprintf(stderr, "%sError: cannot chdir to %s%s%s\n", _E, home, _X, _W);
	perror("chdir");
	fprintf(stderr, "%s", _X);
	exit(1);
    }

    /* if (! force), open() will fail if file already exists */
    flags |= (force ? O_TRUNC : O_EXCL);

    if ((fd = open(PID_FILE, flags, S_IRUSR|S_IWUSR)) < 0) {
	return 0;
    }
    pid = getpid();
    write(fd, (void *) &pid, sizeof(pid));
    close(fd);
    return 1;
}

/**
 * Redirect stdout/stderr to the indicated files. Used for daemon mode.
 *
 * @param[in] outfile Name of file to receive stdout.
 * @param[in] errfile Name of file to receive stderr.
 */
static void
redirect(char *outfile, char *errfile)
{
    int	fd;

    if (0 < (fd = open(outfile, O_CREAT|O_TRUNC|O_WRONLY|O_SYNC,
		       S_IRUSR|S_IWUSR))) {
	dup2(fd, 1);
	close(fd);
    }
    if (0 < (fd = open(errfile, O_CREAT|O_TRUNC|O_WRONLY|O_SYNC,
		       S_IRUSR|S_IWUSR))) {
	dup2(fd, 2);
	close(fd);
    }
}

/**
 * Print usage message and exit.
 *
 * @param[in] cmd Name of command.
 * @param[in] exitval Exit value passed to exit().
 */
static void
usage(char *cmd, int exitval)
{
    fprintf(stderr,
	    "usage: %s [-p port] [-a addr] [-F] [-C] [-m] "
	    "[-x] [-d] [-v]\n"
	    "       %s -h\n\n"
	    "where:\n"
	    "    -p\tport to attach to (default: %d)\n"
	    "    -a\thost dotted IPv4 address to attach to (default: %s)\n"
	    "    -F\tflush (start with an empty) cache of client keys\n"
	    "    -C\tignore cache error on startup (starts with empty cache)\n"
	    "    -m\tmonochrome mode\n"
	    "    -x\tforce start at risk of multiple KMS processes\n"
	    "    -d\tdetach from current shell and run in daemon mode\n"
	    "    -v\tincrease verbosity\n"
	    "    -h\tthis help message\n",
	    cmd, cmd, MASQ_KMS_DFLT_PORT, _kms_host);
    exit(exitval);
}

int
main(int argc, char *argv[])
{
    int			opt;
    int			port = MASQ_KMS_DFLT_PORT;

    extern char		*optarg;
    extern int		optind;
    int			do_flush = 0;
    int			ignore_cache_error = 0;
    int			i;
    int			force_start = 0;

    MASQ_status_t	mstat;
    cache_status_t	cstat;

    time_t		now = time((time_t *) 0);
    char	        timebuf[MASQ_EXPDATE_LEN + 1];

    char		*home = get_home();
    char		*certfile = cert_file(home);
    char		*keyfile  = key_file(home);
    char		*cafile   = ca_file(home);

    // set up signal and alarm handlers
    struct sigaction	sigact = {
	.sa_flags = SA_SIGINFO,
	.sa_sigaction = handle_signal
    };
    sigaction(SIGHUP, &sigact, NULL);	// shutdown
    sigaction(SIGINT, &sigact, NULL);	// shutdown
    sigaction(SIGUSR1, &sigact, NULL);	// flush cache
    sigaction(SIGUSR2, &sigact, NULL);	// re-read config
    struct sigaction	sigalm = {
	.sa_flags = SA_SIGINFO,
	.sa_sigaction = handle_alarm
    };

    // parse command-line arguments
    while (-1 != (opt = getopt(argc, argv, "p:a:FCmxdvh"))) {
	
	switch (opt) {
	    
	case 'p':
	    // listening port
	    port = atoi(optarg);
	    break;

	case 'a':
	    // host address
	    _kms_host = optarg;
	    break;

	case 'F':
	    // don't do flush here in case there's a '-d' following
	    // (done below)
	    do_flush = 1;
	    break;
	    
	case 'C':
	    ignore_cache_error = 1;
	    break;

	case 'm':
	    monochrome_mode = 1;
	    break;
	    
	case 'x':
	    force_start = 1;
	    break;

	case 'd':
	    daemon_mode = 1;
	    break;
	    
	case 'v':
	    verbose++;
	    break;
	    
	case 'h':
	case '?':
	    usage(argv[0], opt != 'h');
	}
    }

    if (daemon_mode) {
	printf("%sKMS daemon mode invoked%s\n", _W, _X);
	fflush(stdout);

	switch (fork()) {
	case -1:
	    fprintf(stderr, "%s", _E);
	    perror("fork");
	    fprintf(stderr, "%s", _X);
	    return 1;
	    break;

	case 0:
	    // child
	    (void) setsid();	// detach from parent process group
	    if (verbose) {
		printf("Redirecting output to ~/stdout and ~/stderr\n");
		fflush(stdout);
	    }
	    redirect("stdout", "stderr");
	    do_monochrome();	// color text makes more sense in foreground
	    break;

	default:
	    // parent
	    sleep(1);	// give stdout a chance to catch up
	    return 0;
	    break;
	}
    }

    // wait until after possible fork() so we have the correct pid
    if (! save_pid(force_start)) {
	fprintf(stderr,
		"%sWARNING: Another KMS process may be running\n"
		"Recommend using '%s%skms_ctrl -s%s%s' "
		"then '%s%s%s -x%s%s'%s\n\n",
		_W, _X, _C, _X, _W, _X, _C, argv[0], _X, _W, _X);
	usage(argv[0], 1);
    }

    if (! daemon_mode) {
	char	mstr[sizeof(_mstr)];
	obfus_str(_mstr, sizeof(_mstr), mstr);
	printf("%s%s%s\n", _M, mstr, _X);
	fflush(stdout);
    }

    if (monochrome_mode) {
	do_monochrome();
    }

    if (verbose) {
	printf("%sUsing wolfTLS%s\n", _I, _X);
    }
    
    // read config file
    if (MASQ_STATUS_SUCCESS != (mstat = cfg_init(CONFIG_FILE))) {
	if (verbose) {
	    tprintf(("cfg_init(%s) ret %s\n",
		     CONFIG_FILE, MASQ_status_to_str(mstat)));
	}
	return 1;
    }

    if (do_flush) {
	if (cache_success !=
	    (cstat = cache_save(NULL, &_exp, CACHE_FILE))) {
	    printf("got status %d from cache flush\n", cstat);
	}
    }
    
    // do this after possible daemon detachment as alarms are not inherited
    // on fork()
    sigaction(SIGALRM, &sigalm, NULL);	// do scheduled tasks

    // read shared parameters cache
    cstat = cache_params_restore(&_params, PARAMS_FILE);
    
    switch (cstat) {
    case cache_success:		// hunky dory
	break;
	
    case cache_no_file:
	printf("parameters file (%s) not found, exiting\n", PARAMS_FILE);
	(void) unlink(PID_FILE);
	return(1);
	break;
	
    case cache_file_err:
	printf("error reading parameters file, exiting\n");
	(void) unlink(PID_FILE);
	return(1);
	break;
	
    case cache_data_err:
	printf("corrputed data in parameters file, exiting\n");
	(void) unlink(PID_FILE);
	return(1);
	break;

    case cache_nomem:
	printf("memory issues reading parameters file, exiting\n");
	(void) unlink(PID_FILE);
	return(1);
	break;
	
    default:
	printf("unexpected error %d from cache restoration\n", cstat);
	break;
    }

    // read Client cache
    cstat = cache_restore(&_head, &_exp, CACHE_FILE);
    
    switch (cstat) {
    case cache_success:		// hunky dory
    case cache_no_file:		// no cache file, start with empty cache
	break;
	
    case cache_file_err:
	if (ignore_cache_error) {
	    printf("cache file access error, rebuilding as we go along\n");
	    _head = NULL;
	} else {
	    printf("error reading cache file, exiting\n");
	    (void) unlink(PID_FILE);
	    return(1);
	}
	break;
	
    case cache_data_err:
	if (ignore_cache_error) {
	    printf("corrputed data in cache file, rebuilding as we go along\n");
	    _head = NULL;
	} else {
	    printf("corrputed data in cache file, exiting\n");
	    (void) unlink(PID_FILE);
	    return(1);
	}
	break;

    case cache_nomem:
	printf("memory issues reading cache file, exiting\n");
	return(1);
	break;
	
    default:
	printf("unexpected error %d from cache restoration\n", cstat);
	break;
    }

    // parse config file options
    get_config_options();
    // read config file client info
    add_clients_to_cache(&_head);

    // sets expiration dates and timer values
    get_time(timebuf, sizeof(timebuf));

    // handle cache save timer directly
    _cfgval[CFG_CACHE_SAVE].next = now + _cfgval[CFG_CACHE_SAVE].v.tval;
    if (verbose) {
	tprintf(("%s() setting CACHE_SAVE to %s\n", __FUNCTION__,
		 timestr(_cfgval[CFG_CACHE_SAVE].next)));
    }

    // start timers
    next_alarm();

    if (initialize_tls(_kms_host, port, certfile, keyfile, cafile)) {
	tprintf(("%sError initializing TLS library, exiting%s\n", _E, _X));
	_running = 0;
    }

    // loop waiting on incoming connections
    while (_running) {
	handle_request();
    }
    
    if (verbose) {
	tprintf(("KMS no longer waiting for Clients, bye!\n"));
    }

    // orderly cleanup and exit

    // wolfSSL cleanup
    if (_tls_ctx) {
	wolfSSL_CTX_free(_tls_ctx);
	_tls_ctx = NULL;
    }
    if (_tls_init) {
	_tls_init = 0;
	wolfSSL_Cleanup();
    }
    if (_listenfd >= 0) {
	close(_listenfd);
	_listenfd = (-1);
    }

    // memory scrubbing and release
    for (i = 0; i < KMS_num_shared; i++) {
	memset(_params.p[i].ptr, 0, _params.p[i].len);
	free(_params.p[i].ptr);
	_params.p[i].ptr = NULL;
	_params.p[i].len = 0;
    }
    cache_save(_head, &_exp, CACHE_FILE);
    while (NULL != _head) {
	cache_free_client(&_head, _head);
    }
    cfg_clear();

    // remove lock file
    (void) unlink(PID_FILE);

    return 0;
}
