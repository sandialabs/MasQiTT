/**
 * @file cache.c
 * Routines for manipulating the KMS cache of private and public keys.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <arpa/inet.h>

#include "crypto.h"
#include "cache.h"

const char	*CACHE_FILE  = "cache.smqtt";
const char	*PARAMS_FILE = "params.smqtt";
const char	*PID_FILE    = ".kms.pid";

KMS_client_t *
cache_find_client(KMS_client_t *head,
		  char *client_id,
		  cache_status_t *status)
{
    KMS_client_t	*c = NULL;

    *status = cache_success;

    for (c = head; NULL != c; c = c->next) {
	if (! strcmp(client_id, c->client_id)) {
	    return c;
	}
    }

    *status = cache_no_client;
    return c;
}

KMS_priv_t *
cache_find_privkey(KMS_client_t *head,
		   char *client_id,
		   char *topic,
		   char *expdate,
		   cache_status_t *status)
{
    KMS_client_t	*c;
    KMS_priv_t		*p;

    if (NULL == (c = cache_find_client(head, client_id, status))) {
	return NULL;
    }

    for (p = c->cache; NULL != p; p = p->next) {
	if ( (! strcmp(topic, p->topic)) && (! strcmp(expdate, p->expdate))) {
	    return p;
	}
    }

    *status = cache_no_private;
    return p;
}

KMS_client_t *
cache_new_client(KMS_client_t **head,
		 char *client_id,
		 MASQ_role_t role,
		 cache_status_t *status)
{
    KMS_client_t	*c;

    /* make sure we're not duplicating an existing client */
    if (NULL != (c = cache_find_client(*head, client_id, status))) {
	*status = cache_dup_client;
	return NULL;
    }
    *status = cache_success;

    if (NULL == (c = (KMS_client_t *) calloc(1, sizeof(*c)))) {
	*status = cache_nomem;
	return NULL;
    }
    strncpy(c->client_id, client_id, sizeof(c->client_id));
    c->role = role;
    c->cache = NULL;
    c->next = *head;
    *head = c;

    return c;
}

KMS_priv_t *
cache_new_privkey(KMS_client_t *head,
		  char *client_id,
		  char *topic,
		  char *expdate,
		  KMS_data_t *key,
		  cache_status_t *status)
{
    KMS_client_t	*c;
    KMS_priv_t		*p;
    int			i, j;

    if (NULL == (c = cache_find_client(head, client_id, status))) {
	return NULL;
    }

    if (NULL != (p = cache_find_privkey(head, client_id,
					topic, expdate, status))) {
	*status = cache_dup_private;
	return NULL;
    }

    if (NULL == (p = (KMS_priv_t *) calloc(1, sizeof(*p)))) {
	*status = cache_nomem;
	return NULL;
    }

    p->used = 0;
    strncpy(p->topic, topic, sizeof(p->topic));
    strncpy(p->expdate, expdate, sizeof(p->expdate));
    p->key.num = 0;
    for (i = 0; i < key->num; i++) {
	if (NULL == (p->key.data[i].ptr = calloc(1, key->data[i].len))) {
	    for (j = 0; j < p->key.num; j++) {
		free(p->key.data[j].ptr);
	    }
	    p->key.num = 0;
	    *status = cache_nomem;
	    return NULL;
	}
	memcpy(p->key.data[i].ptr, key->data[i].ptr, key->data[i].len);
	p->key.data[i].len = key->data[i].len;
	p->key.num++;	// keep track of key.num this way in case we need to
			// back out of a nomem situation (the free() above)
    }
    p->next = c->cache;
    c->cache = p;

    *status = cache_success;
    return p;
}

void
cache_free_client(KMS_client_t **head,
		  KMS_client_t *c)
{
    KMS_client_t	*c1, *c2;
    KMS_priv_t		*p, *q;
    
    if ((NULL == head) || (NULL == *head) || (NULL == c)) {
	return;
    }

    // detach it from the head pointer list
    if (*head == c) {
	*head = c->next;
    } else {
	for (c1 = c2 = *head; NULL != c1; c1 = c1->next) {
	    if (c1 == c) {
		c2->next = c->next;
		break;
	    }
	    c2 = c1;
	}
    }

    for (p = c->cache; NULL != p; p = q) {
	q = p->next;
	memset((void *) p, 0, sizeof(*p));
	free(p);
    }
    
    memset((void *) c, 0, sizeof(*c));
    free(c);
}

void
cache_free_privkey(KMS_client_t *c,
		   KMS_priv_t *p)
{
    KMS_priv_t	*p1, *p2;
    int		i;
    
    if ((NULL == c) || (NULL == p)) {
	return;
    }

    // detach it from the cache list
    if (c->cache == p) {
	c->cache = p->next;
    } else {
	for (p1 = p2 = c->cache; NULL != p1; p1 = p1->next) {
	    if (p1 == p) {
		p2->next = p->next;
		break;
	    }
	    p2 = p1;
	}
    }

    for (i = 0; i < p->key.num; i++) {
	if (NULL != p->key.data[i].ptr) {
	    memset(p->key.data[i].ptr, 0, p->key.data[i].len);
	    free(p->key.data[i].ptr);
	}
    }

    memset((void *) p, 0, sizeof(*p));
    free(p);
}

void
cache_expire(KMS_client_t *head,
	     char *date)
{
    KMS_client_t	*c;
    KMS_priv_t		*p;
    int			done;

    for (c = head; NULL != c; c = c->next) {

	done = 0;
	while (! done) {
	    done = 1;	// best to restart after each deletion
	    for (p = c->cache; NULL != p; p = p->next) {
		if (strcmp(p->expdate, date) < 0) {
		    cache_free_privkey(c, p);
		    done = 0;
		    break;
		}
	    }
	}
    }
}

/*
 * The following macros write integer values to the file in network
 * (big-endian) order. It's not a matter of cross-platform compatability as
 * it's unlikely to be sharing a cache or parameters file among systems with
 * different endian-ness, more a desire to make hex dumps more readable
 * without having to swap byte orders in your (my) head.
 */

static uint32_t		_xint;		// used in macros below
static uint16_t		_xshort;	// used in macros below

#undef	_writeint
#define	_writeint	do {						\
	_xint = htonl(tmpint);						\
	if (sizeof(_xint) != write(fd, &_xint, sizeof(_xint))) {	\
	    printf("error in line %d\n", __LINE__);			\
	    return cache_data_err;					\
	}								\
    } while(0)
#undef	_writeshort
#define	_writeshort	do {						\
	_xshort = htons(tmpshort);					\
	if (sizeof(_xshort) != write(fd, &_xshort, sizeof(_xshort))) {	\
	    printf("error in line %d\n", __LINE__);			\
	    return cache_data_err;					\
	}								\
    } while(0)
#undef	_writetime
#define	_writetime	do {						\
	_xint = htonl(tmptime >> 32);					\
	if (sizeof(_xint) != write(fd, &_xint, sizeof(_xint))) {	\
	    printf("error in line %d\n", __LINE__);			\
	    return cache_data_err;					\
	}								\
	_xint = htonl(tmptime & 0xffffffff);				\
	if (sizeof(_xint) != write(fd, &_xint, sizeof(_xint))) {	\
	    printf("error in line %d\n", __LINE__);			\
	    return cache_data_err;					\
	}								\
    } while(0)
#undef	_write
#define	_write(fd, addr, len)	do {			\
	if (len != write(fd, addr, len)) {		\
	    printf("error in line %d\n", __LINE__);	\
	    return cache_data_err;			\
	}						\
    } while (0)

#define	mk_magic(a,b,c,d)	((a)<<24|(b)<<16|(c)<<8|(d))
#define	MAGIC1	mk_magic('P','r','i','v')	//!< File type
#define	MAGIC2	mk_magic('K','e','y', 1)	//!< Type + version
#define	EXPDATE	mk_magic('E','x','p','D')	//!< Expiration dates
#define	CLIENT	mk_magic('C','l','n','t')	//!< KMS_client_t
#define	PRIV	mk_magic('P','r','i','v')	//!< KMS_priv_t
#define	END	mk_magic('E','n','d','!')	//!< End of file marker

cache_status_t
cache_save(KMS_client_t *head,
	   KMS_exp_t *dates,
	   const char *filename)
{
    int			fd;
    KMS_client_t	*c;
    KMS_priv_t		*p;
    uint32_t		tmpint;
    uint16_t		tmpshort;
    time_t		tmptime;
    int			i;

    if (0 > (fd = open(filename, O_CREAT|O_TRUNC|O_RDWR, S_IRUSR|S_IWUSR))) {
	perror("cache_save: open()");
	return cache_file_err;
    }

    tmpint = MAGIC1; _writeint;
    tmpint = MAGIC2; _writeint;

    if (NULL != dates) {
	tmpint = EXPDATE; _writeint;
	tmpshort = KMS_NUM_EXP; _writeshort;
	tmptime = dates->expdate; _writetime;
	tmptime = dates->nextexp; _writetime;
    }

    for (c = head; NULL != c; c = c->next) {
	tmpint = CLIENT; _writeint;
	_write(fd, c->client_id, MASQ_CLIENTID_LEN);
	tmpshort = c->role; _writeshort;

	for (p = c->cache; NULL != p; p = p->next) {
	    tmpint = PRIV; _writeint;
	    tmpshort = p->used ? 1 : 0; _writeshort;
	    tmpshort = strlen(p->topic); _writeshort;
	    _write(fd, p->topic, tmpshort);
	    _write(fd, p->expdate, MASQ_EXPDATE_LEN);
	    tmpshort = (short) p->key.num; _writeshort;
	    for (i = 0; i < p->key.num; i++) {
		tmpshort = (uint16_t) p->key.data[i].len; _writeshort;
		_write(fd, p->key.data[i].ptr, p->key.data[i].len);
	    }
	}
    }

    tmpint = END; _writeint;
    
    close(fd);
    return cache_success;
}

#define	MAGIC3	mk_magic('P','a','r','a')	//!< File type
#define	MAGIC4	mk_magic('m','s',' ', 1)	//!< Type + version
#define	P_S1	mk_magic('<','s','1','>')	//!< s1
#define	P_S2	mk_magic('<','s','2','>')	//!< s2
#define	P_S3	mk_magic('<','s','3','>')	//!< s2
#define	P_R	mk_magic('[','R','R',']')	//!< R
#define	P_T	mk_magic('[','T','T',']')	//!< T
#define	P_V	mk_magic('[','V','V',']')	//!< V

static uint32_t	_magic[KMS_num_shared] = { P_S1, P_S2, P_S3, P_R, P_T, P_V };

cache_status_t
cache_params_save(KMS_shared_params_t *params,
		  const char *filename)
{
    int			fd;
    uint32_t		tmpint;
    uint16_t		tmpshort;
    int			i;

    if (0 > (fd = open(filename, O_CREAT|O_TRUNC|O_RDWR, S_IRUSR|S_IWUSR))) {
	perror("cache_save: open()");
	return cache_file_err;
    }

    tmpint = MAGIC3; _writeint;
    tmpint = MAGIC4; _writeint;

    for (i = 0; i < KMS_num_shared; i++) {
	tmpint = _magic[i]; _writeint;
	tmpshort = (int) params->p[i].len; _writeshort;
	_write(fd, params->p[i].ptr, params->p[i].len);
    }

    tmpint = END; _writeint;
    
    close(fd);
    return cache_success;
}

/*
 * The following macros read integer values from the file in network
 * (big-endian) order. See comment above accompanying the _write* macros.
 */

#undef	_readint
#define	_readint	do {						\
	if (sizeof(_xint) != read(fd, &_xint, sizeof(_xint))) {		\
	    printf("error in line %d\n", __LINE__);			\
	    return cache_data_err;					\
	}								\
	tmpint = ntohl(_xint);						\
    } while(0)
#undef	_readshort
#define	_readshort	do {						\
	if (sizeof(_xshort) != read(fd, &_xshort, sizeof(_xshort))) {	\
	    printf("error in line %d\n", __LINE__);			\
	    return cache_data_err;					\
	}								\
	tmpshort = ntohs(_xshort);					\
    } while(0)
#undef	_readtime
#define	_readtime	do {						\
	if (sizeof(_xint) != read(fd, &_xint, sizeof(_xint))) {		\
	    printf("error in line %d\n", __LINE__);			\
	    return cache_data_err;					\
	}								\
	tmptime = ntohl(_xint);						\
	tmptime <<= 32;							\
	if (sizeof(_xint) != read(fd, &_xint, sizeof(_xint))) {		\
	    printf("error in line %d\n", __LINE__);			\
	    return cache_data_err;					\
	}								\
        tmptime += ntohl(_xint);					\
    } while(0)
#undef	_read
#define	_read(fd, addr, len)	do {			\
	if (len != read(fd, addr, len)) {		\
	    printf("error in line %d\n", __LINE__);	\
	    return cache_data_err;			\
	}						\
    } while (0)

/*
 * One challenge reading back cached data is that it's written first to
 * last, while the cache_new_*() routines prepend to the front. Accordingly,
 * we'll maintain our own head pointer and then reverse the order for the
 * head parameter just before returning. Likewise, KMS_priv_t entries must
 * be reversed in each KMS_client_t.
 */
cache_status_t
cache_restore(KMS_client_t **head,
	      KMS_exp_t *dates,
	      const char *filename)
{
    int			fd;
    KMS_client_t	*c, *c2, *my_head = NULL;
    KMS_client_t	my_client;
    KMS_priv_t		*p, *p2;
    KMS_priv_t		my_priv;
    uint32_t		tmpint;
    uint16_t		tmpshort;
    time_t		tmptime;
    char		this_client_id[MASQ_CLIENTID_LEN + 1];
    cache_status_t	status;
    int			done = 0;
    int			i, j;

    *head = NULL;
    
    if (0 > (fd = open(filename, O_RDONLY))) {
	if (ENOENT == errno) {
	    return cache_no_file;
	} else {
	    perror("cache_read: open()");
	    return cache_file_err;
	}
    }

    _readint; if (MAGIC1 != tmpint) { return cache_data_err; }
    _readint; if (MAGIC2 != tmpint) { return cache_data_err; }

    *head = NULL;

    while (! done) {
	
	_readint;
	
	switch (tmpint) {
	case CLIENT:
	    memset((void *) &my_client, 0, sizeof(my_client));

	    if (NULL != my_head) {
		// starting a new client, need to reverse the priv entries
		p = c->cache;
		c->cache = NULL;
		for (p2 = p; NULL != p2; p = p2) {
		    p2 = p->next;
		    p->next = c->cache;
		    c->cache = p;
		}
	    }
	    
	    _read(fd, my_client.client_id, MASQ_CLIENTID_LEN);
	    my_client.client_id[MASQ_CLIENTID_LEN] = '\0';
	    strcpy(this_client_id, my_client.client_id);
	    
	    _readshort; my_client.role = tmpshort;
	    c = cache_new_client(&my_head,
				 my_client.client_id,
				 my_client.role,
				 &status);
	    if (cache_success != status) { return status; }
	    break;

	case PRIV:
	    memset((void *) &my_priv, 0, sizeof(my_priv));

	    _readshort; my_priv.used = tmpshort ? 1 : 0;
	    _readshort;
	    // TODO: recover calloc()ed space
	    if (tmpshort > (sizeof(my_priv.topic)-1)) { return cache_data_err; }
	    _read(fd, my_priv.topic, tmpshort);
	    my_priv.topic[tmpshort] = '\0';
	    _read(fd, my_priv.expdate, MASQ_EXPDATE_LEN);
	    _readshort; my_priv.key.num = tmpshort;
	    for (i = 0; i < my_priv.key.num; i++) {
		_readshort; my_priv.key.data[i].len = tmpshort;
		if (NULL == (my_priv.key.data[i].ptr = calloc(1, tmpshort))) {
		    for (j = 0; j < i; j++) {
			free(my_priv.key.data[j].ptr);
		    }
		    // TODO: recover (all) calloc()ed space
		    return cache_nomem;
		}
		_read(fd, my_priv.key.data[i].ptr, tmpshort);
	    }

	    p = cache_new_privkey(my_head,
				  this_client_id,
				  my_priv.topic,
				  my_priv.expdate,
				  &my_priv.key,
				  &status);

	    p->used = my_priv.used;
	    for (i = 0; i < my_priv.key.num; i++) {
		free(my_priv.key.data[i].ptr);
		my_priv.key.data[i].ptr = NULL;
		my_priv.key.data[i].len = 0;
	    }
	    my_priv.key.num = 0;
	    if (cache_success != status) { return status; }
	    break;

	case EXPDATE:
	    _readshort;
	    if (KMS_NUM_EXP != tmpshort) { return cache_data_err; }
	    _readtime; if (NULL != dates) { dates->expdate = tmptime; }
	    _readtime; if (NULL != dates) { dates->nextexp = tmptime; }
	    break;

	case END:
	    close(fd);
	    if (NULL != my_head) {
		// have an in-process client, need to reverse the priv entries
		p = c->cache;
		c->cache = NULL;
		for (p2 = p; NULL != p2; p = p2) {
		    p2 = p->next;
		    p->next = c->cache;
		    c->cache = p;
		}
	    }
	    // reverse clients for return
	    for (c = c2 = my_head; NULL != c2; c = c2) {
		c2 = c->next;
		c->next = *head;
		*head = c;
	    }
	    
	    done = 1;
	    break;

	default:
	    // TODO: recover calloc()ed space
	    return cache_data_err;
	}
    }
    
    return cache_success;
}

#undef	_X
#define	_X(magic, idx)					\
    case magic:						\
        _readshort; tmpsize = (size_t) tmpshort;		\
	if (NULL == (cp = calloc(1, tmpsize))) {	\
	    return cache_nomem;				\
	}						\
	_read(fd, cp, tmpsize);				\
	params->p[idx].len = tmpsize;			\
	params->p[idx].ptr = cp;			\
	break

cache_status_t
cache_params_restore(KMS_shared_params_t *params,
		     const char *filename)
{
    int			fd;
    uint32_t		tmpint;
    uint16_t		tmpshort;
    size_t		tmpsize;
    int			done = 0;
    unsigned char	*cp;
    int			i;

    if (NULL == params) {
	return cache_invalid;
    }
    for (i = 0; i < KMS_num_shared; i++) {
	params->p[i].len = 0;
	params->p[i].ptr = NULL;
    }

    if (0 > (fd = open(filename, O_RDONLY))) {
	if (ENOENT == errno) {
	    return cache_no_file;
	} else {
	    perror("cache_read: open()");
	    return cache_file_err;
	}
    }

    _readint; if (MAGIC3 != tmpint) { return cache_data_err; }
    _readint; if (MAGIC4 != tmpint) { return cache_data_err; }

    while (! done) {
	
	_readint;
	
	switch (tmpint) {

	_X(P_S1, KMS_shared_s1);
	_X(P_S2, KMS_shared_s2);
	_X(P_S3, KMS_shared_s3);
	_X(P_R,  KMS_shared_R);
	_X(P_T,  KMS_shared_T);
	_X(P_V,  KMS_shared_V);

	case END:
	    close(fd);
	    done = 1;
	    break;

	default:
	    // recover calloc()ed space
	    for (i = 0; i < KMS_num_shared; i++) {
		if (params->p[i].len) {
		    free(params->p[i].ptr);
		    params->p[i].len = 0;
		    params->p[i].ptr = NULL;
		}
	    }
	    return cache_data_err;
	}
    }
    
    return cache_success;
}

#undef	_X

#undef	_readint
#undef	_readshort
#undef	_readtime
#undef	_read

void
cache_time_to_str(time_t t,
		  char *s)
{
    time_t	my_t = t;
    struct tm	tm, *tmp;

    if (NULL == s) { return; }

    if (t < 0) {
	strcpy(s, "99991231T235959Z");
	return;
    }
    
    tmp = gmtime_r(&my_t, &tm);
    
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
    // gcc complains about this snprintf() without the #pragma directives
    snprintf(s, MASQ_EXPDATE_LEN + 1, "%04d%02d%02dT%02d%02d%02dZ",
	     tmp->tm_year + 1900, tmp->tm_mon + 1, tmp->tm_mday,
	     tmp->tm_hour, tmp->tm_min, tmp->tm_sec);
#pragma GCC diagnostic pop
}

char
cache_role_to_char(MASQ_role_t role)
{
    char	retv = '?';
    switch (role) {
    case MASQ_role_publisher: retv = 'P'; break;
    case MASQ_role_subscriber: retv = 'S'; break;
    case MASQ_role_both: retv = 'B'; break;
    case MASQ_role_none: retv = '-'; break;
    }
    return retv;
}

void
cache_print(KMS_client_t *head,
	    KMS_exp_t *exp,
	    char *hdr,
	    int legend,
	    int print_wid)
{
    KMS_client_t	*c;
    KMS_priv_t		*p;
    char		kbuf[(2 * MASQ_AESKEY_LEN)+1];
    size_t		i, j;
    int			topic_wid = strlen("Topic");
    int			key_wid;

    // prelim pass to figure max width of topic names
    for (c = head; NULL != c; c = c->next) {
	for (p = c->cache; NULL != p; p = p->next) {
	    topic_wid = (strlen(p->topic) > topic_wid ?
			 strlen(p->topic) : topic_wid);
	}
    }
    if (! print_wid) { print_wid = 80; }
    // magic 7 value is width of R/U fields plus spaces
    key_wid = print_wid -
	(MASQ_CLIENTID_LEN + MASQ_EXPDATE_LEN + topic_wid + 7);
    if (key_wid > (MASQ_AESKEY_LEN * 2)) {
	key_wid = MASQ_AESKEY_LEN * 2;
    }

    if (NULL != hdr) {
	printf("==== %s\n", hdr);
    }

    if (legend) {
	printf("%-*s R %-*s %-*s %-*s U\n",
	       MASQ_CLIENTID_LEN, "Client",
	       MASQ_EXPDATE_LEN, "Exp Date",
	       topic_wid, "Topic",
	       key_wid, "Private key");
    }

    for (c = head; NULL != c; c = c->next) {
	
	if (NULL == c->cache) {
	    printf("%*s %c\n", MASQ_CLIENTID_LEN, c->client_id,
		   cache_role_to_char(c->role));
	    continue;
	}
	
	for (p = c->cache; NULL != p; p = p->next) {

	    kbuf[0] = '\0';
	    if ((p->key.data[0].len * 2) > key_wid) {
		for (i = 0; i < (key_wid / 2) - 1; i++) {
		    sprintf(&kbuf[i*2], "%02x",
			    ((unsigned char *) p->key.data[0].ptr)[i] & 0xff);
		}
		for (i = strlen(kbuf); i < key_wid; i++) {
		    kbuf[i] = '.'; kbuf[i+1] = '\0';
		}
	    } else {
		for (i = 0; i < p->key.data[0].len; i++) {
		    sprintf(&kbuf[i*2], "%02x",
			    ((unsigned char *) p->key.data[0].ptr)[i] & 0xff);
		}
	    }
	    
	    printf("%-*s %c %-*s %-*s %s %c\n",
		   MASQ_CLIENTID_LEN, c->client_id, cache_role_to_char(c->role),
		   MASQ_EXPDATE_LEN, p->expdate,
		   topic_wid, p->topic,
		   kbuf, (p->used ? 'Y' : 'N'));
	    for (j = 1; j < p->key.num; j++) {
		kbuf[0] = '\0';
		if ((p->key.data[j].len * 2) > key_wid) {
		    for (i = 0; i < (key_wid / 2) - 1; i++) {
			sprintf(&kbuf[i*2], "%02x",
				((unsigned char *) p->key.data[j].ptr)[i]&0xff);
		    }
		    for (i = strlen(kbuf); i < key_wid; i++) {
			kbuf[i] = '.'; kbuf[i+1] = '\0';
		    }
		} else {
		    for (i = 0; i < p->key.data[j].len; i++) {
			sprintf(&kbuf[i*2], "%02x",
				((unsigned char *) p->key.data[j].ptr)[i]&0xff);
		    }
		}
		printf("%-*s %c %-*s %-*s %s\n",
		       MASQ_CLIENTID_LEN, "", ' ',
		       MASQ_EXPDATE_LEN, "",
		       topic_wid, "",
		       kbuf);
	    }
	}
    }

    if (NULL != exp) {
	char	tbuf[MASQ_EXPDATE_LEN + 1];
	cache_time_to_str(exp->expdate, tbuf);
	printf("%*s   %s\n", MASQ_CLIENTID_LEN, "Current", tbuf);
	cache_time_to_str(exp->nextexp, tbuf);
	printf("%*s   %s\n", MASQ_CLIENTID_LEN, "Next", tbuf);
    }
}

static char	*_p_hdr[KMS_num_shared] = { "s1", "s2", "s3", "R", "T", "V" };

void
cache_params_print(KMS_shared_params_t *params,
		   char *hdr,
		   int legend,
		   int print_wid)
{
    int		i, j;
    int		parm_wid;
    int		this_wid;
    int		p_wid;

    if (! print_wid) { print_wid = 80; }
    parm_wid = print_wid - 7;

    if (NULL != hdr) {
	printf("==== %s\n", hdr);
    }

    if (legend) {
	printf("P  Len Value\n");
    }

    for (i = 0; i < KMS_num_shared; i++) {
	if (params->p[i].len) {
	    printf("%-2s %3ld ", _p_hdr[i], params->p[i].len);
	    
	    p_wid = parm_wid;
	    this_wid = params->p[i].len * 2;
	    if (this_wid < p_wid) {
		p_wid = this_wid;
	    } else if (this_wid > parm_wid) {
		p_wid = parm_wid;
	    }
	    for (j = 0; j < p_wid - 1; j += 2) {
		printf("%02x", params->p[i].ptr[j/2] & 0xff);
	    }
	    for ( ; j < p_wid; j++) { printf("."); }
	    printf("\n");
	}
    }
}

const char *
cache_status_to_str(cache_status_t status)
{
    const char	*retv = "???";

#undef	_X
#define	_X(v,s)	case cache_ ## v: retv = s; break
    switch (status) {
    _X(success, "Operation was successful");
    _X(no_client, "Client not found");
    _X(no_private, "Private key not found");
    _X(dup_client, "Client already in cache");
    _X(dup_private, "Private key already in cache");
    _X(nomem, "Malloc failed");
    _X(too_big, "Not enough space");
    _X(no_file, "File not found");
    _X(file_err, "Error handling cache file");
    _X(data_err, "Unparseable data from cache file");
    _X(invalid, "Invalid parameter");
    }
#undef	_X
    return retv;
}

#ifdef	UNITTEST
struct {
    char	*client_id;
    char	*what;		// topic name or subscription
} _clients[] = {
    // publishers
#define	PUB_TL	0
    { "TankLevel00037a1", "t/level" },
#define	PUB_TT	1
    { "TankTemp000a0032", "t/temp" },
#define	PUB_RT	2
    { "TankTemp000a0032", "r/temp" },
#define	PUB_PT	3
    { "PumpTemp007c0480", "p/temp" },
    // subscribers
#define	SUB_DP	4	// display panel
    { "Display999999997", "#" },
#define	SUB_PC	5	// pump controller
    { "PumpUnit00006177", "tank/level pump/temp" }
};
#define	NUM_CLIENTS	((sizeof(_clients)/sizeof(_clients[0])))

char	*_topics[] = {
    "t/level",
    "t/temp",
    "p/temp",
    "p/rate",
    "r/temp",
};
#define	NUM_TOPICS	((sizeof(_topics)/sizeof(_topics[0])))

char *_dates[] = {
#define	DATE_EARLY	0
    "20230913T000000Z",
#define	DATE_LATE	1
    "20230914T000000Z",
#define	DATE_EXP	2
    "20230913T040000Z"
};

#define	DAY	(24 * 60 * 60)

int
main(int argc, char *argv[])
{
    KMS_client_t	*head = NULL;
    KMS_client_t	*c;
    KMS_priv_t		*p;
    cache_status_t	status;
    unsigned char	kek[2][MASQ_AESKEY_LEN];
    KMS_data_t		my_data;
    int			i, j;
    KMS_exp_t		exp;
    KMS_exp_t		exp2;
    int			nexp;

    exp.expdate = time((time_t *) 0);
    exp.expdate += DAY;
    exp.expdate -= (exp.expdate % DAY);
    exp.nextexp = exp.expdate + DAY;

#define	NUM_KEK	(sizeof(kek)/sizeof(kek[0]))

    c = cache_new_client(&head, _clients[PUB_TL].client_id,
			 MASQ_role_publisher, &status);
    if (NULL == c) {
	printf("uh oh at line %d, status = %d\n", __LINE__, status);
	return(1);
    }
    printf("exp = %ld %ld\n", exp.expdate, exp.nextexp);
    cache_print(head, &exp, "one client", 1, 0);

    for (i = 0; i < NUM_TOPICS; i++) {
	for (j = 0; j < NUM_KEK; j++) {
	    MASQ_rand_bytes(kek[j], sizeof(kek[j]));
	    my_data.data[j].ptr = kek[j];
	    my_data.data[j].len = sizeof(kek[j]);
	}
	my_data.num = j;
	p = cache_new_privkey(head, _clients[PUB_TL].client_id,
			      _topics[i], _dates[DATE_LATE],
			      &my_data, &status);
	if (NULL == p) {
	    printf("uh oh at line %d, status = %d\n", __LINE__, status);
	    return(1);
	}
	p->used = (i % 2) ? 0 : 1;
    }
    cache_print(head, &exp, "... with privkey", 1, 0);

    c = cache_new_client(&head, _clients[SUB_PC].client_id,
			 MASQ_role_both, &status);
    if (NULL == c) {
	printf("uh oh at line %d, status = %d\n", __LINE__, status);
	return(1);
    }

    for (i = 0; i < 3; i += 2) {
	for (j = 0; j < NUM_KEK; j++) {
	    MASQ_rand_bytes(kek[j], sizeof(kek[j]));
	    my_data.data[j].ptr = kek[j];
	    my_data.data[j].len = sizeof(kek[j]);
	}
	my_data.num = j;
	p = cache_new_privkey(head, _clients[SUB_PC].client_id,
			      _topics[i], _dates[DATE_EARLY],
			      &my_data, &status);
	if (NULL == p) {
	    printf("uh oh at line %d, status = %d\n", __LINE__, status);
	    return(1);
	}
	p->used = 1;
	
	for (j = 0; j < NUM_KEK; j++) {
	    MASQ_rand_bytes(kek[j], sizeof(kek[j]));
	    my_data.data[j].ptr = kek[j];
	    my_data.data[j].len = sizeof(kek[j]);
	}
	my_data.num = j;
	p = cache_new_privkey(head, _clients[SUB_PC].client_id,
			      _topics[i], _dates[DATE_LATE],
			      &my_data, &status);
	if (NULL == p) {
	    printf("uh oh at line %d, status = %d\n", __LINE__, status);
	    return(1);
	}
    }
    cache_print(head, &exp, "two subscribers", 1, 0);
    
    cache_expire(head, _dates[DATE_EXP]);
    cache_print(head, &exp, "after expiration", 1, 0);

    status = cache_save(head, &exp, "kms.cache");
    if (cache_success != status) {
	printf("uh oh at line %d, status = %d\n", __LINE__, status);
	return(1);
    }

    while (NULL != head) {
	printf("clearing %s ...\n", head->client_id);
	cache_free_client(&head, head);
	cache_print(head, &exp, "========", 0, 0);
    }

    status = cache_restore(&head, &exp2, "kms.cache");
    if (cache_success != status) {
	printf("uh oh at line %d, status = %d\n", __LINE__, status);
	return(1);
    }
    cache_print(head, &exp2, "after cache_restore()", 1, 0);
    if ((exp.expdate != exp2.expdate) || (exp.nextexp != exp2.nextexp)) {
	printf("uh oh, date mismatch exp %ld/%ld next %ld/%ld\n",
	       exp.expdate, exp2.expdate, exp.nextexp, exp2.nextexp);
    }

    return 0;
}
#endif
