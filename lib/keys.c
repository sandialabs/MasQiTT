#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "crypto.h"

#ifdef	DEBUG
#undef	DEBUG
#endif
#ifdef	ebug
#define	DEBUG(x)	do { printf x; } while (0)
#else
#define	DEBUG(x)
#endif

/** @file
 *
 * See keys.h for documentation on these functions.
 */

MASQ_KS_mek_t *
MASQ_KS_new(MASQ_KS_mek_t	**head,
	    char *topic,
	    char *expdate,
	    char *seqnum,
	    char *clientid,
	    MASQ_mek_strategy_t strat,
	    unsigned long int max,
	    KMS_data_t *puk,
	    unsigned char *mek,
	    size_t mek_len)
{
    /*
     * This can be called by a Publisher to store a MEK (mek != NULL)
     * or by a Subscruber to store a private key (puk != NULL)
     */
    MASQ_KS_mek_t	*p;
    int			i;

    DEBUG(("%s(%s, %s, %s, %s)\n",
	   __FUNCTION__, topic, expdate, seqnum, clientid));

    if (((NULL == mek) && (NULL == puk)) || (NULL == head)) {
	DEBUG(("%s() (mek [%p] and puk [%p]) or head [%p] == NULL\n",
	       __FUNCTION__, mek, puk, head));
	return NULL;
    }
    
    if (mek && mek_len > sizeof(p->mek)) {
	DEBUG(("%s() mek_len [%lu] > sizeof(p->mek) [%lu]\n",
	       __FUNCTION__, mek_len, sizeof(p->mek)));
	return NULL;
    }

    if (NULL == (p = calloc(1, sizeof(MASQ_KS_mek_t)))) {
	DEBUG(("%s() calloc failed", __FUNCTION__));
	return NULL;
    }
#undef	_X
#define	_X(x)					\
    if (NULL != x) {				\
	strncpy(p->x, x, sizeof(p->x));		\
    }

    _X(topic);
    _X(expdate);
    _X(seqnum);
    _X(clientid);
#undef	_X
    p->max = max;
    if (MASQ_key_persistent_time == strat) {
	time_t	now = time((time_t *) 0);
	p->tally = (unsigned long int) now + max;
    } else {
	p->tally = 0;
    }
    i = 0;
    if (NULL != puk) {
	for (i = 0; i < 2; i++) {
	    p->puk.data[i].len = puk->data[i].len;
	    p->puk.data[i].ptr = calloc(1, puk->data[i].len);
	    memcpy(p->puk.data[i].ptr, puk->data[i].ptr, puk->data[i].len);
	}
    }
    p->puk.num = i;
    for (/* i */; i < KMS_data_num_fields; i++) {
	p->puk.data[i].ptr = NULL;
	p->puk.data[i].len = 0;
    }
    memcpy((void *) p->mek, mek, mek_len);

    p->next = *head;
    *head = p;

    return p;	
}

int
MASQ_KS_delete(MASQ_KS_mek_t	**head,
	       MASQ_KS_mek_t	*entry)
{
    MASQ_KS_mek_t	*p, *q;

    DEBUG(("%s(%p, %p)\n", __FUNCTION__, *head, entry));

    for (p = q = *head; NULL != p; q = p, p = p->next) {
	if (p == entry) {
	    if (q == *head) {
		*head = p->next;
	    } else {
		q->next = p->next;
	    }
	    memset((void *) p, 0xc5, sizeof(MASQ_KS_mek_t));
	    free(p);
	    return 1;
	}
    }
    return 0;
}

MASQ_KS_mek_t *
MASQ_KS_find_mek(MASQ_KS_mek_t	*head,
		 char *topic,
		 char *expdate,
		 char *seqnum,
		 char *clientid)
{
    MASQ_KS_mek_t	*p;
    int			match_all;

    DEBUG(("%s(%s, %s, %s, %s)\n", __FUNCTION__,
	   topic, expdate, seqnum, clientid));

    for (p = head; NULL != p; p = p->next) {
	match_all = 1;
	if ((NULL != topic) &&
	    strncmp(topic, p->topic, MASQ_MAXTOPIC_LEN)) {
	    match_all = 0;
	}
	if (match_all && (NULL != expdate) &&
	    strncmp(expdate, p->expdate, MASQ_EXPDATE_LEN)) {
	    match_all = 0;
	}
	if (match_all && (NULL != seqnum) &&
	    strncmp(seqnum, p->seqnum, MASQ_SEQNUM_LEN)) {
	    match_all = 0;
	}
	if (match_all && (NULL != clientid) &&
	    strncmp(clientid, p->clientid, MASQ_CLIENTID_LEN)) {
	    match_all = 0;
	}
	if (match_all) {
	    break;
	}
    }

    return(p);
}
