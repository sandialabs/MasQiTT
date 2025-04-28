#ifndef	CRYPTO_KEYS_H_INCLUDED
#define	CRYPTO_KEYS_H_INCLUDED

/**
 * These functions are used to manage a local cache of message encryption
 * keys.
 */

#ifndef	MASQ_CRYPTO_H_INCLUDED
#error "#include crypto.h instead of keys.h"
#endif

/**
 * Persistent key information, used for storing and retrieving
 * previously-determined Message Encryption Keys.
 *
 * Publishers do not use the clientid field, so it is set to an empty
 * string (clientid[0] = '\0';)
 */
typedef struct MASQ_KS_mek_s {
    struct MASQ_KS_mek_s	*next;		//!< Singly-linked list
    char	topic[MASQ_MAXTOPIC_LEN+1];	//!< Topic Name
    char	expdate[MASQ_EXPDATE_LEN+1];	//!< Key expiration date
    char	seqnum[MASQ_SEQNUM_LEN+1];	//!< Sequence number
    char	clientid[MASQ_CLIENTID_LEN+1];	//!< Client ID (Subcriber only)
    unsigned long int	max;			//!< Expiration limit
    unsigned long int	tally;			//!< Current expiration count
    KMS_data_t		puk;			//!< K0M/K1M (IBE private key)
    unsigned char	mek[MASQ_AESKEY_LEN];	//!< MEK (Pub/Sub Pers keys)
} MASQ_KS_mek_t;

/**
 * Alloc a new mek_t and put it in the list.
 *
 * Newly allocated MASQ_KS_mek_t is prepended to the list pointed at by
 * head. Pass NULL in @p *head for an empty list.
 *
 * Parameters below described as strings must be '\0' terminated or
 * NULL. Strings will be truncated to their maximum Masqitt-specified length
 * if needed. Strings passed as NULL are disregarded.
 *
 * @param[in,out] head Pointer to head of list of MASQ_KS_mek_t structs
 * @param[in] topic Topic Name string
 * @param[in] expdate Expiration Date string
 * @param[in] seqnum Sequence Number string
 * @param[in] clientid Client ID string
 * @param[in] strat Message encryption key strategy
 * @param[in] max Max age, counter, or expiration time as desired by caller
 * @param[in] puk IBE private key
 * @param[in] mek Message Encryption Key
 * @param[in] mek_len Length of MEK
 * @return Pointer on success, else NULL
 */
extern MASQ_KS_mek_t *
MASQ_KS_new(MASQ_KS_mek_t **head,
	    char *topic,
	    char *expdate,
	    char *seqnum,
	    char *clientid,
	    MASQ_mek_strategy_t strat,
	    unsigned long int max,
	    KMS_data_t *puk,
	    unsigned char *mek,
	    size_t mek_len);

/**
 * Remove a @p MASQ_KS_mek_t entry from a list and clear/free its contents.
 *
 * This is normally called after finding a @p MASQ_KS_mek_t entry using @ref
 * MASQ_KS_find_mek().
 *
 * @param[in,out] head Pointer to head of list of @p MASQ_KS_mek_t structs
 * @param[in] entry MEK entry to delete.
 */
extern int
MASQ_KS_delete(MASQ_KS_mek_t **head,
	       MASQ_KS_mek_t *entry);

/**
 * Find MEK matching specified values.
 *
 * Parameters below described as strings must be '\0' terminated or
 * NULL. Strings passed as NULL are ignored for purposes of matching.
 *
 * @param[in] head Pointer to head of list of MASQ_KS_mek_t structs
 * @param[in] topic Topic Name string
 * @param[in] expdate Expiration Date string
 * @param[in] seqnum Sequence Number string
 * @param[in] clientid Client ID string
 * @return Pointer on success, else NULL
 */
extern MASQ_KS_mek_t *
MASQ_KS_find_mek(MASQ_KS_mek_t *head,
		 char *topic,
		 char *expdate,
		 char *seqnum,
		 char *clientid);

#endif	// CRYPTO_KEYS_H_INCLUDED
