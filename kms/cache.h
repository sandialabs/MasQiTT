#ifndef	MASQ_KMS_DATA_H
#define	MASQ_KMS_DATA_H

/**
 * @file cache.h
 * Routines for manipulating the KMS cache of private and public keys.
 */

#include "masqlib.h"
#include "kms_msg.h"

extern const char	*CACHE_FILE;
extern const char	*PARAMS_FILE;
extern const char	*PID_FILE;

/**
 * Private key information.
 */
typedef struct KMS_priv_s {
    struct KMS_priv_s	*next;		//!< Next private key in list.
    int			used:1;		//!< Has this key been requested?
    char		topic[MASQ_MAXTOPIC_LEN+1];	//!< Topic Name.
    char		expdate[MASQ_EXPDATE_LEN+1];	//!< Key expiration.
    KMS_data_t		key;				//!< Cached private key.
} KMS_priv_t;

/**
 * Client information.
 */
typedef struct KMS_client_s {
    struct KMS_client_s	*next;		//!< Next Client in list
    char		client_id[MASQ_CLIENTID_LEN + 1];	//!< Client ID.
    MASQ_role_t		role;		//!< Clent role.
    KMS_priv_t		*cache;	//!< Private key cache. Publishers won't have cache entries.
} KMS_client_t;

#define	KMS_NUM_EXP	2

/**
 * Expiration dates information.
 */
typedef struct {
    time_t	expdate;	//!< Current public key expiration date
    time_t	nextexp;	//!< Next public key expiration date
} KMS_exp_t;

enum {
    KMS_shared_s1 = 0,	//!< Secret value s1
    KMS_shared_s2,	//!< Secret value s2
    KMS_shared_s3,	//!< Secret value s2
    KMS_shared_R,	//!< Public value R
    KMS_shared_T,	//!< Public value T
    KMS_shared_V,	//!< Public value V
    KMS_num_shared
};

/**
 * Shared parameters.
 */
typedef struct {
    struct {
	size_t		len;	//!< Length of parameter value
	unsigned char	*ptr;	//!< Pointer to parameter value
    } p[KMS_num_shared];
} KMS_shared_params_t;

/**
 * Return values for cache operations.
 */
typedef enum {
    cache_success = 0,		//!< Operation was successful.
    cache_no_client,		//!< Client not found.
    cache_no_private,		//!< Private key not found.
    cache_dup_client,		//!< Client already in cache.
    cache_dup_private,		//!< Private key already in cache.
    cache_nomem,		//!< Malloc failed.
    cache_too_big,		//!< Not enough space.
    cache_no_file,		//!< File not found.
    cache_file_err,		//!< Error handling cache file.
    cache_data_err,		//!< Unparseable data from cache file.
    cache_invalid,		//!< Invalid parameter.
} cache_status_t;

/**
 * Get string representation of a status code.
 *
 * @param[in] status Status code.
 * @return String represenation, "???" for invalid status code.
 */
extern const char *
cache_status_to_str(cache_status_t status);

/**
 * Find Client in cache.
 *
 * @param[in] head Pointer to cache.
 * @param[in] client_id ID of Client to locate.
 * @param[out] status @ref cache_success if found, else @ref cache_no_client.
 * @return Pointer to client if found, else NULL.
 */
extern KMS_client_t *
cache_find_client(KMS_client_t *head,
		  char *client_id,
		  cache_status_t *status);

/**
 * Find private key in cache.
 *
 * @param[in] head Pointer to cache.
 * @param[in] client_id ID of Client to locate.
 * @param[in] topic Name of Topic of interest.
 * @param[in] expdate Expiration date associted with the key.
 * @param[out] status @ref cache_success if found, else @ref cache_no_client
 *   or @ref cache_no_private.
 * @return Pointer to private key if found, else NULL.
 */
extern KMS_priv_t *
cache_find_privkey(KMS_client_t *head,
		   char *client_id,
		   char *topic,
		   char *expdate,
		   cache_status_t *status);

/**
 * Add client to the cache.
 *
 * @param[in,out] head Pointer to cache pointer, updated as needed. *head
 *   should be NULL on first call.
 * @param[in] client_id ID of Client to add.
 * @param[in] role Client role.
 * @param[out] status @ref cache_success if added, else
 *   @ref cache_dup_client or @ref cache_nomem.
 * @return Pointer to client if added, else NULL.
 */
extern KMS_client_t *
cache_new_client(KMS_client_t **head,
		 char *client_id,
		 MASQ_role_t role,
		 cache_status_t *status);

/**
 * Add private key to the cache.
 *
 * @param[in,out] head Pointer to cache.
 * @param[in] client_id ID of Client.
 * @param[in] topic Name of Topic of interest.
 * @param[in] expdate Expiration date associted with the key.
 * @param[in] key Private key to add.
 * @param[out] status @ref cache_success if added, else @ref cache_no_client,
 *   @ref cache_dup_private, or @ref cache_nomem.
 * @return Pointer to client if added, else NULL.
 */
extern KMS_priv_t *
cache_new_privkey(KMS_client_t *head,
		  char *client_id,
		  char *topic,
		  char *expdate,
		  KMS_data_t *key,
		  cache_status_t *status);

/**
 * Remove Client from cache and zeroize/free() relevant memory.
 *
 * @param[in,out] head Pointer to cache pointer, updated as needed.
 * @param[in] c Client to remove.
 */
extern void
cache_free_client(KMS_client_t **head,
		  KMS_client_t *c);

/**
 * Remove private key from cache and zeroize/free() relevant memory.
 *
 * @param[in] c Client with private key to remove.
 * @param[in] p Private key to remove.
 */
extern void
cache_free_privkey(KMS_client_t *c,
		   KMS_priv_t *p);

/**
 * Remove all private keys older than provided date.
 *
 * @param head Pointer to cache.
 * @param date Cutoff date; private keys with expiration dates before this
 *   will be removed.
 */
extern void
cache_expire(KMS_client_t *head,
	     char *date);

/**
 * Write contents of cache to file.
 *
 * @param[in] head Pointer to cache.
 * @param[in] dates Public key expiration dates (current, next).
 * @param[in] filename Name of file to receive cache contents.
 * @return @ref cache_success on success, else @ref cache_file_error
 */
extern cache_status_t
cache_save(KMS_client_t *head,
	   KMS_exp_t *expdate,
	   const char *filename);

/**
 * Initialize contents of cache with data read from file.
 *
 * @param[out] head Pointer to cache pointer.
 * @param[out] dates Buffer to receive public key expiration dates.
 * @param[in] filename Name of file containing cache contents.
 * @return @ref cache_success on success, else error indication.
 */
extern cache_status_t
cache_restore(KMS_client_t **head,
	      KMS_exp_t *expdate,
	      const char *filename);

/**
 * Translate time_t to ISO string.
 *
 * @param[in] t Time to translate.
 * @param[out] s Buffer to receive string, assumes s is at least
 *     (MASQ_EXPDATE_LEN + 1) bytes long
 */
extern void
cache_time_to_str(time_t t,
		  char *s);

/**
 * Convenience routine for representing Client role.
 *
 * @param[in] role Client role.
 * @return Character value ('P', 'S', 'B', '-', or '?')
 */
extern char
cache_role_to_char(MASQ_role_t role);

/**
 * Pretty-print the contents of the private key cache.
 *
 * @param[in] head Pointer to cache.
 * @param[in] exp Pointer to public key expiration dates.
 * @param[in] hdr If non-NULL, header to print at top of output.
 * @param[in] legend If non-zero, print column headings.
 * @param[in] print_wid If non-zero, maximum width of print output, else 80.
 */
extern void
cache_print(KMS_client_t *head,
	    KMS_exp_t *exp,
	    char *hdr,
	    int legend,
	    int print_wid);

/**
 * Write shared parameters to file.
 *
 * @param[in] params Pointer to shared parameters.
 * @param[in] filename Name of file to receive cache contents.
 * @return @ref cache_success on success, else @ref cache_file_error
 */
extern cache_status_t
cache_params_save(KMS_shared_params_t *params,
		  const char *filename);

/**
 * Initialize shared parameters with values from file.
 *
 * @param[out] params Pointer to shared parameters.
 * @param[in] filename Name of file containing cache contents.
 * @return @ref cache_success on success, else error indication.
 */
extern cache_status_t
cache_params_restore(KMS_shared_params_t *params,
		     const char *filename);

/**
 * Pretty-print the shared parameters.
 *
 * @param[in] params Pointer to shared parameters.
 * @param[in] hdr If non-NULL, header to print at top of output.
 * @param[in] legend If non-zero, print column headings.
 * @param[in] print_wid If non-zero, maximum width of print output, else 80.
 */
extern void
cache_params_print(KMS_shared_params_t *params,
		   char *hdr,
		   int legend,
		   int print_wid);

#endif	// MASQ_KMS_DATA_H
