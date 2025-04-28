#ifndef	KMS_CONFIG_H_INCLUDED
#define	KMS_CONFIG_H_INCLUDED

/**
 * @file cfg.h
 * Routines for reading KMS configurtion file settings.
 */

#include <time.h>

#include "masqlib.h"

extern const char	*CONFIG_FILE;

/**
 * Structure representing Client-specific configuration data
 */
typedef struct {
    const char	*client_id;	//!< Client ID.
    MASQ_role_t	role;		//!< Client role.
} KMS_client_info_t;

/**
 * Intialize configuration file parser.
 *
 * @param[in] config_file Path of configuration file
 * @return MASQ_STATUS_SUCCESS on success, else MASQ_ERR_INVAL (parsing
 * error) or MASQ_ERR_NOT_FOUND (missing "clients" section)
 */
extern MASQ_status_t
cfg_init(const char *config_file);

/**
 * Free configuration related memory.
 */
extern void
cfg_clear(void);

/**
 * Get string data field from configuration.
 *
 * The returned pointer is managed by the underlying configuration file
 * library and must not be free()d by the caller.
 *
 * @param[in] field Name of configuration field to look up.
 * @param[out] out Value of configuration field.
 * @return MASQ_STATUS_SUCCESS if found, else MASQ_ERR_NOT_FOUND
 */
extern MASQ_status_t
cfg_get_field(const char *field,
	      const char **out);

/**
 * Get boolean data field from configuration.
 *
 * @param[in] field Name of configuration field to look up.
 * @param[out] bool Value of configuration field.
 * @return MASQ_STATUS_SUCCESS if found, else MASQ_ERR_NOT_FOUND
 */
extern MASQ_status_t
cfg_get_bool(const char *field,
	     int *boolval);

/**
 * Get Nth client entry from configuration.
 *
 * @param[in] n 0-indexed offset into clients list.
 * @param[out] client Filled with client info on success.
 * @return MASQ_STATUS_SUCCESS if found, else MASQ_ERR_NOT_FOUND (past end of
 * clients list) or  MASQ_ERR_BAD_ENTRY (client is configured incorrectly),
 */
extern MASQ_status_t
cfg_get_client_n(int n,
		 KMS_client_info_t *client);

/**
 * Translate time value string to number of seconds.
 *
 * Time values are formatted NN[x], where NN represents an integer, and
 * an optional modifier, x, is one of
 * - `s` for seconds (default if not specified)
 * - `m` for minutes
 * - `h` for hours
 * - `d` for days
 * - `w` for weeks (7 days)
 * - `y` for years (365.25 days)
 *
 * @param[in] in String to parse.
 * @return Number of seconds, -1 in case of incorrectly formatted string.
 */
extern time_t
cfg_time_translate(char *in);

/* Convenience values
 */
#define	SEC_MINUTE	(60)			// seconds in a minute
#define	SEC_HOUR	(SEC_MINUTE * 60)	// etc...
#define	SEC_DAY		(SEC_HOUR * 24)
#define	SEC_WEEK	(SEC_DAY * 7)
#define	SEC_YEAR	((SEC_DAY * 365) + (SEC_HOUR * 6))

/**
 * Translate date value string to GMT time_t.
 *
 * Date strings are formatted in MasQiTT standard date format:
 *   yyyymmddThhmmssZ
 *
 * @param[in] in String to parse.
 * @return Unix time_t (GMT), -1 in case of incorrectly formatted string.
 */
extern time_t
cfg_date_parse(char *in);

#endif	// KMS_CONFIG_H_INCLUDED
