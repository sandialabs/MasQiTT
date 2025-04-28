/**
 * @file cfg.c
 * Routines for reading KMS configurtion file settings.
 */

#define	_XOPEN_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <libconfig.h>

// #defining _XOPEN_SOURCE to get strptime() hides the following
extern int	strcasecmp(const char *s1, const char *s2);

#include "cfg.h"

const char	*CONFIG_FILE = "kms.cfg";

static int		_cfg_init = 0;
static config_t		_cfgbuf, *_cfg = &_cfgbuf;
static config_setting_t	*_clients = NULL;

MASQ_status_t
cfg_init(const char *config_file)
{
    int	status;
    
    if (_cfg_init) {
	return MASQ_STATUS_SUCCESS;
    }
    
    config_init(_cfg);
    status = config_read_file(_cfg, config_file);
    if (CONFIG_TRUE != status) {
	printf("Error reading config file: %s at line %d\n",
	       config_error_text(_cfg),
	       config_error_line(_cfg));
	return MASQ_ERR_INVAL;
    }

    _clients = config_lookup(_cfg, "clients");
    if (NULL == _clients) {
	printf("Error reading config file: no clients specified\n");
	return MASQ_ERR_NOT_FOUND;
    }
    
    _cfg_init = 1;
    return MASQ_STATUS_SUCCESS;
}

void
cfg_clear(void)
{
    if (! _cfg_init) return;
    config_clear(_cfg);
    _clients = NULL;
    _cfg_init = 0;
}

MASQ_status_t
cfg_get_field(const char *field,
	      const char **out)
{
    //printf("%s(%s)\n", __FUNCTION__, field);
    return (CONFIG_TRUE == config_lookup_string(_cfg, field, out)) ? 
	MASQ_STATUS_SUCCESS : MASQ_ERR_NOT_FOUND;
}

MASQ_status_t
cfg_get_bool(const char *field,
	     int *boolval)
{
    //printf("%s(%s)\n", __FUNCTION__, field);
    return (CONFIG_TRUE == config_lookup_bool(_cfg, field, boolval)) ? 
	MASQ_STATUS_SUCCESS : MASQ_ERR_NOT_FOUND;
}

MASQ_status_t
cfg_get_client_n(int n,
		 KMS_client_info_t *client)
{
    config_setting_t	*cp;
    const char		*id, *role;

    if (NULL == client) {
	return MASQ_ERR_INVAL;
    }

    // retrieve client info
    if (NULL == (cp = config_setting_get_elem(_clients, n))) {
	return MASQ_ERR_NOT_FOUND;
    }

    // get fields
    if ((CONFIG_TRUE != config_setting_lookup_string(cp, "id",   &id)) ||
	(CONFIG_TRUE != config_setting_lookup_string(cp, "role", &role))) {
	return MASQ_ERR_BAD_ENTRY;
    }

    // validate fields
    if (MASQ_CLIENTID_LEN != strlen(id)) {
	return MASQ_ERR_BAD_ENTRY;
    }

    if (! strcasecmp(role, "publisher")) {
	client->role = MASQ_role_publisher;
    } else if (! strcasecmp(role, "subscriber")) {
	client->role = MASQ_role_subscriber;
    } else if (! strcasecmp(role, "both")) {
	client->role = MASQ_role_both;
    } else {
	return MASQ_ERR_BAD_ENTRY;
    }

    client->client_id = id;

    return MASQ_STATUS_SUCCESS;
}

time_t
cfg_time_translate(char *in)
{
    time_t	retv = -1;
    int		l;
    int		mult = 's';
    char	tmp[80];

    if ((NULL == in) || (! (l = strlen(in))) || (l > (sizeof(tmp)-1))) {
	return retv;
    }
    strcpy(tmp, in);	// may need to modify it, so make local copy

    if ((l > 1) && (isalpha(tmp[l-1]))) {
	mult = tmp[l-1];
	tmp[l-1] = '\0';
    }

    if (0 >= (retv = atoi(tmp))) {
	return -1;
    }

    switch (mult) {
    case 's':
	// nothing to do
	break;

    case 'm':
	retv *= SEC_MINUTE;
	break;
	
    case 'h':
	retv *= SEC_HOUR;
	break;
	
    case 'd':
	retv *= SEC_DAY;
	break;
	
    case 'w':
	retv *= SEC_WEEK;
	break;
	
    case 'y':
	retv *= SEC_YEAR;
	break;
	
    default:
	// invalid modifier
	return -1;
	break;
    }

    return retv;
}

// this seems to be missing from #include files (?)
time_t	timegm(struct tm *tm);

time_t
cfg_date_parse(char *in)
{
    time_t	retv = (-1);
    struct tm	tm;
    
    if (NULL != strptime(in, "%Y%m%dT%H%M%SZ", &tm)) {
	retv = timegm(&tm);
    }

    return retv;
}
