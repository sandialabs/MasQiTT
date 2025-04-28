/**
 * @file print_cache.c
 * Print contents of KMS private key and shared paramter caches.
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <pwd.h>

#include "cache.h"

static int		_do_private = 0;	//!< Print private keys?
static int		_do_shared = 0;		//!< Print shared parameters?
static int		_do_all = 0;		//!< Print both?
static KMS_client_t	*_head = NULL;		//!< Client cache

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
	fprintf(stderr, "Error: can not find user info\n");
	perror("getpwuid");
	exit(1);
    }
    
    return pwp->pw_dir;
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
	    "usage: %s [-p|-s|-a] [-w wid]\n"
	    "       %s -h\n\n"
	    "where:\n"
	    "    -p\tprint only Publisher private keys (default)\n"
	    "    -s\tprint only IBE system parameters\n"
	    "    -a\tprint keys and parameters\n"
	    "    -w\tmax width of print output (default: 80)\n"
	    "    -h\tthis help message\n",
	    cmd, cmd);
    exit(exitval);
}

int
main(int argc, char *argv[])
{
    cache_status_t	cstat;
    char		*home = get_home();

    int			opt;
    extern char		*optarg;
    int			print_wid = 0;

    KMS_exp_t		exp;
    KMS_shared_params_t	params;
    int			i;

    if (chdir(home)) {
	fprintf(stderr, "Error: cannot chdir to %s\n", home);
	perror("chdir");
	exit(1);
    }

    // parse command-line arguments
    while (-1 != (opt = getopt(argc, argv, "psaw:h"))) {
	
	switch (opt) {

	case 'p':
	    // print only private keys
	    _do_private = 1;
	    break;

	case 's':
	    // print only shared parameters
	    _do_shared = 1;
	    break;

	case 'a':
	    // print private keys and shared parameters
	    _do_all = 1;
	    break;

	case 'w':
	    // print width
	    print_wid = atoi(optarg);
	    break;
	    
	case 'h':
	case '?':
	    usage(argv[0], opt != 'h');
	}
    }

    switch (_do_private + _do_shared + _do_all) {
    case 0:
	_do_private = 1;
	break;
    case 1:
	if (_do_all) {
	    _do_private = _do_shared = 1;
	}
	break;
    default:
	fprintf(stderr, "only one of -p/-s/-a allowed\n\n");
	usage(argv[0], 1);
	break;
    }
    
    if (_do_private) {
	    
	// read Client cache
	cstat = cache_restore(&_head, &exp, CACHE_FILE);
    
	if (cache_success != cstat) {
	    fprintf(stderr, "Got error reading private keys: %s, exiting\n",
		    cache_status_to_str(cstat));
	    return 1;
	}

	cache_print(_head, &exp, (char *) CACHE_FILE, 1, print_wid);

	while (NULL != _head) {
	    cache_free_client(&_head, _head);
	}
    }

    if (_do_shared) {
	if (_do_private) { printf("\n"); }

	// read shared parameters
	cstat = cache_params_restore(&params, PARAMS_FILE);
    
	if (cache_success != cstat) {
	    fprintf(stderr, "Got error reading shared parameters: %s, exiting\n",
		    cache_status_to_str(cstat));
	    return 1;
	}

	cache_params_print(&params, (char *) PARAMS_FILE, 1, print_wid);

	for (i = 0; i < KMS_num_shared; i++) {
	    memset(params.p[i].ptr, 0, params.p[i].len);
	    free(params.p[i].ptr);
	    params.p[i].ptr = NULL;
	    params.p[i].len = 0;
	}
    }
	
    return 0;
}
