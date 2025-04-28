/**
 * @file make_params.c
 * Create and populate shared parameters file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#define	__USE_GNU	// for sigabbrev_np()
#include <string.h>
#include <pwd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/time.h>
#include <termios.h>

#include "cache.h"
#include "crypto.h"
#include "strings.h"
#include "api.h"

static int	verbose = 0;

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
	    "usage: %s [-v]\n"
	    "       %s -h\n\n"
	    "where:\n"
	    "    -v\tincrease verbosity\n"
	    "    -h\tthis help message\n",
	    cmd, cmd);
    exit(exitval);
}

static struct termios	_saveterm;
static int		_termset = 0;

static void
echo_off(void)
{
    struct termios	term;

    if (_termset) return;

    // get terminal echo state
    tcgetattr(fileno(stdin), &_saveterm);

    // turn off echo
    term = _saveterm;
    term.c_lflag &= ~ECHO;	// turn off echo
    term.c_lflag &= ~ICANON;	// make unbuffered
    tcsetattr(fileno(stdin), TCSANOW, &term);

    _termset = 1;
}

static void
echo_restore(void)
{
    if (! _termset) return;
    
    tcsetattr(fileno(stdin), 0, &_saveterm);
    _termset = 0;
}

/**
 * If we get a signal during get_entropy, restore terminal as needed
 */
static void
handle_signal(int sig, siginfo_t *sig_info, void *vctxt)
{
    // don't care about params, but keep compiler from complaining...
    (void) sig_info; (void) vctxt;

    switch (sig) {

    case SIGHUP:
    case SIGINT:
	fprintf(stderr, "\nAborting, no parameters generated\n");
	break;

    default:
	fprintf(stderr,
		"\nUnhandled signal: %s, no parameters generated\n",
		sigabbrev_np(sig));
	break;
    }

    echo_restore();
    exit(1);
}

// low-level MIRACL Core interface to seed PRNG
extern void
MC_seed_RNG(unsigned char *buf, size_t len);

/**
 * Accumulate entropy for random number generation.
 *
 * Parameter generation is done deep in the MIRACL Core library in
 * a way that bypasses the normal (desired) MASQ_crypto_add_entropy()
 * interface, so we use accumulated entropy to directly seed the low-level
 * PRNG instead.
 *
 * Method: turn off local echo and prompt user for keyboard input. in a
 * loop read /dev/random, then for each character read add it to a buffer
 * and every N characters follow up with the high resolution time-of-day
 * clock value. seed RNG with accumlated data. turn echo back on.
 */
static void
get_entropy(void)
{
#define	RANDBUF_SIZ	16
#define	NUM_ROUNDS	15
#define	CHARS_PER_ROUND	20
    int			fd;
    ssize_t		n, tot;
    int			r, c, left;
    struct {
	unsigned char	randbuf[RANDBUF_SIZ];
	unsigned char	charbuf[CHARS_PER_ROUND];
	struct timeval	tv;
    } ent[NUM_ROUNDS];
    unsigned char	thischar, lastchar = 0;
    int			lastcount = 0, numwarn = 0;
    char		msg[sizeof(_msgs[0])];

    // set up signal handlers to restore echo if needed
    struct sigaction	sigact = {
	.sa_flags = SA_SIGINFO,
	.sa_sigaction = handle_signal
    };
    sigaction(SIGHUP, &sigact, NULL);	// shutdown
    sigaction(SIGINT, &sigact, NULL);	// shutdown

    if (0 > (fd = open("/dev/random", O_RDONLY))) {
	perror("open(/dev/random");
	exit(1);
    }

    echo_off();

    left = NUM_ROUNDS * CHARS_PER_ROUND;
    printf("Type some keyboard gibberish, please %4d", left); fflush(stdout);
    thischar = fgetc(stdin);

    for (r = 0; r < NUM_ROUNDS; r++) {
	tot = 0;
	while (tot < sizeof(ent[r].randbuf)) {
	    n = read(fd, &ent[r].randbuf[tot], sizeof(ent[r].randbuf) - tot);
	    tot += n;
	}
	for (c = 0; c < CHARS_PER_ROUND; c++) {
	    while (thischar == lastchar) {
		if (++lastcount == 4) {
		    obfus_str(_msgs[numwarn], sizeof(_msgs[0]), msg);
		    if (numwarn < ((sizeof(_msgs)/sizeof(_msgs[0])) - 1)) {
			numwarn++;
		    }
		    printf("\n%s\nType some keyboard gibberish, please %4d",
			   msg, left);
		    fflush(stdout);
		}
		thischar = fgetc(stdin);
	    }
	    ent[r].charbuf[c] = lastchar = thischar;
	    lastcount = 0;

	    printf("\b\b\b\b%4d", --left); fflush(stdout);
	}
	gettimeofday(&ent[r].tv, NULL);
    }
    close(fd);

    printf("\nThank you!\n"); fflush(stdout);
    MC_seed_RNG((unsigned char *) &ent, sizeof(ent));
    memset(&ent, 0, sizeof(ent));
    echo_restore();

    // restore signal handling defaults
    sigact.sa_flags = 0;
    sigact.sa_handler = SIG_DFL;
    sigaction(SIGHUP, &sigact, NULL);
    sigaction(SIGINT, &sigact, NULL);
}

int
main(int argc, char *argv[])
{
    struct passwd	*pwp = getpwuid(geteuid());
    cache_status_t	cstat;
    KMS_shared_params_t	params;
    MASQ_status_t	rc;
    int			retv = 0;

    BB1_pubparams	*PP = BB1_pubparams_new(BBFS_BN254);
    BB1_pksk		*sks = BB1_pksk_new(BBGS_BN254);

    int			opt;
    extern char		*optarg;

    if ((NULL == PP) || (NULL == sks)) {
	printf("Cannot allocate params storage, bailing\n");
	return 1;
    }

    // change directory to home dir
    if ((NULL == pwp) || chdir(pwp->pw_dir)) {
	printf("Cannot chdir to home directory, bailing\n");
	retv = 1;
	goto err_out;
    }

    if (! access(PARAMS_FILE, F_OK)) {
	printf("Params file (%s) already exists, bailing\n", PARAMS_FILE);
	retv = 1;
	goto err_out;
    }

    // parse command-line arguments
    while (-1 != (opt = getopt(argc, argv, "vh"))) {
	
	switch (opt) {

	case 'v':
	    verbose++;
	    break;
	    
	case 'h':
	case '?':
	    usage(argv[0], opt != 'h');
	}
    }

    get_entropy();

    // generate shared parameters
    if (MASQ_STATUS_SUCCESS != (rc = BB1_BN254_setup(PP, sks))) {
	printf("Got error from BB1_BN254_setup(): %s, bailing\n",
	       MASQ_status_to_str(rc));
	retv = 1;
	goto err_out;
    }

#define	oct_to_params(f, O)					      \
    do {							      \
	params.p[KMS_shared_ ## f].len = (size_t) O->f->len;	      \
	params.p[KMS_shared_ ## f].ptr = (unsigned char *) O->f->val; \
    } while (0)
    
    // convert to library-friendly representation
    oct_to_params(s1, sks);
    oct_to_params(s2, sks);
    oct_to_params(s3, sks);
    oct_to_params( R, PP);
    oct_to_params( T, PP);
    oct_to_params( V, PP);

#undef	oct_to_params
    
    if (verbose) {
	printf("Saving parameters in %s\n", PARAMS_FILE); fflush(stdout);
    }
    cstat = cache_params_save(&params, PARAMS_FILE);

    if (cache_success != cstat) {
	printf("cache_params_save() returned %s\n", cache_status_to_str(cstat));
	retv = 1;
    }

 err_out:
    BB1_pubparams_free(PP);
    BB1_pksk_free(sks);

    return retv;
}
