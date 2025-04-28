/**
 * @file kms_ctrl.c
 * MasQiTT KMS control utility.
 *
 * kms_ctrl sends signals to the KMS process to
 * - shut down the KMS
 * - tell the KMS to write its cache to disk
 * - tell the KMS to re-read its configuration file
 */

// Linux
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <pwd.h>

// MasQiTT
#include "cache.h"

int	verbose = 0;

typedef struct {
    char	flag;
    const char	*descr;
    const char	*proc;
} stat_info;

static stat_info	stat_lookup[] = {
    // from proc(5) manpage
    { 'R', "running", "Running" },
    { 'S', "running", "Sleeping in an interruptible wait" },
    { 'D', "waiting on disk", "Waiting in uninterruptible disk sleep" },
    { 'Z', "a zombie", "Zombie" },
    { 'T', "stopped on a signal", "Stopped on a signal" },
    { 't', "being debugged", "Tracing stop" },
    { 'X', "dead", "Dead" },
};
#define	NUM_STAT_LOOKUP	(sizeof(stat_lookup)/sizeof(stat_lookup[0]))

static const char *
stat_to_str(char stat)
{
    int	i;

    const char	*ret = "???";

    for (i = 0; i < NUM_STAT_LOOKUP; i++) {
	if (stat_lookup[i].flag == stat) {
	    ret = stat_lookup[i].descr;
	    break;
	}
    }

    return ret;
}

static const char *
stat_to_procstr(char stat)
{
    int	i;

    const char	*ret = "???";

    for (i = 0; i < NUM_STAT_LOOKUP; i++) {
	if (stat_lookup[i].flag == stat) {
	    ret = stat_lookup[i].proc;
	    break;
	}
    }

    return ret;
}

static int
report_status(pid_t pid)
{
    int		fd;
    int		nread;
    int		sret;
    char	statflag = '?';
    const char	*status;
    const char	*proc;
    char	fname[32];
    char	statbuf[1024];	// overkill

    snprintf(fname, sizeof(fname), "/proc/%d/stat", pid);

    if (0 > (fd = open(fname, O_RDONLY))) {
	fprintf(stderr, "Can not open %s, exiting\n", fname);
	perror("open");
	return 1;
    }

    if (0 > (nread = read(fd, (void *) statbuf, sizeof(statbuf)))) {
	fprintf(stderr, "Can not read from %s, exiting\n", fname);
	perror("read");
	close(fd);
	return 1;
    }
    close(fd);
    statbuf[nread] = '\0';
    
    sret = sscanf(statbuf, "%*d %*s %c", &statflag);
    if (1 != sret) {
	fprintf(stderr, "Data format problem, exiting\n");
	perror("sscanf");
	fprintf(stderr, "Got: %s\n", statbuf);
	return 1;
    }

    status = stat_to_str(statflag);
    if (verbose) {
	proc = stat_to_procstr(statflag);
	printf("KMS is %s (%s).\n", status, proc);
    } else {
	printf("KMS is %s.\n", status);
    }

    return 0;
}

static void
usage(char *cmd, int exitval)
{
    fprintf(stderr,
	    "usage: %s -i [-q] | -s | -d | -c\n"
	    "       %s <option> -v\n"
	    "       %s -h\n\n"
	    "where:\n"
	    "    -i\tget information about KMS process status\n"
	    "\treturns 0 if running, else 1 (if `%s -iq` ; then)\n"
	    "    -q\tquiet, nothing printed to stdout\n"
	    "    -s\ttell the KMS to shut down\n"
	    "    -d\ttell the KMS to save its cache to disk\n"
	    "    -c\ttell the KMS to re-read its config file\n"
	    "    -v\tincrease verbosity (overrides -q)\n"
	    "    -h\tthis help message\n",
	    cmd, cmd, cmd, cmd);
    exit(exitval);
}

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

int
main(int argc, char **argv)
{
    int		retval = 0;
    int		opt;
    pid_t	pid;
    int		fd;
    char	*home = get_home();

    int		do_info     = 0;
    int		be_quiet    = 0;
    int		do_shutdown = 0;
    int		do_write    = 0;
    int		do_reread   = 0;
    int		sig = 0;
    char	*sig_str = "";

    extern char	*optarg;

    // parse command-line arguments
    while (-1 != (opt = getopt(argc, argv, "iqsdcvh"))) {
	
	switch (opt) {
	    
	case 'i':
	    do_info = 1;
	    break;

	case 'q':
	    be_quiet = 1;
	    break;

	case 's':
	    do_shutdown = 1;
	    sig = SIGHUP;
	    sig_str = "SIGHUP";
	    break;

	case 'd':
	    do_write = 1;
	    sig = SIGUSR1;
	    sig_str = "SIGUSR1";
	    break;

	case 'c':
	    do_reread = 1;
	    sig = SIGUSR2;
	    sig_str = "SIGUSR2";
	    break;

	case 'v':
	    verbose++;
	    break;
	    
	case 'h':
	case '?':
	    usage(argv[0], opt != 'h');
	    break;
	}
    }

    if (verbose) {
	be_quiet = 0;
    }

    if (1 != (do_info + do_shutdown + do_write + do_reread)) {
	fprintf(stderr, "must specify one and only one of -i/-s/-d/-c\n\n");
	usage(argv[0], 1);
    }

    if (chdir(home)) {
	fprintf(stderr, "Error: cannot chdir to %s\n", home);
	perror("chdir");
	exit(1);
    }

    if ((fd = open(PID_FILE, O_RDONLY)) < 0) {
	if (do_info) {
	    if (! be_quiet) {
		printf("KMS is not running.\n");
	    }
	    return 1;
	} else {
	    fprintf(stderr, "No PID file found, is KMS even running?\n");
	    return 1;
	}
    }
    
    if (sizeof(pid) != read(fd, (void *) &pid, sizeof(pid))) {
	fprintf(stderr, "Problem reading PID file\n");
	close(fd);
	return 1;
    }
    close(fd);

    if (verbose) {
	printf("Checking for process at PID %d\n", pid);
	fflush(stdout);
    }

    if (kill(pid, 0)) {
	if (do_info) {
	    if (! be_quiet) {
		printf("KMS does not appear to be running.\n");
	    }
	    return 0;
	} else {
	    fprintf(stderr, "No process at indicated PID or no permission\n");
	    return 1;
	}
    }

    if (do_info) {

	retval = report_status(pid);
	
    } else {

	if (verbose) {
	    printf("Sending %s to PID %d\n", sig_str, pid);
	    fflush(stdout);
	}

	/* do it */
	(void) kill(pid, sig);
    }

    return retval;
}

