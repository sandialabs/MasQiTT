/*
 * Use RNG to generate random Client ID and base-62 encode it
 *
 * 62^5  =             916,132,832 =         0x369b13e0 (largest 32-bit fit)
 * 62^8  =     218,340,105,584,896 = 0x0000c694446f0100
 * 62^10 = 839,299,365,868,340,224 = 0x0ba5ca5392cb0400 (largest 64-bit fit)
 */

#include <stdio.h>

#include <sys/types.h>
#include <string.h>

#include "crypto.h"

static const char	*_alpha =
    "0123456789"
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

#define	ALPHA_LEN	(62)
#define	CLIENT_ID_LEN	(16)
#define	CHARS_PER_RAND	(8)

static void
gen_id(char *outbuf, size_t len)
{
    uint64_t		rand;
    size_t		i, n;
    char		*cp = outbuf;
    
    for (i = n = 0; i < len; i++) {
	if (0 == n) {
	    MASQ_rand_bytes((unsigned char *) &rand, sizeof(rand));
	    n = CHARS_PER_RAND;
	}
	*cp++ = _alpha[rand % ALPHA_LEN];
	rand /= ALPHA_LEN;
	n--;
    }
    *cp = '\0';
}

int
main(int argc, char *argv[])
{
    char		clientid[CLIENT_ID_LEN + 1];
    int			i;
    int			num = 1;

    if (argc > 1) {
	if (0 >= (num = atoi(argv[1]))) {
	    num = 1;
	}
    }

    for (i = 0; i < num; i++) {
	gen_id(clientid, CLIENT_ID_LEN);
	printf("%s\n", clientid);
    }
    
    return(0);
}
