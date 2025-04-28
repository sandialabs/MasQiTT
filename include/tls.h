#ifndef	MASQ_TLS_H_INCLUDED
#define	MASQ_TLS_H_INCLUDED

/** @file
 *
 * Collect configuration #define/#undef values and #include files here to
 * support TLS processing.
 */

/* seem to need the following to avoid compiler complaints about hardening
 */
#define	TFM_TIMING_RESISTANT
#define	ECC_TIMING_RESISTANT
#define	WC_RSA_BLINDING
#undef	WC_NO_HARDEN
#undef	WC_NO_CACHE_RESISTANT

/* need the following to turn on TLS 1.3
 */
#define	WOLFSSL_TLS13

#include <wolfssl/ssl.h>

#undef	SHA256	// collides with a MIRACL Core #define

#endif	// MASQ_TLS_H_INCLUDED
