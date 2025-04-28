#ifndef	KMS_STRINGS_H_INCLUDED
#define	KMS_STRINGS_H_INCLUDED

/**
 * @file strings.h
 */

extern unsigned char	_mstr[1129];	// MasQiTT logo
extern unsigned char	_msgs[5][38];	// Messages printed by make_params

/**
 * Lightweight string obfuscation. Performs a simple byte-by-byte XOR with a
 * fixed set of random bytes. Two obfuscations equals the original.
 *
 * @param[in] in Data to obfuscate/deobfuscate.
 * @param[in] in_len Length of input data.
 * @param[out] out Storage for obfuscated/deobfuscated data.
 *   Must be at least @p in_len bytes long.
 */
extern void
obfus_str(unsigned char *in, size_t in_len, unsigned char *out);

#endif	// KMS_STRINGS_H_INCLUDED
