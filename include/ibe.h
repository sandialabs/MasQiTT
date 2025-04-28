#ifndef	IBE_H_INCLUDED
#define	IBE_H_INCLUDED

#include "pair_BN254.h"

#include "masqlib.h"

/**
 * @brief Idenity-Based Encryption Header file for BB1.
 *
 * Header file for implementing BB1 based upon bls.h in form. We largely
 * follow the description as provided by IEEE 1363.3 IEEE Standard for
 * Identity-Based Cryptographic Techniques using Pairings.
 *
 * Also includes routines for interfacing with the MIRACL Core library to
 * support BB1 processing. These are intended to be called only by other
 * library code.
 *
 * Routine name prefixes:
 * - `MC` for MIRACL Core glue
 * - `OCT` for MIRACL Core `octet` creation and destruction
 * - `BB1*` for BB1-specific computations, plus creation and destruction of
 *    BB1-specific `octet`-derived structures
 */

/* Field size is assumed to be greater than or equal to group size. */

#define	BBGS_BN254	MODBYTES_256_56 /** BN Group Size */
#define	BBFS_BN254	MODBYTES_256_56 /** BN Field Size */

/*----------------------------*/
/* Additional octet functions */
/*----------------------------*/

/*-----------*/
/* BB1 types */
/*-----------*/

// private key-server keys
typedef struct {
    octet	*s1;	// BIG_XXX of group size BBGZ_ZZZ
    octet	*s2;	// BIG_XXX of group size BBGZ_ZZZ
    octet	*s3;	// BIG_XXX of group size BBGZ_ZZZ
} BB1_pksk;

// Public parameters
typedef struct {
    /* We are going to use provided generators. */
    octet	*R;	// s1Q1 -- element of G1 (ECP_ZZZ point),
			// size of 2*BBFS_ZZZ + 1 (uncompressed)
    octet	*T;	// s3Q1 -- element of G1 (ECP_ZZZ point),
			// size of 2*BBFS_ZZZ + 1 (uncompressed)
    octet	*V;	// e(s2Q2, R) -- represents a F12_YYYY
			//-- MIRACL is G2 x G1, size of 12*BBFS_ZZZ
} BB1_pubparams;

// private user key
typedef struct {
    octet	*K0M;	// Element of G2 (ECP2_ZZZ point),
			// size of 4*BBFS_ZZZ + 1 (uncompressed)
    octet	*K1M;	// Element of G2 (ECP2_ZZZ point),
			// size of 4*BBFS_ZZZ + 1 (uncompressed)
} BB1_puk;

// BB1 key encapsulation
typedef struct {
    octet	*E0;	// Element of G1 (ECP_ZZZ point),
			// size of 2*BBFS_ZZZ + 1 (uncompressed)
    octet	*E1;	// Element of G1 (ECP_ZZZ point),
			// size of 2*BBFS_ZZZ + 1 (uncompressed)
} BB1_encaps;

/*-------------------*/
/* BB1 API functions */
/*-------------------*/

/**
 * BB1-KEM-Setup -- Setup parameters and key-server.
 *
 * Initialize public parameters are:
 * - G1, G2, G3 and the pairing e
 * - Generators for Q1 and Q2 for G1 and G2, respectively
 * - R = s1Q1, T = s3Q1
 * - V = e(s1Q1, s2Q2)
 *
 * The groups and pairing will be determined by which curve the code
 * is compiled against, so nothing needs to be accomplished. Similarly,
 * generators are already selected for G1 and G2 and can be extracted
 * by the API. These facts leave the generation of the server secrets
 * and the parameters R, T, and V. Additionally, precomputation for
 * the pairing can be done here like in the bls.c example.
 *
 * @param[in] PP The public parameters.
 * @param[out] sks The server's secret keys.
 * @return MASQ_STATUS_SUCCESS if parameters generated successfully,
 *    otherwise MASQ_ERR_MIRACL for problems returned by MIRACL Core
 *    library.
 */
extern MASQ_status_t
BB1_BN254_setup(BB1_pubparams *PP, BB1_pksk *sks);

/**
 * BB1-KEM-Extract -- User key generation.
 *
 * @param[in]  PP  The public parameters
 * @param[in]  sks The server's secret key
 * @param[in]  id  A user identity to extract the key for
 * @param[out] pk  The associated user's private key (K_{0, M}, K_{1, M})
 * @return MASQ_STATUS_SUCCESS if no error; otherwise MASQ_ERR_MIRACL for
 *    problems returned by MIRACL Core library or MASQ_ERR_NOMEM if `octet`
 *    allocation fails.
 */
extern MASQ_status_t
BB1G_BN254_extract(BB1_pubparams *PP, BB1_pksk *sks, octet *id, BB1_puk *pk);

/**
 * BB1-Verification -- User key verfication.
 *
 * @param[in] PP The public parameters
 * @param[in] id The user's identity
 * @param[in] pk The server's public key
 * @return MASQ_STATUS_SUCCESS if user's key verifies, MASQ_ERR_INVAL if
 *    verification fails; otherwise MASQ_ERR_MIRACL for problems returned by
 *    MIRACL Core library or MASQ_ERR_NOMEM if `octet` allocation fails.
 */
extern MASQ_status_t
BB1_BN254_verify_key(BB1_pubparams *PP, octet *id, BB1_puk *puk);

/**
 * Encapsulate AES key for encryption.
 *
 * This implements the first half of the Persistent MEK strategy.
 *
 * @param[in] PP The public parameters.
 * @param[in] id The user's identity.
 * @param[out] key Randomly generated AES key.
 * @param[out] enc_key Encapsulated version of @p key.
 * @return MASQ_STATUS_SUCCESS if no error; otherwise MASQ_ERR_MIRACL for
 *    problems returned by MIRACL Core library or MASQ_ERR_NOMEM if `octet`
 *    allocation fails.
 */
extern MASQ_status_t
BB1_encapsulate_key(BB1_pubparams *PP, octet *id,
		    octet *key, BB1_encaps *enc_key);

// The encapsulated key size
#define	MASQ_ENCAPS_KEY_LEN	(2 * ((2 * BBFS_BN254) + 1))

/**
 * Decapsulate AES key for decryption.
 *
 * This implements the second half of the Persistent MEK strategy.
 *
 * @param[in] puk The private user key.
 * @param[in] id The user's identity.
 * @param[in] ct The encasulated AES key.
 * @param[out] key Decapsulated version of @p ct.
 * @return MASQ_STATUS_SUCCESS if no error; otherwise MASQ_ERR_MIRACL for
 *    problems returned by MIRACL Core library or MASQ_ERR_NOMEM if `octet`
 *    allocation fails.
 */
extern MASQ_status_t
BB1_decapsulate_key(BB1_puk *puk, octet *id, octet *ct, octet *key);

/**
 * The ciphertext size returned by encrypt.
 *
 * When using the encrypt function, the returned ciphertext includes a
 * preamble encoding an AES key. This is a convenience function which
 * calculates the size of the space one needs to allocate for the
 * output of the encrypt function.
 *
 * @param[in] plaintext_size The size of the plaintext.
 * @return Size of ciphertext returned by encrypt.
 */
extern int
BB1_encrypt_size(int plaintext_size);

/**
 * The plaintext size returned by decrypt.
 *
 * When using the decrypt function, the inputted ciphertext includes a
 * preamble encoding the AES key. This is a convenience function which
 * calculates the size of the space one needs to allocate for the
 * output plaintext of the decrypt function.
 *
 * @param[in] ciphertext_size The size of the ciphertext.
 * @return Size of the plaintext returned by decrypt.
 */
extern int
BB1_decrypt_size(int ciphertext_size);

/**
 * Encrypt a message.
 *
 * @param[in] PP The public parameters
 * @param[in] id The user's identity
 * @param[in] header Header data to be authenticated, but not
 *            encrypted
 * @param[in] plaintext The plaintext to encrypt
 * @param[out] ciphertext The result ciphertext. Size of the
 *             ciphertext is going to be size of the plaintext padded
 *             to 128-bit blocks plus the 4*BBFS_BN254 + 2 for the
 *             encrypted shared secret.
 * @return MASQ_STATUS_SUCCESS if no error; otherwise MASQ_ERR_MIRACL for
 *    problems returned by MIRACL Core library, MASQ_ERR_NOMEM if `octet`
 *    allocation fails, or MASQ_ERR_NOSPACE if insufficent space given for
 *    encrypted result (see BB1_encrypt_size()).
 */
extern MASQ_status_t
BB1_encrypt(BB1_pubparams *PP, octet *id, octet *header,
	    octet *plaintext, octet *ciphertext);

/**
 * Decrypt a message.
 *
 * @param[in] id The user's identity
 * @param[in] pk The user's private key
 * @param[in] header Header data to be authenticated, but not
 *            encrypted
 * @param[in] ciphertext The ciphertext to decrypt
 * @param[out] plaintext The resulting plaintext
 * @return MASQ_STATUS_SUCCESS if no error; otherwise MASQ_ERR_MIRACL for
 *    problems returned by MIRACL Core library, MASQ_ERR_NOMEM if `octet`
 *    allocation fails, or MASQ_ERR_NOSPACE if insufficent space given for
 *    encrypted result (see BB1_decrypt_size()).
 */
extern MASQ_status_t
BB1_decrypt(octet *id, BB1_puk *pk, octet *header,
	    octet *ciphertext, octet *plaintext);

/** @file miracl.h
 *
 */

#if CURVE_SECURITY_BN254 != 128
#error "MIRACL Core CURVE_SECURITY_BN254 != 128"
#endif
#define	BB1_AESKEYLEN	AESKEY_BN254	//!< Length of AES key (bytes)
#define	BB1_IVLEN	(96/8)		//!< Length of init vector (bytes)
#define	BB1_TAGLEN	(128/8)		//!< Length of GCM tag (bytes)
#define	BB1_HASHLEN	HASH_TYPE_BN254	//!< Length of SHA256 hash (bytes)

/**
 * Initialize MC library interface.
 *
 * @param[in] protoid Protocol ID to implement. This implementation
 *    recognizes only "1.0/1".
 * @return Status, MASQ_STATUS_SUCCESS or MASQ_ERR_BAD_PROTOID
 */
extern MASQ_status_t
MC_crypto_init(const char *protoid);

/**
 * Close the MC library interface.
 */
extern void
MC_crypto_close(void);

/**
 * Get the MIRACL PRNG.
 *
 * @return Pointer to initialized MIRACL PRNG instance.
 */
extern csprng *
MC_get_RNG(void);

/**
 * Get random bytes.
 *
 * @param[in] buf Pointer for random data storage.
 * @param[in] len Number of bytes to return in @p buf.
 */
extern void
MC_rand_bytes(unsigned char *buf, size_t len);

/**
 * Calculate a SHA256 hash value.
 *
 * @param[in] inbuf Data to hash
 * @param[in] inlen Length of data to hash
 * @param[out] outbuf Storage for hash value
 * @param[in] outlen Length of buffer for hash value
 * @return 1 on sucess, 0 if an error occurs
 */
extern int
MC_hash(unsigned char *inbuf, size_t inlen,
	unsigned char *outbuf, size_t outlen);

/**
 * Initialize a SHA256 calculation. Use this and MC_hash_add()
 * if providing data to be hashed in multiple chunks.
 *
 * @param[in] inbuf If non-NULL, data to hash
 * @param[in] inlen Length of data to hash
 * @return Pointer to hash context, needed for FAUX_hash_add() or NULL on error
 */
extern void *
MC_hash_init(unsigned char *inbuf, size_t inlen);

/**
 * Continue or finalize a SHA256 hash calculation. Providing a pointer to
 * receive the hash value (@p outbuf) finalizes the hash and invalidates the
 * @p ctx.
 *
 * @param[in] ctx Hash context as provided by FAUX_hash_init()
 * @param[in] inbuf if non-NULL, data to add to hash
 * @param[in] inlen Length of data to hash
 * @param[out] outbuf If non-NULL, storage for hash value
 * @param[in] outlen Length of buffer for hash value
 * @return 1 on sucess, 0 if an error occurs
 */
extern int
MC_hash_add(void *ctx,
	    unsigned char *inbuf, size_t inlen,
	    unsigned char *outbuf, size_t outlen);

#define	MC_B64ENC_LEN(x)	((((x) + 2) / 3) * 4)
#define	MC_B64DEC_LEN(x)	((((x) + 3) / 4) * 3)

/**
 * Base64 encode binary data
 *
 * Leaves NULL-terminated string in outpuf
 *
 * @param[in] inbuf Data to encode
 * @param[in] inlen Length of data to encode
 * @param[out] outbuf Storage for encoded value
 * @param[in] outlen Length of buffer for encoded value
 * @param[in] pad Append '=' pad chars as needed?
 * @return 1 on sucess, 0 if an error occurs
 */
extern int
MC_base64_encode(unsigned char *inbuf, size_t inlen,
		 char *outbuf, size_t outlen, int pad);

/**
 * Base64 decode string
 *
 * This will not gracefully handle non-base64 encoding characters including
 * '\\n'; trailing '=' are fine. Leaves binary data in output.
 *
 * @param[in] inbuf String to decode
 * @param[in] inlen Length of string to decode
 * @param[out] outbuf Storage for decoded value
 * @param[in,out] outlen Length of buffer for decoded value
 * @return 1 on sucess with outlen updated, 0 if an error occurs
 */
extern int
MC_base64_decode(char *inbuf, size_t inlen,
		 unsigned char *outbuf, size_t *outlen);

/**
 * Encryption/decryption parameters.
 *
 * Rather than wrangle an obnoxiously long parameter list for encrypting or
 * decrypting data, MC_AESGCM_encrypt() and MC_AESGCM_decrypt() take a
 * single argument that is a pointer to a MC_aesgcm_params structure. Some
 * of the fields behave differently depending on which funcion is called,
 * and those differences are pointed out as needed. All of the *_len
 * parameters are input values that give the length (in bytes) of the buffer
 * it accompanies. Note that in GCM, the length of plaintext and ciphertext
 * are the same.
 */
typedef struct {

    unsigned char *key;	//!< Encryption key (in)
    size_t key_len;	//!< Length of encryption key
    
    unsigned char *iv;	//!< Initialization vector (in)
    size_t iv_len;	//!< Length of initialization vector
    			//!< (normally @ref BB1_IVLEN)
    
    unsigned char *hdr;	//!< Header (additional authentication data) (in)
    size_t hdr_len;	//!< Length of header, may be zero
    
    unsigned char *pt;	//!< Plaintext (in for encrypt, out for decrypt)
    size_t pt_len;	//!< Length of plaintext buffer
    
    unsigned char *ct;	//!< Ciphertext (out for encrypt, in for decrypt)
    size_t ct_len;	//!< Length of ciphertext buffer
    
    unsigned char *tag;	//!< Authentication tag (out for encrypt, in for decrypt)
    size_t tag_len;	//!< Length of authentication tag

} MC_aesgcm_params;

/**
 * Encrypt data using AES/GCM.
 *
 * @param[in] params See above.
 * @return 1 on sucess, 0 if an error occurs
 */
extern int
MC_AESGCM_encrypt(MC_aesgcm_params *p);

/**
 * Decrypt data using AES/GCM.
 *
 * Note that the authencation tag from decryption is not returned, but the
 * provided tag from encryption is checked against it. If there is a
 * mismatch this function returns an error.
 *
 * @param[in] params See above.
 * @return 1 on sucess, 0 if an error occurs
 */
extern int
MC_AESGCM_decrypt(MC_aesgcm_params *p);

/**
 * Allocate space for a new octet structure.
 *
 * @param[in] size Length of data for octet to hold.
 * @return Pointer to octet or NULL if NOMEM. Contents of O->val are
 *    initialized to zero.
 */
extern octet *
OCT_new(int size);

/**
 * Free previously allocated octet structure.
 *
 * @param[in] O Octet to free.
 * @return MASQ_STATUS_SUCCESS.
 */
extern void
OCT_free(octet *O);

/**
 * Allocate space for BB1_pksk.
 *
 * @param[in] group_size The size of the group in bytes.
 * @return Pointer to BB1_pksk, NULL if allocation fails.
 */
extern BB1_pksk *
BB1_pksk_new(int group_size);

/**
 * Free a BB1_pksk.
 *
 * @param[in] p Pointer to BB1_pksk to free.
 */
extern void
BB1_pksk_free(BB1_pksk *p);

/**
 * Allocate space for BB1_pubparams.
 *
 * @param[in] field_size The size of the finite field in bytes.
 * @return Pointer to BB1_pubparams, NULL if allocation fails.
 */
extern BB1_pubparams *
BB1_pubparams_new(int field_size);

/**
 * Free a BB1_pubparams.
 *
 * @param[in] pp Pointer to BB1_pubparams to free.
 */
extern void
BB1_pubparams_free(BB1_pubparams * pp);

/**
 * Allocate space for BB1_puk.
 *
 * @param[in] field_size The size of the finite field in bytes.
 * @return Pointer to BB1_puk, NULL if allocation fails.
 */
extern BB1_puk *
BB1_puk_new(int field_size);

/**
 * Free a BB1_puk.
 *
 * @param[in] p Pointer to BB1_puk to free.
 */
extern void
BB1_puk_free(BB1_puk *p);

/**
 * Allocate space for BB1_encaps.
 *
 * @pram[in] field_size The size of the finite field in bytes.
 * @return Pointer to BB1_encaps, NULL if allocation fails.
 */
extern BB1_encaps *
BB1_encaps_new(int field_size);

/** @brief Free a BB1_encaps.
 *
 * @pram[in] enc Pointer to BB1_encaps to free.
 */
extern void
BB1_encaps_free(BB1_encaps *enc);

#endif	// IBE_H_INCLUDED
