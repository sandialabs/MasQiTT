/** Implementation of the BB1 identity-based KEM and BB1 IBE.
 *
 * This implementation largely follows the description as provided by IEEE
 * 1363.3 IEEE Standard for Identity-Based Cryptographic Techniques using
 * Pairings, though we shall feel free to use pre-existing primitives from
 * the MIRACL library where appropriate as opposed to implementing our own
 * from the standard.
 *
 * Also found here: crypto primitives -- PRNG, SHA256, and AES/GCM routines
 * to collect the pain of calling MIRACL Core routines into one place. "MC_"
 * prefix: MIRACL Core
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include "ibe.h"
#include "randapi.h"

/** hash_to_field taken from bls.c */
#ifndef CEIL
#define CEIL(a, b) (((a)-1)/(b)+1)
#endif

#ifndef MIN
#define MIN(a, b) \
  ({ typeof (a) _a = (a); \
     typeof (b) _b = (b); \
     _a < _b ? _a : _b; })
#endif

#ifdef	ebug
#define	DSTATIC
#else
#define	DSTATIC	static
#endif

#undef	_clear
#define	_clear(x)	memset((void *) &x, 0, sizeof(x))
#define	_clearx(x)	memset((void *) x, 0, sizeof(x))

/** output u[i] \in F_p
 * https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/
 *
 * @brief Hash to a finite field.
 *
 * @param[in] hash The hash family of SHA2 (MC_SHA2) or SHA3 (MC_SHA3)
 * @param[in] hlen The SHA output length. In this case it will come
 *            from the curve.
 * @param[out] u Array of outputs.
 * @param[in] DST A domain separation tag
 * @param[in] M The input message.
 * @param[in] ctr The number of elements in the field to output (i.e.,
 *            the size of u).
 */
static void
hash_to_field(int hash, int hlen, FP_BN254 *u, octet *DST, octet *M, int ctr)
{
    int		i, j, L, nbq;
    BIG_256_56	q, w;
    DBIG_256_56	dx;
    char	fd[128];
    octet	*OKM = OCT_new(256);

    BIG_256_56_rcopy(q, Modulus_BN254);
    nbq = BIG_256_56_nbits(q);
    L = CEIL(nbq + CURVE_SECURITY_BN254, 8);
    XMD_Expand(hash, hlen, OKM, L * ctr, DST, M);

    for (i = 0; i < ctr; i++) {
        for (j = 0; j < L; j++) {
            fd[j] = OKM->val[i * L + j];
	}
        BIG_256_56_dfromBytesLen(dx, fd, L);
        BIG_256_56_ctdmod(w, dx, q, 8 * L - nbq);
        FP_BN254_nres(&u[i], w);
    }
    OCT_free(OKM);
}

/*****************/
/* BB1 functions */
/*****************/

MASQ_status_t
BB1_BN254_setup(BB1_pubparams *PP, BB1_pksk *sks)
{
    if ((PP == NULL) || (sks == NULL)) {
	return MASQ_ERR_INVAL;
    }
    
    // Extracting generating points for G1 and G2
    ECP_BN254	Q1_point;
    ECP2_BN254	Q2_point;

    //octet Q1, Q2
    if (!ECP_BN254_generator(&Q1_point)) {
	return MASQ_ERR_MIRACL;
    }
    if (!ECP2_BN254_generator(&Q2_point)) {
	return MASQ_ERR_MIRACL;
    }

    // Get the random number generator
    csprng	*RNG = MC_get_RNG();

    // Generate the secrets
    // The secrets should be modulo the group order. So, we should
    // generate them that way directly and then turn them to octets
    
    BIG_256_56	curve_order;		// curve order
    BIG_256_56_rcopy(curve_order, CURVE_Order_BN254);
    
    BIG_256_56	ps1, ps2, ps3;		// pre-secrets
    BIG_256_56_randomnum(ps1, curve_order, RNG);
    BIG_256_56_toBytes(sks->s1->val, ps1);
    sks->s1->len = BBGS_BN254;

    BIG_256_56_randomnum(ps2, curve_order, RNG);
    BIG_256_56_toBytes(sks->s2->val, ps2);
    sks->s2->len = BBGS_BN254;

    BIG_256_56_randomnum(ps3, curve_order, RNG);
    BIG_256_56_toBytes(sks->s3->val, ps3);
    sks->s3->len = BBGS_BN254;

    // Calculating derived parameters
    ECP_BN254	R;
    ECP_BN254	T;
    ECP2_BN254	pV;
    FP12_BN254	V;

    ECP_BN254_copy(&R, &Q1_point);	// Mult is in place, so need copy
    PAIR_BN254_G1mul(&R, ps1);

    ECP_BN254_copy(&T, &Q1_point);
    PAIR_BN254_G1mul(&T, ps3);

    ECP2_BN254_copy(&pV, &Q2_point);
    PAIR_BN254_G2mul(&pV, ps2);

    PAIR_BN254_ate(&V, &pV, &R);

    PAIR_BN254_fexp(&V);

    // Store off in PP
    ECP_BN254_toOctet(PP->R, &R, false);
    ECP_BN254_toOctet(PP->T, &T, false);
    FP12_BN254_toOctet(PP->V, &V);

    _clear(Q1_point);
    _clear(Q2_point);
    _clear(curve_order);
    _clear(ps1);
    _clear(ps2);
    _clear(ps3);
    _clear(R);
    _clear(T);
    _clear(pV);
    _clear(V);

    return MASQ_STATUS_SUCCESS;
}

MASQ_status_t
BB1G_BN254_extract(BB1_pubparams *PP, BB1_pksk *sks, octet *id, BB1_puk *pk)
{
    // We want to replace this with HashToRange
    BIG_256_56	id_big;
    FP_BN254	u[1];

    if ((PP == NULL) || (sks == NULL) || (id == NULL) || (pk == NULL)) {
	return MASQ_ERR_INVAL;
    }

    octet	*DST = OCT_new(8);
    if (DST == NULL) {
        return MASQ_ERR_NOMEM;
    }

    OCT_jstring(DST, (char *) "BB1_SHA2");
    hash_to_field(MC_SHA2, HASH_TYPE_BN254, u, DST, id, 1);
    OCT_free(DST);
    FP_BN254_redc(id_big, u);	// u is a pointer to the first and only value

    // Get the random number generator
    csprng	*RNG = MC_get_RNG();

    BIG_256_56	group_order, r;

    BIG_256_56_rcopy(group_order, CURVE_Order_BN254);
    BIG_256_56_randomnum(r, group_order, RNG);

    BIG_256_56	s1, s2, s3;

    BIG_256_56_fromBytes(s1, (sks->s1)->val);
    BIG_256_56_fromBytes(s2, (sks->s2)->val);
    BIG_256_56_fromBytes(s3, (sks->s3)->val);

    // s1*s3 + r(s1*M + s3)
    // not sure if these functions are safe to reuse variables in
    BIG_256_56	s1M, s1Ms3, rs1Ms3, s1s2, result;

    BIG_256_56_modmul(s1M, s1, id_big, group_order);	// s1M
    BIG_256_56_modadd(s1Ms3, s1M, s3, group_order);	// (s1M + s3)
    BIG_256_56_modmul(rs1Ms3, s1Ms3, r, group_order);	// r(s1M + s3)
    BIG_256_56_modmul(s1s2, s1, s2, group_order);	// s1*s2
    BIG_256_56_modadd(result, s1s2, rs1Ms3, group_order); // s1s2 + r(s1M + s3)

    // K0M = tQ2
    // K1M = rQ2
    ECP2_BN254	K0M, K1M;

    if (!ECP2_BN254_generator(&K0M)) {
        return MASQ_ERR_MIRACL;
    }
    if (!ECP2_BN254_generator(&K1M)) {
        return MASQ_ERR_MIRACL;
    }

    PAIR_BN254_G2mul(&K0M, result);
    PAIR_BN254_G2mul(&K1M, r);

    // Set pk fields
    ECP2_BN254_toOctet(pk->K0M, &K0M, false);
    ECP2_BN254_toOctet(pk->K1M, &K1M, false);

    _clear(s1);
    _clear(s2);
    _clear(s3);
    _clear(s1M);
    _clear(s1Ms3);
    _clear(rs1Ms3);
    _clear(s1s2);
    _clear(result);
    _clear(K0M);
    _clear(K1M);
    
    return MASQ_STATUS_SUCCESS;
}

MASQ_status_t
BB1_BN254_verify_key(BB1_pubparams *PP, octet *id, BB1_puk *pk)
{
    if ((PP == NULL) || (id == NULL) || (pk == NULL)) {
	return MASQ_ERR_INVAL;
    }
    
    // has id.
    BIG_256_56	id_big;
    FP_BN254	u[1];
    octet	*DST = OCT_new(8);
    int		ret;

    if (DST == NULL) {
        return MASQ_ERR_NOMEM;
    }

    OCT_jstring(DST, (char *) "BB1_SHA2");
    hash_to_field(MC_SHA2, HASH_TYPE_BN254, u, DST, id, 1);
    OCT_free(DST);
    FP_BN254_redc(id_big, u);	// u is a pointer to the first and only value

    // T0 = e(Q1, K0M)
    // T1 = e(MR + T, K1M)
    FP12_BN254	T0;
    ECP_BN254	Q1;

    if (!ECP_BN254_generator(&Q1)) {
        return MASQ_ERR_MIRACL;
    }
    
    ECP2_BN254      K0M;

    if (!ECP2_BN254_fromOctet(&K0M, pk->K0M)) {
        return MASQ_ERR_MIRACL;
    }
    PAIR_BN254_ate(&T0, &K0M, &Q1);
    PAIR_BN254_fexp(&T0);

    FP12_BN254	T1;
    ECP_BN254	MR, T;
    ECP2_BN254	K1M;

    if (!ECP_BN254_fromOctet(&MR, PP->R)) {
        return MASQ_ERR_MIRACL;
    }
    PAIR_BN254_G1mul(&MR, id_big);
    if (!ECP_BN254_fromOctet(&T, PP->T)) {
        return MASQ_ERR_MIRACL;
    }
    ECP_BN254_add(&MR, &T);
    if (!ECP2_BN254_fromOctet(&K1M, pk->K1M)) {
        return MASQ_ERR_MIRACL;
    }
    PAIR_BN254_ate(&T1, &K1M, &MR);
    PAIR_BN254_fexp(&T1);

    FP12_BN254	V;

    FP12_BN254_fromOctet(&V, PP->V);
    FP12_BN254_mul(&T1, &V);

    ret = FP12_BN254_equals(&T0, &T1);

    _clear(T0);
    _clear(T1);
    _clear(K0M);
    _clear(K1M);
    _clear(Q1);
    _clear(MR);
    _clear(T);
    _clear(V);
    
    return ret ? MASQ_STATUS_SUCCESS : MASQ_ERR_INVAL;
}

/**
 * BB1-KEM-EN -- Encapsulate method.
 *
 * @param[in] PP The public parameters.
 * @param[in] id The user's identity.
 * @param[out] ct The key encapsulated ciphertext.
 * @param[out] ss The key, size of HASH_TYPE_BN254.
 * @return MASQ_STATUS_SUCCESS if no error; otherwise MASQ_ERR_MIRACL for
 *    problems returned by MIRACL Core library or MASQ_ERR_NOMEM if `octet`
 *    allocation fails.
 */
DSTATIC MASQ_status_t
BB1S_BN254_encapsulate(BB1_pubparams *PP, octet *id, BB1_encaps *ct, octet *ss)
{
    MASQ_status_t	return_value = MASQ_STATUS_SUCCESS;
    
    if ((PP == NULL) || (id == NULL) || (ct == NULL) || (ss == NULL)) {
	return MASQ_ERR_INVAL;
    }
    
    // Get the random number generator
    csprng	*RNG = MC_get_RNG();

    BIG_256_56	group_order, r;

    BIG_256_56_rcopy(group_order, CURVE_Order_BN254);
    BIG_256_56_randomnum(r, group_order, RNG);

    ECP_BN254	E0;

    if (!ECP_BN254_generator(&E0)) {
        return MASQ_ERR_MIRACL;
    }
    PAIR_BN254_G1mul(&E0, r);
    ECP_BN254_toOctet(ct->E0, &E0, false);

    // Get group element for identity
    BIG_256_56	id_big;
    FP_BN254	u[1];
    octet	*DST = OCT_new(8);

    if (DST == NULL) {
        return MASQ_ERR_NOMEM;
    }

    OCT_jstring(DST, (char *) "BB1_SHA2");
    hash_to_field(MC_SHA2, HASH_TYPE_BN254, u, DST, id, 1);
    OCT_free(DST); DST = NULL;
    FP_BN254_redc(id_big, u);	// u is a pointer to the first and only value

    // (rM)R + rT
    ECP_BN254	E1, T;

    if (!ECP_BN254_fromOctet(&E1, PP->R)) {	// E1 = R
        return_value = MASQ_ERR_MIRACL;
	goto encaps_error;
    }
    if (!ECP_BN254_fromOctet(&T, PP->T)) {	// T = T
        return_value = MASQ_ERR_MIRACL;
	goto encaps_error;
    }

    BIG_256_56	rM;

    BIG_256_56_modmul(rM, r, id_big, group_order);

    PAIR_BN254_G1mul(&E1, rM);	// E1 = (rM)R
    PAIR_BN254_G1mul(&T, r);	// T = rT
    ECP_BN254_add(&E1, &T);	// E1 = (rM)R + rT

    ECP_BN254_toOctet(ct->E0, &E0, false);
    ECP_BN254_toOctet(ct->E1, &E1, false);

    // B = V^r
    // hash B
    FP12_BN254	V, Vr;

    FP12_BN254_fromOctet(&V, PP->V);
    FP12_BN254_pow(&Vr, &V, r);

    octet	*oct_vr = OCT_new(12 * BBFS_BN254);

    if (oct_vr == NULL) {
        return_value = MASQ_ERR_MIRACL;
	goto encaps_error;
    }
    FP12_BN254_toOctet(oct_vr, &Vr);

    // now we hash
    SPhash(MC_SHA2, HASH_TYPE_BN254, ss, oct_vr);

    ss->len = MIN(HASH_TYPE_BN254, AESKEY_BN254);

 encaps_error:

    OCT_free(oct_vr);
    _clear(group_order);
    _clear(r);
    _clear(E0);
    _clear(E1);
    _clear(id_big);
    _clearx(u);
    _clear(T);
    _clear(rM);
    _clear(V);
    _clear(Vr);
    
    return return_value;
}

DSTATIC MASQ_status_t
BB1S_BN254_decapsulate(octet *id, BB1_puk *pk, BB1_encaps *ct, octet *ss)
{
    MASQ_status_t	return_value = MASQ_STATUS_SUCCESS;
    // We want to replace this with HashToRange
    // This is also probably enough code to put in
    // its own function.
    // Get group element for identity
    BIG_256_56	id_big;
    FP_BN254	u[1];
    
    if ((id == NULL) || (pk == NULL) || (ct == NULL) || (ss == NULL)) {
	return MASQ_ERR_INVAL;
    }
    
    octet	*DST = OCT_new(8);

    if (DST == NULL) {
        return MASQ_ERR_NOMEM;
    }

    OCT_jstring(DST, (char *) "BB1_SHA2");
    hash_to_field(MC_SHA2, HASH_TYPE_BN254, u, DST, id, 1);
    OCT_free(DST);
    FP_BN254_redc(id_big, u);	// u is a pointer to the first and only value

    // B = e(E0, K0M)/e(E1, K1M) = e(E0, K0M)e(-E1, K1M)
    // MIRACL does G2 \times G1 so we have to flip everything

    FP12_BN254	result;
    ECP_BN254	E0, E1;
    ECP2_BN254	K0M, K1M;

    if (!ECP_BN254_fromOctet(&E0, ct->E0)) {
	return_value = MASQ_ERR_MIRACL;
	goto decaps_error;
    }
    if (!ECP_BN254_fromOctet(&E1, ct->E1)) {
	return_value = MASQ_ERR_MIRACL;
	goto decaps_error;
    }
    if (!ECP2_BN254_fromOctet(&K0M, pk->K0M)) {
	return_value = MASQ_ERR_MIRACL;
	goto decaps_error;
    }
    if (!ECP2_BN254_fromOctet(&K1M, pk->K1M)) {
	return_value = MASQ_ERR_MIRACL;
	goto decaps_error;
    }
    ECP_BN254_neg(&E1);

    PAIR_BN254_double_ate(&result, &K0M, &E0, &K1M, &E1);
    PAIR_BN254_fexp(&result);

    octet	*oct_vr = OCT_new(12 * BBFS_BN254);

    if (oct_vr == NULL) {
        return_value = MASQ_ERR_NOMEM;
	goto decaps_error;
    }
    FP12_BN254_toOctet(oct_vr, &result);

    SPhash(MC_SHA2, HASH_TYPE_BN254, ss, oct_vr);

    ss->len = MIN(HASH_TYPE_BN254, AESKEY_BN254);

 decaps_error:

    OCT_free(oct_vr);
    _clear(id_big);
    _clearx(u);
    _clear(result);
    _clear(E0);
    _clear(E1);
    _clear(K0M);
    _clear(K1M);
    
    return return_value;
}

#define	ENCRYPTION_OVERHEAD	(MASQ_ENCAPS_KEY_LEN + BB1_IVLEN + BB1_TAGLEN)

int
BB1_encrypt_size(int plaintext_size)
{
    // The ciphertext contains the encapsulated key BB1_encaps, the AES-GCM
    // IV, the encrypted text, and the tag.
    return plaintext_size + ENCRYPTION_OVERHEAD;
}

int
BB1_decrypt_size(int ciphertext_size)
{
    // The ciphertext contains the encapsulated key BB1_encaps, the AES-GCM
    // IV, the encrypted text, and the tag.
    return ciphertext_size - ENCRYPTION_OVERHEAD;
}

MASQ_status_t
BB1_encapsulate_key(BB1_pubparams *PP, octet *id,
		    octet *key, BB1_encaps *enc_key)
{
    BB1_encaps	*ct         = BB1_encaps_new(BBFS_BN254);
    octet	*ss         = OCT_new(BB1_HASHLEN);
    MASQ_status_t	return_value = MASQ_STATUS_SUCCESS;
    
    if ((PP == NULL) || (id == NULL) || (enc_key == NULL) ||
	(key == NULL) || (key->max < BB1_AESKEYLEN)) {
        return_value = MASQ_ERR_INVAL;
        goto encaps_error;
    }
    
    if ((ct == NULL) || (ss == NULL)) {
        return_value = MASQ_ERR_NOMEM;
        goto encaps_error;
    }
    
    // Create encapsulated key
    if (MASQ_STATUS_SUCCESS !=
	(return_value = BB1S_BN254_encapsulate(PP, id, ct, ss))) {
        goto encaps_error;
    }
    OCT_copy(enc_key->E0, ct->E0);
    OCT_copy(enc_key->E1, ct->E1);
    BB1_encaps_free(ct); ct = NULL;

    // Derive AES key
    key->len = 0;
    OCT_jbytes(key, ss->val, key->max);
    OCT_free(ss); ss = NULL;
    
 encaps_error:

    BB1_encaps_free(ct);
    OCT_free(ss);

    return return_value;
}

MASQ_status_t
BB1_decapsulate_key(BB1_puk *puk, octet *id, octet *ct, octet *key)
{
    BB1_encaps	*enc_key = BB1_encaps_new(BBFS_BN254);
    octet	*ss      = OCT_new(BB1_HASHLEN);
    MASQ_status_t	return_value = MASQ_STATUS_SUCCESS;
    
    if ((puk == NULL) || (id == NULL) || (ct == NULL) || (key == NULL)) {
        return_value = MASQ_ERR_INVAL;
        goto decaps_error;
    }
    
    if (key->max < BB1_AESKEYLEN) {
        return_value = MASQ_ERR_NOSPACE;
        goto decaps_error;
    }
    
    if ((ct == NULL) || (ss == NULL)) {
        return_value = MASQ_ERR_NOMEM;
        goto decaps_error;
    }

    // extract encapsulated key
    OCT_jbytes(enc_key->E0, ct->val, (2 * BBFS_BN254) + 1);
    OCT_jbytes(enc_key->E1,
	       &ct->val[(2 * BBFS_BN254) + 1], (2 * BBFS_BN254) + 1);
    
    // Recover encapsulated key
    if (MASQ_STATUS_SUCCESS !=
	(return_value = BB1S_BN254_decapsulate(id, puk, enc_key, ss))) {
        goto decaps_error;
    }
    BB1_encaps_free(enc_key); enc_key = NULL;

    // Derive AES key
    key->len = 0;
    OCT_jbytes(key, ss->val, key->max);
    OCT_free(ss); ss = NULL;
    
 decaps_error:

    BB1_encaps_free(enc_key);
    OCT_free(ss);

    return return_value;
}

MASQ_status_t
BB1_encrypt(BB1_pubparams *PP, octet *id, octet *header,
	    octet *plaintext, octet *ciphertext)
{
    // The ciphertext is packed with the asymmetric encapsulated key
    // (bb1en), the AES-GCM IV, the encrypted text, and the
    // tag. Structurally, it is packed as
    // bb1en || IV || tag || AES blocks

    if ((PP == NULL) || (id == NULL) || (header == NULL) ||
	(plaintext == NULL) || (ciphertext == NULL)) {
	return MASQ_ERR_INVAL;
    }
    
    int	return_value = MASQ_STATUS_SUCCESS;

    BB1_encaps	*ct         = BB1_encaps_new(BBFS_BN254);
    octet	*ss         = OCT_new(BB1_HASHLEN);
    octet	*key        = OCT_new(BB1_AESKEYLEN);
    octet	*aes_cipher = OCT_new(plaintext->len);
    octet	*IV         = OCT_new(BB1_IVLEN);
    octet	*checksum   = OCT_new(BB1_TAGLEN);

    if (ciphertext->len < BB1_encrypt_size(plaintext->len)) {
	return_value = MASQ_ERR_NOSPACE;
	goto encrypt_error;
    }

    if ((ct == NULL) || (ss == NULL) || (key == NULL) || (aes_cipher == NULL)
        || (IV == NULL) || (checksum == NULL)) {
        return_value = MASQ_ERR_NOMEM;
        goto encrypt_error;
    }
    
    // Get the random number generator
    csprng	*RNG = MC_get_RNG();

    if (MASQ_STATUS_SUCCESS !=
	(return_value = BB1S_BN254_encapsulate(PP, id, ct, ss))) {
        goto encrypt_error;
    }
    
    // Pack on encapsulated key
    OCT_jbytes(ciphertext, ct->E0->val, ct->E0->len);
    OCT_jbytes(ciphertext, ct->E1->val, ct->E1->len);
    BB1_encaps_free(ct); ct = NULL;

    // Derive AES key
    OCT_jbytes(key, ss->val, key->max);
    OCT_free(ss); ss = NULL;

    // AES/GCM encrypt plaintext
    OCT_rand(IV, RNG, IV->max);
    AES_GCM_ENCRYPT(key, IV, header, plaintext, aes_cipher, checksum);
    OCT_free(key); key = NULL;

    // Return ciphertext
    OCT_jbytes(ciphertext, IV->val, IV->len);
    OCT_jbytes(ciphertext, checksum->val, checksum->len);
    OCT_jbytes(ciphertext, aes_cipher->val, aes_cipher->len);
    OCT_free(IV); IV = NULL;
    OCT_free(checksum); checksum = NULL;
    OCT_free(aes_cipher); aes_cipher = NULL;

  encrypt_error:

    BB1_encaps_free(ct);
    OCT_free(ss);
    OCT_free(key);
    OCT_free(aes_cipher);
    OCT_free(IV);
    OCT_free(checksum);

    return return_value;
}

MASQ_status_t
BB1_decrypt(octet *id, BB1_puk *pk, octet *header,
	    octet *ciphertext, octet *plaintext)
{
    // The ciphertext is packed with the asymmetric encapsulated key
    // (bb1enc), the AES-GCM IV, the encrypted text, and the
    // tag. Structurally, it is packed as
    // bb1en || IV || tag || AES blocks

    if ((id == NULL) || (pk == NULL) || (header == NULL) ||
	(plaintext == NULL) || (ciphertext == NULL)) {
	return MASQ_ERR_INVAL;
    }
    
    int	return_value = MASQ_STATUS_SUCCESS;

    int	aes_cipher_length = BB1_decrypt_size(ciphertext->len);

    BB1_encaps	*ct            = BB1_encaps_new(BBFS_BN254);
    octet	*IV            = OCT_new(BB1_IVLEN);
    octet	*sent_checksum = OCT_new(BB1_TAGLEN);
    octet	*ss            = OCT_new(BB1_HASHLEN);
    octet	*calc_checksum = OCT_new(BB1_TAGLEN);
    octet	*aes_cipher    = OCT_new(aes_cipher_length);
    octet	*key           = OCT_new(BB1_AESKEYLEN);

    if (plaintext->len < aes_cipher_length) {
	return_value = MASQ_ERR_NOSPACE;
	goto decrypt_error;
    }

    if ((ct == NULL) || (IV == NULL) || (sent_checksum == NULL) || (ss == NULL)
        || (calc_checksum == NULL) || (aes_cipher == NULL) || (key == NULL)) {
        return_value = MASQ_ERR_NOMEM;
        goto decrypt_error;
    }

    // Extract fields from ciphertext blob
    OCT_jbytes(ct->E0, ciphertext->val, (2 * BBFS_BN254) + 1);
    OCT_jbytes(ct->E1, &ciphertext->val[(2 * BBFS_BN254) + 1],
	       (2 * BBFS_BN254) + 1);
    OCT_jbytes(IV, &ciphertext->val[MASQ_ENCAPS_KEY_LEN], IV->max);
    OCT_jbytes(sent_checksum, &ciphertext->val[MASQ_ENCAPS_KEY_LEN + IV->len],
	       sent_checksum->max);
    OCT_jbytes(aes_cipher,
	       &ciphertext->val[MASQ_ENCAPS_KEY_LEN + IV->len +
				sent_checksum->len],
	       aes_cipher_length);

    if (MASQ_STATUS_SUCCESS !=
	(return_value = BB1S_BN254_decapsulate(id, pk, ct, ss))) {
        goto decrypt_error;
    }
    BB1_encaps_free(ct); ct = NULL;

    // Recover AES encryption key
    OCT_jbytes(key, ss->val, key->max);
    OCT_free(ss); ss = NULL;

    // Return decrypted plaintext
    AES_GCM_DECRYPT(key, IV, header, aes_cipher, plaintext, calc_checksum);
    if (! OCT_comp(calc_checksum, sent_checksum)) {
	return_value = MASQ_ERR_DECRYPT;
	goto decrypt_error;
    }
    
    OCT_free(key); key = NULL;
    OCT_free(aes_cipher); aes_cipher = NULL;
    OCT_free(IV); IV = NULL;
    OCT_free(sent_checksum); sent_checksum = NULL;
    OCT_free(calc_checksum); calc_checksum = NULL;

  decrypt_error:

    BB1_encaps_free(ct);
    OCT_free(IV);
    OCT_free(sent_checksum);
    OCT_free(calc_checksum);
    OCT_free(aes_cipher);
    OCT_free(ss);
    OCT_free(key);

    return return_value;
}

static const char	*_protoid = "1.0/1";
static int	_crypto_init = 0;
static csprng	_RNG = { 0 };   // CSPRNG source
static bool	_RNG_Initialized = false;
static void	MC_initialize_RNG(void);

MASQ_status_t
MC_crypto_init(const char *protoid)
{
    if (_crypto_init) {
	return MASQ_STATUS_SUCCESS;
    }

    if ((NULL == protoid) || strncmp(protoid, _protoid, 16)) {
	return MASQ_ERR_BAD_PROTOID;
    }

    MC_initialize_RNG();

    _crypto_init = 1;
    return MASQ_STATUS_SUCCESS;
}

void
MC_crypto_close(void)
{
    if (_RNG_Initialized) {
	KILL_CSPRNG(&_RNG);
	_RNG_Initialized = false;
    }
}

/**
 * Random number generator setup
 */

/* used by create_seed() to churn seed bytes
 * nothing special about these values, originally grabbed from /dev/random
 */
static char     _xor[] = {
    0x86, 0x10, 0x6e, 0xf8, 0x3a, 0xaf, 0xa6, 0x86,
    0xb3, 0xc0, 0x88, 0x82, 0x62, 0xd0, 0xd6, 0x6b,
    0xe7, 0xa8, 0x74
};
#define XOR_LEN sizeof(_xor)

static bool     _seed_init = false;
static pid_t    _seed_pid;
static char     _seed_cnt = 0;

/** @brief create a seed for use in initializing the RNG.
 *
 * @param[out] seed The created seed value.
 */
static void
create_seed(octet *seed)
{

    pid_t	pid;
    time_t	tim = time((time_t *) 0);
    int		i, j;
    char	bias = tim & 0xff;
    char	randbuf[16];
    int		fd, n;

    if (!_seed_init) {
        _seed_pid = getpid();
        _seed_cnt = _seed_pid & 0xff;
        _seed_init = true;
    }

    pid = _seed_pid;

    for (i = 0; (i < seed->max) && (i < 4); i++) {
        seed->val[i] = (tim + _seed_cnt) & 0xff;
        tim >>= 8;
    }
    while ((i < seed->max) && (i < 6)) {
        seed->val[i] = pid & 0xff;
        pid >>= 8;
        i++;
    }

#define RAND_FILE "/dev/random"
    // Best effort reading from RAND_FILE, which may not return full request.
    if (!access(RAND_FILE, R_OK)) {
        if (0 <= (fd = open(RAND_FILE, O_RDONLY | O_NDELAY))) {
	    for (j = 0; j < ((seed->max - 6) / sizeof(randbuf)); j++) {
		n = read(fd, (void *) randbuf, sizeof(randbuf));
		while ((i < seed->max) && (0 < n)) {
		    seed->val[i++] = randbuf[--n];
		}
	    }
	    close(fd);
        }
    }
    
    // Pad out remaining bytes
    n = i;
    for (/*nope*/; i < seed->max; i++) {
        seed->val[i] = (seed->val[i - n] + bias + i + _seed_cnt) & 0xff;
    }
    // Flip about half the bits
    for (i = 0; i < seed->max; i++) {
        seed->val[i] ^= _xor[(_seed_cnt + i) % XOR_LEN];
    }

    // If this gets called again with the same time_t value and
    // /dev/random does not exist or is returning no data, make sure the
    // next seed is permuted (XORed) differently than the current seed.
    _seed_cnt = (_seed_cnt + 3) & 0xff;

    // Bytes used in the octet
    seed->len = seed->max;
}


/**
 * Initialize a random number generator if it has not already been.
 *
 * The random number generator instance is stored as _RNG and this function
 * will initialize _RNG if it has not already been initialized. Otherwise,
 * this function will return the _RNG instance. Functions should not access
 * _RNG directly, but should use this function to ensure that _RNG is
 * initialized before use.
 */
static void
MC_initialize_RNG(void)
{
    if (!_RNG_Initialized) {

        octet	*RAW = OCT_new(128);

	if (RAW) {
	    create_seed(RAW);
	    CREATE_CSPRNG(&_RNG, RAW);      //initialize RNG
	    OCT_free(RAW);
	} else {
	    // degraded mode
	    octet	BADRAW = { .val = "a97tE08hgu6d", .len = 12, .max = 12 };
	    fprintf(stderr, "DANGER! Poor RNG seeding\n");
	    CREATE_CSPRNG(&_RNG, &BADRAW);
	}
	_RNG_Initialized = true;
    }
}

/*
 * Provided for the benefit of make_params, but not otherwise documented.
 */
void
MC_seed_RNG(unsigned char *buf, size_t len)
{
    octet	seed;
    
    if (_RNG_Initialized) {
	// starting over
	KILL_CSPRNG(&_RNG);
    }

    seed.val = (char *) buf;
    seed.len = seed.max = (int) len;
    CREATE_CSPRNG(&_RNG, &seed);      //initialize RNG

    _RNG_Initialized = true;
}

csprng *
MC_get_RNG(void)
{
    MC_initialize_RNG();	// just in case
    return &_RNG;
}

/*
 * MIRACL Core handles data as `octet`s, while the code calling these
 * routines speak pointers and data lengths. These macros translate the
 * latter into the former.
 */
// for octets used as input
#define	inbuf_to_octet(OCT, p, l) \
    do { OCT.val = (char *) p; OCT.len = OCT.max = (int) l; } while (0)
// for octets used as output
#define	outbuf_to_octet(OCT, p, l) \
    do { OCT.val = (char *) p; OCT.len = 0; OCT.max = (int) l; } while (0)

void
MC_rand_bytes(unsigned char *buf, size_t len)
{
    octet	r;
    outbuf_to_octet(r, buf, len);
    OCT_rand(&r, &_RNG, r.max);
}

int
MC_hash(unsigned char *inbuf, size_t inlen,
	unsigned char *outbuf, size_t outlen)
{
    hash256	H;
    char	*cp = (char *) inbuf;
    size_t	i;
    
    if ((NULL == inbuf) || (NULL == outbuf) || (outlen < BB1_HASHLEN)) {
	fprintf(stderr, "%s:%d: bad params\n", __FUNCTION__, __LINE__);
	return 0;
    }

    HASH256_init(&H);
    for (i = 0; i < inlen; i++) {
	HASH256_process(&H, *cp++);
    }
    HASH256_hash(&H, (char *) outbuf);
}

void *
MC_hash_init(unsigned char *inbuf, size_t inlen)
{
    hash256	*H = (hash256 *) calloc(1, sizeof(hash256));
    char	*cp = (char *) inbuf;
    size_t	i;

    if (NULL == H) {
	return NULL;
    }

    HASH256_init(H);
    
    if (NULL != inbuf)  {
	for (i = 0; i < inlen; i++) {
	    HASH256_process(H, *cp++);
	}
    }

    return (void *) H;
}

int
MC_hash_add(void *ctx,
	    unsigned char *inbuf, size_t inlen,
	    unsigned char *outbuf, size_t outlen)
{
    hash256	*H = (hash256 *) ctx;
    char	*cp = (char *) inbuf;
    size_t	i;

    if ((NULL == ctx) ||
	((NULL == inbuf) && (NULL == outbuf)) ||
	((NULL != outbuf) && (outlen < BB1_HASHLEN))) {
	fprintf(stderr, "%s:%d: bad params\n", __FUNCTION__, __LINE__);
	return 0;
    }
    
    for (i = 0; i < inlen; i++) {
	HASH256_process(H, *cp++);
    }

    if (NULL != outbuf) {
	HASH256_hash(H, (char *) outbuf);
	free(H);
    }

    return 1;
}

/*
 * Base 64 routines provided here as MIRACL Core support of Base 64 encoding
 * assumes '\0'-terminated strings on input, rather than arbitrary binary
 * data as here.
 */
static char	*_b64_e =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";
static int	_b64_d[256];
static int	_b64_init = 0;

int
MC_base64_encode(unsigned char *inbuf, size_t inbuf_len,
		 char *outbuf, size_t outbuf_len, int pad)
{
    int		i;
    int		a, b, c, d;
    char	*outp = outbuf;

    //printf("%s(%lu, %lu)\n", __FUNCTION__, inbuf_len, outbuf_len);

    if ((NULL == inbuf) || (NULL == outbuf) ||
	(outbuf_len < MC_B64ENC_LEN(inbuf_len) + 1)) {
	return 0;
    }

    for (i = 0; i <= (inbuf_len - 2); i += 3) {
	a = (inbuf[i] >> 2) & 0x3f;
	b = ((inbuf[i] & 0x3) << 4) + ((inbuf[i+1] >> 4) & 0xf);
	c = ((inbuf[i+1] & 0xf) << 2) + ((inbuf[i+2] >> 6) & 0x3);
	d = inbuf[i+2] & 0x3f;
	//printf("%02x %02x %02x %02x\n", a, b, c, d);
	*outp++ = _b64_e[a];
	*outp++ = _b64_e[b];
	*outp++ = _b64_e[c];
	*outp++ = _b64_e[d];
    }

    switch (inbuf_len - i) {
    case 1:
	a = (inbuf[i] >> 2) & 0x3f;
	b = ((inbuf[i] & 0x3) << 4);
	//printf("%02x %02x\n", a, b);
	*outp++ = _b64_e[a];
	*outp++ = _b64_e[b];
	if (pad) {
	    *outp++ = '=';
	    *outp++ = '=';
	}
	break;
    case 2:
	a = (inbuf[i] >> 2) & 0x3f;
	b = ((inbuf[i] & 0x3) << 4) + ((inbuf[i+1] >> 4) & 0xf);
	c = ((inbuf[i+1] & 0xf) << 4);
	//printf("%02x %02x %02x\n", a, b, c);
	*outp++ = _b64_e[a];
	*outp++ = _b64_e[b];
	*outp++ = _b64_e[c];
	if (pad) {
	    *outp++ = '=';
	}
    }

    *outp = '\0';

    return 1;
}

int
MC_base64_decode(char *inbuf, size_t inbuf_len,
		   unsigned char *outbuf, size_t *outbuf_len)
{
    size_t		i, n;

    //printf("%s(%lu, %lu) vs %lu\n", __FUNCTION__,
    //	   inbuf_len, *outbuf_len, MC_B64DEC_LEN(inbuf_len));
    
    if ((NULL == inbuf) || (NULL == outbuf) ||
	(NULL == outbuf_len) ||
	(*outbuf_len < MC_B64DEC_LEN(inbuf_len) - 3)) {
	return 0;
    }

    if (! _b64_init) {
	for (i = 0; i < 256; i++) _b64_d[i] = -1;
	for (i = 0; i < strlen(_b64_e); i++) {
	    _b64_d[(int) _b64_e[i]] = i;
	}
	_b64_init = 1;
    }

    for (i = n = 0; i <= (inbuf_len - 3); i += 4) {
	
	if ((0 > _b64_d[(int) inbuf[i]]) || (0 > _b64_d[(int) inbuf[i+1]]) ||
	    (('=' != inbuf[i+2]) && (0 > _b64_d[(int) inbuf[i+2]])) ||
	    (('=' != inbuf[i+3]) && (0 > _b64_d[(int) inbuf[i+3]]))) {
	    fprintf(stderr, "bad char!\n");
	    return 0;
	}
	
	outbuf[n++] = (_b64_d[(int) inbuf[i]] << 2) +
	    (_b64_d[(int) inbuf[i+1]] >> 4);
	if ('=' == inbuf[i+2]) {
	    goto b64d_out;
	}
	outbuf[n++] = ((_b64_d[(int) inbuf[i+1]] & 0xf) << 4) +
	    (_b64_d[(int) inbuf[i+2]] >> 2);
	if ('=' == inbuf[i+3]) {
	    goto b64d_out;
	}
	outbuf[n++] = ((_b64_d[(int) inbuf[i+2]] & 0x3) << 6) +
	    _b64_d[(int) inbuf[i+3]];
    }

    if ((inbuf_len - i) > 1) {
	if ((0 > _b64_d[(int) inbuf[i]]) || (0 > _b64_d[(int) inbuf[i+1]])) {
	    fprintf(stderr, "bad char!\n");
	    return 0;
	}
	outbuf[n++] = (_b64_d[(int) inbuf[i]] << 2) +
	    (_b64_d[(int) inbuf[i+1]] >> 4);

	if ((inbuf_len - i) > 2) {
	    if (0 > _b64_d[(int) inbuf[i+2]]) {
		fprintf(stderr, "bad char!\n");
		return 0;
	    }
	    outbuf[n++] = ((_b64_d[(int) inbuf[i+1]] & 0xf) << 4) +
		(_b64_d[(int) inbuf[i+2]] >> 2);
	}
    }

 b64d_out:
    *outbuf_len = n;

    return 1;
}

int
MC_AESGCM_encrypt(MC_aesgcm_params *p)
{
    octet	KEY, IV, HDR, PT, CT, TAG;

    /* validate parameters */
    if ((NULL == p) || (NULL == p->iv) || (NULL == p->key) ||
	(NULL == p->pt) || (NULL == p->ct) || (NULL == p->tag)) {
	fprintf(stderr, "NULL arg passed to %s\n", __FUNCTION__);
	return 0;
    }
    
    if ((BB1_IVLEN != p->iv_len) || (BB1_AESKEYLEN != p->key_len) ||
	(0 == p->pt_len) || (0 == p->ct_len) || (BB1_TAGLEN > p->tag_len) ||
	(p->ct_len < p->pt_len)) {
	fprintf(stderr, "bad length passed to %s\n", __FUNCTION__);
	fprintf(stderr, "  iv_len=%ld, key_len=%ld, pt_len=%ld "
		"ct_len=%ld, tag_len=%ld\n",
		p->iv_len, p->key_len, p->pt_len, p->ct_len, p->tag_len);
	return 0;
    }
    
    if (NULL == p->hdr) {
	p->hdr_len = 0;
    }

    inbuf_to_octet(KEY, p->key, p->key_len);
    inbuf_to_octet(IV, p->iv, p->iv_len);
    inbuf_to_octet(HDR, p->hdr, p->hdr_len);
    inbuf_to_octet(PT, p->pt, p->pt_len);
    outbuf_to_octet(CT, p->ct, p->ct_len);
    outbuf_to_octet(TAG, p->tag, p->tag_len);
    
    AES_GCM_ENCRYPT(&KEY, &IV, &HDR, &PT, &CT, &TAG);

    return 1;
}

int
MC_AESGCM_decrypt(MC_aesgcm_params *p)
{
    int		return_value = 1;
    octet	KEY, IV, HDR, CT, PT, TAG;

    /* validate parameters */
    if ((NULL == p) || (NULL == p->iv) || (NULL == p->key) ||
	(NULL == p->ct) || (NULL == p->pt) || (NULL == p->tag)) {
	fprintf(stderr, "NULL arg passed to %s\n", __FUNCTION__);
	return 0;
    }
    
    if ((BB1_IVLEN != p->iv_len) || (BB1_AESKEYLEN != p->key_len) ||
	(0 == p->ct_len) || (0 == p->pt_len) || (BB1_TAGLEN > p->tag_len) ||
	(p->pt_len < p->ct_len)) {
	fprintf(stderr, "bad length passed to %s\n", __FUNCTION__);
	fprintf(stderr, "  iv_len=%ld, key_len=%ld, ct_len=%ld "
		"pt_len=%ld, tag_len=%ld\n",
		p->iv_len, p->key_len, p->ct_len, p->pt_len, p->tag_len);
	return 0;
    }
    
    if (NULL == p->hdr) {
	p->hdr_len = 0;
    }

    inbuf_to_octet(KEY, p->key, p->key_len);
    inbuf_to_octet(IV, p->iv, p->iv_len);
    inbuf_to_octet(HDR, p->hdr, p->hdr_len);
    inbuf_to_octet(CT, p->ct, p->ct_len);
    outbuf_to_octet(PT, p->pt, p->pt_len);
    inbuf_to_octet(TAG, p->tag, BB1_TAGLEN);

    octet	*CHECK = OCT_new((int) BB1_TAGLEN);
    if (NULL == CHECK) {
	return 0;
    }
    
    AES_GCM_DECRYPT(&KEY, &IV, &HDR, &CT, &PT, CHECK);

    /* verify correct decryption */
    return_value = OCT_comp(&TAG, CHECK);
    
    OCT_free(CHECK);
    return return_value;
}

octet *
OCT_new(int size)
{
    octet	*octp;
    char	*octvalp;

    if (size <= 0) {
        return NULL;
    }

    /* create octet */
    octp = (octet *) calloc(1, sizeof(octet));
    if (octp == NULL) {
        return NULL;
    }

    octvalp = (char *) calloc(1, size);
    if (octvalp == NULL) {
        free(octp);
        return NULL;
    }

    octp->len = 0;
    octp->max = size;
    octp->val = octvalp;

    return octp;
}

void
OCT_free(octet *O)
{
    if (O == NULL) {
        return;
    }

    if (O->val != NULL) {
	memset(O->val, 0, O->max);
        free(O->val);
        O->val = NULL;
    }
    free(O);
}

BB1_pksk *
BB1_pksk_new(int group_size)
{
    BB1_pksk	*p = (BB1_pksk *) calloc(1, sizeof(BB1_pksk));

    if (p == NULL) {
        return NULL;
    }
    p->s1 = OCT_new(group_size);
    p->s2 = OCT_new(group_size);
    p->s3 = OCT_new(group_size);
    if ((p->s1 == NULL) || (p->s2 == NULL) || (p->s3 == NULL)) {
        OCT_free(p->s1);
        OCT_free(p->s2);
        OCT_free(p->s3);
        free(p);
        return NULL;
    }
    return p;
}

void
BB1_pksk_free(BB1_pksk *p)
{
    if (p == NULL) {
        return;
    }
    OCT_free(p->s1);
    OCT_free(p->s2);
    OCT_free(p->s3);
    free(p);
}

BB1_pubparams *
BB1_pubparams_new(int field_size)
{
    BB1_pubparams	*pp = (BB1_pubparams *) calloc(1, sizeof(BB1_pubparams));

    if (pp == NULL) {
	return MASQ_STATUS_SUCCESS;
    }

    pp->R = OCT_new((2 * field_size) + 1);
    pp->T = OCT_new((2 * field_size) + 1);
    pp->V = OCT_new(12 * field_size);
    if ((pp->R == NULL) || (pp->T == NULL) || (pp->V == NULL)) {
        OCT_free(pp->R);
        OCT_free(pp->T);
        OCT_free(pp->V);
        free(pp);
        return NULL;
    }
    return pp;
}

void
BB1_pubparams_free(BB1_pubparams *pp)
{
    if (pp == NULL) {
	return;
    }
    OCT_free(pp->R);
    OCT_free(pp->T);
    OCT_free(pp->V);
    free(pp);
}

BB1_puk *
BB1_puk_new(int field_size)
{
    BB1_puk	*p = (BB1_puk *) calloc(1, sizeof(BB1_puk));

    if (p == NULL) {
        return NULL;
    }
    p->K0M = OCT_new((4 * field_size) + 1);
    p->K1M = OCT_new((4 * field_size) + 1);
    if ((p->K0M == NULL) || (p->K1M == NULL)) {
        OCT_free(p->K0M);
        OCT_free(p->K1M);
        free(p);
        return NULL;
    }
    return p;
}

void
BB1_puk_free(BB1_puk *p)
{
    if (p == NULL) {
	return;
    }
    OCT_free(p->K0M);
    OCT_free(p->K1M);
    free(p);
}

BB1_encaps *
BB1_encaps_new(int field_size)
{
    BB1_encaps	*enc = (BB1_encaps *) calloc(1, sizeof(BB1_encaps));

    if (enc == NULL) {
        return NULL;
    }
    enc->E0 = OCT_new((2 * field_size) + 1);
    enc->E1 = OCT_new((2 * field_size) + 1);
    if ((enc->E0 == NULL) || (enc->E1 == NULL)) {
        OCT_free(enc->E0);
        OCT_free(enc->E1);
        free(enc);
        return NULL;
    }
    return enc;
}

void
BB1_encaps_free(BB1_encaps *enc)
{
    if (enc == NULL) {
	return;
    }
    OCT_free(enc->E0);
    OCT_free(enc->E1);
    free(enc);
}
