#ifndef	MASQ_CRYPTO_API_H_INCLUDED
#define	MASQ_CRYPTO_API_H_INCLUDED	1

#include "masqlib.h"
/** @file
 *
 * This is your API for MasQiTT crypto magic. Client code should need to
 * #include only @ref api.h. It pulls in the other needed .h files.
 *
 * Publisher code will generally call:
 *
 * - MASQ_crypto_api_init()
 * - MASQ_crypto_api_encrypt()
 * - MASQ_crypto_api_encrypt()
 * - ...
 * - MASQ_crypto_api_close()
 *
 * Subscribers will generally call:
 *
 * - MASQ_crypto_api_init()
 * - MASQ_crypto_api_decrypt()
 * - MASQ_crypto_api_decrypt()
 * - ...
 * - MASQ_crypto_api_close()
 *
 * Of particular interest is the @p MASQ_user_properties_t struct
 * defined in masqlib.h. Calling MASQ_crypto_api_encrypt()
 * returns data in this struct that should be used to create an MQTT
 * PUBLISH packet. Conversely, this struct must be populated with
 * data obtained by parsing a received PUBLISH packet and provided to
 * MASQ_crypto_api_decrypt().
 */

/**
 * Initialize the MasQiTT crypto library.
 *
 * @param[in] protoid Protocol ID
 * @param[in] role MASQ_role_publisher, MASQ_role_subscriber, or MASQ_role_both
 * @param[in] clientid Client ID of caller, '\0'-terminated.
 * @param[in] strategy If a Publisher, MEK encapsulation strategy to use;
 *    else MASQ_key_none.
 * @param[in] strat_val If a Publisher and using persistent MEKs,
 *    threshold criteria for generating a new MEK.
 * @param[in] kms_host Name or address of KMS host ('\0'-terminated string);
 *    if NULL, use "localost"
 * @param[in] kms_port TCP/IP port KMS listens on; if <= 0, use default
 * @param[in] ca_file File containing CA TLS certificate(s)
 * @param[in] cert_file File containing my TLS certificate
 * @param[in] key_file File containing my TLS private key
 * @param[out] state Pointer to crypto state information, must be provided to other API calls.
 * @return Success or error code.
 */
extern MASQ_status_t
MASQ_crypto_api_init(const char *protoid,
		     MASQ_role_t role,
		     char *clientid,
		     MASQ_mek_strategy_t strategy,
		     unsigned long int strat_val,
		     char *kms_host,
		     int kms_port,
		     char *ca_file,
		     char *cert_file,
		     char *key_file,
#ifdef	ebug
		     int debug,
#endif
		     void **state);

/**
 * Add extra data to state for additional key-generation entropy.
 *
 * The intent is for broker-controlled random(-ish) data to be added to the
 * crypto state and incorporated into the generation of Message Encryption
 * Keys.
 *
 * @param[in] data Data to add to state.
 * @param[in] data_len Length of data in @p data.
 */
extern void
MASQ_crypto_api_add_entropy(unsigned char *data, size_t data_len);

/**
 * Close down MasQiTT crypto library housekeeping.
 *
 * @param[in] state Crypto state as returned by MASQ_crypto_api_init().
 */
extern void
MASQ_crypto_api_close(void *state);

/**
 * Encrypt a Topic.
 *
 * If this function returns MASQ_STATUS_ANOTHER, the packet is a MEK-only
 * packet and it is the caller's responsibility to create/send the returned
 * contents as a PUBLISH packet with the Retain bit set (packet type of 0x31
 * instead of 0x30). The caller should then call this function again with
 * the same Topic Name to retrieve the packet info for the encrypted Topic
 * Value and send that one as well.
 *
 * @param[in] state Crypto state as returned by MASQ_crypto_api_init().
 * @param[in] topic_name Topic Name, '\0'-terminated.
 * @param[in] topic_value Pointer to Topic Value.
 * @param[in] topic_value_len Length of Topic Value.
 * @param[out] user_properties User Properties to include in the PUBLISH packet
 *    (caller provides storage).
 * @param[out] outbuf Pointer to buffer to receive encrypted Topic Value.
 * @param[in,out] outbuf_len Length of output buffer.
 *    On input specifies space available, on output specifies space used.
 * @return Success or error code.
 */
extern MASQ_status_t
MASQ_crypto_api_encrypt(void *state,
			char *topic_name,
			unsigned char *topic_value,
			size_t topic_value_len,
			MASQ_user_properties_t *user_properties,
			unsigned char *outbuf,
			size_t *outbuf_len);

/**
 * Decrypt a Topic.
 *
 * If this function returns MASQ_STATUS_KEY_MGMT, this is a MEK-only packet
 * and the crypto library has recovered the persistent MEK that will be used
 * for decrypting subsequent packets. There is no Topic Value returned in
 * this case.
 *
 * @param[in] state Crypto state as returned by MASQ_crypto_api_init().
 * @param[in] topic_name Topic Name, '\0'-terminated.
 * @param[in] user_properties User Properties extracted from PUBLISH packet.
 * @param[in] inbuf Pointer to buffer with encrypted Topic Value.
 * @param[in] inbuf_len Length of encrypted Topic Value.
 * @param[out] topic_value Pointer to buffer to receive decrypted Topic Value.
 * @param[in,out] topic_value_len Length of Topic Value.
 *    On input specifies space available, on output specifies space used.
 * @return Success or error code.
 */
extern MASQ_status_t
MASQ_crypto_api_decrypt(void *state,
			char *topic_name,
			MASQ_user_properties_t *user_properties,
			unsigned char *inbuf,
			size_t inbuf_len,
			unsigned char *topic_value,
			size_t *topic_value_len);

/**
 * Get overhead for encrypting Topic Values.
 *
 * This returns (in @p overhead_bytes) the number of additional bytes that
 * must be provided in a buffer to receive an encrypted Topic Value beyond
 * the number of bytes in the Topic Value itself. Conversely, a decrypted
 * Topic Value will be this many bytes shorter than its encrypted version.
 *
 * If a Publisher is using persistent MEKs, the @p mek_bytes parameter is
 * filled in with the number of bytes in a MEK-only payload. Before calling
 * MASQ_crypto_api_encrypt(), the caller should ensure the payload buffer is
 * sized to the maximum of @p mek_bytes and (length of Topic Value + @p
 * overhead_bytes).
 *
 * Subscribers should call this using MASQ_crypto_api_mek_to_strat() as the
 * first parameter and non-NULL values for @p overhead_bytes and @p
 * mek_bytes, though only the value returned in @p overhead_bytes is of
 * interest.
 *
 * @param[in] strategy Crypto strategy.
 * @param[out] overhead_bytes Number of bytes added by encryption and reduced by decryption.
 * @param[out] mek_bytes Number of bytes in a MEK-only payload.
 * @return Success or error code.
 */
extern MASQ_status_t
MASQ_crypto_api_overhead(MASQ_mek_strategy_t strategy,
			 size_t *overhead_bytes,
			 size_t *mek_bytes);

/**
 * Retreive key management strategy from the crypto state.
 *
 * Once a Publisher has MASQ_crypto_api_init(), it is no longer necessary to
 * cache the strategy. Calls to MASQ_crypto_api_overhead() can retrieve the
 * strategy using this call.
 *
 * @param[in] state Crypto state as returned by MASQ_crypto_api_init().
 * @param[out] strategy Crypto strategy.
 * @return Success or error code.
 */
extern MASQ_status_t
MASQ_crypto_api_get_strategy(void *state,
			     MASQ_mek_strategy_t *strategy);

/**
 * Translate MEK field to strategy value.
 *
 * Publishers select a key management strategy when calling
 * MASQ_crypto_api_init(), but Subscribers handle whatever strategy is
 * thrown at them. This function is useful for translating the "KM"
 * User Property from a received PUBLISH packet to a strategy for use
 * with MASQ_crypto_api_overhead(), as in:
 *
 * `MASQ_crypto_api_overhead(MASQ_crypto_api_mek_to_strat(mek_string), ...)`
 *
 * @param[in] mek "KM" User Property value ('\0'-terminated)
 *   from a received PUBLISH packet.
 * @return corresponding MASQ_mek_strategy_t value (MASQ_key_none if error)
 */
extern MASQ_mek_strategy_t
MASQ_crypto_api_mek_to_strat(char *mek);

/**
 * Get string representation of a status code.
 *
 * @param[in] status Status code.
 * @return String represenation, "???" for invalid status code.
 */
extern const char *
MASQ_status_to_str(MASQ_status_t status);

/**
 * Get string representation of a MEK strategy
 *
 * @param[in] strategy Strategy value
 * @return String represenation, "???" for invalid strategy code.
 */
extern const char *
MASQ_strategy_to_str(MASQ_mek_strategy_t strategy);

#endif	// MASQ_CRYPTO_API_H_INCLUDED
