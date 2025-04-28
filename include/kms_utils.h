#ifndef MASQ_KMS_UTILS_H_INCLUDED
#define MASQ_KMS_UTILS_H_INCLUDED

/** @file

KMS packet manipulation utility functions
=========================================

This code is lifted from Mosquitto and stripped down to what's needed to
support the code in @ref kms_packet.c. Using the Mosquitto code directly
proved daunting as the packet creating routines push the data to a network
connection and don't give an opportunity to simply retrieve the contents of
the packet.
 */

#include <stdint.h>
#include <stdio.h>

/** KMS packet
 *
 * This used for encoding information to a packet (string of bytes in
 * payload) and decoding information from a packet.
 */
typedef struct {
    uint8_t	command;		//!< Command value
    uint8_t	remaining_count;	//!< # VBI bytes for remaining_length
    uint32_t	remaining_length;	//!< length yet to be processed
    uint32_t	pos;			//!< current position in payload
    uint32_t	packet_length;		//!< total packet length
    uint8_t	*payload;		//!< raw packet contents
} KMS_packet;

/** Print contents of a KMS_packet structure for debugging support.
 *
 * @param[in] packet Pointer to a packet.
 * @param[in] header If non-NULL, printed as a header line.
 * @param[in] abbrev If non-zero prints a one-line abbreviated format, else
 *    one line per field. Value is used as the width of the string field for
 *    printing hdr.
 */
extern void
KMS_packet_dump(KMS_packet *packet,
		char *header,
		int abbrev);

/** Read and return next Byte field in packet.
 *
 * @param[in] packet Packet to read from.
 * @param[out] byte Byte read from packet.
 * @return KMS_ERR_SUCCESS on succes, else error.
 */
extern int
KMS_packet_read_byte(KMS_packet *packet,
		     uint8_t *byte);

/** Append a Byte field to a packet.
 *
 * @param[in] packet Packet to write to.
 * @param[in] byte Byte to write to packet.
 * @return KMS_ERR_SUCCESS on succes, else error.
 */
extern int
KMS_packet_write_byte(KMS_packet *packet,
		      uint8_t byte);

/** Read and return next bytes in packet.
 *
 * Used with KMS_packet_read_uint16() to read Binary and String fields.
 *
 * @param[in] packet Packet to read from.
 * @param[out] bytes Bytes read from packet. Caller's responsibility to
 *    free() after use.
 * @param[in] count Number of bytes to read.
 * @return KMS_ERR_SUCCESS on succes, else error.
 */
extern int
KMS_packet_read_bytes(KMS_packet *packet,
		      void *bytes,
		      size_t count);

/** Append bytes to a packet.
 *
 * Used with KMS_packet_write_uint16() to append Binary and String fields.
 *
 * @param[in] packet Packet to write to.
 * @param[in] bytes Bytes to write to packet.
 * @param[in] count Number of bytes to write.
 * @return KMS_ERR_SUCCESS on succes, else error.
 */
extern int
KMS_packet_write_bytes(KMS_packet *packet,
		   const void *bytes,
		   size_t count);

/** Read and return next Binary field in packet.
 *
 * @param[in] packet Packet to read from.
 * @param[out] data Bytes read from packet. Caller's responsibility to
 *    free() after use.
 * @param[out] count Number of bytes read.
 * @return KMS_ERR_SUCCESS on succes, else error.
 */
extern int
KMS_packet_read_binary(KMS_packet *packet,
		       uint8_t **data,
		       size_t *length);

/** Append Binary field to a packet.
 *
 * @param[in] packet Packet to write to.
 * @param[in] data Bytes to write to packet.
 * @param[in] count Number of bytes to write.
 * @return KMS_ERR_SUCCESS on succes, else error.
 */
extern int
KMS_packet_write_binary(KMS_packet *packet,
			uint8_t *data,
			size_t length);

/** Read and return next String field in packet.
 *
 * @param[in] packet Packet to read from.
 * @param[out] str String read from packet. '\0'-terminated by the function
 *    and caller's responsibility to free() after use.
 * @param[out] count Number of bytes (not number of UTF-8 code points) read,
 *    not including '\0' at end.
 * @return KMS_ERR_SUCCESS on succes, else error.
 */
extern int
KMS_packet_read_string(KMS_packet *packet,
		       char **str,
		       size_t *length);

/** Append String field to a packet.
 *
 * @param[in] packet Packet to write to.
 * @param[in] data Bytes to write to packet.
 * @param[in] count Number of bytes (not number of UTF-8 code points) to write.
 * @return KMS_ERR_SUCCESS on succes, else error.
 */
extern int
KMS_packet_write_string(KMS_packet *packet,
			const char *str,
			uint16_t length);

/** Read and return next Two Byte Integer (2BI) field in packet.
 *
 * @param[in] packet Packet to read from.
 * @param[out] word 2BI read from packet.
 * @return KMS_ERR_SUCCESS on succes, else error.
 */
extern int
KMS_packet_read_uint16(KMS_packet *packet,
		       uint16_t *word);

/** Append a Two Byte Integer (2BI) field to a packet.
 *
 * @param[in] packet Packet to write to.
 * @param[in] word 2BI to write to packet.
 * @return KMS_ERR_SUCCESS on succes, else error.
 */
extern int
KMS_packet_write_uint16(KMS_packet *packet,
			uint16_t word);

/** Read and return next Four Byte Integer (4BI) field in packet.
 *
 * @param[in] packet Packet to read from.
 * @param[out] word 4BI read from packet.
 * @return KMS_ERR_SUCCESS on succes, else error.
 */
extern int
KMS_packet_read_uint32(KMS_packet *packet,
		       uint32_t *word);

/** Append a Four Byte Integer (4BI) field to a packet.
 *
 * @param[in] packet Packet to write to.
 * @param[in] word 4BI to write to packet.
 * @return KMS_ERR_SUCCESS on succes, else error.
 */
extern int
KMS_packet_write_uint32(KMS_packet *packet,
			uint32_t word);

/** Read and return next Variable Byte Integer (VBI) field in packet.
 *
 * @param[in] packet Packet to read from.
 * @param[out] word VBI read from packet.
 * #param[out] bytes If non-NULL, number of bytes to encode word.
 * @return KMS_ERR_SUCCESS on succes, else error.
 */
extern int
KMS_packet_read_varint(KMS_packet *packet,
		       uint32_t *word,
		       uint8_t *bytes);

/** Append a Variable Byte Integer (VBI) field to a packet.
 *
 * @param[in] packet Packet to write to.
 * @param[in] word VBI to write to packet.
 * @return KMS_ERR_SUCCESS on succes, else error.
 */
extern int
KMS_packet_write_varint(KMS_packet *packet,
		    uint32_t word);

/** Determine number of bytes needed to represent a Variable Byte Integer.
 *
 * @param[in] word Value to encode.
 * @return Number of bytes. A value of 5 indicates word is too large to
 *    encode.
 */
extern unsigned int
KMS_packet_varint_bytes(uint32_t word);

/** Malloc() space to contain packet contents.
 *
 * Note that these fields must be set in packet before calling: command,
 * remaining_length (number of bytes to represent the VH and
 * PL). KMS_packet_alloc() will set the pos, packet_length, and payload
 * fields, as well as pre-fill the FH.
 *
 * @param[in] packet Packet to allocate space for.
 * @return KMS_ERR_SUCCESS on succes, else error.
 */
extern int
KMS_packet_alloc(KMS_packet *packet);

/** Release malloc()'d space and zero out contents of KMS_packet struct.
 *
 * @param[in] packet Packet to clean up.
 */
extern void
KMS_packet_cleanup(KMS_packet *packet);

#define	KMS_SELECT_SUCCESS	0	//!< select() successful
#define	KMS_SELECT_TIMEOUT	(-1)	//!< Timed out
#define	KMS_SELECT_SOCKERR	(-2)	//!< Error on socket
#define	KMS_SELECT_SELERR	(-3)	//!< Error on select() call

/** Network communications convenience function to wait until ready to receive.
 * Adapted from wolfssl/test.h
 *
 * @param[in] socketfd Socket to check.
 * @param[in] to_sec Number of seconds to wait.
 * @return KMS_SELECT_SUCCESS on success, else KMS_SELECT_* error
 */
extern int
KMS_select_rx(int socketfd, int to_sec);

/** Network communications convenience function to wait until ready to send.
 * Adapted from wolfssl/test.h
 *
 * @param[in] socketfd Socket to check.
 * @param[in] to_sec Number of seconds to wait.
 * @return KMS_SELECT_SUCCESS on success, else KMS_SELECT_* error
 */
extern int
KMS_select_tx(int socketfd, int to_sec);

/** KMS_select_xx() status to string representation.
 * @param[in] status Status value.
 * @return String representation.
 */
extern char *
KMS_select_str(int status);

#endif	// MASQ_KMS_UTILS_H_INCLUDED
