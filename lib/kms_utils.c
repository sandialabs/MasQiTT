/** @file

Function calls are documented once in @ref kms_packet_utils.h to avoid
duplication and drift. Doxygen helpfully includes them in this
listing.
 */

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdint.h>
#include <sys/select.h>
#include "tls.h"
#include <wolfssl/test.h>

#include "kms_msg.h"
#include "kms_utils.h"

static int	KMS_packet_validate_utf8(const char *str, int len);

/** Print contents of a KMS_packet structure for debugging support.
 *
 * @param[in] packet Pointer to a packet.
 * @param[in] header If non-NULL, printed as a header line.
 * @param[in] abbrev If non-zero prints a one-line abbreviated format, else
 *    one line per field. Value is used as the width of the string field for
 *    printing hdr.
 */
void
KMS_packet_dump(KMS_packet *packet, char *header, int abbrev)
{
    if (abbrev) {
	if (NULL != header) {
	    // abbrev doubles as width of header print string
	    printf("PKT> %*s ", abbrev, header);
	}
	printf("cmd %x | rc %3d | rl %3d | pos %3d | pl %3d | pl %s\n",
	       packet->command, packet->remaining_count,
	       packet->remaining_length, packet->pos,
	       packet->packet_length, (packet->payload ? "ptr" : "null"));
    } else {
	if (NULL != header) {
	    printf("==== %s\n", header);
	}
	printf("         command %d\n", packet->command);
	printf(" remaining_count %d\n", packet->remaining_count);
	printf("remaining_length %d\n", packet->remaining_length);
	printf("             pos %d\n", packet->pos);
	printf("   packet_length %d\n", packet->packet_length);
	printf("         payload %p\n", packet->payload);
    }
}

/** Read and return next Byte field in packet.
 *
 * @param[in] packet Packet to read from.
 * @param[out] byte Byte read from packet.
 * @return KMS_ERR_SUCCESS on succes, else error.
 */
int
KMS_packet_read_byte(KMS_packet *packet,
		     uint8_t *byte)
{
    if (NULL == packet)
	return KMS_ERR_INVAL;
    if (packet->pos + 1 > packet->packet_length)
        return KMS_ERR_MALFORMED_PACKET;

    *byte = packet->payload[packet->pos++];

    return KMS_ERR_SUCCESS;
}


int
KMS_packet_write_byte(KMS_packet *packet,
		      uint8_t byte)
{
    if (NULL == packet)
	return KMS_ERR_INVAL;
    if (packet->pos + 1 > packet->packet_length)
	return KMS_ERR_NOSPACE;

    packet->payload[packet->pos++] = byte;

    return KMS_ERR_SUCCESS;
}


int
KMS_packet_read_bytes(KMS_packet *packet,
		      void *bytes,
		      size_t count)
{
    if (NULL == packet)
	return KMS_ERR_INVAL;
    if (packet->pos + count > packet->packet_length)
        return KMS_ERR_MALFORMED_PACKET;

    memcpy(bytes, &(packet->payload[packet->pos]), count);
    packet->pos += count;

    return KMS_ERR_SUCCESS;
}


int
KMS_packet_write_bytes(KMS_packet *packet,
		       const void *bytes,
		       size_t count)
{
    if (NULL == packet)
	return KMS_ERR_INVAL;
    if (packet->pos + count > packet->packet_length)
        return KMS_ERR_MALFORMED_PACKET;

    memcpy(&(packet->payload[packet->pos]), bytes, count);
    packet->pos += count;

    return KMS_ERR_SUCCESS;
}


int
KMS_packet_read_binary(KMS_packet *packet,
		       uint8_t **data,
		       size_t *length)
{
    uint16_t        slen;
    int             rc;

    if (NULL == packet)
	return KMS_ERR_INVAL;
    rc = KMS_packet_read_uint16(packet, &slen);
    if (rc)
        return rc;

    if (slen == 0) {
        *data = NULL;
        *length = 0;
        return KMS_ERR_SUCCESS;
    }

    if (packet->pos + slen > packet->packet_length)
        return KMS_ERR_MALFORMED_PACKET;

    *data = malloc(slen + 1U);
    if (*data) {
        memcpy(*data, &(packet->payload[packet->pos]), slen);
        ((uint8_t *) (*data))[slen] = '\0';
        packet->pos += slen;
    } else {
        return KMS_ERR_NOMEM;
    }

    *length = slen;
    return KMS_ERR_SUCCESS;
}


int
KMS_packet_write_binary(KMS_packet *packet,
			uint8_t *data,
			size_t length)
{
    int             rc;

    if (NULL == packet)
	return KMS_ERR_INVAL;
    if (packet->pos + 2 + length > packet->packet_length)
        return KMS_ERR_NOSPACE;

    if (KMS_ERR_SUCCESS !=
	(rc = KMS_packet_write_uint16(packet, (uint16_t) length)))
	return rc;
    if (KMS_ERR_SUCCESS !=
	(rc = KMS_packet_write_bytes(packet, data, length)))
	return rc;
    return KMS_ERR_SUCCESS;
}


int
KMS_packet_read_string(KMS_packet *packet,
		       char **str,
		       size_t *length)
{
    int             rc;

    rc = KMS_packet_read_binary(packet, (uint8_t **) str, length);
    if (rc)
        return rc;
    if (*length == 0)
        return KMS_ERR_SUCCESS;

    if (KMS_packet_validate_utf8(*str, *length)) {
        free(*str);
        *str = NULL;
        *length = 0;
        return KMS_ERR_MALFORMED_UTF8;
    }

    return KMS_ERR_SUCCESS;
}


int
KMS_packet_write_string(KMS_packet *packet,
			const char *str,
			uint16_t length)
{
    int             rc;

    if (NULL == packet)
	return KMS_ERR_INVAL;

    if (KMS_ERR_SUCCESS != (rc = KMS_packet_write_uint16(packet, length)))
	return rc;
    if (KMS_ERR_SUCCESS != (rc = KMS_packet_write_bytes(packet, str, length)))
	return rc;

    return KMS_ERR_SUCCESS;
}


int
KMS_packet_read_uint16(KMS_packet *packet,
		       uint16_t *word)
{
    uint32_t	val = 0;
    int		i;

    if (NULL == packet)
	return KMS_ERR_INVAL;
    if (packet->pos + 2 > packet->packet_length)
        return KMS_ERR_MALFORMED_PACKET;

    for (i = 0; i < 2; i++) {
        val = (val << 8) + packet->payload[packet->pos++];
    }

    *word = (uint16_t) val;

    return KMS_ERR_SUCCESS;
}


int
KMS_packet_write_uint16(KMS_packet *packet,
			uint16_t word)
{
    if (packet->pos + 2 > packet->packet_length)
        return KMS_ERR_NOSPACE;
    
    KMS_packet_write_byte(packet, (uint8_t) ((word >> 8) & 0xff));
    KMS_packet_write_byte(packet, (uint8_t) ( word       & 0xff));

    return KMS_ERR_SUCCESS;
}


int
KMS_packet_read_uint32(KMS_packet *packet,
		       uint32_t *word)
{
    uint32_t        val = 0;
    int             i;

    if (NULL == packet)
	return KMS_ERR_INVAL;
    if (packet->pos + 4 > packet->packet_length)
        return KMS_ERR_MALFORMED_PACKET;

    for (i = 0; i < 4; i++) {
        val = (val << 8) + packet->payload[packet->pos++];
    }

    *word = val;

    return KMS_ERR_SUCCESS;
}


int
KMS_packet_write_uint32(KMS_packet *packet,
			uint32_t word)
{
    if (packet->pos + 4 > packet->packet_length)
        return KMS_ERR_NOSPACE;
    
    KMS_packet_write_byte(packet, (uint8_t) ((word >> 24) & 0xff));
    KMS_packet_write_byte(packet, (uint8_t) ((word >> 16) & 0xff));
    KMS_packet_write_byte(packet, (uint8_t) ((word >>  8) & 0xff));
    KMS_packet_write_byte(packet, (uint8_t) ( word        & 0xff));

    return KMS_ERR_SUCCESS;
}


int
KMS_packet_read_varint(KMS_packet *packet,
		       uint32_t *word,
		       uint8_t *bytes)
{
    int             i;
    uint8_t         byte;
    unsigned int    remaining_mult = 1;
    uint32_t        lword = 0;
    uint8_t         lbytes = 0;

    for (i = 0; i < 4; i++) {
        if (packet->pos < packet->packet_length) {
            lbytes++;
            byte = packet->payload[packet->pos++];
            lword += (byte & 0x7f) * remaining_mult;
            remaining_mult *= 0x80;
            if ((byte & 0x80) == 0) {
                if (lbytes > 1 && byte == 0) {
                    /* Catch overlong encodings */
                    return KMS_ERR_MALFORMED_PACKET;
                } else {
                    *word = lword;
                    if (bytes)
                        (*bytes) = lbytes;
                    return KMS_ERR_SUCCESS;
                }
            }
        } else {
            return KMS_ERR_MALFORMED_PACKET;
        }
    }
    return KMS_ERR_MALFORMED_PACKET;
}


int
KMS_packet_write_varint(KMS_packet *packet,
			uint32_t word)
{
    uint8_t         byte;
    int             count = 0;

    do {
        byte = (uint8_t) (word % 128);
        word = word / 128;
        /* If there are more digits to encode, set the top bit of this digit */
        if (word > 0) {
            byte = byte | 0x80;
        }
        KMS_packet_write_byte(packet, byte);
        count++;
    } while (word > 0 && count < 5);

    if (count == 5) {
        return KMS_ERR_INVAL;
    }
    return KMS_ERR_SUCCESS;
}

unsigned int
KMS_packet_varint_bytes(uint32_t word)
{
    if (word < 128) {
        return 1;
    } else if (word < 16384) {
        return 2;
    } else if (word < 2097152) {
        return 3;
    } else if (word < 268435456) {
        return 4;
    }
    return 5;
}

/*
 * These need to be set before calling:
 * packet->command
 * packet->remaining_length (length of VH + PL)
 */
int
KMS_packet_alloc(KMS_packet *packet)
{
    uint8_t	remaining_bytes[5], byte;
    uint32_t	remaining_length;
    int		i;

    if (NULL == packet)
	return KMS_ERR_INVAL;

    remaining_length = packet->remaining_length;
    packet->payload = NULL;
    packet->remaining_count = 0;
    
    do {
	byte = remaining_length % 128;
	remaining_length /= 128;
	/* If there are more digits to encode, set the top bit of this digit */
	if (remaining_length > 0) {
	    byte = byte | 0x80;
	}
	remaining_bytes[packet->remaining_count++] = byte;
    } while ((remaining_length > 0) && (packet->remaining_count < 5));
    
    if (packet->remaining_count > 4) {
	return KMS_ERR_PAYLOAD_SIZE;
    }
    
    packet->packet_length = packet->remaining_length + 1 +
	(uint8_t) packet->remaining_count;
    
    packet->payload = malloc(packet->packet_length);
    if (NULL == packet->payload) {
	return KMS_ERR_NOMEM;
    }
    
    packet->payload[0] = packet->command;
    for (i = 0; i < packet->remaining_count; i++) {
	packet->payload[i+1] = remaining_bytes[i];
    }
    packet->pos = (uint32_t) (packet->remaining_count + 1);
    
    return KMS_ERR_SUCCESS;
}

void
KMS_packet_cleanup(KMS_packet *packet)
{
    if (!packet) return;

    /* Free data and reset values */
    packet->command = 0;
    packet->remaining_count = 0;
    packet->remaining_length = 0;
    if (packet->payload) {
	free(packet->payload);
	packet->payload = NULL;
    }
    packet->pos = 0;
}

/*
 * Note that this checks for proper UTF-8 code point encoding, but it does
 * not determine if a code point is a valid Unicode character.
 */
static int
KMS_packet_validate_utf8(const char *str,
			 int len)
{
    int	i;
    int	j;
    int	codelen;
    int	codepoint;
    const unsigned char *ustr = (const unsigned char *) str;

    if (NULL == str) {
	return KMS_ERR_INVAL;
    }
    
    if ((len < 0) || (len > 65536)) {
	return KMS_ERR_INVAL;
    }

    for (i = 0; i < len; i++) {
	if (0 == ustr[i]) {
	    return KMS_ERR_MALFORMED_UTF8;
	} else if (ustr[i] <= 0x7f) {
	    codelen = 1;
	    codepoint = ustr[i];
	} else if ((ustr[i] & 0xE0) == 0xC0) {
	    /* 110xxxxx - 2 byte sequence */
	    if (ustr[i] == 0xC0 || ustr[i] == 0xC1) {
		/* Invalid bytes */
		return KMS_ERR_MALFORMED_UTF8;
	    }
	    codelen = 2;
	    codepoint = (ustr[i] & 0x1F);
	} else if ((ustr[i] & 0xF0) == 0xE0) {
	    /* 1110xxxx - 3 byte sequence */
	    codelen = 3;
	    codepoint = (ustr[i] & 0x0F);
	} else if ((ustr[i] & 0xF8) == 0xF0) {
	    /* 11110xxx - 4 byte sequence */
	    if (ustr[i] > 0xF4) {
		/* Invalid, this would produce values > 0x10FFFF. */
		return KMS_ERR_MALFORMED_UTF8;
	    }
	    codelen = 4;
	    codepoint = (ustr[i] & 0x07);
	} else {
	    /* Unexpected continuation byte. */
	    return KMS_ERR_MALFORMED_UTF8;
	}

	/* Reconstruct full code point */
	if (i == len-codelen+1) {
	    /* Not enough data */
	    return KMS_ERR_MALFORMED_UTF8;
	}
	for (j = 0; j < codelen-1; j++) {
	    if ((ustr[++i] & 0xC0) != 0x80) {
		/* Not a continuation byte */
		return KMS_ERR_MALFORMED_UTF8;
	    }
	    codepoint = (codepoint<<6) | (ustr[i] & 0x3F);
	}

	/* Check for UTF-16 high/low surrogates */
	if ((codepoint >= 0xD800) && (codepoint <= 0xDFFF)) {
	    return KMS_ERR_MALFORMED_UTF8;
	}

	/* Check for overlong or out of range encodings */
	/* Checking codelen == 2 isn't necessary here, because it is already
	 * covered above in the C0 and C1 checks.
	 * if(codelen == 2 && codepoint < 0x0080){
	 *	 return KMS_ERR_MALFORMED_UTF8;
	 * }else
	 */
	if ((codelen == 3) && (codepoint < 0x0800)) {
	    return KMS_ERR_MALFORMED_UTF8;
	} else if ((codelen == 4) &&
		   ((codepoint < 0x10000) || (codepoint > 0x10FFFF))) {
	    return KMS_ERR_MALFORMED_UTF8;
	}

	/* Check for non-characters */
	if ((codepoint >= 0xFDD0) && (codepoint <= 0xFDEF)) {
	    return KMS_ERR_MALFORMED_UTF8;
	}
	if (((codepoint & 0xFFFF) == 0xFFFE) ||
	    ((codepoint & 0xFFFF) == 0xFFFF)) {
	    return KMS_ERR_MALFORMED_UTF8;
	}
	/* Check for control characters */
	if ((codepoint <= 0x001F) ||
	    ((codepoint >= 0x007F) && (codepoint <= 0x009F))) {
	    return KMS_ERR_MALFORMED_UTF8;
	}
    }
    return KMS_ERR_SUCCESS;
}

// for tcp_select_ex() see wolfssl/test.h
static int
KMS_select_ex(int socketfd, int to_sec, int rx)
{
    int	retv;
    int	result = tcp_select_ex(socketfd, to_sec, rx);

    switch (result) {
    case TEST_TIMEOUT:
	retv = KMS_SELECT_TIMEOUT;
	break;
    case TEST_RECV_READY:
    case TEST_SEND_READY:
	retv = 0;
	break;
    case TEST_ERROR_READY:
	retv = KMS_SELECT_SOCKERR;
	break;
    default:
	retv = KMS_SELECT_SELERR;
	break;
    }

    return retv;
}

int
KMS_select_rx(int socketfd, int to_sec)
{
    return KMS_select_ex(socketfd, to_sec, 1);
}

int
KMS_select_tx(int socketfd, int to_sec)
{
    return KMS_select_ex(socketfd, to_sec, 0);
}

char *
KMS_select_str(int status)
{
    char	*ret = "???";

#undef	_X
#define	_X(x)	case KMS_SELECT_ ## x: ret = #x; break
    switch (status) {
    _X(SUCCESS);
    _X(TIMEOUT);
    _X(SOCKERR);
    _X(SELERR);
    }
#undef	_X

    return ret;
}
