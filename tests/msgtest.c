#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>

#include "masqlib.h"
#include "kms_msg.h"
#include "kms_utils.h"

static char	_rprotoid[12];
static char	_clientid[MASQ_CLIENTID_LEN + 1];
static char	_otherid[MASQ_CLIENTID_LEN + 1];
static char	_expdate[MASQ_EXPDATE_LEN + 1];
static char	_topic[MASQ_MAXTOPIC_LEN + 1];

// doing these as #defines instead of char* for: _E "foo" _X
// error (red)
#define	_E	"\033[1;91m"
// warn (yellow)
#define	_W	"\033[1;93m"
// info (green)
#define	_I	"\033[1;92m"
// restore
#define	_X	"\033[m"

static void
reset_req(KMS_req_t *req)
{
#undef	_XR
#define	_XR(f, b)				\
    do {					\
	req->req[KMS_req_ ## f].ptr = b; \
	req->req[KMS_req_ ## f].len = sizeof(b);	\
    } while (0)
    _XR(proto_id, _rprotoid);
    _XR(client_id, _clientid);
    _XR(other_id, _otherid);
    _XR(exp_date, _expdate);
    _XR(topic_name, _topic);
#undef	_XR
}

struct {
    char	*client_id;
    char	*what;		// topic name or subscription
} _clients[] = {
    // publishers
#define	PUB_TL	0
    { "TankLevel00037a1", "tank/level" },
#define	PUB_TT	1
    { "TankTemp000a0032", "tank/temp" },
#define	PUB_RT	2
    { "TankTemp000a0032", "room/temp" },
#define	PUB_PT	3
    { "PumpTemp007c0480", "pump/temp" },
    // subscribers
#define	SUB_DP	4	// display panel
    { "Display999999997", "#" },
#define	SUB_PC	5	// pump controller
    { "PumpUnit00006177", "tank/level pump/temp" }
};
#define	NUM_CLIENTS	((sizeof(_clients)/sizeof(_clients[0])))
static char	*_protoid = "1.0/1";

static void
clear_data(KMS_data_t *data)
{
    int	i;
    
    for (i = 0; i < KMS_data_num_fields; i++) {
	if (NULL == data->data[i].ptr) {
	    data->data[i].len = 0;
	} else {
	    memset((void *) data->data[i].ptr, 0, data->data[i].len);
	}
    }
}

static char _dates[3][MASQ_EXPDATE_LEN + 1] = { { 0 }, { 0 }, { 0 } };
#define	DT_TOD	0
#define	DT_EXP	1
#define	DT_NEXP	2

void
time_to_str(time_t t,
	    char *s)
{
    time_t	my_t = t;
    struct tm	tm, *tmp;

    if (NULL == s) { return; }

    if (t < 0) {
	strcpy(s, "99991231T235959Z");
	return;
    }
    
    tmp = gmtime_r(&my_t, &tm);
    
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
    // gcc complains about this snprintf() without the #pragma directives
    snprintf(s, MASQ_EXPDATE_LEN + 1, "%04d%02d%02dT%02d%02d%02dZ",
	     tmp->tm_year + 1900, tmp->tm_mon + 1, tmp->tm_mday,
	     tmp->tm_hour, tmp->tm_min, tmp->tm_sec);
#pragma GCC diagnostic pop
}

#define	EXP	(14 * 24 * 60 * 60)

static void
get_time(void)
{
    time_t	now, then;
    
    now = time((time_t *) 0);
    time_to_str(now, _dates[DT_TOD]);
    
    then = now + EXP;
    then -= now % EXP;
    time_to_str(then, _dates[DT_EXP]);

    then += EXP;
    time_to_str(then, _dates[DT_NEXP]);
}

int main(int argc, char *argv[])
{
    unsigned char	buf[1024];
    size_t		buflen;
    int			rc;
    int			i;
    KMS_req_t		myreq;
    KMS_time_t		mytime;
    KMS_data_t		mydata;
    KMS_data_t		outdata = { 0 };
    uint8_t		reason;

    char		curtime[MASQ_EXPDATE_LEN + 1];
    char		expdate[MASQ_EXPDATE_LEN + 1];
    char		nextexp[MASQ_EXPDATE_LEN + 1];
    KMS_time_t		outtime = {
	.time[KMS_time_cur] = { curtime, sizeof(curtime) },
	.time[KMS_time_exp_date] = { expdate, sizeof(expdate) },
	.time[KMS_time_next_exp] = { nextexp, sizeof(nextexp) },
    };

    KMS_req_t		outreq;

    srandom(13);
    get_time();

    printf("\n------------- TIMEREQ\n\n");

    buflen = sizeof(buf);
    myreq.req[KMS_req_proto_id].ptr = _protoid;
    myreq.req[KMS_req_client_id].ptr = _clients[PUB_PT].client_id;
    myreq.req[KMS_req_other_id].ptr = NULL;
    myreq.req[KMS_req_exp_date].ptr = NULL;
    myreq.req[KMS_req_topic_name].ptr = NULL;
    KMS_pkt_dump_req(&myreq, "KMS_make_timereq");
    rc = KMS_make_timereq(&myreq, buf, &buflen);

    if (KMS_ERR_SUCCESS == rc) {
	KMS_pkt_dump(buf, buflen, "TIMEREQ packet", 1);
	printf("%sSuccess%s\n", _I, _X);
    } else {
	printf("%sGot error%s %s%s%s\n", _E, _X, _W, KMS_error_string(rc), _X);
    }

    reset_req(&outreq);
    rc = KMS_parse_timereq(buf, buflen, &outreq);

    if (KMS_ERR_SUCCESS == rc) {
	KMS_pkt_dump_req(&outreq, "KMS_parse_timereq");
	printf("%sSuccess%s\n", _I, _X);
    } else {
	printf("%sGot error%s %s%s%s\n", _E, _X, _W, KMS_error_string(rc), _X);
    }

    printf("\n------------- TIMERESP\n\n");

    buflen = sizeof(buf);
    mytime.time[KMS_time_cur].ptr = _dates[DT_TOD];
    mytime.time[KMS_time_exp_date].ptr = _dates[DT_EXP];
    mytime.time[KMS_time_next_exp].ptr = _dates[DT_NEXP];
    KMS_pkt_dump_time(&mytime, "KMS_make_timeresp");
    rc = KMS_make_timeresp(KMS_REASON_SUCCESS, &mytime, NULL,
			   buf, &buflen);

    if (KMS_ERR_SUCCESS == rc) {
	KMS_pkt_dump(buf, buflen, "TIMERESP packet", 1);
	printf("%sSuccess%s\n", _I, _X);
    } else {
	printf("%sGot error%s %s%s%s\n", _E, _X, _W, KMS_error_string(rc), _X);
    }
    
    rc = KMS_parse_timeresp(buf, buflen, &reason, &outtime, NULL);

    if (KMS_ERR_SUCCESS == rc) {
	if (KMS_REASON_SUCCESS == reason) {
	    KMS_pkt_dump_time(&outtime, "KMS_parse_timeresp");
	} else {
	    printf("==== KMS_parse_timeresp\n> %s%s%s\n",
		   _W, KMS_reason_string(reason), _X);
	}
	printf("%sSuccess%s\n", _I, _X);
    } else {
	printf("%sGot error%s %s%s%s\n", _E, _X, _W, KMS_error_string(rc), _X);
    }
    
    buflen = sizeof(buf);
    rc = KMS_make_timeresp(KMS_REASON_CLIENTID_ERR,
			   NULL, NULL,
			   buf, &buflen);

    if (KMS_ERR_SUCCESS == rc) {
	KMS_pkt_dump(buf, buflen, "TIMERESP packet (w/ error)", 1);
	printf("%sSuccess%s\n", _I, _X);
    } else {
	printf("%sGot error%s %s%s%s\n", _E, _X, _W, KMS_error_string(rc), _X);
    }

    rc = KMS_parse_timeresp(buf, buflen, &reason, &outtime, NULL);

    if (KMS_ERR_SUCCESS == rc) {
	if (KMS_REASON_SUCCESS == reason) {
	    KMS_pkt_dump_time(&outtime, "KMS_parse_timeresp");
	} else {
	    printf("==== KMS_parse_timeresp\n> %s%s%s\n",
		   _W, KMS_reason_string(reason), _X);
	}
	printf("%sSuccess%s\n", _I, _X);
    } else {
	printf("%sGot error%s %s%s%s\n", _E, _X, _W, KMS_error_string(rc), _X);
    }
    
    printf("\n------------- PUBREQ\n\n");

    buflen = sizeof(buf);
    myreq.req[KMS_req_proto_id].ptr = _protoid;
    myreq.req[KMS_req_client_id].ptr = _clients[PUB_TT].client_id;
    myreq.req[KMS_req_other_id].ptr = NULL;
    myreq.req[KMS_req_exp_date].ptr = NULL;
    myreq.req[KMS_req_topic_name].ptr = NULL;
    KMS_pkt_dump_req(&myreq, "KMS_make_pubreq");
    rc = KMS_make_pubreq(&myreq, buf, &buflen);

    if (KMS_ERR_SUCCESS == rc) {
	KMS_pkt_dump(buf, buflen, "PUBREQ packet", 1);
	printf("%sSuccess%s\n", _I, _X);
    } else {
	printf("%sGot error%s %s%s%s\n", _E, _X, _W, KMS_error_string(rc), _X);
    }

    reset_req(&outreq);
    rc = KMS_parse_pubreq(buf, buflen, &outreq);

    if (KMS_ERR_SUCCESS == rc) {
	KMS_pkt_dump_req(&outreq, "KMS_parse_pubreq");
	printf("%sSuccess%s\n", _I, _X);
    } else {
	printf("%sGot error%s %s%s%s\n", _E, _X, _W, KMS_error_string(rc), _X);
    }

    printf("\n------------- PUBRESP\n\n");

    buflen = sizeof(buf);
    mydata.num = 2;
    mydata.data[0].ptr = (void *) "some random data";
    mydata.data[0].len = strlen(mydata.data[0].ptr);
    mydata.data[1].ptr = (void *) "other data here";
    mydata.data[1].len = strlen(mydata.data[1].ptr);
    rc = KMS_make_pubresp(KMS_REASON_SUCCESS,
			  &mydata,
			  NULL,
			  buf, &buflen);

    if (KMS_ERR_SUCCESS == rc) {
	KMS_pkt_dump(buf, buflen, "PUBRESP packet", 1);
	printf("%sSuccess%s\n", _I, _X);
    } else {
	printf("%sGot error%s %s%s%s\n", _E, _X, _W, KMS_error_string(rc), _X);
    }

    clear_data(&outdata);
    rc = KMS_parse_pubresp(buf, buflen, &reason, &outdata, NULL);

    if (KMS_ERR_SUCCESS == rc) {
	if (KMS_REASON_SUCCESS == reason) {
	    KMS_pkt_dump_data(&outdata, "KMS_parse_pubresp");
	    for (i = 0; i < outdata.num; i++) {
		free(outdata.data[i].ptr);
		outdata.data[i].ptr = NULL;
	    }
	} else {
	    printf("==== KMS_parse_pubresp\n> %s%s%s\n",
		   _W, KMS_reason_string(reason), _X);
	}
	printf("%sSuccess%s\n", _I, _X);
    } else {
	printf("%sGot error%s %s%s%s\n", _E, _X, _W, KMS_error_string(rc), _X);
    }

    printf("\n------------- PRIVREQ\n\n");

    buflen = sizeof(buf);
    myreq.req[KMS_req_proto_id].ptr = _protoid;
    myreq.req[KMS_req_client_id].ptr = _clients[SUB_PC].client_id;
    myreq.req[KMS_req_other_id].ptr = _clients[PUB_TL].client_id;
    myreq.req[KMS_req_exp_date].ptr = _dates[DT_EXP];
    myreq.req[KMS_req_topic_name].ptr = "tank/level";
    KMS_pkt_dump_req(&myreq, "KMS_make_privreq");
    rc = KMS_make_privreq(&myreq, buf, &buflen);

    if (KMS_ERR_SUCCESS == rc) {
	KMS_pkt_dump(buf, buflen, "PRIVREQ packet", 1);
	printf("%sSuccess%s\n", _I, _X);
    } else {
	printf("%sGot error%s %s%s%s\n", _E, _X, _W, KMS_error_string(rc), _X);
    }

    reset_req(&outreq);
    rc = KMS_parse_privreq(buf, buflen, &outreq);

    if (KMS_ERR_SUCCESS == rc) {
	KMS_pkt_dump_req(&outreq, "KMS_parse_privreq");
	printf("%sSuccess%s\n", _I, _X);
    } else {
	printf("%sGot error%s %s%s%s\n", _E, _X, _W, KMS_error_string(rc), _X);
    }

    printf("\n------------- PRIVRESP\n\n");

#define	BLEN	128
    uint8_t	buf0[BLEN+1], buf1[BLEN+1];
    int32_t	r0, r1;
    buflen = sizeof(buf);
    mydata.num = 2;
    buf0[0] = buf1[0] = 0;
    for (i = 0; i < BLEN; i++) {
	if (0 == (i % 3)) { r0 = random(); r1 = random(); }
	buf0[i+1] = r0 % 0xff; r0 >>= 8;
	buf1[i+1] = r1 % 0xff; r1 >>= 8;
    }
    mydata.data[0].ptr = (void *) buf0;
    mydata.data[0].len = sizeof(buf0);
    mydata.data[1].ptr = (void *) buf1;
    mydata.data[1].len = sizeof(buf1);
    rc = KMS_make_privresp(KMS_REASON_SUCCESS,
			   &mydata,
			   NULL,
			   buf, &buflen);

    if (KMS_ERR_SUCCESS == rc) {
	KMS_pkt_dump(buf, buflen, "PRIVRESP packet", 1);
	printf("%sSuccess%s\n", _I, _X);
    } else {
	printf("%sGot error%s %s%s%s\n", _E, _X, _W, KMS_error_string(rc), _X);
    }

    outdata.data[0].ptr = (void *) buf0;
    outdata.data[0].len = sizeof(buf0);
    outdata.data[1].ptr = (void *) buf1;
    outdata.data[1].len = sizeof(buf1);
    rc = KMS_parse_privresp(buf, buflen, &reason, &outdata, NULL);

    if (KMS_ERR_SUCCESS == rc) {
	if (KMS_REASON_SUCCESS == reason) {
	    KMS_pkt_dump_data(&outdata, "KMS_parse_privresp");
	    for (i = 0; i < outdata.num; i++) {
		//free(outdata.data[i].ptr);
		outdata.data[i].ptr = NULL;
	    }
	} else {
	    printf("==== KMS_parse_privresp\n> %s%s%s\n",
		   _W, KMS_reason_string(reason), _X);
	}
	printf("%sSuccess%s\n", _I, _X);
    } else {
	printf("%sGot error%s %s%s%s\n", _E, _X, _W, KMS_error_string(rc), _X);
    }

    return(0);
}
