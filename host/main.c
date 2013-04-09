/* simtrace - main program for the host PC
 *
 * (C) 2010-2011 by Harald Welte <hwelte@hmw-consulting.de>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 
 *  as published by the Free Software Foundation
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#define _GNU_SOURCE
#include <getopt.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libusb.h>

#include "simtrace.h"
#include "simtrace_usb.h"
#include "apdu_split.h"

#include <osmocom/core/gsmtap.h>
#include <osmocom/core/gsmtap_util.h>
#include <osmocom/core/utils.h>

static struct apdu_split *as;
static struct gsmtap_inst *g_gti;
FILE* dump_usb_file  = 0;

static int gsmtap_send_sim(const uint8_t *apdu, unsigned int len)
{
	struct gsmtap_hdr *gh;
	unsigned int gross_len = len + sizeof(*gh);
	uint8_t *buf = malloc(gross_len);
	int rc;

	if (!buf)
		return -ENOMEM;

	memset(buf, 0, sizeof(*gh));
	gh = (struct gsmtap_hdr *) buf;
	gh->version = GSMTAP_VERSION;
	gh->hdr_len = sizeof(*gh)/4;
	gh->type = GSMTAP_TYPE_SIM;

	memcpy(buf + sizeof(*gh), apdu, len);

	rc = write(gsmtap_inst_fd(g_gti), buf, gross_len);
	if (rc < 0) {
		perror("write gsmtap");
		free(buf);
		return rc;
	}

	free(buf);
	return 0;
}

static void apdu_out_cb(uint8_t *buf, unsigned int len, void *user_data)
{
	printf("APDU: %s\n", osmo_hexdump(buf, len));
	gsmtap_send_sim(buf, len);
}

static int process_usb_msg(uint8_t *buf, int len)
{
	struct simtrace_hdr *sh = (struct simtrace_hdr *)buf;
	uint8_t *payload = buf += sizeof(*sh);
	int payload_len = len - sizeof(*sh);

	if (payload_len < 0)
		return -EINVAL;
	
	switch (sh->cmd) {
	case SIMTRACE_MSGT_DATA:
		/* special treatment for ATR */
		if (sh->flags & SIMTRACE_FLAG_ATR) {
			printf("ATR ");
			apdu_out_cb(payload, payload_len, NULL);
			break;
		}
		if (sh->flags & SIMTRACE_FLAG_PPS_FIDI) {
			printf("PPS(Fi=%u/Di=%u) ",
				sh->res[0], sh->res[1]);
		}
		/* everything else goes into APDU splitter */
		apdu_split_in(as, payload, payload_len);
#if 0
		/* If waiting time has expired, signal explicit boundary */
		if (sh->flags & SIMTRACE_FLAG_WTIME_EXP)
			apdu_split_boundary(as);
#endif
		break;
	case SIMTRACE_MSGT_RESET:
	default:
		printf("unknown simtrace msg type 0x%02x\n", sh->cmd);
		break;
	}
}

static void print_welcome(void)
{
	printf("simtrace - GSM SIM and smartcard tracing\n"
	       "(C) 2010 by Harald Welte <laforge@gnumonks.org>\n\n");
}

static void print_help(void)
{
	printf( "\t-i\t--gsmtap-ip\tA.B.C.D\n"
		"\t-a\t--skip-atr\n"
		"\t-h\t--help\n"
		"\t-k\t--keep-running\n"
		"\t-d\t--dump-usb\tfilename\n"
		"\t-r\t--replay\tfilename\n"
		"\n"
		);
}

static const struct option opts[] = {
	{ "gsmtap-ip", 1, 0, 'i' },
	{ "skip-atr", 0, 0, 'a' },
	{ "help", 0, 0, 'h' },
	{ "keep-running", 0, 0, 'k' },
	{ "dump-usb", 1, 0, 'd' },
	{ "replay", 1, 0, 'r' },
	{ NULL, 0, 0, 0 }
};

static void run_mainloop(struct libusb_device_handle *devh)
{
	unsigned int msg_count, byte_count = 0;
	char buf[16*265];
	int xfer_len;
	int rc;

	printf("Entering main loop\n");
	apdu_split_reset(as);

	while (1) {
		rc = libusb_bulk_transfer(devh, SIMTRACE_IN_EP, buf, sizeof(buf), &xfer_len, 100000);
		if (rc < 0 && rc != LIBUSB_ERROR_TIMEOUT) {
			fprintf(stderr, "BULK IN transfer error; rc=%d\n", rc);
			return;
		}
		if (xfer_len > 0) {
			//printf("URB: %s\n", osmo_hexdump(buf, rc));
			process_usb_msg(buf, xfer_len);
			msg_count++;
			byte_count += xfer_len;
			if (dump_usb_file!=0) {
				fwrite(&xfer_len,sizeof(xfer_len),1,dump_usb_file);
				fwrite(buf,1,xfer_len,dump_usb_file);
			}
		}
	}
}

static void replay_mainloop(FILE* dump_usb_file)
{
	unsigned int msg_count, byte_count = 0;
	char buf[16*265];
	int xfer_len=0;
	int rc=0;
	int nitems=0;

	printf("Entering main replay loop\n");
	apdu_split_reset(as);

	while (1) {
		nitems = fread(&xfer_len,sizeof(xfer_len),1,dump_usb_file);	
		if(nitems!=1) {
			return;
		 }
		printf("xfer_len:%d\n",xfer_len);
		if (xfer_len > 0) {
			nitems = fread(buf,1,xfer_len,dump_usb_file);
			if(nitems!=xfer_len) {
				return;
			}
			printf("URB: %s\n", osmo_hexdump(buf, rc));
			process_usb_msg(buf, xfer_len);
			msg_count++;
			byte_count += xfer_len;
			}
	}
}


int main(int argc, char **argv)
{
	char *gsmtap_host = "127.0.0.1";
	int rc;
	int c, ret = 1;
	int skip_atr = 0;
	int keep_running = 0;
	int dump_usb = 0;
	int replay = 0;
	struct libusb_device_handle *devh;

	print_welcome();

	while (1) {
		int option_index = 0;

		c = getopt_long(argc, argv, "i:ahkd:r:", opts, &option_index);
		if (c == -1)
			break;
		switch (c) {
		case 'h':
			print_help();
			exit(0);
			break;
		case 'i':
			gsmtap_host = optarg;
			break;
		case 'a':
			skip_atr = 1;
			break;
		case 'k':
			keep_running = 1;
			break;
		case 'd':
			dump_usb = 1;
			dump_usb_file = fopen(optarg,"wb");
			break;
		case 'r':
			replay = 1;
			dump_usb_file =  fopen(optarg,"rb");
			printf("replaying file %s...\n",optarg);
			break;
		}
	}

	rc = libusb_init(NULL);
	if (rc < 0) {
		fprintf(stderr, "libusb initialization failed\n");
		goto close_exit;
	}

	g_gti = gsmtap_source_init(gsmtap_host, GSMTAP_UDP_PORT, 0);
	if (!g_gti) {
		perror("unable to open GSMTAP");
		goto close_exit;
	}
	gsmtap_source_add_sink(g_gti);

	as = apdu_split_init(&apdu_out_cb, NULL);
	if (!as)
		goto release_exit;

	if (replay) {
		printf("done replaying file...\n");
		replay_mainloop(dump_usb_file);
		fclose(dump_usb_file);
	}
	else
	{
		do {
			devh = libusb_open_device_with_vid_pid(NULL, SIMTRACE_USB_VENDOR, SIMTRACE_USB_PRODUCT);
			if (!devh) {
				fprintf(stderr, "can't open USB device\n");
				goto close_exit;
			}

			rc = libusb_claim_interface(devh, 0);
			if (rc < 0) {
				fprintf(stderr, "can't claim interface; rc=%d\n", rc);
				goto close_exit;
			}

			run_mainloop(devh);
			ret = 0;

			libusb_release_interface(devh, 0);
	close_exit:
			if (devh)
				libusb_close(devh);
			if (keep_running)
				sleep(1);
		} while (keep_running);
	}

release_exit:
	libusb_exit(NULL);
	return ret;
}
