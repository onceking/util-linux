/*
 * Copyright (c) 1983, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * 1999-02-22 Arkadiusz Miśkiewicz <misiek@pld.ORG.PL>
 * - added Native Language Support
 * Sun Mar 21 1999 - Arnaldo Carvalho de Melo <acme@conectiva.com.br>
 * - fixed strerr(errno) in gettext calls
 */

#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/time.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <getopt.h>

#include "c.h"
#include "strutils.h"
#include "xalloc.h"

#define	SYSLOG_NAMES
#include <syslog.h>

static int decode(char *name, CODE *codetab)
{
	register CODE *c;

	if (name == NULL || *name == '\0')
		return -1;
	if (isdigit(*name)) {
		int num;
		char *end = NULL;

		num = strtol(name, &end, 10);
		if (errno || name == end || (end && *end))
			return -1;
		for (c = codetab; c->c_name; c++)
			if (num == c->c_val)
				return num;
		return -1;
	}
	for (c = codetab; c->c_name; c++)
		if (!strcasecmp(name, c->c_name))
			return (c->c_val);

	return -1;
}

static int pencode(char *s)
{
	char *save;
	int fac, lev;

	for (save = s; *s && *s != '.'; ++s);
	if (*s) {
		*s = '\0';
		fac = decode(save, facilitynames);
		if (fac < 0)
			errx(EXIT_FAILURE, "unknown facility name: %s", save);
		*s++ = '.';
	}
	else {
		fac = LOG_USER;
		s = save;
	}
	lev = decode(s, prioritynames);
	if (lev < 0)
		errx(EXIT_FAILURE, "unknown priority name: %s", save);
	return ((lev & LOG_PRIMASK) | (fac & LOG_FACMASK));
}

static int inet_socket(uint16_t port)
{
	int fd;
	struct sockaddr_in dest;

	if(!port)
		errx(EXIT_FAILURE, "Port number is required");

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		errx(EXIT_FAILURE, "failed to create socket.");

	dest.sin_family = AF_INET;
	dest.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	dest.sin_port = htons(port);
	if (connect(fd, (struct sockaddr *)&dest, sizeof(struct sockaddr)) == -1) {
		close(fd);
		errx(EXIT_FAILURE, "failed to connect to port %s", port);
	}

	return fd;
}

static void usage(FILE *out)
{
	fputs(
		"\n"
		"Usage:\n"
		" logger [options]\n"
		"\n"
		"Options:\n"
		" -P, --port <number>   use this UDP port\n"
		" -p, --priority <prio> mark given message with this priority\n"
		" -s, --stderr          output message to standard error as well\n"
		" -t, --tag <tag>       mark every line with this tag\n"
		"\n"
		" -h, --help     display this help and exit\n", out);
}

static void log_from_stdin(int LogSock, int pri, char const* tag){
	char buf[1024] = "";
	char *msg;
	while (fgets(buf, sizeof(buf), stdin) != NULL) {
		/* glibc is buggy and adds an additional newline,
		   so we have to remove it here until glibc is fixed */
		int len = strlen(buf);

		if (len > 0 && buf[len - 1] == '\n')
			buf[len - 1] = '\0';

		msg = buf;



       char buf[1000];
       char const* cp, *tp;
       time_t now;


       if (tag)
	       cp = tag;
       else {
	       cp = getlogin();
	       if (!cp)
		       cp = "<someone>";
       }
       time(&now);
       tp = ctime(&now)+4;

       snprintf(buf, sizeof(buf), "<%d>%.15s %.200s: %.400s",
		pri, tp, cp, msg);

       if (write(fd, buf, strlen(buf)+1) < 0)
	       return; /* error */

	}
}

/*
 * logger -- read and log utility
 *
 *	Reads from an input and arranges to write the result on the system
 *	log.
 */
int main(int argc, char **argv)
{
	int LogSock;
	int ch, pri;
	char *tag;
	uint16_t port;
	static const struct option longopts[] = {
		{ "priority",	required_argument,  0, 'p' },
		{ "tag",	required_argument,  0, 't' },
		{ "port",	required_argument,  0, 'P' },
		{ "help",	no_argument,	    0, 'h' },
		{ NULL,		0, 0, 0 }
	};

	tag = NULL;
	pri = LOG_NOTICE;
	while ((ch = getopt_long(argc, argv, "p:st:P:Vh", longopts, NULL)) != -1) {
		int iport = 0;
		switch (ch) {
		case 'p':		/* priority */
			pri = pencode(optarg);
			break;
		case 't':		/* tag */
			tag = optarg;
			break;
		case 'P':
			iport = atoi(optarg);
			if(iport > (uint16_t)-1 || iport <= 0)
				errx(EXIT_FAILURE, "Invalid port number");
			port = iport;
			break;
		case 'h':
			usage(stdout);
			exit(EXIT_SUCCESS);
		case '?':
		default:
			usage(stderr);
			exit(EXIT_FAILURE);
		}
	}
	argc -= optind;
	argv += optind;

	if (argc > 0)
		errx(EXIT_FAILURE, "extra command line arguments.");

	/* setup for logging */
	LogSock = inet_socket(port);
	log_from_stdin(LogSock, pri, tag);
	close(LogSock);
	return EXIT_SUCCESS;
}
