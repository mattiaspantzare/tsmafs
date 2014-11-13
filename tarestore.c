/*	$Id: tarestore.c,v 1.7 2012/01/11 12:11:52 ragge Exp $	*/
/*
 * Copyright (c) 2009 ITS, Lulea University of Technology
 * All rights reserved.
 *
 * Written by Anders Magnusson for ITS, Lulea University of Technology
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY ITS ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL ITS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#include <sys/types.h>
#include <sys/stat.h>

#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#define __USE_XOPEN
#include <time.h>

#include <afs/param.h>
#include <afs/afsint.h>
#define FSINT_COMMON_XG
#include <afs/afscbint.h>
#include <sys/ioctl.h>
#include <afs/venus.h>
#include <afs/cellconfig.h>
#include <afs/afs.h>
#include <afs/vldbint.h>
#include <afs/volint.h>
#include <afs/afsutil.h>
#include <afs/afsutil_prototypes.h>
#include <afs/volser.h>
#include <afs/voldefs.h>
#include <afs/dir.h>
#include <afs/auth.h>
#include <afs/acl.h>
#include <afs/print.h>
#include <afs/ptuser.h>

#include <arpa/inet.h>

#include "tsmafs.h"

#define TSMBUFLEN	(32768-4)	/* recommended in API manual */

char *fspace, *volarg;
int dflag, qflag, iflag;
char *hl = "/*";
char *ll = "/*";
static int curfile = -1;

void usage(void);

static void
prtmode(int mode)
{
	int i;

	for (i = 6; i >= 0; i -= 3) {
		int sh = mode >> i;
		printf("%c%c%c", sh & 4 ? 'r' : '-', sh & 2 ? 'w' : '-',
		    sh & 1 ? 'x' : '-');
	}
}

static int
mkdirp(char *p, int m)
{
	char *q;

	if (*p == '/')
		p++;
	q = p;
	for (;;) {
		while (*q && *q != '/')
			q++;
		if (*q == 0) {
			if (mkdir(p, m) < 0 && errno != EEXIST)
				return -1;
			return 0;
		}
		*q = 0;
		if (mkdir(p, m) < 0 && errno != EEXIST) {
			return -1;
		}
		*q++ = '/';
	}
}

static int
create_and_write(struct taquery *taq, struct dirattribute *ta, char *buf, int len)
{
	char comb[1024+256];	/* XXX use defines */
	int typ = GETTYP(ta->cwtype);
	int rv;
	char *comp;

	printf("%c", typ == 1 ? '-' : typ == 2 ? 'd' : typ == 3 ? 'l' : '?');
	prtmode(ta->mode);
	sprintf(comb, "%s%s", taq->hl, taq->ll);
	comp = &comb[1];
	printf("%10d%10d %s\n", ta->owner, ta->group, comp);
	if (qflag)
		return 0;
	switch (typ) {
	case 2:
		if ((rv = mkdirp(comp, ta->mode)) < 0 && errno != EEXIST)
			fprintf(stderr, "mkdir: %s\n", strerror(errno));
		if ((rv = mkdir(comp, ta->mode)) < 0 && errno != EEXIST)
			fprintf(stderr, "mkdir: %s\n", strerror(errno));
		if ((rv = chown(comp, ta->owner, ta->group)) < 0)
			fprintf(stderr, "chown: %s\n", strerror(errno));
		break;
	case 3:
		buf[len] = 0;
		if ((rv = symlink(buf, comp)) < 0)
			fprintf(stderr, "symlink: %s\n", strerror(errno));
		if (lchown(comp, ta->owner, ta->group) < 0)
			fprintf(stderr, "chown: %s\n", strerror(errno));
		break;
	case 1:
		if ((rv = mkdirp(taq->hl, 0755)) < 0)
			fprintf(stderr, "mkdirp: %s\n", strerror(errno));
		if ((rv = open(comp, O_WRONLY|O_CREAT, ta->mode)) < 0) {
			fprintf(stderr, "open: %s\n", strerror(errno));
			break;
		}
		curfile = rv;
		if ((rv = fchown(curfile, ta->owner, ta->group)) < 0)
			fprintf(stderr, "fchown: %s\n", strerror(errno));
		if ((rv = write(curfile, buf, len)) < 0)
			fprintf(stderr, "write: %s\n", strerror(errno));
		else if (rv != len)
			fprintf(stderr, "write: short write (%d != %d\n",
			    len, rv);
		else
			rv = 0;
		break;
	default:
		printf("type %d not supported\n", typ);
		rv = -1;
		break;
	}
	return rv;
}

static int
write_and_check(char *buf, int len)
{
	int rv;

	if (qflag)
		return 0;

	if ((rv = write(curfile, buf, len)) < 0)
		fprintf(stderr, "write: %s\n", strerror(errno));
	else if (rv != len)
		fprintf(stderr, "write: short write (%d != %d\n",
		    len, rv);
	else
		rv = 0;
	return rv;
}

static int
set_permissions(struct taquery *taq, struct dirattribute *ta)
{
	struct timeval tv[2];
	int typ = GETTYP(ta->cwtype);
	int rv = 0;

	if (qflag)
		return 0;

	switch (typ) {
	case 1: /* file */
		tv[0].tv_sec = tv[1].tv_sec = ta->time;
		tv[0].tv_usec = tv[1].tv_usec = 0;
		if ((rv = futimes(curfile, tv)) < 0)
			fprintf(stderr, "futimes: %s\n", strerror(errno));
		if ((rv = close(curfile)) < 0)
			fprintf(stderr, "close: %s\n", strerror(errno));
		break;
	case 2:
	case 3:
		break;
	default:
		fprintf(stderr, "set_permissions");
		rv = 1;
	}
	return rv;
}

static void
ntohblk(uint32_t *blk, int n)
{
	int i;

	for (i = 0; i < n; i++)
		blk[i] = ntohl(blk[i]);
}

/*
 * If less than 4k elements, return taq, otherwise just return a list
 * of around 4k elements.
 */
static struct taquery *
tail4k(struct taquery **taq)
{
	struct taquery *w, *elm4k;
	int i;

	w = *taq;
	i = 0;
	while (i < 4000 && w) {
		w = w->next;
		i++;
	}
	if (i < 4000)
		return *taq;
	elm4k = w->next;
	w->next = NULL;
	w = *taq;
	*taq = elm4k;
	return w;
}

/*
 * Act like traditional Unix interactive restore.
 */
static void
interactive(char *hl)
{
	struct dirattribute ta;
	struct taquery *taq, *taqp, *tail;
#define HLMAX   (VOLSER_MAXVOLNAME+AFSPATHMAX)
	char hlname[HLMAX];
	char llname[AFSNAMEMAX];
	char inbuf[20], *c;

	(void)tsmquery(fspace, hl, "/*", &taqp, NULL);

#define	CMP(str)	(strcmp(c, str) == 0)
again:
	printf("tarestore > ");
	gets(inbuf);
	if ((c = strtok(inbuf, " ")) == NULL)
		goto again;
	if (CMP("ls")) { /* list files */
		for (taq = taqp; taq; taq = taq->next) {
			memcpy(&ta, taq->da, sizeof(ta));
			ntohblk(&ta.cwtype, sizeof(ta)/sizeof(uint32_t));
			printf("%s", &taq->ll[1]);
			int typ = GETTYP(ta.cwtype);
			if (typ == 2)
				printf("/");
			else if (typ == 3)
				printf("@");
			printf("\n");
		}
	} else if (CMP("ll")) { /* list files long */
		for (taq = taqp; taq; taq = taq->next) {
			memcpy(&ta, taq->da, sizeof(ta));
			ntohblk(&ta.cwtype, sizeof(ta)/sizeof(uint32_t));
			int typ = GETTYP(ta.cwtype);
			printf("%c", typ == 1 ? '-' : typ == 2 ? 'd' :
			    typ == 3 ? 'l' : '?');
			prtmode(ta.mode);
			printf("%7d%7d ", ta.owner, ta.group);
			printf("%s", &taq->ll[1]);
			if (typ == 2) printf("/");
			else if (typ == 3) printf("@");
			printf("\n");
		}
	} else if (CMP("quit")) { 
		return;
	} else if (CMP("?") || CMP("help")) { 
		printf("Available commands are:\n");
		printf("\tls - list directory\n");
		printf("\tll - long directory listing\n");
		printf("\tquit - immediately exit program\n");
		printf("\thelp or `?' - print this list\n");
	} else
		printf("%s: unknown command; type ? for help\n", inbuf);
	goto again;
}

int
main(int argc, char *argv[])
{
	struct tm tm;
	char buf[TSMBUFLEN];
	struct dirattribute ta;
	struct taquery *taq, *taqp, *tail;
	char hlevel[1024];	/* XXX use define */
	char *tstr = NULL;
	int ch, rw, got, rv = 1;

	while ((ch = getopt(argc, argv, "v:f:h:l:qdit:")) != -1) {
		switch (ch) {
		case 'f':
			fspace = optarg;
			break;
		case 'v':
			volarg = optarg;
			break;
		case 'h':
			hl = optarg;
			break;
		case 'l':
			ll = optarg;
			break;
		case 'q': /* Query only, no restore */
			qflag = 1;
			break;
		case 'd': /* debugging */
			dflag = 1;
			break;
		case 'i': /* interactive */
			iflag = 1;
			break;
		case 't': /* PIT time */
			tstr = optarg;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	/*
	 * Giving the hl and ll names are intended for superusers/debugging.
	 * The normal way of specifying objects are using the filespace,
	 * volume and path inside volume.
	 */
	if (argc && (hl || ll))
		errx(1, "-h or -l cannot be used with file arguments");
	if (argc > 1)
		errx(1, "can currently only handle one restore path");
	if (argc)
		errx(1, "cannot deal with paths (yet!)");

	if (fspace == NULL)
		errx(1, "filespace must be given on restore");

	if (volarg == NULL)
		errx(1, "volume name must be given on restore");

	if (tsminit(fspace, 1))
		return 1;

	if (iflag) {
		 sprintf(hlevel, "/%s", volarg);
		interactive(hlevel);
		goto die;
	}

	sprintf(hlevel, "/%s%s", volarg, hl);

	memset(&tm, 0, sizeof(tm));
	if (tstr) {
		strptime(tstr, "%Y-%m-%d %H:%M:%S", &tm);
		printf("Restoring from %s\n", asctime(&tm));
		tm.tm_year += 1900;
		tm.tm_mon++;
	}

	if (tsmquery(fspace, hlevel, ll, &taqp, tstr ? &tm : 0))
		goto die;
#ifdef notyet
	/* sort list of objects in TSM order */
	taqp = elemsort(taqp);
#endif

	do {
		tail = tail4k(&taqp);
		if (tsmbeginget(tail))
			goto die;
		for (taq = tail; taq; taq = taq->next) {
			memcpy(&ta, taq->da, sizeof(ta));
			ntohblk(&ta.cwtype, sizeof(ta)/sizeof(uint32_t));
			if ((rw = tsmgetdata(taq, buf, TSMBUFLEN, &got,1)) < 0)
				goto die;
			if (create_and_write(taq, &ta, buf, got))
				goto die;

			while (rw > 0) {
				if ((rw = tsmgetdata(NULL, buf, TSMBUFLEN,
				    &got, 0)) < 0)
					goto die;
				if (write_and_check(buf, got))
					goto die;
			}
			if (tsmenddata())
				goto die;
			set_permissions(taq, &ta);
		}
		if (tsmendget())
			goto die;
	} while (tail != taqp);

	rv = 0;
die:
	tsmshutdown();
	return rv;
}

void
usage()
{
	fprintf(stderr, "Usage: tarestore -f fs [-v vol] [-h hl] [-l ll] "
	    "[-dq] [file...]\n");
	exit(1);
}
