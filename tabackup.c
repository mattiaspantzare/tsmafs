/*	$Id: tabackup.c,v 1.26 2012/04/12 10:09:19 ragge Exp $	*/
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
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <err.h>
#include <fnmatch.h>
#include <netdb.h>
#include <ctype.h>

#include <afs/param.h>
#include <afs/afsint.h>
#define	FSINT_COMMON_XG
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

#include <rx/rxkad.h>
#include <rx/rx_null.h>

#include <afs/com_err.h>

#include "tsmafs.h"

#ifndef timersub
#define timersub(h, l, res) do {			\
	(res)->tv_sec = (h)->tv_sec - (l)->tv_sec;	\
	(res)->tv_usec = (h)->tv_usec - (l)->tv_usec;	\
	if ((res)->tv_usec < 0) {			\
		(res)->tv_sec--;			\
		(res)->tv_usec += 1000000;		\
	}						\
} while (0)
#endif

/* Globals from argument list */
int localauth, nflag, dflag, archive, Fflag, Iflag, iflag;
char *fspace;
static int intrans;	/* Currently doing a tsm transaction */

/* statistics */
enum { TOTAL, BUPPED, NONEED, SKIPPED, FAILED };
int fil[5], dir[5], sym[5];

#define	MAXXFILES	10
char *xfiles[MAXXFILES];
int nxfiles;

#define	TADEBUG(...)	if (dflag) fprintf(stderr, __VA_ARGS__)
#define TSMBUFLEN	(32768-4)	/* recommended in API manual */

#define	SYSACLS	"1\n0\nsystem:administrators 127\n"

static void usage(void);
static void parsedir(char *hl, char *ll, struct rx_connection *sc, AFSFid *fid);
static void acltoids(char *acl, struct dirattribute *dira);

extern struct ubik_client *cstruct;
extern int localauth;

/* Prototype for these routines should be somewhere else */
extern int VLDB_ListAttributesN2(VldbListByAttributes * attrp, char *name,
                                 afs_int32 thisindex, afs_int32 * nentriesp,
                                 nbulkentries * blkentriesp,
                                 afs_int32 * nextindexp);
extern int UV_SetSecurity(register struct rx_securityClass *as,
                          afs_int32 aindex);
extern int UV_SetSecurity(register struct rx_securityClass *as,
                          afs_int32 aindex);
extern int ktc_GetToken(struct ktc_principal *server, struct ktc_token *token,
		int tokenLen, struct ktc_principal *client);
extern int UV_ListOneVolume(afs_int32 aserver, afs_int32 apart,
		afs_int32 volid, struct volintInfo **resultPtr);


static void
htonblk(uint32_t *blk, int n)
{
	int i;

	for (i = 0; i < n; i++)
		blk[i] = htonl(blk[i]);
}

static void
ntohblk(uint32_t *blk, int n)
{
	int i;

	for (i = 0; i < n; i++)
		blk[i] = ntohl(blk[i]);
}

/*
 * Escape the characters \, * and ? and replace them with \\, \# and \!.
 * TSM cannot handle them.
 */
static void
strescape(char *ut, char *in, int max)
{
	int i = 1, c;

	max--;
	*ut++ = '/';
	for (;;) {
		if ((c = *in) == '\\') {
			*ut++ = '\\', i++;
		} else if (c == '*') {
			*ut++ = '\\', i++;
			c = '#';
		} else if (c == '?') {
			*ut++ = '\\', i++;
			c = '!';
		}
		*ut++ = c;
		in++;
		i++;
		if (c == 0 || i >= max)
			break;
	}
}

/* ------------------------------------ */


static int
fssetup(struct rx_securityClass **ssc, afs_int32 *sscindex)
{
	struct ktc_principal sname;
	struct ktc_token kt;
	struct rx_securityClass *sc;
	struct afsconf_cell info;
	struct afsconf_dir *tdir;
	afs_int32 scIndex;
	char cn[MAXCELLCHARS];
	char *estr = NULL;
	int rv;

	if ((rv = rx_Init(0)))
		errx(1, "could not initialize rx");
	rx_SetRxDeadTime(90);

	if (localauth) { /* generate token from keyfile */
		if ((tdir = afsconf_Open(AFSDIR_SERVER_ETC_DIRPATH)) == NULL)
			errx(1, "afsconf_Open server failed");
		if ((rv = afsconf_ClientAuth(tdir, &sc, &scIndex))) {
			estr = "Could not access KeyFile";
			goto fail;
		}
		if ((rv = afsconf_GetCellInfo(tdir, tdir->cellName,
		    AFSCONF_FILESERVICE, &info))) {
			estr = "afsconf_GetCellInfo failed";
			goto fail;
		}
		if ((rv = afsconf_GetLatestKey(tdir, 0, 0))) {
			afs_com_err("foo", rv,
			    "(getting key from local KeyFile)\n");
			goto fail;
		}
	} else {
		if ((tdir = afsconf_Open(AFSDIR_CLIENT_ETC_DIRPATH)) == NULL)
			errx(1, "afsconf_Open client failed");
		rv = afsconf_GetLocalCell(tdir, cn, sizeof(cn));
		if (rv) {
			estr = "afsconf_GetLocalCell failed";
			goto fail;
		}
		if ((rv = afsconf_GetCellInfo(tdir, cn,
		    AFSCONF_FILESERVICE, &info))) {
			estr = "afsconf_GetCellInfo failed";
			goto fail;
		}
		strcpy(sname.cell, info.name);
		sname.instance[0] = 0;
		strcpy(sname.name, "afs");
		if ((rv = ktc_GetToken(&sname, &kt, sizeof(kt), NULL))){
			estr = "could not get token";
			goto fail;
		}
		scIndex = 2;
		if ((kt.kvno < 0) || (kt.kvno > 256))
			warnx("funny kvno in ticket");

		sc = rxkad_NewClientSecurityObject(rxkad_clear,
		    &kt.sessionKey, kt.kvno, kt.ticketLen, kt.ticket);
	}
	afsconf_Close(tdir);
	ssc[scIndex] = sc;
	*sscindex = scIndex;

	return 0;
fail:
	afsconf_Close(tdir);
	errx(1, "%s", estr ? estr : "foof");
}

static void
storedir(char *hl, char *ll, struct rx_connection *sc, AFSFid *fid, 
    struct AFSFetchStatus *fs, struct dirattribute *d)
{
	struct dirattribute dira;
	int i;

	TADEBUG("d	%s%s\n", hl, ll);

	dira.cwtype = MKCWTYP(DIRVERSION, Directory);

	dira.vnode = fid->Vnode;
	dira.unique = fid->Unique;
	dira.versl = fs->DataVersion;
	dira.versh = fs->dataVersionHigh;

	dira.owner = fs->Owner;
	dira.group = fs->Group;
	dira.mode = fs->UnixModeBits;
	dira.time = fs->ClientModTime;

	dira.npos = d->npos;
	dira.nneg = d->nneg;
	for (i = 0; i < ACL_MAXENTRIES; i++) {
		dira.acls[i].id = d->acls[i].id;
		dira.acls[i].rights = d->acls[i].rights;
	}

	htonblk((uint32_t *)&dira, sizeof(dira)/sizeof(uint32_t));

	if (tsmstartobj(hl, ll, 0, 0, &dira, sizeof(dira), 0)) {
		dir[BUPPED]--;
		dir[FAILED]++;
		return;
	}
	tsmendobj();
}

static void
storefile(char *hl, char *ll, struct rx_connection *sc, AFSFid *fid, 
    struct AFSFetchStatus *fs)
{
	struct fileattribute fila;
	char buf[TSMBUFLEN];
	struct AFSFetchStatus fst;
	struct AFSCallBack scb;
	struct AFSVolSync vs;
	struct rx_call *rxc = NULL;
	afs_uint64 tsz, tsn;
	afs_uint32 xh, xl;
	int rv, i;

	TADEBUG("%c	%s%s\n", fs->FileType == 1 ? 'f' : 'l', hl, ll);

	fila.cwtype = MKCWTYP(FILEVERSION, fs->FileType);

	fila.vnode = fid->Vnode;
	fila.unique = fid->Unique;
	fila.versl = fs->DataVersion;
	fila.versh = fs->dataVersionHigh;

	fila.owner = fs->Owner;
	fila.group = fs->Group;
	fila.mode = fs->UnixModeBits;
	fila.time = fs->ClientModTime;

	fila.npos = fila.nneg = 0;
	for (i = 0; i < ACL_MAXENTRIES; i++)
		fila.acls[i].id = fila.acls[i].rights = 0;

	htonblk((uint32_t *)&fila, sizeof(fila)/sizeof(uint32_t));

	if (tsmstartobj(hl, ll, fs->Length_hi, fs->Length, &fila,
	    sizeof(fila), 1)) {
		if (fs->FileType == 1)
			fil[BUPPED]--, fil[FAILED]++;
		else
			sym[BUPPED]--, sym[FAILED]++;
		return;
	}

	tsz = (((afs_uint64)fs->Length_hi << 32) | (afs_uint64)fs->Length);
	rxc = rx_NewCall(sc);
	if ((rv = StartRXAFS_FetchData64(rxc, fid, 0, tsz)) != 0) {
		warnx("StartRXAFS_FetchData64 for %s%s failed: %d", hl, ll, rv);
		goto fail;
	}

	rx_Read32(rxc, &xh);
	rx_Read32(rxc, &xl);
	xl = ntohl(xl);
	xh = ntohl(xh);
	tsn = (((afs_uint64)xh << 32) | (afs_uint64)xl);

	if (tsn != tsz) {
		warnx("storefile: tsn (%lld) != tsz (%lld)", tsn, tsz);
		warnx("storefile: %s/%s", hl, ll);
		goto fail;
	}
	while (tsz > 0) {
		int b, len = min(tsz, TSMBUFLEN);

		if ((b = rx_Read(rxc, buf, len)) < 0)
			break;
		if (tsmwrtblk(buf, b) != 0)
			break;
		tsz -= b;
	}
	if (tsz != 0)
		warnx("tsz != 0");

	rv = EndRXAFS_FetchData64(rxc, &fst, &scb, &vs);

fail:
	if (rxc)
		rv = rx_EndCall(rxc, rv);
	tsmendobj();
}

static int
skipdir(char *s)
{
	int i;

	if (*s == '/')
		s++;

	for (i = 0; i < nxfiles; i++) {
		if (strcmp(s, xfiles[i]) == 0)
			return 1;
}
	return 0;
}

/*
 * Fetch status information for an element in a directory.
 */
static void
extrent(char *hl, char *ll, struct rx_connection *sc, AFSFid *fid,
    struct taquery **taqp)
{
	struct dirattribute ta, dira;
	struct taquery *taq, *otaq;
	struct AFSFetchStatus fst;
	struct AFSOpaque opaq;
	struct AFSVolSync vs;
	char acl[AFSOPAQUEMAX];
	int rv, savdata, savattr;

	opaq.AFSOpaque_val = acl;
	opaq.AFSOpaque_len = AFSOPAQUEMAX;
	if ((rv = RXAFS_FetchACL(sc, fid, &opaq, &fst, &vs)) != 0) {
		warnx("RXAFS_FetchStatus for %s%s failed: (%d) %s", hl, ll, 
		    rv, afs_error_message(rv));
		strcpy(acl, SYSACLS); /* livrem */
	}
	acltoids(acl, &dira);

	/* Check if something should be backed up */
	taq = NULL;
	if (taqp) {
		otaq = NULL;
		for (taq = *taqp; taq; otaq = taq, taq = taq->next)
			if (strcmp(ll, taq->ll) == 0)
				break;
		if (taq) { /* Got one */
			if (otaq == NULL)
				*taqp = taq->next;
			else
				otaq->next = taq->next;
			memcpy(&ta, taq->da, sizeof(ta));
			ntohblk(&ta.cwtype, sizeof(ta)/sizeof(uint32_t));
		}
	}
	savdata = savattr = 1;
	if (taq && ta.vnode == fid->Vnode && ta.unique == fid->Unique &&
	    ta.versl == fst.DataVersion &&
	    ta.versh == fst.dataVersionHigh) {
		if (dflag)
			printf("Don't save data for %s%s\n", hl, ll);
		savdata = 0;
	} else if (dflag)
		printf("Store file %s%s\n", hl, ll);

	if (taq && ta.owner == fst.Owner && ta.group == fst.Group &&
	    ta.mode == fst.UnixModeBits && ta.time == fst.ClientModTime) {
		if (fst.FileType == Directory) {
			if (ta.npos == dira.npos && ta.nneg == dira.nneg &&
			    memcmp(ta.acls, dira.acls,
			    sizeof(struct taacl)) == 0) {
				savattr = 0;
			}
		} else {
			if (dflag)
				printf("Don't save attributes for %s%s\n",
				    hl, ll);
			savattr = 0;
		}
	} else if (dflag && !skipdir(ll))
		printf("Store attributes %s%s\n", hl, ll);
		
	if (dflag > 1) {
		printf("FetchStatus for %s%s:\n", hl, ll);
		printf("vers %d type %d linkcnt %d\n", fst.InterfaceVersion, 
		    fst.FileType, fst.LinkCount);
		printf("verslo %d vershi %d\n", fst.DataVersion,
		    fst.dataVersionHigh);
		printf("lengthlo %d lengthhi %d\n", fst.Length, fst.Length_hi);
		printf("Author %d Owner %d CallerAccess %d AnonymousAccess %d\n",
		    fst.Author, fst.Owner, fst.CallerAccess, fst.AnonymousAccess);
		printf("UnixModeBits %o ClientModTime %d ServerModTime %d\n",
		    fst.UnixModeBits, fst.ClientModTime, fst.ServerModTime);
		printf("Group %d SyncCounter %d lockCount %d\n",
		    fst.Group, fst.SyncCounter, fst.lockCount);
		printf("Vnode %d Unique %d\n", fid->Vnode, fid->Unique);
	}

	if ((savattr || savdata) && intrans == 0) {
		if ((rv = tsmstart()))
			return;
		intrans = 1;
	}
	switch (fst.FileType) {
	case Directory:
		if (skipdir(ll))
			break;
		dir[TOTAL]++;
		if (savattr) {
			storedir(hl, ll, sc, fid, &fst, &dira);
			dir[BUPPED]++;
		} else
			dir[NONEED]++;
		parsedir(hl, ll, sc, fid);
		break;
	case SymbolicLink:
		sym[TOTAL]++;
		if (savdata || savattr) {
			storefile(hl, ll, sc, fid, &fst);
			sym[BUPPED]++;
		} else
			sym[NONEED]++;
		break;
	case File:
		fil[TOTAL]++;
		if (savdata || savattr) {
			storefile(hl, ll, sc, fid, &fst);
			fil[BUPPED]++;
			if ((fil[BUPPED] % 1000) == 0)
				printf("++++ Files saved: %d\n", fil[BUPPED]);
		} else
			fil[NONEED]++;
		break;
	default:
		warnx("object %s%s has unknown type %d", hl, ll, fst.FileType);
		break;
	}
	if (taq)
		tsmtaqfree(taq);
}

/*
 * parse a directory and traverse down for each element.
 */
static void
parsedir(char *hl, char *ll, struct rx_connection *sc, AFSFid *fid)
{
	struct taquery *taq;
#define	DIRPSZ	((BIGMAXPAGES+1)*AFS_PAGESIZE)
#define	HLMAX	(VOLSER_MAXVOLNAME+AFSPATHMAX)
	char dirbuf[DIRPSZ];
	char hlname[HLMAX];
	char llname[AFSNAMEMAX];
	struct AFSFetchStatus fst;
	struct AFSVolSync vs;
	struct AFSCallBack scb;
	struct DirHeader *dhp;
	struct DirEntry *ep;
	struct rx_call *scall;
	AFSFid nfid;
	afs_uint32 xh, fsz;
	int rv, i;

	/* get directory structure */
	scall = rx_NewCall(sc);
	if ((rv = StartRXAFS_FetchData64(scall, fid, 0, DIRPSZ)) != 0) {
		warnx("StartRXAFS_FetchData64 for %s%s failed: %d", hl, ll, rv);
		return;
	}
	rx_Read32(scall, &xh);
	rx_Read32(scall, &fsz);
	fsz = ntohl(fsz);
	xh = ntohl(xh);

	if (fsz > DIRPSZ) {
		warnx("dir %s%s: fsz > DIRPSZ", hl,ll);
		return;
	}
	rv = rx_Read(scall, dirbuf, (afs_uint32)fsz);
	if (rv != fsz) {
		warnx("dir %s%s: fsz != rv", hl,ll);
		return;
	}

	rv = EndRXAFS_FetchData64(scall, &fst, &scb, &vs);
	if ((rv = rx_EndCall(scall, rv))) {
		warnx("EndRXAFS_FetchData64: %s", afs_error_message(rv));
		return;
	}

	if (snprintf(hlname, HLMAX, "%s%s", hl, ll) >= HLMAX) {
		warnx("Path too long: %s%s",  hl, ll);
		return;
	}

	if (intrans) {
		if ((rv = tsmend())) /* must end transaction before query */
			return;
		intrans = 0;
	}

	/* fetch dir element status to decide if we need to do backup */
	if ((rv = tsmquery(fspace, hlname, "/*", &taq, NULL)))
		taq = NULL; /* backup anyway */

	dhp = (struct DirHeader *)dirbuf;
	for (i = 0; i < NHASHENT; i++) {
		int num = ntohs(dhp->hashTable[i]);
		while (num) {
			char *de = dirbuf + (num >> LEPP) * AFS_PAGESIZE;
			if (de >= dirbuf + fsz)
				break;
			ep = (struct DirEntry *)(de + 32 * (num & (EPP - 1)));
			if (strcmp(ep->name, ".") && strcmp(ep->name, "..")) {
				nfid.Volume = fid->Volume;
				nfid.Vnode = htonl(ep->fid.vnode);
				nfid.Unique = htonl(ep->fid.vunique);
				strescape(llname, ep->name, AFSNAMEMAX);
				extrent(hlname, llname, sc, &nfid, &taq);
			}
			num = ntohs(ep->next);
		}
	}
	/* XXX memory leaks below */
	for (; taq; taq = taq->next) {
		struct taquery *tal;

		if (strcmp(taq->ll, "/") == 0) /* special case */
			continue; /* XXX memory leak */

		i = sprintf(hlname, "%s%s*", taq->hl, taq->ll);
		if (intrans) {
			if ((rv = tsmend())) /* must end before query */
				return; /* XXX what do? */
			intrans = 0;
		}

		if ((rv = tsmquery(fspace, hlname, "/*", &tal, NULL)))
			return; /* ignore */
		if ((rv = tsmstart()))
			return;
		intrans = 1;
		for (; tal; tal = tal->next) {
			if (dflag)
				printf("remove: %s%s\n", tal->hl, tal->ll);
			(void)tsmdelobj(tal->tsmresp);
		}
		(void)tsmdelobj(taq->tsmresp);
		if (dflag)
			printf("remove: %s%s\n", taq->hl, taq->ll);
	}
}

/* Get current cell name */
static void
getcellname(char *fsp)
{
	struct afsconf_dir *ad;
	int rv;

	if ((ad = afsconf_Open(AFSDIR_CLIENT_ETC_DIRPATH)) == NULL)
		if ((ad = afsconf_Open(AFSDIR_SERVER_ETC_DIRPATH)) == NULL)
			errx(1, "cannot find any afs config dir");
	if ((rv = afsconf_GetLocalCell(ad, fsp, MAXCELLCHARS)) != 0)
		errx(1, "cannot find cell name");
	(void)afsconf_Close(ad);
}

static struct rx_connection *
setupconn(afs_uint32 srvno, struct rx_securityClass **ssc, int sscindex)
{
	static struct rx_connection *rxs;
	static afs_uint32 srvs;

	if (srvs == srvno)
		return rxs;
	if (rxs != NULL)
		rx_DestroyConnection(rxs);
	rxs = rx_NewConnection(srvno, htons(AFSCONF_FILEPORT), 1, 
	    ssc[sscindex], sscindex);
	if (rxs == NULL)
		warnx("cannot contact server %x", srvno);
	srvs = srvno;
	return rxs;
}

/*
 * Check if a volume should be skipped.
 */
static int
checkvol(struct tavol *vl, afs_uint32 *vt)
{
	struct taquery *taq;
	struct volintInfo *vii;
	afs_uint32 tt;
	char ll[VOLSER_MAXVOLNAME+1] = "/";
	int code, rv;

	code = UV_ListOneVolume(vl->srvno, htonl(vl->partid), vl->volid, &vii);
	if (code) {
		*vt = 0;
		warnx("checkvol error %d\n", code);
		return 1; /* try backup */
	}
	*vt = vii->updateDate;
	strcat(ll, vl->name);
	if ((rv = tsmquery(fspace, "/", ll, &taq, NULL))) {
		if (dflag)
			warnx("tsmquery failed: %d", rv);
		return 1; /* failed, try backup */
	}
	if (taq == NULL)
		return 1; /* must backup */

	tt = ntohl(taq->da->time);
	tsmtaqfree(taq);
	if (tt == vii->updateDate) {
		printf("**** VOLUME %s UNCHANGED ****\n", vl->name);
		return 0;
	}
	return 1;
}

static int
backupvol(struct tavol *vl, struct rx_connection *rxs)
{
	struct timeval tin, tut, tot;
	struct dirattribute dira;
	struct taquery *taq;
	struct AFSFetchStatus fst;
	struct AFSOpaque opaq;
	struct AFSVolSync vs;
	char acl[AFSOPAQUEMAX];
	char hl[VOLSER_MAXVOLNAME+1] = "/"; /* + '/' */
	char ll[] = "";
	afs_uint32 vt;
	AFSFid fid;
	int rv, savdir, i;

	if (!Fflag && checkvol(vl, &vt) == 0)
		return 0;

	printf("****  BACKING VOLUME %s ****\n", vl->name);

	(void)gettimeofday(&tin, NULL);

	fid.Volume = vl->volid;
	fid.Vnode = 1;
	fid.Unique = 1;
	strcat(hl, vl->name);

	opaq.AFSOpaque_val = acl;
	opaq.AFSOpaque_len = AFSOPAQUEMAX;
        if ((rv = RXAFS_FetchACL(rxs, &fid, &opaq, &fst, &vs)) != 0) {
                warnx("RXAFS_FetchACL for %s%s failed: (%d) %s", hl, ll,
                    rv, afs_error_message(rv));
                strcpy(acl, SYSACLS); /* h{ngslen */
        }
	acltoids(acl, &dira);

	/* Special handling of top dir in volume */
	if ((rv = tsmquery(fspace, hl, "/", &taq, NULL)))
		taq = NULL; /* backup anyway */

	savdir = 1;
	if (taq) {
		struct dirattribute ta;
		memcpy(&ta, taq->da, sizeof(ta));
		ntohblk(&ta.cwtype, sizeof(ta)/sizeof(uint32_t));
		if (ta.owner == fst.Owner && ta.group == fst.Group &&
		    ta.mode == fst.UnixModeBits &&
		    ta.time == fst.ClientModTime &&
		    ta.npos == dira.npos && ta.nneg == dira.nneg &&
		    memcmp(ta.acls, dira.acls, sizeof(struct taacl)) == 0) {
			if (dflag)
				printf("Don't save attributes for %s/\n", hl);
			savdir = 0;
		}
		free(taq->tsmresp);
		free(taq);
		
	}
	if (dflag && savdir)
		printf("Store attributes for %s/\n", hl);

	dir[TOTAL]++;
	if (savdir) {
		if ((rv = tsmstart()))
			return rv;
		intrans = 1;
		storedir(hl, "/", rxs, &fid, &fst, &dira);
		dir[BUPPED]++;
	} else
		dir[NONEED]++;

	/* start traversal down to check directory status */
	parsedir(hl, ll, rxs, &fid);

	if (intrans == 0)
		if ((rv = tsmstart()))
			return rv;

	/* store volume time info */
	dira.cwtype = 0;
	dira.time = vt;
	htonblk((uint32_t *)&dira, sizeof(dira)/sizeof(uint32_t));
	if (tsmstartobj("/", hl, 0, 0, &dira, sizeof(dira), 0) == 0)
		tsmendobj();

	rv = tsmend();
	intrans = 0;

	(void)gettimeofday(&tut, NULL);

	timersub(&tut, &tin, &tot);

	printf("****  VOLUME %s BACKUP STATISTICS  ****\n", vl->name);
	printf("Files: total %-8d saved %-8d in store %-8d failed %d\n",
	    fil[TOTAL], fil[BUPPED], fil[NONEED], fil[FAILED]);
	printf("Dirs:  total %-8d saved %-8d in store %-8d failed %d\n",
	    dir[TOTAL], dir[BUPPED], dir[NONEED], dir[FAILED]);
	printf("Links: total %-8d saved %-8d in store %-8d failed %d\n",
	    sym[TOTAL], sym[BUPPED], sym[NONEED], sym[FAILED]);
	printf("Time spent: %02ld:%02ld.%02ld\n\n",
	    tot.tv_sec/60, tot.tv_sec%60, tot.tv_usec/10000);
	for (i = 0; i < 5; i++)
		sym[i] = dir[i] = fil[i] = 0;
	return rv;
}

static int
cmpvol(const void *p1, const void *p2)
{
	struct tavol const *const*v1 = p1, *const*v2 = p2;

	return strcmp((*v1)->name, (*v2)->name);
}

/*
 * Sort all volumes in order.
 */
static struct tavol *
sortvols(struct tavol *vlp)
{
	struct tavol **ap;
	struct tavol *vl;
	int i, nelem;

	if (vlp == NULL)
		return NULL;

	for (vl = vlp, nelem = 0; vl; vl = vl->next, nelem++)
		;
	ap = malloc(sizeof(struct tavol *) * nelem);
	for (vl = vlp, i = 0; i < nelem; i++, vl = vl->next)
		ap[i] = vl;
	if (vl != NULL)
		errx(1, "sortvols");
	qsort(ap, nelem, sizeof(struct tavol *), cmpvol);
	for (i = 0; i < nelem-1; i++)
		ap[i]->next = ap[i+1];
	ap[i]->next = NULL;
	vl = ap[0];
	free(ap);
	return vl;
}

static void
transend(void)
{
	if (!intrans)
		return;
	if (tsmend())
		return;
	intrans = 0;
}

/*
 * Inactivate all files in a volume.
 */
static void
inafiles(char *c)
{
	struct taquery *taq, *taqp;
	char hlevel[1024];	/* XXX use define */

	printf("****  INACTIVATING VOLUME %s ****\n", c);

	// first check: /vol/*/*
	sprintf(hlevel, "/%s/*", c);
	transend();
	if (tsmquery(fspace, hlevel, "/*", &taqp, 0))
		return;
	if (taqp) {
		if (tsmstart())
			return;
		intrans = 1;
		for (taq = taqp; taq; taq = taq->next) {
			(void)tsmdelobj(taq->tsmresp);
		}
	}

	// second check: /vol/*
	sprintf(hlevel, "/%s", c);
	transend();
	if (tsmquery(fspace, hlevel, "/*", &taqp, 0))
		return;
	if (taqp) {
		if (tsmstart())
			return;
		intrans = 1;
		for (taq = taqp; taq; taq = taq->next) {
			(void)tsmdelobj(taq->tsmresp);
		}
	}

	// third check: /vol
	transend();
	if (tsmquery(fspace, "/*", hlevel, &taqp, 0))
		return;
	if (taqp) {
		if (tsmstart())
			return;
		intrans = 1;
		for (taq = taqp; taq; taq = taq->next) {
			(void)tsmdelobj(taq->tsmresp);
		}
	}
}

/* Return 1 if volume is not in afs */
static int
notinafs(char *n, struct tavol *vlp)
{
	struct tavol *vl;

	for (vl = vlp; vl; vl = vl->next)
		if (strcmp(n, vl->name) == 0)
			return 0;
	return 1;
}

/*
 * Inactivate volumes not found in AFS.
 */
static void
inactivatevol(char *volarg, struct tavol *vlp)
{
	char hlevel[1024];	/* XXX use define */
	struct taquery *taq, *taqp;

	sprintf(hlevel, "/%s", volarg);

	if (tsmquery(fspace, hlevel, "/", &taqp, 0))
		return;

	for (taq = taqp; taq; taq = taq->next) {
		if (notinafs(&taq->hl[1], vlp))
			inafiles(&taq->hl[1]);
	}
}

int
main(int argc, char **argv)
{
	afs_int32 RXAFSCB_ExecuteRequest(struct rx_call *);
	struct rx_securityClass *scs;
	struct rx_connection *rxs = NULL;
	struct rx_securityClass *ssc[3];
	struct rlimit rl;
	char fsp[MAXCELLCHARS+1];
	struct tavol *vl, *vlp;
	char *server, *part;
	char *volarg = "*";
	int i, ch, sscindex, rv = 1;

	server = fspace = part = NULL;
	while ((ch = getopt(argc, argv, "Fc:v:s:f:p:adnx:iI")) != -1) {
		switch (ch) {
		case 'v':
			volarg = optarg;
			break;
		case 's':
			server = optarg;
			break;
		case 'f':
			fspace = optarg;
			break;
		case 'p':
			part = optarg;
			break;
		case 'l':
			localauth = 1;
			break;
		case 'a':
			archive = 1;
			break;
		case 'n':
			nflag = 1;
			break;
		case 'd':
			dflag = 1;
			break;
		case 'F': /* Force backup even on clean volumes */
			Fflag = 1;
			break;
		case 'i': /* Only inactivate volumes, do not backup anything */
			iflag = 1;
			break;
		case 'I': /* Do not inactivate volumes missing in AFS */
			Iflag = 1;
			break;
		case 'x':
			if (nxfiles >= MAXXFILES)
				warnx("too many excluded files, %s ignored",
				    optarg);
			else
				xfiles[nxfiles++] = optarg;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	/* for deep hierarchies we may need much stack */
	if (getrlimit(RLIMIT_STACK, &rl) >= 0) {
		rl.rlim_cur = RLIM_INFINITY;
		rl.rlim_max = RLIM_INFINITY;
		if (setrlimit(RLIMIT_STACK, &rl) < 0)
			warn("setrlimit");
	} else
		warn("getrlimit");

	setvbuf(stdout, (char *)NULL, _IOLBF, 0); /* Always line-buffered */

	if (fspace == NULL) {
		fsp[0] = '/';
		getcellname(&fsp[1]);
		if (dflag)
			fprintf(stderr, "Using filespace %s\n", fsp);
		fspace = fsp;
	}

	if (tsminit(fspace, 0))
		goto die;

	if ((i = pr_Initialize(1, AFSDIR_CLIENT_ETC_DIRPATH, NULL))) {
		afs_com_err("foo", i, "while initializing");
		goto die;
	}
	/* Fix vldb security */
	if ((i = vsu_ClientInit(0, (char *)AFSDIR_CLIENT_ETC_DIRPATH, NULL,
	    localauth, &cstruct, UV_SetSecurity))) {
		afs_com_err("foo", i, "while initializing");
		goto die;
	}

	/* Get a list of all matching volumes */
	vlp = getvols(server, part, volarg);

	/* Initialize rx for file transfers */
	if (fssetup(ssc, &sscindex))
		goto die;

	/* We need callbacks even if they are not used. */
	scs = rxnull_NewServerSecurityObject();
	if (rx_NewService(0, 1, "afs", &scs, 1, RXAFSCB_ExecuteRequest) == 0)
		errx(1, "rx_NewService");
	rx_StartServer(0);

	/* Bokstavsordning */
	vlp = sortvols(vlp);

	/* Traverse over all volumes to be backed up */
	if (iflag == 0) {
		for (vl = vlp; vl; vl = vl->next) {
			if ((rxs = setupconn(vl->srvno, ssc, sscindex)) == NULL)
				continue;
			if (backupvol(vl, rxs))
				goto die;
		}
	}

	if (Iflag == 0) /* Inactivate missing volumes */
		inactivatevol(volarg, vlp);

	rv = 0;

die:	if (rxs)
		rx_DestroyConnection(rxs);
	tsmshutdown();
	return rv;
}

void
usage()
{
	fprintf(stderr, "Usage: tsmbackup [-v vol] [-f fs] "
	    "[-s server] [-p part] [-land]\n");
	exit(1);
}

/*
 * Get a list of volumes from the VLDB server located on
 * server and partition (if not null) and volname.
 * volname can be wildcarded as shell file names.
 */
struct tavol *
getvols(char *server, char *part, char *volname)
{
	struct VldbListByAttributes attributes;
	struct nvldbentry *vllist;
	nbulkentries arrayEntries;
	struct tavol *vlpole = NULL, *vl;
	int j, vcode, thisindex, nextindex, centries;

	attributes.Mask = 0;
	if (server != NULL) {
		struct hostent *hp;
		afs_int32 sip;

		if ((hp = gethostbyname(server)) == NULL)
			errx(1, "server %s not found", server);
		memcpy(&sip, hp->h_addr, sizeof(sip));
		attributes.server = ntohl(sip);
		attributes.Mask |= VLLIST_SERVER;
	}
	if (part != NULL) {
		afs_int32 sp;
		if ((sp = volutil_GetPartitionID(part)) < 0)
			errx(1, "partition %s wrong", part);
		attributes.partition = sp;
		attributes.Mask |= VLLIST_PARTITION;
	}

	for (thisindex = 0; (thisindex != -1); thisindex = nextindex) {
		memset(&arrayEntries, 0, sizeof(arrayEntries));
		centries = 0;
		nextindex = -1;
		vcode = VLDB_ListAttributesN2(&attributes, 0, thisindex,
		    &centries, &arrayEntries, &nextindex);
		if (vcode == RXGEN_OPCODE)
			errx(1, "too old vldb version");
		if (vcode)
			errx(1, "vldb error %d\n", vcode);
		for (j = 0; j < centries; j++) {
			vllist = &arrayEntries.nbulkentries_val[j];
			if (fnmatch(volname, vllist->name, 0) == FNM_NOMATCH)
				continue;
#if 0
{
	struct nvldbentry *vl = vllist;
	int i;

        printf("name: %s nservers %d\n",
            vl->name, vl->nServers);
        for (i = 0; i < NMAXNSERVERS; i++) {
                printf("    servnr %x servp %d servfl 0x%x\n", 
                    vl->serverNumber[i],
                    vl->serverPartition[i],
                    vl->serverFlags[i]);
        }
        for (i = 0; i < MAXTYPES; i++)
                printf("    volumeid %d\n", vl->volumeId[i]);
        printf("    clone %d flags 0x%x match %d\n", 
            vl->cloneId, vl->flags, vl->matchindex);
}
#endif

			if ((vllist->flags & VLF_BACKEXISTS) == 0) {
				warnx("%s has no backup volume", vllist->name);
				continue;
			}
			if ((vl = malloc(sizeof(struct tavol))) == NULL)
				errx(1, "out of memory");
			vl->name = strdup(vllist->name);
			/* XXX only check servernumber 0, can it fail? */
			vl->srvno = htonl(vllist->serverNumber[0]);
			vl->partid = htonl(vllist->serverPartition[0]);
			vl->volid = vllist->volumeId[BACKVOL];
			vl->next = vlpole;
			vlpole = vl;
		}
	}
	return vlpole;
}

/*
 * Convert an acl string to an id array.
 */
void
acltoids(char *p, struct dirattribute *d)
{
	prname nm[PR_MAXNAMELEN*ACL_MAXENTRIES];
	afs_int32 perm[ACL_MAXENTRIES];
	namelist names;
	idlist ids;
	int i, j, tot;


	memset(d, 0, sizeof(struct dirattribute));
	errno = 0;
	d->npos = strtol(p, &p, 0);
	p++; /* skip \n */
	d->nneg = strtol(p, &p, 0);
	p++; /* skip \n */
	if (errno)
		return;

	tot = d->npos + d->nneg;
	names.namelist_val = nm;
	names.namelist_len = tot;
	for (i = 0; i < tot; i++) {
		for (j = 0; j < PR_MAXNAMELEN; j++) {
			if (isspace((int)*p))
				break;
			names.namelist_val[i][j] = *p++;
		}
		names.namelist_val[i][j] = 0;
		perm[i] = strtol(p, &p, 0);
		p++; /* skip \n */
	}
	ids.idlist_val = 0;
	ids.idlist_len = 0;
	if ((i = pr_NameToId(&names, &ids)))
		afs_com_err("foo", i, "; pr_NameToId", 0);

#if 0
	struct prcheckentry aentry;
	namelist names;
	idlist ids;
	afs_int32 id = 14431;
	afs_int32 sec = 0;
	char *n[2];
	int i;

	n[0] = "ragge";
	n[1] = "system:backup";
	names.namelist_val = (prname *) malloc(2*PR_MAXNAMELEN);
	strncpy(names.namelist_val[0], n[0], PR_MAXNAMELEN);
	strncpy(names.namelist_val[1], n[1], PR_MAXNAMELEN);
	names.namelist_len = 2;
	ids.idlist_val = 0;
	ids.idlist_len = 0;
	if ((i = pr_NameToId(&names, &ids)))
		afs_com_err("foo", i, "; pr_NameToId", id);
	if (ids.idlist_len)
		printf("id1: %d %d\n", ids.idlist_val[0], ids.idlist_val[1]);

	if ((i = pr_ListEntry(id, &aentry)))
		afs_com_err("foo", i, "; unable to find entry for (id: %d)", id);
	printf("user: %s id: %d\n", aentry.name, aentry.id);
	exit(1);
#endif
}

/* Gee, all those callbacks */
static	struct interfaceAddr ifa;

afs_int32
SRXAFSCB_GetXStats(
        /*IN */ struct rx_call *z_call,
        /*IN */ afs_int32 clientVersionNumber,
        /*IN */ afs_int32 collectionNumber,
        /*OUT*/ afs_int32 * srvVersionNumberP,
        /*OUT*/ afs_int32 * timeP,
        /*OUT*/ AFSCB_CollData * dataP) {
	return 0;
}

afs_int32
SRXAFSCB_CallBack(
        /*IN */ struct rx_call *z_call,
        /*IN */ AFSCBFids * Fids_Array,
        /*IN */ AFSCBs * CallBacks_Array){
	return 0;
}

afs_int32
SRXAFSCB_GetServerPrefs(
        /*IN */ struct rx_call *z_call,
        /*IN */ afs_int32 serverIndex,
        /*OUT*/ afs_int32 * srvrAddr,
        /*OUT*/ afs_int32 * srvrRank){
	return RXGEN_OPCODE;
}

afs_int32
SRXAFSCB_ProbeUuid(
        /*IN */ struct rx_call *z_call,
        /*IN */ afsUUID * clientUuid){
	/* When can this be called? */
	return !afs_uuid_equal(clientUuid, &ifa.uuid);
}

afs_int32
SRXAFSCB_InitCallBackState(
        /*IN */ struct rx_call *z_call)
{
	return 0;
}

afs_int32
SRXAFSCB_XStatsVersion(
        /*IN */ struct rx_call *z_call,
        /*OUT*/ afs_int32 * versionNumberP)
{
	return 0;
}

afs_int32
SRXAFSCB_GetCE(
        /*IN */ struct rx_call *z_call,
        /*IN */ afs_int32 index,
        /*OUT*/ AFSDBCacheEntry * ce)
{
	return 0;
}

afs_int32
SRXAFSCB_GetCE64(
        /*IN */ struct rx_call *z_call,
        /*IN */ afs_int32 index,
        /*OUT*/ AFSDBCacheEntry64 * ce)
{
	return 0;
}

afs_int32
SRXAFSCB_Probe(
        /*IN */ struct rx_call *z_call)
{
	return 0;
}

afs_int32
SRXAFSCB_InitCallBackState3(
        /*IN */ struct rx_call *z_call,
        /*IN */ afsUUID * serverUuid)
{
	return 0;
}

afs_int32
SRXAFSCB_GetLocalCell(
        /*IN */ struct rx_call *z_call,
        /*OUT*/ char * *cellName)
{
	return RXGEN_OPCODE;
}

afs_int32
SRXAFSCB_GetCacheConfig(
        /*IN */ struct rx_call *z_call,
        /*IN */ afs_uint32 callerVersion,
        /*OUT*/ afs_uint32 * serverVersion,
        /*OUT*/ afs_uint32 * configCount,
        /*OUT*/ cacheConfig * config)
{
	return RXGEN_OPCODE;
}

afs_int32
SRXAFSCB_GetCellByNum(
        /*IN */ struct rx_call *z_call,
        /*IN */ afs_int32 cellNumber,
        /*OUT*/ char * *cellName,
        /*OUT*/ serverList * cellHosts)
{
	return RXGEN_OPCODE;
}

afs_int32
SRXAFSCB_GetLock(
        /*IN */ struct rx_call *z_call,
        /*IN */ afs_int32 index,
        /*OUT*/ AFSDBLock * lock)
{
	return 0;
}

afs_int32
SRXAFSCB_InitCallBackState2(
        /*IN */ struct rx_call *z_call,
        /*OUT*/ struct interfaceAddr * addr)
{
	return RXGEN_OPCODE;
}

afs_int32
SRXAFSCB_WhoAreYou(
        /*IN */ struct rx_call *z_call,
        /*OUT*/ struct interfaceAddr * addr)
{

	afs_uuid_create(&ifa.uuid);
	ifa.numberOfInterfaces =
	    rx_getAllAddr(ifa.addr_in, AFS_MAX_INTERFACE_ADDR);
	*addr = ifa;
	return 0;
}

afs_int32
SRXAFSCB_GetCellServDB(
        /*IN */ struct rx_call *z_call,
        /*IN */ afs_int32 cellIndex,
        /*OUT*/ char * *cellName,
        /*OUT*/ serverList * cellHosts)
{
	return RXGEN_OPCODE;
}

afs_int32
SRXAFSCB_TellMeAboutYourself(
        /*IN */ struct rx_call *z_call,
        /*OUT*/ struct interfaceAddr * addr,
        /*OUT*/ Capabilities * capabilities)
{
	return RXGEN_OPCODE;
}


