/*	$Id: tsmafs.c,v 1.14 2012/01/11 12:11:52 ragge Exp $	*/
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


#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <fnmatch.h>
#include <time.h>

#include "dsmrc.h"
#include "dsmapitd.h"
#include "dsmapifp.h"

#include "tsmafs.h"

/* Globals from argument list */
int localauth, nflag, dflag;
static dsUint32_t dsmHandle;
extern char *fspace;
static int maxobjtxn, curobjtxn;

#define	TADEBUG(...)	if (dflag) fprintf(stderr, __VA_ARGS__)

void tsmerror(char *prestr, dsInt16_t rv);

#define	TSMBUFLEN	(32768-4)	/* recommended in API manual */

static struct taquery *taqpole;

int
tsmtaqfree(struct taquery *taq)
{
	taq->next = taqpole;
	taqpole = taq;
	return 0;
}

static struct taquery *
fetchtaq(void)
{
	struct taquery *taq;

	if (taqpole) {
		taq = taqpole;
		taqpole = taqpole->next;
	} else {
		if ((taq = malloc(sizeof(struct taquery))) == NULL)
			err(1, "malloc");
		if ((taq->tsmresp = malloc(sizeof(qryRespBackupData))) == NULL)
			err(1, "malloc");
	}
	return taq;
}

int
tsmstartobj(char *hl, char *ll, uint32_t hi, uint32_t lo, 
    void *attr, int attrlen, int isfile)
{
	dsmObjName objName;
	mcBindKey BindKey;
	ObjAttr objAttr;
	int rv;

	strcpy(objName.fs, fspace);
	strcpy(objName.hl, hl);
	strcpy(objName.ll, ll);
	objName.objType = isfile ? DSM_OBJ_FILE : DSM_OBJ_DIRECTORY;

	BindKey.stVersion = mcBindKeyVersion;

	if ((rv = dsmBindMC(dsmHandle, &objName, stBackup, &BindKey))
	    != DSM_RC_OK) {
		tsmerror("dsmBindMC", rv);
		return 1;
	}

	memset(&objAttr, 0, sizeof(ObjAttr));
	objAttr.stVersion = ObjAttrVersion;
	objAttr.owner[0] = 0;
	objAttr.sizeEstimate.hi = hi;
	objAttr.sizeEstimate.lo = lo;
	objAttr.objCompressed = bFalse;
	objAttr.objInfo = attr;
	objAttr.objInfoLength = attrlen;

	if ((rv = dsmSendObj(dsmHandle, stBackup, NULL, &objName,
	    &objAttr, NULL)) != DSM_RC_OK) {
		if (rv == DSM_RC_NEEDTO_ENDTXN) {
			TADEBUG("restarting transaction\n");
			if (tsmend())
				return 1;
			if ((rv = dsmBeginTxn(dsmHandle)) != DSM_RC_OK) {
				tsmerror("dsmBeginTxn", rv);
                		return 1;
			}
			if ((rv = dsmSendObj(dsmHandle, stBackup, NULL, 
			    &objName, &objAttr, NULL)) != DSM_RC_OK) {
				tsmerror("dsmSendObj", rv);
				return 1;
			}
		} else {
			tsmerror("dsmSendObj", rv);
                	return 1;
		}
        }
	return 0;
}

int
tsmwrtblk(char *blk, int len)
{
	DataBlk	dataBlk;
	int rv;

	dataBlk.stVersion = DataBlkVersion;
	dataBlk.bufferLen = len;
	dataBlk.bufferPtr = blk;
	dataBlk.numBytes = 0;

	if ((rv = dsmSendData(dsmHandle, &dataBlk)) != DSM_RC_OK)
		tsmerror("store blk", rv);
	return rv;
}

void
tsmendobj()
{
	int rv;

	if ((rv = dsmEndSendObj(dsmHandle)) != DSM_RC_OK)
		tsmerror("dsmEndSendObj", rv);
}

int
tsminit(char *fs, int restore)
{
	regFSData	regFS;
	dsmApiVersionEx	apiLibVer, apiApplVer;
	dsmInitExIn_t	initIn;
	dsmInitExOut_t	initOut;
	dsInt16_t	rv, appVersion, libVersion;
	ApiSessInfo	apis;

	memset(&apiLibVer, 0, sizeof(apiLibVer));
	dsmQueryApiVersionEx(&apiLibVer);

	appVersion = (10000 * DSM_API_VERSION)+(1000 * DSM_API_RELEASE) +
		(100 * DSM_API_LEVEL) + DSM_API_SUBLEVEL;

	libVersion = (apiLibVer.version * 10000) + (apiLibVer.release * 1000) +
	    (apiLibVer.level * 100) + (apiLibVer.subLevel);

	if (libVersion < appVersion)
		errx(1, "libVersion (%x) < appVersion (%x)",
		    libVersion, appVersion);

	memset(&initIn, 0, sizeof(dsmInitExIn_t));
	memset(&initOut, 0, sizeof(dsmInitExOut_t));
	memset(&apiApplVer, 0, sizeof(dsmApiVersionEx));
	apiApplVer.version = DSM_API_VERSION;
	apiApplVer.release = DSM_API_RELEASE;
	apiApplVer.level = DSM_API_LEVEL;
	apiApplVer.subLevel = DSM_API_SUBLEVEL;


	initIn.stVersion = dsmInitExInVersion;
	initIn.apiVersionExP = &apiApplVer;
	initIn.clientNodeNameP = NULL;
	initIn.clientOwnerNameP = NULL;
	initIn.clientPasswordP = NULL;
	initIn.applicationTypeP = "OpenAFS";
	initIn.configfile = NULL;
	initIn.options = NULL;
	initIn.userNameP = NULL;
	initIn.userPasswordP = NULL;

	rv = dsmInitEx(&dsmHandle, &initIn, &initOut);
	if (rv != 0) {
		if (rv == DSM_RC_REJECT_VERIFIER_EXPIRED)
			errx(1, "TSM password expired");
		else
			tsmerror("dsmInitEx failed", rv);
		return rv;
	}

	memset(&apis, 0, sizeof(ApiSessInfo));
	apis.stVersion = ApiSessInfoVersion;
	if ((rv = dsmQuerySessInfo(dsmHandle, &apis)) == DSM_RC_OK)
		maxobjtxn = apis.maxObjPerTxn;

	if (rv != 0) {
		tsmerror("dsmQuerySessInfo failed", rv);
		return rv;
	}

        if (restore == 0) {
		memset(&regFS, 0, sizeof(regFS));
		regFS.fsName = fs;
		regFS.fsType = "OpenAFS";
		if ((rv = dsmRegisterFS(dsmHandle, &regFS)) != DSM_RC_OK &&
		    rv != DSM_RC_FS_ALREADY_REGED)
			tsmerror("dsmRegisterFS", rv);
		if (rv == DSM_RC_FS_ALREADY_REGED) {
			TADEBUG("filespace %s already registered\n", fs);
			rv = 0;
		} else
			TADEBUG("filespace %s registered\n", fs);
	}
	return rv;
}

int
tsmstart()
{
	int rv;

	if ((rv = dsmBeginTxn(dsmHandle)) != DSM_RC_OK)
		tsmerror("dsmBeginTxn", rv);
	curobjtxn = 0;
	return rv;
}

int
tsmend()
{
	dsUint16_t reason;
	int rv, vote;
	
	vote = nflag ? DSM_VOTE_ABORT : DSM_VOTE_COMMIT;
	if ((rv = dsmEndTxn(dsmHandle, vote, &reason)) != DSM_RC_OK &&
	    rv != DSM_RC_CHECK_REASON_CODE) {
		tsmerror("dsmEndTxn", rv);
		(void)dsmEndTxn(dsmHandle, DSM_VOTE_ABORT, &reason);
	}
	return nflag ? 0 : rv;
}

int
tsmshutdown(void)
{
	int rv;

	if ((rv = dsmTerminate(dsmHandle)) != DSM_RC_OK)
		tsmerror("dsmTerminate", rv);
	return rv;
}

void
tsmerror(char *prestr, dsInt16_t rv)
{
	char str[DSM_MAX_RC_MSG_LENGTH];

	dsmRCMsg(dsmHandle, rv, str);
	if (prestr)
		warnx("%s: %s", prestr, str);
	else
		warnx("%s", str);
}

int
tsmquery(char *fs, char *hl, char *ll, struct taquery **taqp, struct tm *tm)
{
	qryRespBackupData *qaresp;
	struct taquery *taq, *tapole = NULL, *tarev = NULL;
	struct taquery *ftaq;
	DataBlk db;
	dsmObjName on;
	qryBackupData qa;
	int rv, nq;

	strcpy(on.fs, fs);
	strcpy(on.hl, hl);
	strcpy(on.ll, ll);
	on.objType = DSM_OBJ_WILDCARD;

	qa.stVersion = qryBackupDataVersion;
	qa.objName = &on;
	qa.owner = "";
	qa.objState = DSM_ACTIVE;
	if (tm != NULL) {
		qa.pitDate.year = tm->tm_year;
		qa.pitDate.month = tm->tm_mon;
		qa.pitDate.day = tm->tm_mday;
		qa.pitDate.hour = tm->tm_hour;
		qa.pitDate.minute = tm->tm_min;
		qa.pitDate.second = tm->tm_sec;
		qa.objState = DSM_ANY_MATCH;
	} else
		qa.pitDate.year = DATE_MINUS_INFINITE;

	if ((rv = dsmBeginQuery(dsmHandle,qtBackup, &qa))) {
		tsmerror("dsmBeginQuery", rv);
		return rv;
	}
	db.stVersion = DataBlkVersion;
	ftaq = fetchtaq();

	db.bufferLen = sizeof(qryRespBackupData);
	db.bufferPtr = ftaq->tsmresp;
	qaresp = (qryRespBackupData *)db.bufferPtr;
	qaresp->stVersion = qryRespBackupDataVersion;

	nq = 0;
e0:	while ((rv = dsmGetNextQObj(dsmHandle, &db)) == DSM_RC_MORE_DATA) {
		taq = ftaq;
		taq->da = (struct dirattribute *)&qaresp->objInfo;
		taq->fs = qaresp->objName.fs;
		taq->hl = qaresp->objName.hl;
		taq->ll = qaresp->objName.ll;
		taq->next = tapole;
		tapole = taq;
		ftaq = fetchtaq();
		db.bufferPtr = ftaq->tsmresp;
		qaresp = (qryRespBackupData *)db.bufferPtr;
		qaresp->stVersion = qryRespBackupDataVersion;
		nq++;
		if (dflag && (nq % 1000) == 0)
			printf("**** Status taken of %d objects\n", nq);
	}
	if (rv == DSM_RC_UNKNOWN_FORMAT) {
		/* XXX what to do??? */
		printf("unknown format...\n");
		goto e0;
	}
	if (dflag)
		printf("!!!! Total %d objects\n", nq);
	if (rv == DSM_RC_FINISHED || rv == DSM_RC_ABORT_NO_MATCH) {
		rv = 0;
	} else {
		tsmerror("dsmGetNextQObj", rv);
		return rv;
	}
	if ((rv = dsmEndQuery(dsmHandle)))
		tsmerror("dsmEndQuery", rv);
	while (tapole) {
		taq = tarev;
		tarev = tapole;
		tapole = tapole->next;
		tarev->next = taq;
	}
	*taqp = tarev;
	return rv;
}

int
tsmqueryadv(char *fs, char *hl, char *ll, struct taquery **taqp,
	int state, time_t date)
{
	qryRespBackupData *qaresp;
	struct taquery *taq, *tapole = NULL, *tarev = NULL;
	struct taquery *ftaq;
	DataBlk db;
	dsmObjName on;
	qryBackupData qa;
	int rv, nq;

	strcpy(on.fs, fs);
	strcpy(on.hl, hl);
	strcpy(on.ll, ll);
	on.objType = DSM_OBJ_WILDCARD;

	qa.stVersion = qryBackupDataVersion;
	qa.objName = &on;
	qa.owner = "";
	qa.objState = DSM_ACTIVE;
	qa.pitDate.year = DATE_MINUS_INFINITE;

	if ((rv = dsmBeginQuery(dsmHandle,qtBackup, &qa))) {
		tsmerror("dsmBeginQuery", rv);
		return rv;
	}
	db.stVersion = DataBlkVersion;
	ftaq = fetchtaq();

	db.bufferLen = sizeof(qryRespBackupData);
	db.bufferPtr = ftaq->tsmresp;
	qaresp = (qryRespBackupData *)db.bufferPtr;
	qaresp->stVersion = qryRespBackupDataVersion;

	nq = 0;
	while ((rv = dsmGetNextQObj(dsmHandle, &db)) == DSM_RC_MORE_DATA) {
		taq = ftaq;
		taq->da = (struct dirattribute *)&qaresp->objInfo;
		taq->fs = qaresp->objName.fs;
		taq->hl = qaresp->objName.hl;
		taq->ll = qaresp->objName.ll;
		taq->next = tapole;
		tapole = taq;
		ftaq = fetchtaq();
		db.bufferPtr = ftaq->tsmresp;
		qaresp = (qryRespBackupData *)db.bufferPtr;
		qaresp->stVersion = qryRespBackupDataVersion;
		nq++;
		if (dflag && (nq % 1000) == 0)
			printf("**** Status taken of %d objects\n", nq);
	}
	if (dflag)
		printf("!!!! Total %d objects\n", nq);
	if (rv == DSM_RC_FINISHED || rv == DSM_RC_ABORT_NO_MATCH)
		rv = 0;
	else {
		tsmerror("dsmGetNextQObj", rv);
		return rv;
	}
	if ((rv = dsmEndQuery(dsmHandle)))
		tsmerror("dsmEndQuery", rv);
	while (tapole) {
		taq = tarev;
		tarev = tapole;
		tapole = tapole->next;
		tarev->next = taq;
	}
	*taqp = tarev;
	return rv;
}

int
tsmdelobj(void *arg)
{
	qryRespBackupData *qaresp = arg;
	dsmDelInfo di;
	int rv;

	di.backInfo.stVersion = delBackVersion;
	di.backInfo.objNameP = &qaresp->objName;
	di.backInfo.copyGroup = qaresp->copyGroup;

	curobjtxn++;
	if (curobjtxn == maxobjtxn-1) {
		tsmend();
		tsmstart();
	}

	if ((rv = dsmDeleteObj(dsmHandle, dtBackup, di)) != DSM_RC_OK)
		tsmerror("dsmDeleteObj", rv);
	return rv;
}

int
tsmbeginget(struct taquery *taq)
{
	dsmGetList gl;
	struct taquery *w;
	int rv, n, i;

	for (w = taq, n = 0; w; w = w->next)
		n++;

	gl.stVersion = dsmGetListVersion;
	gl.numObjId = n;
	gl.objId = malloc(sizeof(dsStruct64_t) * n);
	for (w = taq, i = 0; w; w = w->next, i++) {
		qryRespBackupData *qaresp = w->tsmresp;
		gl.objId[i] = qaresp->objId;
	}

	if ((rv = dsmBeginGetData(dsmHandle, bTrue, gtBackup, &gl)) != 0)
		tsmerror("dsmBeginGetData", rv);
	return rv;
}

/*
 * Get first data block of an object.
 *
 * Returns
 *	> 0: more data to get.
 * 	= 0: finished
 *	< 0: an error occurred.
 */
int
tsmgetdata(struct taquery *taq, char *buf, int buflen, int *gotlen, int first)
{
	DataBlk db;
	int rv;

	db.stVersion = DataBlkVersion;
	db.bufferLen = buflen;
	db.bufferPtr = buf;

	if (first) {
		qryRespBackupData *qa = taq->tsmresp;
		rv = dsmGetObj(dsmHandle, &qa->objId, &db);
	} else
		rv = dsmGetData(dsmHandle, &db);
	*gotlen = db.numBytes;
	switch (rv) {
	case DSM_RC_MORE_DATA:
		return 1;
	case DSM_RC_FINISHED:
		return 0;
	default:
		tsmerror("dsmGetObj", rv);
		return -1;
	}
}

int
tsmenddata()
{
	int rv;

	if ((rv = dsmEndGetObj(dsmHandle)) != DSM_RC_OK)
		tsmerror("dsmEndGetObj", rv);
	return rv;
}

int
tsmendget()
{
	int rv;

	if ((rv = dsmEndGetData(dsmHandle)) != DSM_RC_OK)
		tsmerror("dsmEndGetData", rv);
	return rv;
}
