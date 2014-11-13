/*	$Id: tsmafs.h,v 1.9 2012/01/11 12:11:52 ragge Exp $	*/
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

/*
 * This stuff is stored at offsets in a byte-array in network byte order
 * to be somewhat platform and alignment independent.
 */
enum { A_CW, A_VNODE, A_UNIQUE, A_VERSL, A_VERSH, A_OWNER, A_GROUP, A_MODE,
	A_TIME, A_NPOS, A_NNEG, A_ACL };

/* ACL struct */
struct taacl {
	uint32_t	id;
	uint32_t	rights;
};

#define	MAXACLS		20	/* XXX to decouple from afs files */

#define DIRVERSION	1
#define FILEVERSION	1
struct dirattribute {	/* Same used for files */
#define fileattribute dirattribute
	uint32_t	cwtype;
#define MKCWTYP(vers, typ)	((vers) | ((typ) << 8))
#define GETVERS(cw)		((cw) & 0377)
#define GETTYP(cw)		(((cw) >> 8) & 0377)
	/* status check values */
	uint32_t	vnode;
	uint32_t	unique;
	uint32_t	versl;
	uint32_t	versh;

	/* standard unix attributes */
	uint32_t	owner;
	uint32_t	group;
	uint32_t	mode;
	uint32_t	time;

	/* ACL arrays */
	uint32_t	npos, nneg;
	struct taacl	acls[MAXACLS];
};

/*
 * Struct returned as a result of a file space query.
 * This might be a linked list if multiple responses.
 */
struct taquery {
	struct taquery *next;
	struct dirattribute *da; /* filled in by tsm routines */
	char *fs, *hl, *ll;	 /* filled in by tsm routines */
	void *tsmresp;		 /* actually qryRespBackupData */
};

int tsminit(char *filespace, int restore);
int tsmstart(void);
int tsmend(void);
int tsmshutdown(void);
int tsmstartobj(char *, char *, uint32_t, uint32_t, void *, int, int);
int tsmwrtblk(char *, int);
void tsmendobj(void);
int tsmquery(char *fs, char *hl, char *ll, struct taquery **, struct tm *);
int tsmqueryadv(char *fs, char *hl, char *ll, struct taquery **taqp,
        int state, time_t date);
int tsmbeginget(struct taquery *);
int tsmgetdata(struct taquery *, char *, int, int *, int);
int tsmenddata(void);
int tsmendget(void);
int tsmtaqfree(struct taquery *);
int tsmdelobj(void *);

/*
 * Linked list ov volumes to backup.
 */
struct tavol {
	struct tavol	*next;
	char		*name;
	uint32_t	srvno;
	uint32_t	partid;
	uint32_t	volid;
};

/*
 * Get a list of volumes from the VLDB server located on
 * server and partition (if not null) and volname.
 * volname can be wildcarded as shell file names.
 */
struct tavol *getvols(char *server, char *part, char *volname);
