#	$Id: Makefile,v 1.9 2011/02/04 10:03:45 ragge Exp $
#
#

#
# The following are for 64-bit redhat.
AFSLIBS=-L/usr/lib64/afs 
TSMLIBS=-L/opt/tivoli/tsm/client/api/bin64 -lApiTSM64
TSMINC=-I/opt/tivoli/tsm/client/api/bin64/sample

# Use these paths instead for 32-bit redhat.
#AFSLIBS=-L/usr/lib/afs 
#TSMLIBS=-L/opt/tivoli/tsm/client/api/bin -lApiDS
#TSMINC=-I/opt/tivoli/tsm/client/api/bin/sample

COMOBJS=tsmafs.o
BUPOBJS=tabackup.o ${COMOBJS}
RSTOBJS=tarestore.o ${COMOBJS}
CFLAGS=-g -Wall -Wmissing-prototypes -Wstrict-prototypes $(TSMINC)
LIBS=$(AFSLIBS) -lrx -llwp -lafsint -lrx -lcom_err -lsys \
	-lvolser -lvldb -lvosadmin -lcfgadmin -lubik -lauth -lrxkad \
	-lafsadminutil -lsys -lresolv -lafsutil -ldes -lcom_err -lacl -lprot \
	-lcom_err -lrx $(TSMLIBS)

all: tabackup tarestore

tabackup: $(BUPOBJS)
	$(CC) $(CFLAGS) -o $@ $(BUPOBJS) $(LIBS)

tarestore: $(RSTOBJS)
	$(CC) $(CFLAGS) -o $@ $(RSTOBJS) $(LIBS)

.c.o:
	$(CC) -g -c $(CFLAGS) $<


clean:
	/bin/rm -f tabackup tarestore $(BUPOBJS) $(RSTOBJS)
