$! BUILD_PCSI_KIT.COM -- Build a PCSI kit
$!
$! Written by Richard Levitte <richard@levitte.org>
$! Release as public domain.
$!
$! Use this comannd procedure from the top of the OpenSSL directory tree.
$! Anything else will fail!
$!
$! P1	directory to build in
$
$	IF P1 .EQS. ""
$	THEN
$	    WRITE SYS$OUTPUT "First argument missing."
$	    WRITE SYS$OUTPUT "Should be the directory where you want things installed."
$	    EXIT
$	ENDIF
$
$	CURR_DIR = F$ENVIRONMENT("DEFAULT")
$
$	ROOT = F$PARSE(P1,"[]A.;0",,,"SYNTAX_ONLY,NO_CONCEAL") - "A.;0"
$	ROOT_DEV = F$PARSE(ROOT,,,"DEVICE","SYNTAX_ONLY")
$	ROOT_DIR = F$PARSE(ROOT,,,"DIRECTORY","SYNTAX_ONLY") -
		   - ".][000000" - "[000000." - "][" - "[" - "]"
$	ROOT = ROOT_DEV + "[" + ROOT_DIR
$
$	KIT_DIR = "''ROOT'" + "]"
$	KIT_AREA = "''ROOT'" + "...]"
$
$	@INSTALL 'P1' SSL$
$
$	COPY [.VMS.COMPAQ]SSL$PCSI.COM 'ROOT'.COM] /LOG
$	SET FILE/PROT=WORLD:RE 'ROOT'.COM]SSL$PCSI.COM
$!
$! Copy SET_ACLS.COM so that access to the kit area has
$! the appropriate protections as well.
$!
$	COPY SET_ACLS.COM 'ROOT'] /LOG
$	SET FILE/PROT=WORLD:RE 'ROOT']SET_ACLS.COM
$!
$!	Create the default CA structure
$!
$	CREATE /DIR /PROTECTION=OWNER:RWED 'ROOT'.CA]
$	CREATE /DIR /PROTECTION=OWNER:RWED 'ROOT'.CA.certs]
$	CREATE /DIR /PROTECTION=OWNER:RWED 'ROOT'.CA.crl]
$	CREATE /DIR /PROTECTION=OWNER:RWED 'ROOT'.CA.newcerts]
$	CREATE /DIR /PROTECTION=OWNER:RWED 'ROOT'.CA.private]
$
$	OPEN   /WRITE ser_file 'CATOP']serial. 
$	WRITE ser_file "01"
$	CLOSE ser_file
$	APPEND/NEW NL: 'CATOP']index.txt
$
$	! The following is to make sure access() doesn't get confused.  It
$	! really needs one file in the directory to give correct answers...
$	COPY NLA0: 'CATOP'.certs].;
$	COPY NLA0: 'CATOP'.crl].;
$	COPY NLA0: 'CATOP'.newcerts].;
$	COPY NLA0: 'CATOP'.private].;
$!
$!
$!	Build the command procedure to build the kit
$!	
$	OPEN/WRITE KIT_FILE CREATE_PCSI_KIT.COM
$!
$	WRITE KIT_FILE "$!"
$	WRITE KIT_FILE "$! CREATE_PCSI_KIT.COM -  This command procedure creates the actual .PCSI kit."
$	WRITE KIT_FILE "$!"
$	WRITE KIT_FILE "$!"
$	WRITE KIT_FILE "$!   Do not edit this file."
$	WRITE KIT_FILE "$!   This file is created by INSTALL.COM, and any changes to this file should"
$	WRITE KIT_FILE "$!   be made in INSTALL.COM."
$	WRITE KIT_FILE "$!"
$	WRITE KIT_FILE "$!"
$	WRITE KIT_FILE " $ product package ssl   /destination = ''KIT_DIR' - "
$	WRITE KIT_FILE "                         /format = sequential - "
$	WRITE KIT_FILE "                         /log - "
$	WRITE KIT_FILE "                         /material = ''KIT_AREA' - "
$	WRITE KIT_FILE "                         /source = ''CURR_DIR'CPQ-AXPVMS-SSL-T0100--1.PCSI$DESC "
$	WRITE KIT_FILE "$!"
$	WRITE KIT_FILE "$ kit_file = f$search(""''KIT_DIR'*.PCSI"") "
$	WRITE KIT_FILE "$ spool compress/method=dcx_axpexe  ''KIT_DIR'''KIT_FILE' ''KIT_DIR'"
$!
$	CLOSE KIT_FILE
$!
$	WRITE SYS$OUTPUT ""
$	WRITE SYS$OUTPUT " Now, to include the 32-bit images and libraries, copy the following"
$	WRITE SYS$OUTPUT " from a 32-bit build tree:"
$	WRITE SYS$OUTPUT ""
$	WRITE SYS$OUTPUT " COPY [.AXP.EXE.CRYPTO]LIBCRYPTO32.OLB ''root'.ALPHA_LIB]"
$	WRITE SYS$OUTPUT " COPY [.AXP.EXE.SSL]LIBSSL32.OLB ''root'.ALPHA_LIB]"
$	WRITE SYS$OUTPUT ""
$	WRITE SYS$OUTPUT " COPY [.AXP.EXE.CRYPTO]SSL$LIBCRYPTO_SHR32.EXE ''root'.ALPHA_EXE]"
$	WRITE SYS$OUTPUT " COPY [.AXP.EXE.SSL]SSL$LIBSSL_SHR32.EXE ''root'.ALPHA_EXE]"
$	WRITE SYS$OUTPUT ""
$!
$	COPY [.VMS.COMPAQ]SSL010.RELEASE_NOTES 'ROOT']/LOG
$	SET FILE/PROT=WORLD:RE 'ROOT']SSL010.RELEASE_NOTES
$!
