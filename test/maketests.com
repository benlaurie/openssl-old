$!
$!  MAKETESTS.COM
$!  Written By:  Robert Byer
$!               Vice-President
$!               A-Com Computing, Inc.
$!               byer@mail.all-net.net
$!
$!  Changes by Richard Levitte <richard@levitte.org>
$!
$!  This command files compiles and creates all the various different
$!  "test" programs for the different types of encryption for OpenSSL.
$!  It was written so it would try to determine what "C" compiler to
$!  use or you can specify which "C" compiler to use.
$!
$!  The test "executeables" will be placed in a directory called
$!  [.xxx.EXE.TEST] where "xxx" denotes AXP or VAX depending on your machines
$!  architecture.
$!
$!  Specify RSAREF as P1 to compile with the RSAREF library instead of
$!  the regular one.  If you specify NORSAREF it will compile with the
$!  regular RSAREF routines.  (Note: If you are in the United States
$!  you MUST compile with RSAREF unless you have a license from RSA).
$!
$!  Note: The RSAREF libraries are NOT INCLUDED and you have to
$!        download it from "ftp://ftp.rsa.com/rsaref".  You have to
$!        get the ".tar-Z" file as the ".zip" file dosen't have the
$!        directory structure stored.  You have to extract the file
$!        into the [.RSAREF] directory under the root directory as that
$!        is where the scripts will look for the files.
$!
$!  Specify DEBUG or NODEBUG P2 to compile with or without debugger
$!  information.
$!
$!  Specify which compiler at P3 to try to compile under.
$!
$!	   VAXC	 For VAX C.
$!	   DECC	 For DEC C.
$!	   GNUC	 For GNU C.
$!
$!  If you don't speficy a compiler, it will try to determine which
$!  "C" compiler to use.
$!
$!  P4, if defined, sets a TCP/IP library to use, through one of the following
$!  keywords:
$!
$!	UCX		for UCX
$!	SOCKETSHR	for SOCKETSHR+NETLIB
$!
$!  P5, if defined, sets a compiler thread NOT needed on OpenVMS 7.1 (and up)
$!
$!
$! Define A TCP/IP Library That We Will Need To Link To.
$! (That is, If Wee Need To Link To One.)
$!
$ TCPIP_LIB = ""
$!
$! Check Which Architecture We Are Using.
$!
$ IF (F$GETSYI("CPU").GE.128) 
$ THEN
$!
$!  The Architecture Is AXP.
$!
$   ARCH := AXP
$!
$! Else...
$!
$ ELSE
$!
$!  The Architecture Is VAX.
$!
$   ARCH := VAX
$!
$! End The Architecture Check.
$!
$ ENDIF
$!
$! Check To Make Sure We Have Valid Command Line Parameters.
$!
$ GOSUB CHECK_OPTIONS
$!
$! Initialise logical names and such
$!
$ GOSUB INITIALISE
$!
$! Tell The User What Kind of Machine We Run On.
$!
$ WRITE SYS$OUTPUT "Compiling On A ",ARCH," Machine."
$!
$! Define The CRYPTO-LIB We Are To Use.
$!
$ CRYPTO_LIB := SYS$DISK:[-.'ARCH'.EXE.CRYPTO]LIBCRYPTO.OLB
$!
$! Define The RSAREF-LIB We Are To Use.
$!
$ RSAREF_LIB := SYS$DISK:[-.'ARCH'.EXE.RSAREF]LIBRSAGLUE.OLB
$!
$! Define The SSL We Are To Use.
$!
$ SSL_LIB := SYS$DISK:[-.'ARCH'.EXE.SSL]LIBSSL.OLB
$!
$! Define The OBJ Directory.
$!
$ OBJ_DIR := SYS$DISK:[-.'ARCH'.OBJ.TEST]
$!
$! Check To See If The Architecture Specific OBJ Directory Exists.
$!
$ IF (F$PARSE(OBJ_DIR).EQS."")
$ THEN
$!
$!  The EXE Directory Dosen't Exist, So Create It.
$!
$   CREATE/DIRECTORY 'OBJ_DIR'
$!
$! End The Architecture Specific OBJ Directory Check.
$!
$ ENDIF
$!
$! Define The EXE Directory.
$!
$ EXE_DIR := SYS$DISK:[-.'ARCH'.EXE.TEST]
$!
$! Check To See If The Architecture Specific EXE Directory Exists.
$!
$ IF (F$PARSE(EXE_DIR).EQS."")
$ THEN
$!
$!  The EXE Directory Dosen't Exist, So Create It.
$!
$   CREATE/DIRECTORY 'EXE_DIR'
$!
$! End The Architecture Specific EXE Directory Check.
$!
$ ENDIF
$!
$! Check To See If We Have The Proper Libraries.
$!
$ GOSUB LIB_CHECK
$!
$! Check To See If We Have A Linker Option File.
$!
$ GOSUB CHECK_OPT_FILE
$!
$! Define The TEST Files.
$!
$ TEST_FILES = "BNTEST,IDEATEST,MD2TEST,MD4TEST,MD5TEST,HMACTEST,"+ -
	       "RC2TEST,RC4TEST,RC5TEST,"+ -
	       "DESTEST,SHATEST,SHA1TEST,MDC2TEST,RMDTEST,"+ -
	       "RANDTEST,DHTEST,"+ -
	       "BFTEST,CASTTEST,SSLTEST,EXPTEST,DSATEST,RSA_TEST,ENGINETEST"
$ TCPIP_PROGRAMS = ",,"
$ IF COMPILER .EQS. "VAXC" THEN -
     TCPIP_PROGRAMS = ",SSLTEST,"
$!
$!  Define A File Counter And Set It To "0".
$!
$ FILE_COUNTER = 0
$!
$! Top Of The File Loop.
$!
$ NEXT_FILE:
$!
$! O.K, Extract The File Name From The File List.
$!
$ FILE_NAME = F$ELEMENT(FILE_COUNTER,",",TEST_FILES)
$!
$! Check To See If We Are At The End Of The File List.
$!
$ IF (FILE_NAME.EQS.",") THEN GOTO FILE_DONE
$!
$! Increment The Counter.
$!
$ FILE_COUNTER = FILE_COUNTER + 1
$!
$! Create The Source File Name.
$!
$ SOURCE_FILE = "SYS$DISK:[]" + FILE_NAME + ".C"
$!
$! Create The Object File Name.
$!
$ OBJECT_FILE = OBJ_DIR + FILE_NAME + ".OBJ"
$!
$! Create The Executable File Name.
$!
$ EXE_FILE = EXE_DIR + FILE_NAME + ".EXE"
$ ON WARNING THEN GOTO NEXT_FILE
$!
$! Check To See If The File We Want To Compile Actually Exists.
$!
$ IF (F$SEARCH(SOURCE_FILE).EQS."")
$ THEN
$!
$!  Tell The User That The File Dosen't Exist.
$!
$   WRITE SYS$OUTPUT ""
$   WRITE SYS$OUTPUT "The File ",SOURCE_FILE," Dosen't Exist."
$   WRITE SYS$OUTPUT ""
$!
$!  Exit The Build.
$!
$   GOTO EXIT
$ ENDIF
$!
$! Tell The User What We Are Building.
$!
$ WRITE SYS$OUTPUT "Building The ",FILE_NAME," Test Program."
$!
$! Compile The File.
$!
$ ON ERROR THEN GOTO NEXT_FILE
$ CC/OBJECT='OBJECT_FILE' 'SOURCE_FILE'
$ ON WARNING THEN GOTO NEXT_FILE
$!
$! Check If What We Are About To Compile Works Without A TCP/IP Library.
$!
$ IF ((TCPIP_LIB.EQS."").AND.((TCPIP_PROGRAMS-FILE_NAME).NES.TCPIP_PROGRAMS))
$ THEN
$!
$!  Inform The User That A TCP/IP Library Is Needed To Compile This Program.
$!
$   WRITE SYS$OUTPUT FILE_NAME," Needs A TCP/IP Library.  Can't Link.  Skipping..."
$   GOTO NEXT_FILE
$!
$! End The TCP/IP Library Check.
$!
$ ENDIF
$!
$! Link The Program, Check To See If We Need To Link With RSAREF Or Not.
$!
$ IF (RSAREF.EQS."TRUE")
$ THEN
$!
$!  Check To See If We Are To Link With A Specific TCP/IP Library.
$!
$   IF (TCPIP_LIB.NES."")
$   THEN
$!
$!    Link With The RSAREF Library And A Specific TCP/IP Library.
$!
$     LINK/'DEBUGGER'/'TRACEBACK' /EXE='EXE_FILE' -
	  'OBJECT_FILE',-
	  'SSL_LIB'/LIBRARY,'CRYPTO_LIB'/LIBRARY,'RSAREF_LIB'/LIBRARY, -
          'TCPIP_LIB','OPT_FILE'/OPTION
$!
$!  Else...
$!
$   ELSE
$!
$!    Link With The RSAREF Library And NO TCP/IP Library.
$!
$     LINK/'DEBUGGER'/'TRACEBACK' /EXE='EXE_FILE' -
	  'OBJECT_FILE', -
          'SSL_LIB'/LIBRARY,'CRYPTO_LIB'/LIBRARY,'RSAREF_LIB'/LIBRARY, -
          'OPT_FILE'/OPTION
$!
$!  End The TCP/IP Library Check.
$!
$   ENDIF
$!
$! Else...
$!
$ ELSE
$!
$!  Don't Link With The RSAREF Routines.
$!
$!
$!  Check To See If We Are To Link With A Specific TCP/IP Library.
$!
$   IF (TCPIP_LIB.NES."")
$   THEN
$!
$!    Don't Link With The RSAREF Routines And TCP/IP Library.
$!
$   LINK/'DEBUGGER'/'TRACEBACK' /EXE='EXE_FILE' -
	'OBJECT_FILE', -
        'SSL_LIB'/LIBRARY,'CRYPTO_LIB'/LIBRARY, -
        'TCPIP_LIB','OPT_FILE'/OPTION
$!
$!  Else...
$!
$   ELSE
$!
$!    Don't Link With The RSAREF Routines And Link With A TCP/IP Library.
$!
$   LINK/'DEBUGGER'/'TRACEBACK' /EXE='EXE_FILE' -
	'OBJECT_FILE', -
        'SSL_LIB'/LIBRARY,'CRYPTO_LIB'/LIBRARY, -
        'OPT_FILE'/OPTION
$!
$!  End The TCP/IP Library Check.
$!
$   ENDIF
$!
$! End The RSAREF Link Check.
$!
$ ENDIF 
$!
$! Go Back And Do It Again.
$!
$ GOTO NEXT_FILE
$!
$! All Done With This Library Part.
$!
$ FILE_DONE:
$!
$! All Done, Time To Exit.
$!
$ EXIT:
$ GOSUB CLEANUP
$ EXIT
$!
$! Check For The Link Option FIle.
$!
$ CHECK_OPT_FILE:
$!
$! Check To See If We Need To Make A VAX C Option File.
$!
$ IF (COMPILER.EQS."VAXC")
$ THEN
$!
$!  Check To See If We Already Have A VAX C Linker Option File.
$!
$   IF (F$SEARCH(OPT_FILE).EQS."")
$   THEN
$!
$!    We Need A VAX C Linker Option File.
$!
$     CREATE 'OPT_FILE'
$DECK
!
! Default System Options File To Link Agianst 
! The Sharable VAX C Runtime Library.
!
SYS$SHARE:VAXCRTL.EXE/SHARE
$EOD
$!
$!  End The Option File Check.
$!
$   ENDIF
$!
$! End The VAXC Check.
$!
$ ENDIF
$!
$! Check To See If We Need A GNU C Option File.
$!
$ IF (COMPILER.EQS."GNUC")
$ THEN
$!
$!  Check To See If We Already Have A GNU C Linker Option File.
$!
$   IF (F$SEARCH(OPT_FILE).EQS."")
$   THEN
$!
$!    We Need A GNU C Linker Option File.
$!
$     CREATE 'OPT_FILE'
$DECK
!
! Default System Options File To Link Agianst 
! The Sharable C Runtime Library.
!
GNU_CC:[000000]GCCLIB/LIBRARY
SYS$SHARE:VAXCRTL/SHARE
$EOD
$!
$!  End The Option File Check.
$!
$   ENDIF
$!
$! End The GNU C Check.
$!
$ ENDIF
$!
$! Check To See If We Need A DEC C Option File.
$!
$ IF (COMPILER.EQS."DECC")
$ THEN
$!
$!  Check To See If We Already Have A DEC C Linker Option File.
$!
$   IF (F$SEARCH(OPT_FILE).EQS."")
$   THEN
$!
$!    Figure Out If We Need An AXP Or A VAX Linker Option File.
$!
$     IF (ARCH.EQS."VAX")
$     THEN
$!
$!      We Need A DEC C Linker Option File For VAX.
$!
$       CREATE 'OPT_FILE'
$DECK
!
! Default System Options File To Link Agianst 
! The Sharable DEC C Runtime Library.
!
SYS$SHARE:DECC$SHR.EXE/SHARE
$EOD
$!
$!    Else...
$!
$     ELSE
$!
$!      Create The AXP Linker Option File.
$!
$       CREATE 'OPT_FILE'
$DECK
!
! Default System Options File For AXP To Link Agianst 
! The Sharable C Runtime Library.
!
SYS$SHARE:CMA$OPEN_LIB_SHR/SHARE
SYS$SHARE:CMA$OPEN_RTL/SHARE
$EOD
$!
$!    End The VAX/AXP DEC C Option File Check.
$!
$     ENDIF
$!
$!  End The Option File Search.
$!
$   ENDIF
$!
$! End The DEC C Check.
$!
$ ENDIF
$!
$!  Tell The User What Linker Option File We Are Using.
$!
$ WRITE SYS$OUTPUT "Using Linker Option File ",OPT_FILE,"."	
$!
$! Time To RETURN.
$!
$ RETURN
$!
$! Check To See If We Have The Appropiate Libraries.
$!
$ LIB_CHECK:
$!
$! Look For The Library LIBCRYPTO.OLB.
$!
$ IF (F$SEARCH(CRYPTO_LIB).EQS."")
$ THEN
$!
$!  Tell The User We Can't Find The LIBCRYPTO.OLB Library.
$!
$   WRITE SYS$OUTPUT ""
$   WRITE SYS$OUTPUT "Can't Find The Library ",CRYPTO_LIB,"."
$   WRITE SYS$OUTPUT "We Can't Link Without It."
$   WRITE SYS$OUTPUT ""
$!
$!  Since We Can't Link Without It, Exit.
$!
$   EXIT
$!
$! End The Crypto Library Check.
$!
$ ENDIF
$!
$! See If We Need The RSAREF Library...
$!
$ IF (RSAREF.EQS."TRUE")
$ THEN
$!
$!  Look For The Library LIBRSAGLUE.OLB.
$!
$   IF (F$SEARCH(RSAREF_LIB).EQS."")
$   THEN
$!
$!    Tell The User We Can't Find The LIBRSAGLUE.OLB Library.
$!
$     WRITE SYS$OUTPUT ""
$     WRITE SYS$OUTPUT "Can't Find The Library ",RSAREF_LIB,"."
$     WRITE SYS$OUTPUT "We Can't Link Without It."
$     WRITE SYS$OUTPUT ""
$!
$!    Since We Can't Link Without It, Exit.
$!
$     EXIT
$   ENDIF
$!
$! End The RSAREF Library Check.
$!
$ ENDIF
$!
$! Look For The Library LIBSSL.OLB.
$!
$ IF (F$SEARCH(SSL_LIB).EQS."")
$ THEN
$!
$!  Tell The User We Can't Find The LIBSSL.OLB Library.
$!
$   WRITE SYS$OUTPUT ""
$   WRITE SYS$OUTPUT "Can't Find The Library ",SSL_LIB,"."
$   WRITE SYS$OUTPUT "Some Of The Test Programs Need To Link To It."
$   WRITE SYS$OUTPUT ""
$!
$!  Since We Can't Link Without It, Exit.
$!
$   EXIT
$!
$! End The SSL Library Check.
$!
$ ENDIF
$!
$! Time To Return.
$!
$ RETURN
$!
$! Check The User's Options.
$!
$ CHECK_OPTIONS:
$!
$! Check To See If P1 Is Blank.
$!
$ IF (P1.EQS."NORSAREF")
$ THEN
$!
$!   P1 Is NORSAREF, So Compile With The Regular RSA Libraries.
$!
$    RSAREF = "FALSE"
$ ELSE
$!
$!  Check To See If We Are To Use The RSAREF Library.
$!
$   IF (P1.EQS."RSAREF")
$   THEN
$!
$!    Check To Make Sure We Have The RSAREF Source Code Directory.
$!
$     IF (F$SEARCH("SYS$DISK:[-.RSAREF]SOURCE.DIR").EQS."")
$     THEN
$!
$!      We Don't Have The RSAREF Souce Code Directory, So Tell The
$!      User This.
$!
$       WRITE SYS$OUTPUT ""
$       WRITE SYS$OUTPUT "It appears that you don't have the RSAREF Souce Code."
$       WRITE SYS$OUTPUT "You need to go to 'ftp://ftp.rsa.com/rsaref'.  You have to"
$       WRITE SYS$OUTPUT "get the '.tar-Z' file as the '.zip' file dosen't have the"
$       WRITE SYS$OUTPUT "directory structure stored.  You have to extract the file"
$       WRITE SYS$OUTPUT "into the [.RSAREF] directory under the root directory"
$       WRITE SYS$OUTPUT "as that is where the scripts will look for the files."
$       WRITE SYS$OUTPUT ""
$!
$!      Time To Exit.
$!
$       EXIT
$!
$!    Else, Compile Using The RSAREF Library.
$!
$     ELSE
$       RSAREF = "TRUE"
$     ENDIF
$   ELSE 
$!
$!    They Entered An Invalid Option..
$!
$     WRITE SYS$OUTPUT ""
$     WRITE SYS$OUTPUT "The Option ",P1," Is Invalid.  The Valid Options Are:"
$     WRITE SYS$OUTPUT ""
$     WRITE SYS$OUTPUT "     RSAREF   :  Compile With The RSAREF Library."
$     WRITE SYS$OUTPUT "     NORSAREF :  Compile With The Regular RSA Library."
$     WRITE SYS$OUTPUT ""
$!
$!    Time To EXIT.
$!
$     EXIT
$!
$!  End The Valid Arguement Check.
$!
$   ENDIF
$!
$! End The P1 Check.
$!
$ ENDIF
$!
$! Check To See If P2 Is Blank.
$!
$ IF (P2.EQS."NODEBUG")
$ THEN
$!
$!   P2 Is NODEBUG, So Compile Without Debugger Information.
$!
$    DEBUGGER  = "NODEBUG"
$    TRACEBACK = "NOTRACEBACK" 
$    GCC_OPTIMIZE = "OPTIMIZE"
$    CC_OPTIMIZE = "OPTIMIZE"
$    WRITE SYS$OUTPUT "No Debugger Information Will Be Produced During Compile."
$    WRITE SYS$OUTPUT "Compiling With Compiler Optimization."
$!
$! Else...
$!
$ ELSE
$!
$!  Check To See If We Are To Compile With Debugger Information.
$!
$   IF (P2.EQS."DEBUG")
$   THEN
$!
$!    Compile With Debugger Information.
$!
$     DEBUGGER  = "DEBUG"
$     TRACEBACK = "TRACEBACK"
$     GCC_OPTIMIZE = "NOOPTIMIZE"
$     CC_OPTIMIZE = "NOOPTIMIZE"
$     WRITE SYS$OUTPUT "Debugger Information Will Be Produced During Compile."
$     WRITE SYS$OUTPUT "Compiling Without Compiler Optimization."
$!
$!  Else...
$!
$   ELSE
$!
$!    Tell The User Entered An Invalid Option..
$!
$     WRITE SYS$OUTPUT ""
$     WRITE SYS$OUTPUT "The Option ",P2," Is Invalid.  The Valid Options Are:"
$     WRITE SYS$OUTPUT ""
$     WRITE SYS$OUTPUT "    DEBUG    :  Compile With The Debugger Information."
$     WRITE SYS$OUTPUT "    NODEBUG  :  Compile Without The Debugger Information."
$     WRITE SYS$OUTPUT ""
$!
$!    Time To EXIT.
$!
$     EXIT
$!
$!  End The Valid Arguement Check.
$!
$   ENDIF
$!
$! End The P3 Check.
$!
$ ENDIF
$!
$! Check To See If P3 Is Blank.
$!
$ IF (P3.EQS."")
$ THEN
$!
$!  O.K., The User Didn't Specify A Compiler, Let's Try To
$!  Find Out Which One To Use.
$!
$!  Check To See If We Have GNU C.
$!
$   IF (F$TRNLNM("GNU_CC").NES."")
$   THEN
$!
$!    Looks Like GNUC, Set To Use GNUC.
$!
$     P3 = "GNUC"
$!
$!  End The GNU C Compiler Check.
$!
$   ELSE
$!
$!  Check To See If We Have VAXC Or DECC.
$!
$     IF (ARCH.EQS."AXP").OR.(F$TRNLNM("DECC$CC_DEFAULT").NES."")
$     THEN 
$!
$!      Looks Like DECC, Set To Use DECC.
$!
$       P3 = "DECC"
$!
$!      Else...
$!
$     ELSE
$!
$!      Looks Like VAXC, Set To Use VAXC.
$!
$       P3 = "VAXC"
$!
$!    End The VAXC Compiler Check.
$!
$     ENDIF
$!
$!  End The DECC & VAXC Compiler Check.
$!
$   ENDIF
$!
$!  End The Compiler Check.
$!
$ ENDIF
$!
$! Check To See If We Have A Option For P4.
$!
$ IF (P4.EQS."")
$ THEN
$!
$!  Find out what socket library we have available
$!
$   IF F$PARSE("SOCKETSHR:") .NES. ""
$   THEN
$!
$!    We have SOCKETSHR, and it is my opinion that it's the best to use.
$!
$     P4 = "SOCKETSHR"
$!
$!    Tell the user
$!
$     WRITE SYS$OUTPUT "Using SOCKETSHR for TCP/IP"
$!
$!    Else, let's look for something else
$!
$   ELSE
$!
$!    Like UCX (the reason to do this before Multinet is that the UCX
$!    emulation is easier to use...)
$!
$     IF F$TRNLNM("UCX$IPC_SHR") .NES. "" -
	 .OR. F$PARSE("SYS$SHARE:UCX$IPC_SHR.EXE") .NES. "" -
	 .OR. F$PARSE("SYS$LIBRARY:UCX$IPC.OLB") .NES. ""
$     THEN
$!
$!	Last resort: a UCX or UCX-compatible library
$!
$	P4 = "UCX"
$!
$!      Tell the user
$!
$       WRITE SYS$OUTPUT "Using UCX or an emulation thereof for TCP/IP"
$!
$!	That was all...
$!
$     ENDIF
$   ENDIF
$ ENDIF
$!
$! Set Up Initial CC Definitions, Possibly With User Ones
$!
$ CCDEFS = "VMS=1,TCPIP_TYPE_''P4'"
$ IF F$TRNLNM("OPENSSL_NO_ASM") THEN CCDEFS = CCDEFS + ",NO_ASM"
$ IF F$TRNLNM("OPENSSL_NO_RSA") THEN CCDEFS = CCDEFS + ",NO_RSA"
$ IF F$TRNLNM("OPENSSL_NO_DSA") THEN CCDEFS = CCDEFS + ",NO_DSA"
$ IF F$TRNLNM("OPENSSL_NO_DH") THEN CCDEFS = CCDEFS + ",NO_DH"
$ IF F$TRNLNM("OPENSSL_NO_MD2") THEN CCDEFS = CCDEFS + ",NO_MD2"
$ IF F$TRNLNM("OPENSSL_NO_MD5") THEN CCDEFS = CCDEFS + ",NO_MD5"
$ IF F$TRNLNM("OPENSSL_NO_RIPEMD") THEN CCDEFS = CCDEFS + ",NO_RIPEMD"
$ IF F$TRNLNM("OPENSSL_NO_SHA") THEN CCDEFS = CCDEFS + ",NO_SHA"
$ IF F$TRNLNM("OPENSSL_NO_SHA0") THEN CCDEFS = CCDEFS + ",NO_SHA0"
$ IF F$TRNLNM("OPENSSL_NO_SHA1") THEN CCDEFS = CCDEFS + ",NO_SHA1"
$ IF F$TRNLNM("OPENSSL_NO_DES")
$ THEN
$   CCDEFS = CCDEFS + ",NO_DES,NO_MDC2"
$ ELSE
$   IF F$TRNLNM("OPENSSL_NO_MDC2") THEN CCDEFS = CCDEFS + ",NO_MDC2"
$ ENDIF
$ IF F$TRNLNM("OPENSSL_NO_RC2") THEN CCDEFS = CCDEFS + ",NO_RC2"
$ IF F$TRNLNM("OPENSSL_NO_RC4") THEN CCDEFS = CCDEFS + ",NO_RC4"
$ IF F$TRNLNM("OPENSSL_NO_RC5") THEN CCDEFS = CCDEFS + ",NO_RC5"
$ IF F$TRNLNM("OPENSSL_NO_IDEA") THEN CCDEFS = CCDEFS + ",NO_IDEA"
$ IF F$TRNLNM("OPENSSL_NO_BF") THEN CCDEFS = CCDEFS + ",NO_BF"
$ IF F$TRNLNM("OPENSSL_NO_CAST") THEN CCDEFS = CCDEFS + ",NO_CAST"
$ IF F$TRNLNM("OPENSSL_NO_HMAC") THEN CCDEFS = CCDEFS + ",NO_HMAC"
$ IF F$TRNLNM("OPENSSL_NO_SSL2") THEN CCDEFS = CCDEFS + ",NO_SSL2"
$ IF F$TYPE(USER_CCDEFS) .NES. "" THEN CCDEFS = CCDEFS + "," + USER_CCDEFS
$ CCEXTRAFLAGS = ""
$ IF F$TYPE(USER_CCFLAGS) .NES. "" THEN CCEXTRAFLAGS = USER_CCFLAGS
$ CCDISABLEWARNINGS = "LONGLONGTYPE,LONGLONGSUFX"
$ IF F$TYPE(USER_CCDISABLEWARNINGS) .NES. "" THEN -
	CCDISABLEWARNINGS = CCDISABLEWARNINGS + "," + USER_CCDISABLEWARNINGS
$!
$!  Check To See If The User Entered A Valid Paramter.
$!
$ IF (P3.EQS."VAXC").OR.(P3.EQS."DECC").OR.(P3.EQS."GNUC")
$ THEN
$!
$!  Check To See If The User Wanted DECC.
$!
$   IF (P3.EQS."DECC")
$   THEN
$!
$!    Looks Like DECC, Set To Use DECC.
$!
$     COMPILER = "DECC"
$!
$!    Tell The User We Are Using DECC.
$!
$     WRITE SYS$OUTPUT "Using DECC 'C' Compiler."
$!
$!    Use DECC...
$!
$     CC = "CC"
$     IF ARCH.EQS."VAX" .AND. F$TRNLNM("DECC$CC_DEFAULT").NES."/DECC" -
	 THEN CC = "CC/DECC"
$     CC = CC + "/''CC_OPTIMIZE'/''DEBUGGER'/STANDARD=ANSI89" + -
           "/NOLIST/PREFIX=ALL" + CCEXTRAFLAGS
$!
$!    Define The Linker Options File Name.
$!
$     OPT_FILE = "SYS$DISK:[]VAX_DECC_OPTIONS.OPT"
$!
$!  End DECC Check.
$!
$   ENDIF
$!
$!  Check To See If We Are To Use VAXC.
$!
$   IF (P3.EQS."VAXC")
$   THEN
$!
$!    Looks Like VAXC, Set To Use VAXC.
$!
$     COMPILER = "VAXC"
$!
$!    Tell The User We Are Using VAX C.
$!
$     WRITE SYS$OUTPUT "Using VAXC 'C' Compiler."
$!
$!    Compile Using VAXC.
$!
$     CC = "CC"
$     IF ARCH.EQS."AXP"
$     THEN
$	WRITE SYS$OUTPUT "There is no VAX C on Alpha!"
$	EXIT
$     ENDIF
$     IF F$TRNLNM("DECC$CC_DEFAULT").EQS."/DECC" THEN CC = "CC/VAXC"
$     CC = CC + "/''CC_OPTIMIZE'/''DEBUGGER'/NOLIST" + CCEXTRAFLAGS
$     CCDEFS = CCDEFS + ",""VAXC"""
$!
$!    Define <sys> As SYS$COMMON:[SYSLIB]
$!
$     DEFINE/NOLOG SYS SYS$COMMON:[SYSLIB]
$!
$!    Define The Linker Options File Name.
$!
$     OPT_FILE = "SYS$DISK:[]VAX_VAXC_OPTIONS.OPT"
$!
$!  End VAXC Check
$!
$   ENDIF
$!
$!  Check To See If We Are To Use GNU C.
$!
$   IF (P3.EQS."GNUC")
$   THEN
$!
$!    Looks Like GNUC, Set To Use GNUC.
$!
$     COMPILER = "GNUC"
$!
$!    Tell The User We Are Using GNUC.
$!
$     WRITE SYS$OUTPUT "Using GNU 'C' Compiler."
$!
$!    Use GNU C...
$!
$     CC = "GCC/NOCASE_HACK/''GCC_OPTIMIZE'/''DEBUGGER'/NOLIST" + CCEXTRAFLAGS
$!
$!    Define The Linker Options File Name.
$!
$     OPT_FILE = "SYS$DISK:[]VAX_GNUC_OPTIONS.OPT"
$!
$!  End The GNU C Check.
$!
$   ENDIF
$!
$!  Set up default defines
$!
$   CCDEFS = """FLAT_INC=1""," + CCDEFS
$!
$!  Check To See If We Are To Compile With RSAREF Routines.
$!
$   IF (RSAREF.EQS."TRUE")
$   THEN
$!
$!    Compile With RSAREF.
$!
$     CCDEFS = CCDEFS + ",""RSAref=1"""
$!
$!    Tell The User This.
$!
$     WRITE SYS$OUTPUT "Compiling With RSAREF Routines."
$!
$!    Else, We Don't Care.  Compile Without The RSAREF Library.
$!
$   ELSE
$!
$!    Tell The User We Are Compile Without The RSAREF Routines.
$!
$     WRITE SYS$OUTPUT "Compiling Without The RSAREF Routines.
$!
$!  End The RSAREF Check.
$!
$   ENDIF
$!
$!  Finish up the definition of CC.
$!
$   IF COMPILER .EQS. "DECC"
$   THEN
$     IF CCDISABLEWARNINGS .EQS. ""
$     THEN
$       CC4DISABLEWARNINGS = "DOLLARID"
$     ELSE
$       CC4DISABLEWARNINGS = CCDISABLEWARNINGS + ",DOLLARID"
$       CCDISABLEWARNINGS = "/WARNING=(DISABLE=(" + CCDISABLEWARNINGS + "))"
$     ENDIF
$     CC4DISABLEWARNINGS = "/WARNING=(DISABLE=(" + CC4DISABLEWARNINGS + "))"
$   ELSE
$     CCDISABLEWARNINGS = ""
$     CC4DISABLEWARNINGS = ""
$   ENDIF
$   CC = CC + "/DEFINE=(" + CCDEFS + ")" + CCDISABLEWARNINGS
$!
$!  Show user the result
$!
$   WRITE SYS$OUTPUT "Main Compiling Command: ",CC
$!
$!  Else The User Entered An Invalid Arguement.
$!
$ ELSE
$!
$!  Tell The User We Don't Know What They Want.
$!
$   WRITE SYS$OUTPUT ""
$   WRITE SYS$OUTPUT "The Option ",P3," Is Invalid.  The Valid Options Are:"
$   WRITE SYS$OUTPUT ""
$   WRITE SYS$OUTPUT "    VAXC  :  To Compile With VAX C."
$   WRITE SYS$OUTPUT "    DECC  :  To Compile With DEC C."
$   WRITE SYS$OUTPUT "    GNUC  :  To Compile With GNU C."
$   WRITE SYS$OUTPUT ""
$!
$!  Time To EXIT.
$!
$   EXIT
$ ENDIF
$!
$! Time to check the contents, and to make sure we get the correct library.
$!
$ IF P4.EQS."SOCKETSHR" .OR. P4.EQS."MULTINET" .OR. P4.EQS."UCX"
$ THEN
$!
$!  Check to see if SOCKETSHR was chosen
$!
$   IF P4.EQS."SOCKETSHR"
$   THEN
$!
$!    Set the library to use SOCKETSHR
$!
$     TCPIP_LIB = "[-.VMS]SOCKETSHR_SHR.OPT/OPT"
$!
$!    Done with SOCKETSHR
$!
$   ENDIF
$!
$!  Check to see if MULTINET was chosen
$!
$   IF P4.EQS."MULTINET"
$   THEN
$!
$!    Set the library to use UXC emulation.
$!
$     P4 = "UCX"
$!
$!    Done with MULTINET
$!
$   ENDIF
$!
$!  Check to see if UCX was chosen
$!
$   IF P4.EQS."UCX"
$   THEN
$!
$!    Set the library to use UCX.
$!
$     TCPIP_LIB = "[-.VMS]UCX_SHR_DECC.OPT/OPT"
$     IF F$TRNLNM("UCX$IPC_SHR") .NES. ""
$     THEN
$       TCPIP_LIB = "[-.VMS]UCX_SHR_DECC_LOG.OPT/OPT"
$     ELSE
$       IF COMPILER .NES. "DECC" .AND. ARCH .EQS. "VAX" THEN -
	  TCPIP_LIB = "[-.VMS]UCX_SHR_VAXC.OPT/OPT"
$     ENDIF
$!
$!    Done with UCX
$!
$   ENDIF
$!
$!  Print info
$!
$   WRITE SYS$OUTPUT "TCP/IP library spec: ", TCPIP_LIB
$!
$!  Else The User Entered An Invalid Arguement.
$!
$ ELSE
$!
$!  Tell The User We Don't Know What They Want.
$!
$   WRITE SYS$OUTPUT ""
$   WRITE SYS$OUTPUT "The Option ",P4," Is Invalid.  The Valid Options Are:"
$   WRITE SYS$OUTPUT ""
$   WRITE SYS$OUTPUT "    SOCKETSHR  :  To link with SOCKETSHR TCP/IP library."
$   WRITE SYS$OUTPUT "    UCX        :  To link with UCX TCP/IP library."
$   WRITE SYS$OUTPUT ""
$!
$!  Time To EXIT.
$!
$   EXIT
$!
$!  Done with TCP/IP libraries
$!
$ ENDIF
$!
$! Special Threads For OpenVMS v7.1 Or Later
$!
$! Written By:  Richard Levitte
$!              richard@levitte.org
$!
$!
$! Check To See If We Have A Option For P5.
$!
$ IF (P5.EQS."")
$ THEN
$!
$!  Get The Version Of VMS We Are Using.
$!
$   ISSEVEN :=
$   TMP = F$ELEMENT(0,"-",F$EXTRACT(1,4,F$GETSYI("VERSION")))
$   TMP = F$INTEGER(F$ELEMENT(0,".",TMP)+F$ELEMENT(1,".",TMP))
$!
$!  Check To See If The VMS Version Is v7.1 Or Later.
$!
$   IF (TMP.GE.71)
$   THEN
$!
$!    We Have OpenVMS v7.1 Or Later, So Use The Special Threads.
$!
$     ISSEVEN := ,PTHREAD_USE_D4
$!
$!  End The VMS Version Check.
$!
$   ENDIF
$!
$! End The P5 Check.
$!
$ ENDIF
$!
$!  Time To RETURN...
$!
$ RETURN
$!
$ INITIALISE:
$!
$! Save old value of the logical name OPENSSL
$!
$ __SAVE_OPENSSL = F$TRNLNM("OPENSSL","LNM$PROCESS_TABLE")
$!
$! Save directory information
$!
$ __HERE = F$PARSE(F$PARSE("A.;",F$ENVIRONMENT("PROCEDURE"))-"A.;","[]A.;") - "A.;"
$ __TOP = __HERE - "TEST]"
$ __INCLUDE = __TOP + "INCLUDE.OPENSSL]"
$!
$! Set up the logical name OPENSSL to point at the include directory
$!
$ DEFINE OPENSSL/NOLOG '__INCLUDE'
$!
$! Done
$!
$ RETURN
$!
$ CLEANUP:
$!
$! Restore the logical name OPENSSL if it had a value
$!
$ IF __SAVE_OPENSSL .EQS. ""
$ THEN
$   DEASSIGN OPENSSL
$ ELSE
$   DEFINE/NOLOG OPENSSL '__SAVE_OPENSSL'
$ ENDIF
$!
$! Done
$!
$ RETURN
