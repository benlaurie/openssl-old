@rem OpenSSL with Mingw32+GNU as
@rem ---------------------------

perl Configure Mingw32 %1 %2 %3 %4 %5 %6 %7 %8

@echo off
echo Generating x86 for GNU assember

echo Bignum
cd crypto\bn\asm
perl x86.pl gaswin > bn-win32.s
cd ..\..\..

echo DES
cd crypto\des\asm
perl des-586.pl gaswin > d-win32.s
cd ..\..\..

echo crypt
cd crypto\des\asm
perl crypt586.pl gaswin > y-win32.s
cd ..\..\..

echo Blowfish
cd crypto\bf\asm
perl bf-586.pl gaswin > b-win32.s
cd ..\..\..

echo CAST5
cd crypto\cast\asm
perl cast-586.pl gaswin > c-win32.s
cd ..\..\..

echo RC4
cd crypto\rc4\asm
perl rc4-586.pl gaswin > r4-win32.s
cd ..\..\..

echo MD5
cd crypto\md5\asm
perl md5-586.pl gaswin > m5-win32.s
cd ..\..\..

echo SHA1
cd crypto\sha\asm
perl sha1-586.pl gaswin > s1-win32.s
cd ..\..\..

echo RIPEMD160
cd crypto\ripemd\asm
perl rmd-586.pl gaswin > rm-win32.s
cd ..\..\..

echo RC5\32
cd crypto\rc5\asm
perl rc5-586.pl gaswin > r5-win32.s
cd ..\..\..

@rem Makefile
perl util\mkfiles.pl >MINFO
perl util\mk1mf.pl gaswin Mingw32 >ms\mingw32a.mak
perl util\mk1mf.pl gaswin Mingw32-files >ms\mingw32f.mak
@rem DLL definition files
perl util\mkdef.pl 32 libeay >ms\libeay32.def
if errorlevel 1 goto end
perl util\mkdef.pl 32 ssleay >ms\ssleay32.def
if errorlevel 1 goto end

@rem Create files -- this can be skipped if using the GNU file utilities
make -f ms/mingw32f.mak
echo You can ignore the error messages above

@rem Build the libraries
make -f ms/mingw32a.mak
if errorlevel 1 goto end

@rem Generate the DLLs and input libraries
dllwrap --dllname libeay32.dll --output-lib out/libeay32.a --def ms/libeay32.def out/libcrypto.a -lwsock32 -lgdi32
if errorlevel 1 goto end
dllwrap --dllname libssl32.dll --output-lib out/libssl32.a --def ms/ssleay32.def out/libssl.a out/libeay32.a
if errorlevel 1 goto end

echo Done compiling OpenSSL

:end

