#!/usr/local/bin/perl
# VCw64lib.pl - the file for Visual C++ 7.[00]/64 for windows XP/64 or .NET/64, static libraries
#

$ssl="ssleay64";
$crypto="libeay64";

$o='\\';
$cp='copy nul+';	# Timestamps get stuffed otherwise
$rm='del';

# C compiler stuff
$cc='cl';
$cflags=' /MD /W3 /WX /Ox /O2 /Ob2 /Gs0 /GF /Gy /nologo -DOPENSSL_SYSNAME_WIN64 -DWIN32_LEAN_AND_MEAN -DL_ENDIAN -DDSO_WIN32';
$lflags="/nologo /subsystem:console /machine:IA64 /opt:ref";
$mlflags='';

$out_def="out64";
$tmp_def="tmp64";
$inc_def="inc64";

if ($debug)
	{
	$cflags=" /MDd /W3 /WX /Zi /Yd /Od /nologo -DOPENSSL_SYSNAME_WIN64 -D_DEBUG -DL_ENDIAN -DWIN32_LEAN_AND_MEAN -DDEBUG -DDSO_WIN32";
	$lflags.=" /debug";
	$mlflags.=' /debug';
	}

$obj='.obj';
$ofile="/Fo";

# EXE linking stuff
$link="link";
$efile="/out:";
$exep='.exe';
if ($no_sock)
	{ $ex_libs=""; }
else
	{ $ex_libs="wsock32.lib user32.lib gdi32.lib"; }

# static library stuff
$mklib='lib';
$ranlib='';
$plib="";
$libp=".lib";
$shlibp=($shlib)?".dll":".lib";
$lfile='/out:';

$shlib_ex_obj="";
$app_ex_obj="setargv.obj";

$bn_asm_obj='';
$bn_asm_src='';
$des_enc_obj='';
$des_enc_src='';
$bf_enc_obj='';
$bf_enc_src='';

if ($shlib)
	{
	$mlflags.=" $lflags /dll";
#	$cflags =~ s| /MD| /MT|;
	$lib_cflag=" -D_WINDLL -D_DLL";
	$out_def="out64dll";
	$tmp_def="tmp64dll";
	}

#$cflags.=" /Fd$out_def/";
$cflags.=" /Fd$out_def".($debug?".dbg":"")."/";

sub do_lib_rule
	{
	local($objs,$target,$name,$shlib)=@_;
	local($ret,$Name);

	$taget =~ s/\//$o/g if $o ne '/';
	($Name=$name) =~ tr/a-z/A-Z/;

#	$target="\$(LIB_D)$o$target";
	$ret.="$target: $objs\n";
	if (!$shlib)
		{
#		$ret.="\t\$(RM) \$(O_$Name)\n";
		$ex =' advapi32.lib';
		$ret.="\t\$(MKLIB) $lfile$target @<<\n  $objs $ex\n<<\n";
		}
	else
		{
		local($ex)=($target =~ /O_SSL/)?' $(L_CRYPTO)':'';
		$ex.=' wsock32.lib gdi32.lib advapi32.lib';
		$ret.="\t\$(LINK) \$(MLFLAGS) $efile$target /def:ms/${Name}.def @<<\n  \$(SHLIB_EX_OBJ) $objs $ex\n<<\n";
		}
	$ret.="\n";
	return($ret);
	}

sub do_link_rule
	{
	local($target,$files,$dep_libs,$libs)=@_;
	local($ret,$_);
	
	$file =~ s/\//$o/g if $o ne '/';
	$n=&bname($targer);
	$ret.="$target: $files $dep_libs\n";
	$ret.="  \$(LINK) \$(LFLAGS) $efile$target @<<\n";
	$ret.="  \$(APP_EX_OBJ) $files $libs\n<<\n\n";
	return($ret);
	}

1;
