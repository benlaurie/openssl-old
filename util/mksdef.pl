
# Perl script to split libeay32.def into two distinct DEF files for use in
# fipdso mode. It works out symbols in each case by running "link" command and
# parsing the output to find the list of missing symbols then splitting
# libeay32.def based on the result.


# Get list of unknown symbols

my @deferr = `link @ARGV`;

my $preamble = "";
my @fipsdll;
my @fipsrest;
my %nosym;

# Add symbols to a hash for easy lookup

foreach (@deferr)
	{
	if (/^.*symbol (\S+)$/)
		{
		$nosym{$1} = 1;
		}
	}

open (IN, "ms/libeay32.def") || die "Can't Open DEF file for splittling";

my $started = 0;

# Parse libeay32.def into two arrays depending on whether the symbol matches
# the missing list.


foreach (<IN>)
	{
	if (/^\s*(\S+)\s*\@/)
		{
		$started = 1;
		if (exists $nosym{$1})
			{
			push @fipsrest, $_;
			}
		else
			{
			push @fipsdll, "\t$1\n";
			}
		}
	$preamble .= $_ unless $started;
	}

close IN;

# Hack! Add some additional exports needed to libcryptofips.dll
#

push @fipsdll, "\tengine_table_unregister\n";
push @fipsdll, "\tengine_table_register\n";
push @fipsdll, "\tengine_table_cleanup\n";
push @fipsdll, "\tengine_table_select\n";
push @fipsdll, "\tengine_set_all_null\n";

# Write out DEF files for each array

write_def("ms/libfips.def", "LIBFIPS", $preamble, \@fipsdll);
write_def("ms/libcryptofips.def", "LIBCRYPTOFIPS", $preamble, \@fipsrest);


sub write_def
	{
	my ($fnam, $defname, $preamble, $rdefs) = @_;
	open (OUT, ">$fnam") || die "Can't Open DEF file $fnam for Writing\n";

	$preamble =~ s/LIBEAY32/$defname/g;
	$preamble =~ s/LIBEAY/$defname/g;

	print OUT $preamble;
	foreach (@$rdefs)
		{
		print OUT $_;
		}
	close OUT;
	}


