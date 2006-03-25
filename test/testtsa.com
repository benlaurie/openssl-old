$!
$! A few very basic tests for the 'ts' time stamping authority command.
$!
$
$	__arch := VAX
$	if f$getsyi("cpu") .ge. 128 then __arch := AXP
$	exe_dir := sys$disk:[-.'__arch'.exe.apps]
$
$	openssl := mcr 'exe_dir'openssl
$	OPENSSL_CONF := [-]CAtsa.cnf
$
$ error:
$	subroutine
$		write sys$error "TSA test failed!"
$		exit 3
$	endsubroutine
$
$ setup_dir:
$	subroutine
$
$		if f$search("tsa.dir") .nes ""
$		then
$			@[-.util]deltree [.tsa]*.*
$ 			set file/prot=(S:RWED,O:RWED,G:RWED,W:RWED) tsa.dir;*
$ 			delete tsa.dir;*
$		endif
$
$		create/dir [.tsa]
$		set default [.tsa]
$	endsubroutine
$
$ clean_up_dir:
$	subroutine
$
$		set default [-]
$		@[-.util]deltree [.tsa]*.*
$ 		set file/prot=(S:RWED,O:RWED,G:RWED,W:RWED) tsa.dir;*
$ 		delete tsa.dir;*
$	endsubroutine
$
$ create_ca:
$	subroutine
$
$		write sys$output "Creating a new CA for the TSA tests..."
$		@[--.util]deltree [.demoCA]*.*
$
$		open/write file VMStsa-response.create_ca
$		write file ""
$		write file "HU"
$		write file "Budapest"
$		write file "Budapest"
$		write file "Gov-CA Ltd."
$		write file "ca1"
$		close file
$		open/read sys$ca_input VMStsa-response.create_ca
$		@[--.apps]CA.com -input sys$ca_input -newca
$		save_severity = $severity
$		close sys$ca_input
$		if save_severity .ne. 1 then call error
$	endsubroutine
$
$ create_tsa_cert:
$	subroutine
$
$		INDEX=p1
$		EXT=p2
$		open/write file VMStsa-response1.create_tsa_cert
$		write file "HU"
$		write file "Budapest"
$		write file "Buda"
$		write file "Hun-TSA Ltd."
$		write file "tsa",INDEX
$		close file
$		define/user sys$input VMStsa-response.create_tsa_cert
$		openssl req -new -
			-out tsa_req'INDEX'.pem -keyout tsa_key'INDEX'.pem
$		if $severity .ne. 1 then call error
$
$		open/write file VMStsa-response2.create_tsa_cert
$		write file "y"
$		write file "y"
$		close file
$		define/user sys$input VMStsa-response.create_tsa_cert
$		openssl ca -in tsa_req'INDEX'.pem -out tsa_cert'INDEX'.pem -
			-extensions "''EXT'"
$		if $severity .ne. 1 then call error
$	endsubroutine
$
$ print_request:
$	subroutine
$
$		openssl ts -query -in 'p1' -text
$	endsubroutine
$
$ create_time_stamp_request1: subroutine
$
$		openssl ts -query -data [-]testtsa.com -policy tsa_policy1 -
			-cert -out req1.tsq
$		if $severity .ne. 1 then call error
$	endsubroutine
$
$ create_time_stamp_request2: subroutine
$
$		openssl ts -query -data [-]testtsa.com -policy tsa_policy2 -
			-no_nonce -out req2.tsq
$		if $severity .ne. 1 then call error
$	endsubroutine
$
$ create_time_stamp_request3: subroutine
$
$		openssl ts -query -data [-]CAtsa.cnf -no_nonce -out req3.tsq
$		if $severity .ne. 1 then call error
$	endsubroutine
$
$ print_response:
$	subroutine
$
$		openssl ts -reply -in 'p1' -text
$		if $severity .ne. 1 then call error
$	endsubroutine
$
$ create_time_stamp_response:
$	subroutine
$
$		openssl ts -reply -section 'p3' -queryfile 'p1' -out 'p2'
$		if $severity .ne. 1 then call error
$	endsubroutine
$
$ time_stamp_response_token_test:
$	subroutine
$
$		RESPONSE2:='p2'.copy_tsr
$		TOKEN_DER:='p2'.token_der
$		openssl ts -reply -in 'p2' -out 'TOKEN_DER' -token_out
$		if $severity .ne. 1 then call error
$		openssl ts -reply -in 'TOKEN_DER' -token_in -out 'RESPONSE2'
$		if $severity .ne. 1 then call error
$		backup/compare 'RESPONSE2' 'p2'
$		if $severity .ne. 1 then call error
$		openssl ts -reply -in 'p2' -text -token_out
$		if $severity .ne. 1 then call error
$		openssl ts -reply -in 'TOKEN_DER' -token_in -text -token_out
$		if $severity .ne. 1 then call error
$		openssl ts -reply -queryfile 'p1' -text -token_out
$		if $severity .ne. 1 then call error
$	endsubroutine
$
$ verify_time_stamp_response:
$	subroutine
$
$		openssl ts -verify -queryfile 'p1' -in 'p2' -
			-CAfile [.demoCA]cacert.pem -untrusted tsa_cert1.pem
$		if $severity .ne. 1 then call error
$		openssl ts -verify -data 'p3' -in 'p2' -
			-CAfile [.demoCA]cacert.pem -untrusted tsa_cert1.pem
$		if $severity .ne. 1 then call error
$	endsubroutine
$
$ verify_time_stamp_token:
$	subroutine
$
$		# create the token from the response first
$		openssl ts -reply -in 'p2' -out 'p2'.token -token_out
$		if $severity .ne. 1 then call error
$		openssl ts -verify -queryfile 'p1' -in 'p2'.token -token_in \
			-CAfile [.demoCA]cacert.pem -untrusted tsa_cert1.pem
$		if $severity .ne. 1 then call error
$		openssl ts -verify -data 'p3' -in 'p2'.token -token_in \
			-CAfile [.demoCA]cacert.pem -untrusted tsa_cert1.pem
$		if $severity .ne. 1 then call error
$	endsubroutine
$
$ verify_time_stamp_response_fail:
$	subroutine
$
$		openssl ts -verify -queryfile 'p1' -in 'p2' -
			-CAfile [.demoCA]cacert.pem -untrusted tsa_cert1.pem
$		# Checks if the verification failed, as it should have.
$		if $severity .ne. 1 then call error
$		write sys$output "Ok"
$	endsubroutine
$
$	! Main body ----------------------------------------------------------
$
$	write sys$output "Setting up TSA test directory..."
$	call setup_dir
$
$	write sys$output "Creating CA for TSA tests..."
$	call create_ca
$
$	write sys$output "Creating tsa_cert1.pem TSA server cert..."
$	call create_tsa_cert 1 tsa_cert
$
$	write sys$output "Creating tsa_cert2.pem non-TSA server cert..."
$	call create_tsa_cert 2 non_tsa_cert
$
$	write sys$output "Creating req1.req time stamp request for file testtsa..."
$	call create_time_stamp_request1
$
$	write sys$output "Printing req1.req..."
$	call print_request req1.tsq
$
$	write sys$output "Generating valid response for req1.req..."
$	call create_time_stamp_response req1.tsq resp1.tsr tsa_config1
$
$	write sys$output "Printing response..."
$	call print_response resp1.tsr
$
$	write sys$output "Verifying valid response..."
$	call verify_time_stamp_response req1.tsq resp1.tsr ../testtsa
$
$	write sys$output "Verifying valid token..."
$	call verify_time_stamp_token req1.tsq resp1.tsr ../testtsa
$
$	! The tests below are commented out, because invalid signer certificates
$	! can no longer be specified in the config file.
$
$	! write sys$output "Generating _invalid_ response for req1.req..."
$	! call create_time_stamp_response req1.tsq resp1_bad.tsr tsa_config2
$
$	! write sys$output "Printing response..."
$	! call print_response resp1_bad.tsr
$
$	! write sys$output "Verifying invalid response, it should fail..."
$	! call verify_time_stamp_response_fail req1.tsq resp1_bad.tsr
$
$	write sys$output "Creating req2.req time stamp request for file testtsa..."
$	call create_time_stamp_request2
$
$	write sys$output "Printing req2.req..."
$	call print_request req2.tsq
$
$	write sys$output "Generating valid response for req2.req..."
$	call create_time_stamp_response req2.tsq resp2.tsr tsa_config1
$
$	write sys$output "Checking '-token_in' and '-token_out' options with '-reply'..."
$	call time_stamp_response_token_test req2.tsq resp2.tsr
$
$	write sys$output "Printing response..."
$	call print_response resp2.tsr
$
$	write sys$output "Verifying valid response..."
$	call verify_time_stamp_response req2.tsq resp2.tsr ../testtsa
$
$	write sys$output "Verifying response against wrong request, it should fail..."
$	call verify_time_stamp_response_fail req1.tsq resp2.tsr
$
$	write sys$output "Verifying response against wrong request, it should fail..."
$	call verify_time_stamp_response_fail req2.tsq resp1.tsr
$
$	write sys$output "Creating req3.req time stamp request for file CAtsa.cnf..."
$	call create_time_stamp_request3
$
$	write sys$output "Printing req3.req..."
$	call print_request req3.tsq
$
$	write sys$output "Verifying response against wrong request, it should fail..."
$	call verify_time_stamp_response_fail req3.tsq resp1.tsr
$
$	write sys$output "Cleaning up..."
$	call clean_up_dir
$
$	exit
