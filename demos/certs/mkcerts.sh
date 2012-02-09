#!/bin/sh

OPENSSL=../../apps/openssl
OPENSSL_CONF=../../apps/openssl.cnf
export OPENSSL_CONF

# Root CA: create certificate directly
CN="Test Root CA" $OPENSSL req -config ca.cnf -x509 -nodes \
	-keyout root.pem -out root.pem -newkey rsa:2048 -days 3650
# Server certificate: create request first
CN="Test Server Cert" $OPENSSL req -config ca.cnf -nodes \
	-keyout skey.pem -out req.pem -newkey rsa:1024
# Sign request: end entity extensions
$OPENSSL x509 -req -in req.pem -CA root.pem -days 3600 \
	-extfile ca.cnf -extensions usr_cert -CAcreateserial -out server.pem
# Intermediate CA: request first
CN="Test Intermediate CA" $OPENSSL req -config ca.cnf -nodes \
	-keyout intkey.pem -out intreq.pem -newkey rsa:2048
# Sign request: CA extensions
$OPENSSL x509 -req -in intreq.pem -CA root.pem -days 3600 \
	-extfile ca.cnf -extensions v3_ca -CAcreateserial -out intca.pem
# Client certificate: request first
CN="Test Client Cert" $OPENSSL req -config ca.cnf -nodes \
	-keyout ckey.pem -out creq.pem -newkey rsa:1024
# Sign using intermediate CA
$OPENSSL x509 -req -in creq.pem -CA intca.pem -CAkey intkey.pem -days 3600 \
	-extfile ca.cnf -extensions usr_cert -CAcreateserial -out client.pem

# Example creating a PKCS#3 DH certificate. 

# First DH parameters

$OPENSSL genpkey -genparam -algorithm DH -pkeyopt dh_paramgen_prime_len:1024 -out dhp.pem

# Uncomment out this line for X9.42 DH parameters instead
$OPENSSL genpkey -genparam -algorithm DH -out dhp.pem -pkeyopt dh_rfc5114:2

# Now a DH private key
$OPENSSL genpkey -paramfile dhp.pem -out dhskey.pem
# Create DH public key file
$OPENSSL pkey -in dhskey.pem -pubout -out dhspub.pem
# Certificate request, key just reuses old one as it is ignored when the
# request is signed.
CN="Test Server DH Cert" $OPENSSL req -config ca.cnf -new \
	-key skey.pem -out dhsreq.pem
# Sign request: end entity DH extensions
$OPENSSL x509 -req -in dhsreq.pem -CA root.pem -days 3600 \
	-force_pubkey dhspub.pem \
	-extfile ca.cnf -extensions dh_cert -CAcreateserial -out dhserver.pem

# DH client certificate

$OPENSSL genpkey -paramfile dhp.pem -out dhckey.pem
$OPENSSL pkey -in dhckey.pem -pubout -out dhcpub.pem
CN="Test Client DH Cert" $OPENSSL req -config ca.cnf -new \
	-key skey.pem -out dhcreq.pem
$OPENSSL x509 -req -in dhcreq.pem -CA root.pem -days 3600 \
	-force_pubkey dhcpub.pem \
	-extfile ca.cnf -extensions dh_cert -CAcreateserial -out dhclient.pem
