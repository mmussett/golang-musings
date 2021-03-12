# Working with CA signed certificates

## Creating your certificates

### OpenSSLcnf

```
#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#
# 
# Configuration file for testing certificate authority.
# The environment variable, CA_HOME, must be set to point to the directory
# containing this file before running any openssl commands.
#
[ ca ]
# `man ca`
default_ca = CA_default

[ CA_default ]
# Directory and file locations.
dir               = /Users/mmussett/security/cert-authority
certs             = $dir/certs
crl_dir           = $dir/crl
new_certs_dir     = $dir/newcerts
database          = $dir/index.txt
serial            = $dir/serial
RANDFILE          = $dir/private/.rand

# The root key and root certificate.
private_key       = $dir/private/ca.key.pem
certificate       = $dir/certs/ca.cert.pem

# For certificate revocation lists.
crlnumber         = $dir/crlnumber
crl               = $dir/crl/ca.crl.pem
crl_extensions    = crl_ext
default_crl_days  = 30

# SHA-1 is deprecated, so use SHA-2 instead.
default_md        = sha256

name_opt          = ca_default
cert_opt          = ca_default
default_days      = 375
preserve          = no
policy            = policy_strict

[ policy_strict ]
# The root CA should only sign intermediate certificates that match.
# See the POLICY FORMAT section of `man ca`.
countryName             = optional
stateOrProvinceName     = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ policy_loose ]
# Allow the intermediate CA to sign a more diverse range of certificates.
# See the POLICY FORMAT section of the `ca` man page.
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
# Options for the `req` tool (`man req`).
default_bits        = 2048
distinguished_name  = req_distinguished_name
string_mask         = utf8only

# SHA-1 is deprecated, so use SHA-2 instead.
default_md          = sha256

# Extension to add when the -x509 option is used.
x509_extensions     = v3_ca

[ req_distinguished_name ]
# See <https://en.wikipedia.org/wiki/Certificate_signing_request>.
countryName                     = Country Name (2 letter code)
stateOrProvinceName             = State or Province Name
localityName                    = Locality Name
0.organizationName              = Organization Name
organizationalUnitName          = Organizational Unit Name
commonName                      = Common Name
emailAddress                    = Email Address

# Optionally, specify some defaults.
countryName_default             = US
stateOrProvinceName_default     = California
localityName_default            = Palo Alto
0.organizationName_default      = GottaEat
organizationalUnitName_default  = IT
emailAddress_default            =

[ v3_ca ]
# Extensions for a typical CA (`man x509v3_config`).
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ v3_intermediate_ca ]
# Extensions for a typical intermediate CA (`man x509v3_config`).
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ usr_cert ]
# Extensions for client certificates (`man x509v3_config`).
basicConstraints = CA:FALSE
nsCertType = client, email
nsComment = "OpenSSL Generated Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, emailProtection

[ server_cert ]
# Extensions for server certificates (`man x509v3_config`).
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[ crl_ext ]
# Extension for CRLs (`man x509v3_config`).
authorityKeyIdentifier=keyid:always

[ ocsp ]
# Extension for OCSP signing certificates (`man ocsp`).
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, OCSPSigning

[ v3_req ]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
```

### CA Certificate

```bash
#!/bin/bash

cd /Users/mmussett/security/cert-authority
export CA_HOME=$(pwd)
export CA_PASSWORD=secret-password

mkdir certs crl newcerts private
chmod 700 private/
touch index.txt index.txt.attr
echo 1000 > serial

# Generate the certificate authority private key
openssl genrsa -aes256 \
   -passout pass:${CA_PASSWORD} \
   -out /Users/mmussett/security/cert-authority/private/ca.key.pem \
   4096

# Restrict Acess to the certificate authority private key to prevent unauthorized use   
chmod 400 /Users/mmussett/security/cert-authority/private/ca.key.pem

# Create the root X.509 certificate.
openssl req -config openssl.cnf \
  -key /Users/mmussett/security/cert-authority/private/ca.key.pem \
  -new -x509 \
  -days 7300 \
  -sha256 \
  -extensions v3_ca \
  -out /Users/mmussett/security/cert-authority/certs/ca.cert.pem \
  -subj '/C=US/ST=CA/L=Palo Alto/O=tibco.com' \
  -passin pass:${CA_PASSWORD}
  
# Restrict Acess to the public X.509 certificate to prevent unauthorized use  
chmod 444 /Users/mmussett/security/cert-authority/certs/ca.cert.pem
```


### Client Certificate

```bash
#!/bin/bash

cd /Users/mmussett/security/cert-authority
export CA_HOME=$(pwd)
export CA_PASSWORD=secret-password

function generate_client_cert() {
	
	local CLIENT_ID=$1
	local CLIENT_ROLE=$2
	local CLIENT_PASSWORD=$3

   # Generate the Client Certificate private key
   openssl genrsa -passout pass:${CLIENT_PASSWORD} \
      -out /Users/mmussett/security/authentication/tls/${CLIENT_ID}.key.pem \
       2048
    
   # Convert the key to PEM format
   openssl pkcs8 -topk8 -inform PEM -outform PEM \
      -in /Users/mmussett/security/authentication/tls/${CLIENT_ID}.key.pem \
      -out /Users/mmussett/security/authentication/tls/${CLIENT_ID}-pk8.pem -nocrypt

   # Generate the client certificate request       
   openssl req -config /Users/mmussett/security/cert-authority/openssl.cnf \
      -key /Users/mmussett/security/authentication/tls/${CLIENT_ID}.key.pem -new -sha256 \
      -out /Users/mmussett/security/authentication/tls/${CLIENT_ID}.csr.pem \
      -subj "/C=US/ST=CA/L=Palo Alto/O=tibco.com/CN=${CLIENT_ROLE}" \
      -passin pass:${CLIENT_PASSWORD}
      
   # Sign the server certificate with the CA
   openssl ca -config /Users/mmussett/security/cert-authority/openssl.cnf \
      -extensions usr_cert \
      -days 100 -notext -md sha256 -batch \
      -in /Users/mmussett/security/authentication/tls/${CLIENT_ID}.csr.pem \
      -out /Users/mmussett/security/authentication/tls/${CLIENT_ID}.cert.pem \
      -passin pass:${CA_PASSWORD}

   # Remove the client key and certifcate request once we are finished
   rm -f /Users/mmussett/security/authentication/tls/${CLIENT_ID}.csr.pem
   rm -f /Users/mmussett/security/authentication/tls/${CLIENT_ID}.key.pem
}

# Create a certificate for Adam with admin role-level access
generate_client_cert admin admin admin-secret
```
 
## Golang code to use certificates in your client

```
    keyPairCerts, err := tls.LoadX509KeyPair("admin.cert.pem", "admin-pk8.pem")
		if err != nil {
			return nil, fmt.Errorf("unable to load key pairs: %s", err)
		}

		// Load CA certificate (PEM format)
		caCert, err := ioutil.ReadFile("ca.cert.pem")
		if err != nil {
			return nil, fmt.Errorf("unable to load ca cert file: %s", err)
		}

		rootCAs, _ := x509.SystemCertPool()
		if rootCAs == nil {
			rootCAs = x509.NewCertPool()
		}

		// Append our cert to the system pool
		if ok := rootCAs.AppendCertsFromPEM(caCert); !ok {
			log.Println("No certs appended, using system certs only")
		}
		// Setup HTTPS client
		tlsConfig := &tls.Config{
			InsecureSkipVerify: false,
			Certificates:       []tls.Certificate{keyPairCerts},
			RootCAs:            rootCAs,
		}
		//tlsConfig.BuildNameToCertificate()
		transport := &http.Transport{TLSClientConfig: tlsConfig}
		client = &http.Client{Transport: transport}
```
