#!/usr/bin/env python

import json
try:
    from http_parser.parser import HttpParser
except ImportError:
    from http_parser.pyparser import HttpParser

import http_sfv
from urllib.parse import parse_qs
import base64
from Cryptodome.Signature import pss
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Signature import DSS
from Cryptodome.Hash import SHA512
from Cryptodome.Hash import SHA256
from Cryptodome.Hash import HMAC
from Cryptodome.PublicKey import RSA
from Cryptodome.PublicKey import ECC
from Cryptodome import Random
from Cryptodome.IO import PEM
from Cryptodome.IO import PKCS8
from Cryptodome.Signature.pss import MGF1
from Cryptodome.Util.asn1 import DerOctetString
from Cryptodome.Util.asn1 import DerBitString
from Cryptodome.Util.asn1 import DerSequence
from nacl.signing import SigningKey
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError
from termcolor import colored
import argparse

mgf512 = lambda x, y: MGF1(x, y, SHA512)

from httpsig import *
from crunchwrap import softwrap, hardwrap


parser = argparse.ArgumentParser(description='Import comments.')

parser.add_argument('target', help='example sections to run', nargs='*')

args = parser.parse_args()


targets = [
    'example',
    'rsapss',
    'clientproxy',
    'revproxy',
    'ttrp',
    'min',
    'header',
    'full',
    'eccres',
    'hmac',
    'reqres',
    'ed25519',
    'transform',
    'static',
    'queryparam',
    'format',
    'gnap',
    'httpsigorgreq',
    'httpsigorgres'
]

if not args.target:
    args.target = targets

results = dict()


rsaTestKeyPublic = """-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAhAKYdtoeoy8zcAcR874L8cnZxKzAGwd7v36APp7Pv6Q2jdsPBRrw
WEBnez6d0UDKDwGbc6nxfEXAy5mbhgajzrw3MOEt8uA5txSKobBpKDeBLOsdJKFq
MGmXCQvEG7YemcxDTRPxAleIAgYYRjTSd/QBwVW9OwNFhekro3RtlinV0a75jfZg
kne/YiktSvLG34lw2zqXBDTC5NHROUqGTlML4PlNZS5Ri2U4aCNx2rUPRcKIlE0P
uKxI4T+HIaFpv8+rdV6eUgOrB2xeI1dSFFn/nnv5OoZJEIB+VmuKn3DCUcCZSFlQ
PSXSfBDiUGhwOw76WuSSsf1D4b/vLoJ10wIDAQAB
-----END RSA PUBLIC KEY-----
"""

rsaTestKeyPrivate = """-----BEGIN RSA PRIVATE KEY-----
MIIEqAIBAAKCAQEAhAKYdtoeoy8zcAcR874L8cnZxKzAGwd7v36APp7Pv6Q2jdsP
BRrwWEBnez6d0UDKDwGbc6nxfEXAy5mbhgajzrw3MOEt8uA5txSKobBpKDeBLOsd
JKFqMGmXCQvEG7YemcxDTRPxAleIAgYYRjTSd/QBwVW9OwNFhekro3RtlinV0a75
jfZgkne/YiktSvLG34lw2zqXBDTC5NHROUqGTlML4PlNZS5Ri2U4aCNx2rUPRcKI
lE0PuKxI4T+HIaFpv8+rdV6eUgOrB2xeI1dSFFn/nnv5OoZJEIB+VmuKn3DCUcCZ
SFlQPSXSfBDiUGhwOw76WuSSsf1D4b/vLoJ10wIDAQABAoIBAG/JZuSWdoVHbi56
vjgCgkjg3lkO1KrO3nrdm6nrgA9P9qaPjxuKoWaKO1cBQlE1pSWp/cKncYgD5WxE
CpAnRUXG2pG4zdkzCYzAh1i+c34L6oZoHsirK6oNcEnHveydfzJL5934egm6p8DW
+m1RQ70yUt4uRc0YSor+q1LGJvGQHReF0WmJBZHrhz5e63Pq7lE0gIwuBqL8SMaA
yRXtK+JGxZpImTq+NHvEWWCu09SCq0r838ceQI55SvzmTkwqtC+8AT2zFviMZkKR
Qo6SPsrqItxZWRty2izawTF0Bf5S2VAx7O+6t3wBsQ1sLptoSgX3QblELY5asI0J
YFz7LJECgYkAsqeUJmqXE3LP8tYoIjMIAKiTm9o6psPlc8CrLI9CH0UbuaA2JCOM
cCNq8SyYbTqgnWlB9ZfcAm/cFpA8tYci9m5vYK8HNxQr+8FS3Qo8N9RJ8d0U5Csw
DzMYfRghAfUGwmlWj5hp1pQzAuhwbOXFtxKHVsMPhz1IBtF9Y8jvgqgYHLbmyiu1
mwJ5AL0pYF0G7x81prlARURwHo0Yf52kEw1dxpx+JXER7hQRWQki5/NsUEtv+8RT
qn2m6qte5DXLyn83b1qRscSdnCCwKtKWUug5q2ZbwVOCJCtmRwmnP131lWRYfj67
B/xJ1ZA6X3GEf4sNReNAtaucPEelgR2nsN0gKQKBiGoqHWbK1qYvBxX2X3kbPDkv
9C+celgZd2PW7aGYLCHq7nPbmfDV0yHcWjOhXZ8jRMjmANVR/eLQ2EfsRLdW69bn
f3ZD7JS1fwGnO3exGmHO3HZG+6AvberKYVYNHahNFEw5TsAcQWDLRpkGybBcxqZo
81YCqlqidwfeO5YtlO7etx1xLyqa2NsCeG9A86UjG+aeNnXEIDk1PDK+EuiThIUa
/2IxKzJKWl1BKr2d4xAfR0ZnEYuRrbeDQYgTImOlfW6/GuYIxKYgEKCFHFqJATAG
IxHrq1PDOiSwXd2GmVVYyEmhZnbcp8CxaEMQoevxAta0ssMK3w6UsDtvUvYvF22m
qQKBiD5GwESzsFPy3Ga0MvZpn3D6EJQLgsnrtUPZx+z2Ep2x0xc5orneB5fGyF1P
WtP+fG5Q6Dpdz3LRfm+KwBCWFKQjg7uTxcjerhBWEYPmEMKYwTJF5PBG9/ddvHLQ
EQeNC8fHGg4UXU8mhHnSBt3EA10qQJfRDs15M38eG2cYwB1PZpDHScDnDA0=
-----END RSA PRIVATE KEY-----
"""

rsaTestKeyPssPublic = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr4tmm3r20Wd/PbqvP1s2
+QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry53mm+
oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7OyrFAHq
gDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUAAN5W
Utzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw9lq4
aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oyc6XI
2wIDAQAB
-----END PUBLIC KEY-----
"""

rsaTestKeyPssPrivate = """-----BEGIN RSA PRIVATE KEY-----
MIIEvgIBADALBgkqhkiG9w0BAQoEggSqMIIEpgIBAAKCAQEAr4tmm3r20Wd/Pbqv
P1s2+QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry5
3mm+oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7Oyr
FAHqgDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUA
AN5WUtzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw
9lq4aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oy
c6XI2wIDAQABAoIBAQCUB8ip+kJiiZVKF8AqfB/aUP0jTAqOQewK1kKJ/iQCXBCq
pbo360gvdt05H5VZ/RDVkEgO2k73VSsbulqezKs8RFs2tEmU+JgTI9MeQJPWcP6X
aKy6LIYs0E2cWgp8GADgoBs8llBq0UhX0KffglIeek3n7Z6Gt4YFge2TAcW2WbN4
XfK7lupFyo6HHyWRiYHMMARQXLJeOSdTn5aMBP0PO4bQyk5ORxTUSeOciPJUFktQ
HkvGbym7KryEfwH8Tks0L7WhzyP60PL3xS9FNOJi9m+zztwYIXGDQuKM2GDsITeD
2mI2oHoPMyAD0wdI7BwSVW18p1h+jgfc4dlexKYRAoGBAOVfuiEiOchGghV5vn5N
RDNscAFnpHj1QgMr6/UG05RTgmcLfVsI1I4bSkbrIuVKviGGf7atlkROALOG/xRx
DLadgBEeNyHL5lz6ihQaFJLVQ0u3U4SB67J0YtVO3R6lXcIjBDHuY8SjYJ7Ci6Z6
vuDcoaEujnlrtUhaMxvSfcUJAoGBAMPsCHXte1uWNAqYad2WdLjPDlKtQJK1diCm
rqmB2g8QE99hDOHItjDBEdpyFBKOIP+NpVtM2KLhRajjcL9Ph8jrID6XUqikQuVi
4J9FV2m42jXMuioTT13idAILanYg8D3idvy/3isDVkON0X3UAVKrgMEne0hJpkPL
FYqgetvDAoGBAKLQ6JZMbSe0pPIJkSamQhsehgL5Rs51iX4m1z7+sYFAJfhvN3Q/
OGIHDRp6HjMUcxHpHw7U+S1TETxePwKLnLKj6hw8jnX2/nZRgWHzgVcY+sPsReRx
NJVf+Cfh6yOtznfX00p+JWOXdSY8glSSHJwRAMog+hFGW1AYdt7w80XBAoGBAImR
NUugqapgaEA8TrFxkJmngXYaAqpA0iYRA7kv3S4QavPBUGtFJHBNULzitydkNtVZ
3w6hgce0h9YThTo/nKc+OZDZbgfN9s7cQ75x0PQCAO4fx2P91Q+mDzDUVTeG30mE
t2m3S0dGe47JiJxifV9P3wNBNrZGSIF3mrORBVNDAoGBAI0QKn2Iv7Sgo4T/XjND
dl2kZTXqGAk8dOhpUiw/HdM3OGWbhHj2NdCzBliOmPyQtAr770GITWvbAI+IRYyF
S7Fnk6ZVVVHsxjtaHy1uJGFlaZzKR4AGNaUTOJMs6NadzCmGPAxNQQOCqoUjn4XR
rOjr9w349JooGXhOxbu8nOxX
-----END RSA PRIVATE KEY-----
"""

eccTestKeyPrivate = """-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFKbhfNZfpDsW43+0+JjUr9K+bTeuxopu653+hBaXGA7oAoGCCqGSM49
AwEHoUQDQgAEqIVYZVLCrPZHGHjP17CTW0/+D9Lfw0EkjqF7xB4FivAxzic30tMM
4GF+hR6Dxh71Z50VGGdldkkDXZCnTNnoXQ==
-----END EC PRIVATE KEY-----
"""

eccTestKeyPublic = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqIVYZVLCrPZHGHjP17CTW0/+D9Lf
w0EkjqF7xB4FivAxzic30tMM4GF+hR6Dxh71Z50VGGdldkkDXZCnTNnoXQ==
-----END PUBLIC KEY-----
"""

sharedSecret = """uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ=="""


ed25519TestKeyPrivate = """-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF
-----END PRIVATE KEY-----
"""

ed25519TestKeyPublic = """-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=
-----END PUBLIC KEY-----
"""

p256PubKey = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWAO+Y/BP3c7Aw7dSWYGkuckwl/e6
H54D/P9uzXDjby0Frysdpcny/NL807iRVfVDDg+ctHhuRTzBwP+lwVdN2g==
-----END PUBLIC KEY-----
"""

p256PrvKey = """-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIMLnTZwmWikcBCrKlXZVUjaq9jwsv22sy/P7yIIonkVwoAoGCCqGSM49
AwEHoUQDQgAEWAO+Y/BP3c7Aw7dSWYGkuckwl/e6H54D/P9uzXDjby0Frysdpcny
/NL807iRVfVDDg+ctHhuRTzBwP+lwVdN2g==
-----END EC PRIVATE KEY-----
"""

exampleRequestMessage = b"""POST /foo?param=Value&Pet=dog HTTP/1.1
Host: example.com
Date: Tue, 20 Apr 2021 02:07:55 GMT
Content-Type: application/json
Content-Length: 18

{"hello": "world"}"""

exampleReverseProxyClientMessage = b"""
POST /foo?param=Value&Pet=dog HTTP/1.1
Host: example.com
Date: Tue, 20 Apr 2021 02:07:55 GMT
Content-Type: application/json
Content-Length: 18

{"hello": "world"}
"""

exampleReverseProxyMessage = b"""
POST /foo?param=Value&Pet=dog HTTP/1.1
Host: origin.host.internal.example
Date: Tue, 20 Apr 2021 02:07:56 GMT
Content-Type: application/json
Content-Length: 18
Forwarded: for=192.0.2.123;host=example.com;proto=https

{"hello": "world"}
"""

exampleClientCertMessage = b"""POST /foo?param=Value&Pet=dog HTTP/1.1
Host: service.internal.example
Date: Tue, 20 Apr 2021 02:07:55 GMT
Content-Type: application/json
Content-Length: 18
Client-Cert: :MIIBqDCCAU6gAwIBAgIBBzAKBggqhkjOPQQDAjA6MRswGQYDVQQKDBJMZXQncyBBdXRoZW50aWNhdGUxGzAZBgNVBAMMEkxBIEludGVybWVkaWF0ZSBDQTAeFw0yMDAxMTQyMjU1MzNaFw0yMTAxMjMyMjU1MzNaMA0xCzAJBgNVBAMMAkJDMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8YnXXfaUgmnMtOXU/IncWalRhebrXmckC8vdgJ1p5Be5F/3YC8OthxM4+k1M6aEAEFcGzkJiNy6J84y7uzo9M6NyMHAwCQYDVR0TBAIwADAfBgNVHSMEGDAWgBRm3WjLa38lbEYCuiCPct0ZaSED2DAOBgNVHQ8BAf8EBAMCBsAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwHQYDVR0RAQH/BBMwEYEPYmRjQGV4YW1wbGUuY29tMAoGCCqGSM49BAMCA0gAMEUCIBHda/r1vaL6G3VliL4/Di6YK0Q6bMjeSkC3dFCOOB8TAiEAx/kHSB4urmiZ0NX5r5XarmPk0wmuydBVoU4hBVZ1yhk=:

{"hello": "world"}
"""

exampleResponseMessage = b"""HTTP/1.1 200 OK
Date: Tue, 20 Apr 2021 02:07:56 GMT
Content-Type: application/json
Content-Length: 23

{"message": "good dog"}"""

exampleRequestRequestMessage = b"""
POST /foo?param=Value&Pet=dog HTTP/1.1
Host: example.com
Date: Tue, 20 Apr 2021 02:07:55 GMT
Content-Type: application/json
Content-Length: 18

{"hello": "world"}
"""

exampleRequestResponseMessage = b"""HTTP/1.1 503 Service Unavailable
Date: Tue, 20 Apr 2021 02:07:56 GMT
Content-Type: application/json
Content-Length: 62

{"busy": true, "message": "Your call is very important to us"}
"""

exampleGetRequest1 = b"""GET /demo?name1=Value1&Name2=value2 HTTP/1.1
Host: example.org
Date: Fri, 15 Jul 2022 14:24:55 GMT
Accept: application/json
Accept: */*
"""

exampleGetRequest2 = b"""GET /demo?name1=Value1&Name2=value2&param=added HTTP/1.1
Host: example.org
Date: Fri, 15 Jul 2022 14:24:55 GMT
Accept: application/json
Accept: */*
Accept-Language: en-US,en;q=0.5
"""

exampleGetRequest3 = b"""GET /demo?name1=Value1&Name2=value2 HTTP/1.1
Host: example.org
Referer: https://developer.example.org/demo
Accept: application/json, */*
"""

exampleGetRequest4 = b"""GET /demo?name1=Value1&Name2=value2 HTTP/1.1
Accept: application/json
Accept: */*
Date: Fri, 15 Jul 2022 14:24:55 GMT
Host: example.org
"""

exampleGetRequest_bad1 = b"""POST /demo?name1=Value1&Name2=value2 HTTP/1.1
Host: example.com
Date: Fri, 15 Jul 2022 14:24:55 GMT
Accept: application/json
Accept: */*
"""

exampleGetRequest_bad2 = b"""GET /demo?name1=Value1&Name2=value2 HTTP/1.1
Host: example.org
Date: Fri, 15 Jul 2022 14:24:55 GMT
Accept: */*
Accept: application/json
"""

exampleTrailer = b"""HTTP/1.1 200 OK
Content-Type: text/plain
Transfer-Encoding: chunked
Trailer: Expires

4
HTTP
7
Message
10
Signatures
0
Expires: Wed, 9 Nov 2022 07:28:00 GMT
"""

if 'example' in args.target:
    print(colored('*' * 30, 'blue'))
    print(colored('*', 'blue') + ' Example Messages')
    print(colored('*' * 30, 'blue'))

    print()
    print(hardwrap(exampleRequestMessage.decode()))
    print()

    components = parse_components(exampleRequestMessage)
    components = add_content_digest(components)
    cd = next((x for x in components['fields'] if x['id'] == "content-digest"), None)

    print()
    print(str(cd['val']))
    print()
    print(hardwrap(str(cd['val'])))
    print()
    print(hardwrap('Content-Digest: ' + str(cd['val'])))
    print()


    print(hardwrap(exampleResponseMessage.decode()))
    print()
    components = parse_components(exampleResponseMessage)
    components = add_content_digest(components)
    cd = next((x for x in components['fields'] if x['id'] == "content-digest"), None)

    print()
    print(str(cd['val']))
    print()
    print(hardwrap(str(cd['val'])))
    print()
    print(hardwrap('Content-Digest: ' + str(cd['val'])))
    print()



if 'rsapss' in args.target:
    ## Base example pieces

    print(colored('*' * 30, 'blue'))
    print(colored('*', 'blue') + ' Covered Content RSAPSS Test')
    print(colored('*' * 30, 'blue'))


    components = parse_components(exampleRequestMessage)

    components = add_content_digest(components)
    cd = next((x for x in components['fields'] if x['id'] == "content-digest"), None)

    print("Content Digest:")
    print()
    print(str(cd['val']))
    print()
    print(hardwrap(str(cd['val'])))
    print()
    print(hardwrap('Content-Digest: ' + str(cd['val'])))
    print()

    siginput = generate_base(
        components, 
        ( # covered components list
            { 'id': "@method" }, 
            { 'id': "@authority" },
            { 'id': "@path" },
            { 'id': "content-digest" },
            { 'id': "content-length" },
            { 'id': "content-type" }
        ),
        {
            'created': 1618884473,
            'keyid': 'test-key-rsa-pss'
        }
    )

    base = siginput['signatureInput']
    sigparams = siginput['signatureParams']

    print("Base string:")
    print()
    print(base)
    print()
    print(hardwrap(base))
    print()
    print(softwrap(base))
    print()
    print(softwrap('Signature-Input: sig1=' + str(sigparams)))
    print()

    key = RSA.import_key(PKCS8.unwrap(PEM.decode(rsaTestKeyPssPrivate)[0])[1])

    h = SHA512.new(base.encode('utf-8'))
    signer = pss.new(key, mask_func=mgf512, salt_bytes=64)

    signed = http_sfv.Item(signer.sign(h))

    print("Signed:")
    print()
    print(signed)
    print()
    print(hardwrap(str(signed).strip(':'), 0))
    print()
    print(hardwrap('Signature: sig1=' + str(signed)))
    print()

    # publicKey = M2Crypto.RSA.load_key_string(rsaTestKeyPssPublic)

    pubKey = RSA.import_key(rsaTestKeyPssPublic)
    verifier = pss.new(pubKey, mask_func=mgf512, salt_bytes=64)

    try:
        verified = verifier.verify(h, signed.value)
        print("Verified:")
        print(colored('> YES!', 'green'))
        results['Covered Content RSAPSS Test'] = 'YES'
        print()
    except (ValueError, TypeError):
        print("Verified:")
        print(colored('> NO!', 'red'))
        results['Covered Content RSAPSS Test'] = 'NO'
        print()


if 'httpsigorgreq' in args.target:
    ## Base example pieces

    print(colored('*' * 30, 'blue'))
    print(colored('*', 'blue') + ' Covered Content RSAPSS Test')
    print(colored('*' * 30, 'blue'))


    msg = b"""POST /foo?param=value&pet=dog HTTP/1.1
Host: example.com
Date: Tue, 20 Apr 2021 02:07:55 GMT
Content-Type: application/json
Content-Length: 18

{"hello": "world"}"""

    components = parse_components(msg)

    components = add_content_digest(components)
    cd = next((x for x in components['fields'] if x['id'] == "content-digest"), None)

    print("Content Digest:")
    print()
    print(str(cd['val']))
    print()
    print(hardwrap(str(cd['val'])))
    print()
    print(hardwrap('Content-Digest: ' + str(cd['val'])))
    print()

    siginput = generate_base(
        components, 
        ( # covered components list
            { 'id': "@method" }, 
            { 'id': "@authority" },
            { 'id': "@path" },
            { 'id': "@query" },
            { 'id': "content-digest" },
            { 'id': "content-length" },
            { 'id': "content-type" }
        ),
        {
            'alg': 'rsa-pss-sha512',
            'created': 1618884473,
            'keyid': 'RSA (X.509 preloaded)'
        }
    )

    base = siginput['signatureInput']
    sigparams = siginput['signatureParams']

    print("Base string:")
    print()
    print(base)
    print()
    print(hardwrap(base))
    print()
    print(softwrap(base))
    print()
    print(softwrap('Signature-Input: sig=' + str(sigparams)))
    print()

    rawKey = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADALBgkqhkiG9w0BAQoEggSqMIIEpgIBAAKCAQEAr4tmm3r20Wd/Pbqv
P1s2+QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry5
3mm+oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7Oyr
FAHqgDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUA
AN5WUtzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw
9lq4aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oy
c6XI2wIDAQABAoIBAQCUB8ip+kJiiZVKF8AqfB/aUP0jTAqOQewK1kKJ/iQCXBCq
pbo360gvdt05H5VZ/RDVkEgO2k73VSsbulqezKs8RFs2tEmU+JgTI9MeQJPWcP6X
aKy6LIYs0E2cWgp8GADgoBs8llBq0UhX0KffglIeek3n7Z6Gt4YFge2TAcW2WbN4
XfK7lupFyo6HHyWRiYHMMARQXLJeOSdTn5aMBP0PO4bQyk5ORxTUSeOciPJUFktQ
HkvGbym7KryEfwH8Tks0L7WhzyP60PL3xS9FNOJi9m+zztwYIXGDQuKM2GDsITeD
2mI2oHoPMyAD0wdI7BwSVW18p1h+jgfc4dlexKYRAoGBAOVfuiEiOchGghV5vn5N
RDNscAFnpHj1QgMr6/UG05RTgmcLfVsI1I4bSkbrIuVKviGGf7atlkROALOG/xRx
DLadgBEeNyHL5lz6ihQaFJLVQ0u3U4SB67J0YtVO3R6lXcIjBDHuY8SjYJ7Ci6Z6
vuDcoaEujnlrtUhaMxvSfcUJAoGBAMPsCHXte1uWNAqYad2WdLjPDlKtQJK1diCm
rqmB2g8QE99hDOHItjDBEdpyFBKOIP+NpVtM2KLhRajjcL9Ph8jrID6XUqikQuVi
4J9FV2m42jXMuioTT13idAILanYg8D3idvy/3isDVkON0X3UAVKrgMEne0hJpkPL
FYqgetvDAoGBAKLQ6JZMbSe0pPIJkSamQhsehgL5Rs51iX4m1z7+sYFAJfhvN3Q/
OGIHDRp6HjMUcxHpHw7U+S1TETxePwKLnLKj6hw8jnX2/nZRgWHzgVcY+sPsReRx
NJVf+Cfh6yOtznfX00p+JWOXdSY8glSSHJwRAMog+hFGW1AYdt7w80XBAoGBAImR
NUugqapgaEA8TrFxkJmngXYaAqpA0iYRA7kv3S4QavPBUGtFJHBNULzitydkNtVZ
3w6hgce0h9YThTo/nKc+OZDZbgfN9s7cQ75x0PQCAO4fx2P91Q+mDzDUVTeG30mE
t2m3S0dGe47JiJxifV9P3wNBNrZGSIF3mrORBVNDAoGBAI0QKn2Iv7Sgo4T/XjND
dl2kZTXqGAk8dOhpUiw/HdM3OGWbhHj2NdCzBliOmPyQtAr770GITWvbAI+IRYyF
S7Fnk6ZVVVHsxjtaHy1uJGFlaZzKR4AGNaUTOJMs6NadzCmGPAxNQQOCqoUjn4XR
rOjr9w349JooGXhOxbu8nOxX
-----END PRIVATE KEY-----
"""

    key = RSA.import_key(PKCS8.unwrap(PEM.decode(rawKey)[0])[1])

    h = SHA512.new(base.encode('utf-8'))
    signer = pss.new(key, mask_func=mgf512, salt_bytes=64)

    signed = http_sfv.Item(signer.sign(h))

    print("Signed:")
    print()
    print(signed)
    print()
    print(hardwrap(str(signed).strip(':'), 0))
    print()
    print(hardwrap('Signature: sig=' + str(signed)))
    print()

    rawPubKey = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr4tmm3r20Wd/PbqvP1s2
+QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry53mm+
oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7OyrFAHq
gDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUAAN5W
Utzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw9lq4
aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oyc6XI
2wIDAQAB
-----END PUBLIC KEY-----
"""

    pubKey = RSA.import_key(rawPubKey)
    verifier = pss.new(pubKey, mask_func=mgf512, salt_bytes=64)

    try:
        verified = verifier.verify(h, signed.value)
        print("Verified:")
        print(colored('> YES!', 'green'))
        results['httpsig.org signed req'] = 'YES'
        print()
    except (ValueError, TypeError):
        print("Verified:")
        print(colored('> NO!', 'red'))
        results['httpsig.org signed req'] = 'NO'
        print()

if 'httpsigorgres' in args.target:
    ## Base example pieces

    print(colored('*' * 30, 'blue'))
    print(colored('*', 'blue') + ' Covered Content RSAPSS Test')
    print(colored('*' * 30, 'blue'))


    msg = b"""HTTP/1.1 200 OK
Date: Tue, 20 Apr 2021 02:07:56 GMT
Content-Type: application/json
Content-Length: 18

{"hello": "world"}"""

    components = parse_components(msg)

    components = add_content_digest(components)
    cd = next((x for x in components['fields'] if x['id'] == "content-digest"), None)

    print("Content Digest:")
    print()
    print(str(cd['val']))
    print()
    print(hardwrap(str(cd['val'])))
    print()
    print(hardwrap('Content-Digest: ' + str(cd['val'])))
    print()

    siginput = generate_base(
        components, 
        ( # covered components list
            { 'id': "@status" },
            { 'id': "content-digest" },
            { 'id': "content-length" },
            { 'id': "content-type" }
        ),
        {
            'alg': 'rsa-pss-sha512',
            'created': 1618884473,
            'keyid': 'RSA (X.509 preloaded)'
        }
    )

    base = siginput['signatureInput']
    sigparams = siginput['signatureParams']

    print("Base string:")
    print()
    print(base)
    print()
    print(hardwrap(base))
    print()
    print(softwrap(base))
    print()
    print(softwrap('Signature-Input: sig=' + str(sigparams)))
    print()

    rawKey = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADALBgkqhkiG9w0BAQoEggSqMIIEpgIBAAKCAQEAr4tmm3r20Wd/Pbqv
P1s2+QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry5
3mm+oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7Oyr
FAHqgDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUA
AN5WUtzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw
9lq4aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oy
c6XI2wIDAQABAoIBAQCUB8ip+kJiiZVKF8AqfB/aUP0jTAqOQewK1kKJ/iQCXBCq
pbo360gvdt05H5VZ/RDVkEgO2k73VSsbulqezKs8RFs2tEmU+JgTI9MeQJPWcP6X
aKy6LIYs0E2cWgp8GADgoBs8llBq0UhX0KffglIeek3n7Z6Gt4YFge2TAcW2WbN4
XfK7lupFyo6HHyWRiYHMMARQXLJeOSdTn5aMBP0PO4bQyk5ORxTUSeOciPJUFktQ
HkvGbym7KryEfwH8Tks0L7WhzyP60PL3xS9FNOJi9m+zztwYIXGDQuKM2GDsITeD
2mI2oHoPMyAD0wdI7BwSVW18p1h+jgfc4dlexKYRAoGBAOVfuiEiOchGghV5vn5N
RDNscAFnpHj1QgMr6/UG05RTgmcLfVsI1I4bSkbrIuVKviGGf7atlkROALOG/xRx
DLadgBEeNyHL5lz6ihQaFJLVQ0u3U4SB67J0YtVO3R6lXcIjBDHuY8SjYJ7Ci6Z6
vuDcoaEujnlrtUhaMxvSfcUJAoGBAMPsCHXte1uWNAqYad2WdLjPDlKtQJK1diCm
rqmB2g8QE99hDOHItjDBEdpyFBKOIP+NpVtM2KLhRajjcL9Ph8jrID6XUqikQuVi
4J9FV2m42jXMuioTT13idAILanYg8D3idvy/3isDVkON0X3UAVKrgMEne0hJpkPL
FYqgetvDAoGBAKLQ6JZMbSe0pPIJkSamQhsehgL5Rs51iX4m1z7+sYFAJfhvN3Q/
OGIHDRp6HjMUcxHpHw7U+S1TETxePwKLnLKj6hw8jnX2/nZRgWHzgVcY+sPsReRx
NJVf+Cfh6yOtznfX00p+JWOXdSY8glSSHJwRAMog+hFGW1AYdt7w80XBAoGBAImR
NUugqapgaEA8TrFxkJmngXYaAqpA0iYRA7kv3S4QavPBUGtFJHBNULzitydkNtVZ
3w6hgce0h9YThTo/nKc+OZDZbgfN9s7cQ75x0PQCAO4fx2P91Q+mDzDUVTeG30mE
t2m3S0dGe47JiJxifV9P3wNBNrZGSIF3mrORBVNDAoGBAI0QKn2Iv7Sgo4T/XjND
dl2kZTXqGAk8dOhpUiw/HdM3OGWbhHj2NdCzBliOmPyQtAr770GITWvbAI+IRYyF
S7Fnk6ZVVVHsxjtaHy1uJGFlaZzKR4AGNaUTOJMs6NadzCmGPAxNQQOCqoUjn4XR
rOjr9w349JooGXhOxbu8nOxX
-----END PRIVATE KEY-----
"""

    key = RSA.import_key(PKCS8.unwrap(PEM.decode(rawKey)[0])[1])

    h = SHA512.new(base.encode('utf-8'))
    signer = pss.new(key, mask_func=mgf512, salt_bytes=64)

    signed = http_sfv.Item(signer.sign(h))

    print("Signed:")
    print()
    print(signed)
    print()
    print(hardwrap(str(signed).strip(':'), 0))
    print()
    print(hardwrap('Signature: sig=' + str(signed)))
    print()

    rawPubKey = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr4tmm3r20Wd/PbqvP1s2
+QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry53mm+
oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7OyrFAHq
gDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUAAN5W
Utzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw9lq4
aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oyc6XI
2wIDAQAB
-----END PUBLIC KEY-----
"""

    pubKey = RSA.import_key(rawPubKey)
    verifier = pss.new(pubKey, mask_func=mgf512, salt_bytes=64)

    try:
        verified = verifier.verify(h, signed.value)
        print("Verified:")
        print(colored('> YES!', 'green'))
        results['httpsig.org signed req'] = 'YES'
        print()
    except (ValueError, TypeError):
        print("Verified:")
        print(colored('> NO!', 'red'))
        results['httpsig.org signed req'] = 'NO'
        print()



if 'revproxy' in args.target:
    print(colored('*' * 30, 'blue'))

    ## reverse proxy signature
    print(colored('*', 'blue') + ' Reverse Proxy Signature ')
    print(colored('*' * 30, 'blue'))

    # Plain message
    components = parse_components(exampleReverseProxyClientMessage)

    # Add content digest
    components = add_content_digest(components)
    cd = next((x for x in components['fields'] if x['id'] == "content-digest"), None)

    print('Content Digest:')
    print()
    print(str(cd['val']))
    print()
    print(hardwrap(str(cd['val'])))
    print()
    print(hardwrap('Content-Digest: ' + str(cd['val'])))
    print()

    # Add Signature

    siginput = generate_base(
        components, 
        ( # covered components list
            { 'id': "@method" },
            { 'id': '@authority' },
            { 'id': "@path" }, 
            { 'id': "content-digest" },
            { 'id': "content-type" },
            { 'id': "content-length" }
        ),
        {
            'created': 1618884475,
            'keyid': 'test-key-ecc-p256'
        }
    )

    base = siginput['signatureInput']
    sigparams = siginput['signatureParams']

    print("Client Base string:")
    print()
    print(base)
    print()
    print(hardwrap(base))
    print()
    print(softwrap(base))
    print()
    print(softwrap(exampleReverseProxyClientMessage.decode()))
    print()
    print(hardwrap(exampleReverseProxyClientMessage.decode()))
    print()
    print(softwrap('Signature-Input: sig1=' + str(sigparams)))
    print()

    key = ECC.import_key(eccTestKeyPrivate)

    h = SHA256.new(base.encode('utf-8'))
    signer = DSS.new(key, 'fips-186-3')

    signed = http_sfv.Item(signer.sign(h))

    print("Client Signed:")
    print()
    print(signed)
    print()
    print(hardwrap(str(signed).strip(':'), 0))
    print()
    print(hardwrap('Signature: sig1=' + str(signed)))
    print()


    pubKey = ECC.import_key(eccTestKeyPublic)
    verifier = DSS.new(pubKey, 'fips-186-3')

    try:
        verified = verifier.verify(h, signed.value)
        print("Verified:")
        print(colored('> YES!', 'green'))
        results['Client Proxy'] = 'YES'
        print()
    except (ValueError, TypeError):
        print("Verified:")
        print(colored('> NO!', 'red'))
        results['Client Proxy'] = 'NO'
        print()


    components = parse_components(exampleReverseProxyMessage)
    components = add_content_digest(components)

    # Add client signature
    sigfield = http_sfv.Dictionary()
    sigfield['sig1'] = signed

    cid = http_sfv.Item('Signature'.lower())
    components['fields'].append(
        {
            'id': cid.value,
            'cid': str(cid),
            'val': str(sigfield)
        }
    )
    cid = http_sfv.Item('Signature'.lower())
    cid.params['key'] = 'sig1'
    components['fields'].append(
        {
            'id': cid.value,
            'cid': str(cid),
            'key': 'sig1',
            'val': str(signed)
        }
    )

    siginputfield = http_sfv.Dictionary()
    sigin = http_sfv.InnerList()
    sigin.parse(sigparams.encode('utf-8')) # we have to re-parse because we're handed the string not the Item
    siginputfield['sig1'] = sigin

    cid = http_sfv.Item('Signature-Input'.lower())
    components['fields'].append(
        {
            'id': cid.value,
            'cid': str(cid),
            'val': str(siginputfield)
        }
    )
    cid = http_sfv.Item('Signature-Input'.lower())
    cid.params['key'] = 'sig1'
    components['fields'].append(
        {
            'id': cid.value,
            'cid': str(cid),
            'key': 'sig1',
            'val': str(sigin)
        }
    )

    siginput = generate_base(
        components, 
        ( # covered components list
            { 'id': "@method" },
            { 'id': '@authority' },
            { 'id': "@path" }, 
            { 'id': "content-digest" },
            { 'id': "content-type" },
            { 'id': "content-length" },
            { 'id': "forwarded" }
        ),
        {
            'created': 1618884480,
            'keyid': 'test-key-rsa',
            'alg': 'rsa-v1_5-sha256',
            'expires': 1618884540
        }
    )

    base = siginput['signatureInput']
    sigparams = siginput['signatureParams']

    print("Proxy Base string:")
    print()
    print(base)
    print()
    print(hardwrap(base))
    print()
    print(softwrap(base))
    print()
    print(softwrap(exampleReverseProxyMessage.decode()))
    print()
    print(softwrap(exampleReverseProxyMessage.decode(), 4))
    print()
    print(hardwrap(exampleReverseProxyMessage.decode()))
    print()
    print(hardwrap(exampleReverseProxyMessage.decode(), 4))
    print()
    print(', \\')
    print(softwrap('  proxy_sig=' + str(sigparams), 4))
    print()

    key = RSA.import_key(rsaTestKeyPrivate)

    h = SHA256.new(base.encode('utf-8'))
    signer = pkcs1_15.new(key)

    signed = http_sfv.Item(signer.sign(h))

    print("Proxy Signed:")
    print()
    print(signed)
    print()
    print(hardwrap(str(signed).strip(':'), 0))
    print()
    print(', \\')
    print(hardwrap('  proxy_sig=' + str(signed), 4))
    print()

    pubKey = RSA.import_key(rsaTestKeyPublic)
    verifier = pkcs1_15.new(pubKey)

    try:
        verified = verifier.verify(h, signed.value)
        print("Verified:")
        print(colored('> YES!', 'green'))
        results['Reverse Proxy'] = 'YES'
        print()
    except (ValueError, TypeError):
        print("Verified:")
        print(colored('> NO!', 'red'))
        results['Reverse Proxy'] = 'NO'
        print()


if 'gnap' in args.target:
    print(colored('*' * 30, 'blue'))

    ## reverse proxy signature
    print(colored('*', 'blue') + ' GNAP Rotation ')
    print(colored('*' * 30, 'blue'))

    # Plain message
    msg = b"""POST /token/PRY5NM33 HTTP/1.1
Host: server.example.com
Authorization: GNAP 4398.34-12-asvDa.a
Content-Type: application/json
Content-Length: 251

{
    "key": {
        "proof": "httpsig",
        "jwk": {
            "kty": "RSA",
            "e": "AQAB",
            "kid": "xyz-2",
            "alg": "RS256",
            "n": "kOB5rR4Jv0GMeLaY6_It_r3ORwdf8ci_JtffXyaSx8xY..."
        }
    }
}
"""
    components = parse_components(msg)

    # Add content digest
    components = add_content_digest(components)
    cd = next((x for x in components['fields'] if x['id'] == "content-digest"), None)

    print('Content Digest:')
    print()
    print(str(cd['val']))
    print()
    print(hardwrap(str(cd['val'])))
    print()
    print(hardwrap('Content-Digest: ' + str(cd['val'])))
    print()

    # Add Signature

    siginput = generate_base(
        components, 
        ( # covered components list
            { 'id': "@method" },
            { 'id': '@target-uri' },
            { 'id': "content-digest" },
            { 'id': "authorization" }
        ),
        {
            'created': 1618884475,
            'keyid': 'test-key-ecc-p256',
            'tag': 'gnap'
        }
    )

    base = siginput['signatureInput']
    sigparams = siginput['signatureParams']

    print("Old Key Base string:")
    print()
    print(base)
    print()
    print(hardwrap(base))
    print()
    print(softwrap(base))
    print()
    print(softwrap(msg.decode()))
    print()
    print(hardwrap(msg.decode()))
    print()
    print(softwrap('Signature-Input: old-key=' + str(sigparams)))
    print()

    key = ECC.import_key(eccTestKeyPrivate)

    h = SHA256.new(base.encode('utf-8'))
    signer = DSS.new(key, 'fips-186-3')

    signed = http_sfv.Item(signer.sign(h))

    print("Client Signed:")
    print()
    print(signed)
    print()
    print(hardwrap(str(signed).strip(':'), 0))
    print()
    print(hardwrap('Signature: old-key=' + str(signed)))
    print()


    pubKey = ECC.import_key(eccTestKeyPublic)
    verifier = DSS.new(pubKey, 'fips-186-3')

    try:
        verified = verifier.verify(h, signed.value)
        print("Verified:")
        print(colored('> YES!', 'green'))
        results['GNAP Old'] = 'YES'
        print()
    except (ValueError, TypeError):
        print("Verified:")
        print(colored('> NO!', 'red'))
        results['GNAP Old'] = 'NO'
        print()


    # Add first signature
    sigfield = http_sfv.Dictionary()
    sigfield['old-key'] = signed

    cid = http_sfv.Item('Signature'.lower())
    components['fields'].append(
        {
            'id': cid.value,
            'cid': str(cid),
            'val': str(sigfield)
        }
    )
    cid = http_sfv.Item('Signature'.lower())
    cid.params['key'] = 'old-key'
    components['fields'].append(
        {
            'id': cid.value,
            'cid': str(cid),
            'key': 'old-key',
            'val': str(signed)
        }
    )

    siginputfield = http_sfv.Dictionary()
    sigin = http_sfv.InnerList()
    sigin.parse(sigparams.encode('utf-8')) # we have to re-parse because we're handed the string not the Item
    siginputfield['old-key'] = sigin

    cid = http_sfv.Item('Signature-Input'.lower())
    components['fields'].append(
        {
            'id': cid.value,
            'cid': str(cid),
            'val': str(siginputfield)
        }
    )
    cid = http_sfv.Item('Signature-Input'.lower())
    cid.params['key'] = 'old-key'
    components['fields'].append(
        {
            'id': cid.value,
            'cid': str(cid),
            'key': 'old-key',
            'val': str(sigin)
        }
    )

    siginput = generate_base(
        components, 
        ( # covered components list
            { 'id': "@method" },
            { 'id': '@target-uri' },
            { 'id': "content-digest" },
            { 'id': "authorization" },
            { 'id': "signature", 'key': 'old-key'},
            { 'id': "signature-input", 'key': 'old-key'}
        ),
        {
            'created': 1618884480,
            'keyid': 'xyz-2',
            'tag': 'gnap-rotate'
        }
    )

    base = siginput['signatureInput']
    sigparams = siginput['signatureParams']

    print("Proxy Base string:")
    print()
    print(base)
    print()
    print(hardwrap(base))
    print()
    print(softwrap(base))
    print()
    print(', \\')
    print(softwrap('  new-key=' + str(sigparams), 4))
    print()

    key = RSA.import_key(rsaTestKeyPrivate)

    h = SHA256.new(base.encode('utf-8'))
    signer = pkcs1_15.new(key)

    signed = http_sfv.Item(signer.sign(h))

    print("Proxy Signed:")
    print()
    print(signed)
    print()
    print(hardwrap(str(signed).strip(':'), 0))
    print()
    print(', \\')
    print(hardwrap('  new-key=' + str(signed), 4))
    print()

    pubKey = RSA.import_key(rsaTestKeyPublic)
    verifier = pkcs1_15.new(pubKey)

    try:
        verified = verifier.verify(h, signed.value)
        print("Verified:")
        print(colored('> YES!', 'green'))
        results['GNAP New'] = 'YES'
        print()
    except (ValueError, TypeError):
        print("Verified:")
        print(colored('> NO!', 'red'))
        results['GNAP New'] = 'NO'
        print()


if 'ttrp' in args.target:
    print(colored('*' * 30, 'blue'))

    ## TLS reverse proxy signature
    print(colored('*', 'blue') + ' TLS Reverse Proxy Signature ')
    print(colored('*' * 30, 'blue'))

    # message with client cert header
    components = parse_components(exampleClientCertMessage)

    siginput = generate_base(
        components, 
        ( # covered components list
            { 'id': "@path" },
            { 'id': '@query' },
            { 'id': "@method" }, 
            { 'id': "@authority" },
            { 'id': "client-cert" }
        ),
        {
            'created': 1618884473,
            'keyid': 'test-key-ecc-p256'
        }
    )

    base = siginput['signatureInput']
    sigparams = siginput['signatureParams']

    print("Base string:")
    print()
    print(base)
    print()
    print(hardwrap(base))
    print()
    print(softwrap(base))
    print()
    print(softwrap(exampleClientCertMessage.decode()))
    print()
    print(hardwrap(exampleClientCertMessage.decode()))
    print()
    print(softwrap('Signature-Input: ttrp=' + str(sigparams)))
    print()

    key = ECC.import_key(eccTestKeyPrivate)

    h = SHA256.new(base.encode('utf-8'))
    signer = DSS.new(key, 'fips-186-3')

    signed = http_sfv.Item(signer.sign(h))

    print("Signed:")
    print()
    print(signed)
    print()
    print(hardwrap(str(signed).strip(':'), 0))
    print()
    print(hardwrap('Signature: ttrp=' + str(signed)))
    print()

    pubKey = ECC.import_key(eccTestKeyPublic)
    verifier = DSS.new(pubKey, 'fips-186-3')

    try:
        verified = verifier.verify(h, signed.value)
        print("Verified:")
        print(colored('> YES!', 'green'))
        results['TTRP'] = 'YES'
        print()
    except (ValueError, TypeError):
        print("Verified:")
        print(colored('> NO!', 'red'))
        results['TTRP'] = 'NO'
        print()


if 'min' in args.target:
    print(colored('*' * 30, 'blue'))

    ## minimal signature
    print(colored('*', 'blue') + ' Minimal Coverage')
    print(colored('*' * 30, 'blue'))


    components = parse_components(exampleRequestMessage)

    siginput = generate_base(
        components, 
        ( # covered components list
        ),
        {
            'created': 1618884473,
            'keyid': 'test-key-rsa-pss',
            'nonce': 'b3k2pp5k7z-50gnwp.yemd'
        }
    )

    base = siginput['signatureInput']
    sigparams = siginput['signatureParams']

    print("Base string:")
    print()
    print(base)
    print()
    print(hardwrap(base))
    print()
    print(softwrap(base))
    print()
    print(softwrap('Signature-Input: sig-b21=' + str(sigparams)))
    print()

    key = RSA.import_key(PKCS8.unwrap(PEM.decode(rsaTestKeyPssPrivate)[0])[1])

    h = SHA512.new(base.encode('utf-8'))
    signer = pss.new(key, mask_func=mgf512, salt_bytes=64)

    signed = http_sfv.Item(signer.sign(h))

    print("Signed:")
    print(signed)
    print()
    print(hardwrap(str(signed).strip(':'), 0))
    print()
    print(hardwrap('Signature: sig-b21=' + str(signed)))

    print()

    pubKey = RSA.import_key(rsaTestKeyPssPublic)
    verifier = pss.new(pubKey, mask_func=mgf512, salt_bytes=64)

    try:
        verified = verifier.verify(h, signed.value)
        print("Verified:")
        print(colored('> YES!', 'green'))
        results['Minimal Coverage'] = 'YES'
        print()
    except (ValueError, TypeError):
        print("Verified:")
        print(colored('> NO!', 'red'))
        results['TLSMinimal Coverage'] = 'NO'
        print()

if 'header' in args.target:
    print(colored('*' * 30, 'blue'))

    ## header coverage
    print(colored('*', 'blue') + ' Header Coverage')
    print(colored('*' * 30, 'blue'))

    components = parse_components(exampleRequestMessage)

    components = add_content_digest(components)
    cd = next((x for x in components['fields'] if x['id'] == "content-digest"), None)

    print('Content Digest:')
    print()
    print(str(cd['val']))
    print()
    print(hardwrap(str(cd['val'])))
    print()
    print(hardwrap('Content-Digest: ' + str(cd['val'])))
    print()

    siginput = generate_base(
        components, 
        ( # covered components list
            { 'id': "@authority" },
            { 'id': "content-digest" },
            { 'id': "@query-param", "name": "Pet"}
        ),
        {
            'created': 1618884473,
            'keyid': 'test-key-rsa-pss',
            'tag': 'header-example'
        }
    )

    base = siginput['signatureInput']
    sigparams = siginput['signatureParams']

    print("Base string:")
    print()
    print(base)
    print()
    print(hardwrap(base))
    print()
    print(softwrap(base))
    print()
    print(softwrap('Signature-Input: sig-b22=' + str(sigparams)))
    print()

    key = RSA.import_key(PKCS8.unwrap(PEM.decode(rsaTestKeyPssPrivate)[0])[1])

    h = SHA512.new(base.encode('utf-8'))
    signer = pss.new(key, mask_func=mgf512, salt_bytes=64)

    signed = http_sfv.Item(signer.sign(h))

    print("Signed:")
    print()
    print(signed)
    print()
    print(hardwrap(str(signed).strip(':'), 0))
    print()
    print(hardwrap('Signature: sig-b22=' + str(signed)))
    print()

    pubKey = RSA.import_key(rsaTestKeyPssPublic)
    verifier = pss.new(pubKey, mask_func=mgf512, salt_bytes=64)

    try:
        verified = verifier.verify(h, signed.value)
        print("Verified:")
        print(colored('> YES!', 'green'))
        results['Header Coverage'] = 'YES'
        print()
    except (ValueError, TypeError):
        print("Verified:")
        print(colored('> NO!', 'red'))
        results['Header Coverage'] = 'NO'
        print()

if 'full' in args.target:
    print(colored('*' * 30, 'blue'))

    ## full coverage
    print(colored('*', 'blue') + ' Full Coverage')
    print(colored('*' * 30, 'blue'))

    components = parse_components(exampleRequestMessage)

    components = add_content_digest(components)
    cd = next((x for x in components['fields'] if x['id'] == "content-digest"), None)

    print('Content Digest:')
    print()
    print(str(cd['val']))
    print()
    print(hardwrap(str(cd['val'])))
    print()
    print(hardwrap('Content-Digest: ' + str(cd['val'])))
    print()

    siginput = generate_base(
        components, 
        ( # covered components list
            { 'id': "date" },
            { 'id': "@method" },
            { 'id': "@path" },
            { 'id': "@query" },
            { 'id': "@authority" },
            { 'id': "content-type" },
            { 'id': "content-digest" },
            { 'id': "content-length" }
        ),
        {
            'created': 1618884473,
            'keyid': 'test-key-rsa-pss'
        }
    )

    base = siginput['signatureInput']
    sigparams = siginput['signatureParams']

    print("Base string:")
    print()
    print(base)
    print()
    print(hardwrap(base))
    print()
    print(softwrap(base))
    print()
    print(softwrap('Signature-Input: sig-b23=' + str(sigparams)))
    print()

    key = RSA.import_key(PKCS8.unwrap(PEM.decode(rsaTestKeyPssPrivate)[0])[1])

    h = SHA512.new(base.encode('utf-8'))
    signer = pss.new(key, mask_func=mgf512, salt_bytes=64)

    signed = http_sfv.Item(signer.sign(h))

    print("Signed:")
    print(signed)
    print()
    print(hardwrap(str(signed).strip(':'), 0))
    print()
    print(hardwrap('Signature: sig-b23=' + str(signed)))
    print()

    pubKey = RSA.import_key(rsaTestKeyPssPublic)
    verifier = pss.new(pubKey, mask_func=mgf512, salt_bytes=64)

    try:
        verified = verifier.verify(h, signed.value)
        print("Verified:")
        print(colored('> YES!', 'green'))
        results['Full Coverage'] = 'YES'
        print()
    except (ValueError, TypeError):
        print("Verified:")
        print(colored('> NO!', 'red'))
        results['Full Coverage'] = 'NO'
        print()

if 'eccres' in args.target:
    print(colored('*' * 30, 'blue'))

    ## ECC
    print(colored('*', 'blue') + ' ECC Response')
    print(colored('*' * 30, 'blue'))

    components = parse_components(exampleResponseMessage)

    components = add_content_digest(components)
    cd = next((x for x in components['fields'] if x['id'] == "content-digest"), None)

    print('Content Digest:')
    print()
    print(str(cd['val']))
    print()
    print(hardwrap(str(cd['val'])))
    print()
    print(hardwrap('Content-Digest: ' + str(cd['val'])))
    print()

    siginput = generate_base(
        components, 
        ( # covered components list
            { 'id': "@status" },
            { 'id': "content-type" },
            { 'id': "content-digest" },
            { 'id': "content-length" }
        ),
        {
            'created': 1618884473,
            'keyid': 'test-key-ecc-p256'
        }
    )

    base = siginput['signatureInput']
    sigparams = siginput['signatureParams']

    print("Base string:")
    print()
    print(base)
    print()
    print(hardwrap(base))
    print()
    print(softwrap(base))
    print()
    print(softwrap('Signature-Input: sig-b24=' + str(sigparams)))
    print()

    key = ECC.import_key(eccTestKeyPrivate)

    h = SHA256.new(base.encode('utf-8'))
    signer = DSS.new(key, 'fips-186-3')

    signed = http_sfv.Item(signer.sign(h))

    print("Signed:")
    print()
    print(signed)
    print()
    print(hardwrap(str(signed).strip(':'), 0))
    print()
    print(hardwrap('Signature: sig-b24=' + str(signed)))
    print()

    pubKey = ECC.import_key(eccTestKeyPublic)
    verifier = DSS.new(pubKey, 'fips-186-3')

    try:
        verified = verifier.verify(h, signed.value)
        print("Verified:")
        print(colored('> YES!', 'green'))
        results['ECC Response'] = 'YES'
        print()
    except (ValueError, TypeError):
        print("Verified:")
        print(colored('> NO!', 'red'))
        results['ECC Response'] = 'NO'
        print()

if 'hmac' in args.target:
    print(colored('*' * 30, 'blue'))

    ## HMAC coverage
    print(colored('*', 'blue') + ' HMAC Coverage')
    print(colored('*' * 30, 'blue'))

    components = parse_components(exampleRequestMessage)

    siginput = generate_base(
        components, 
        ( # covered components list
            { 'id': "date" },
            { 'id': "@authority" },
            { 'id': "content-type" }
        ),
        {
            'created': 1618884473,
            'keyid': 'test-shared-secret'
        }
    )

    base = siginput['signatureInput']
    sigparams = siginput['signatureParams']

    print("Base string:")
    print()
    print(base)
    print()
    print(hardwrap(base))
    print()
    print(softwrap(base))
    print()
    print(softwrap('Signature-Input: sig-b25=' + str(sigparams)))
    print()

    key = base64.b64decode(sharedSecret)

    signer = HMAC.new(key, digestmod=SHA256)
    signer.update(base.encode('utf-8'))

    signed = http_sfv.Item(signer.digest())

    print("Signed:")
    print()
    print(signed)
    print()
    print(hardwrap(str(signed).strip(':'), 0))
    print()
    print(hardwrap('Signature: sig-b25=' + str(signed)))
    print()

    results['HMAC'] = 'LOL' # this is silly but ...

if 'reqres' in args.target:
    print(colored('*' * 30, 'blue'))

    ## Request-Response
    print(colored('*', 'blue') + ' Request-Response')
    print(colored('*' * 30, 'blue'))

    reqComponents = parse_components(exampleRequestRequestMessage)
    reqComponents = add_content_digest(reqComponents)
    rcd = next((x for x in reqComponents['fields'] if x['id'] == "content-digest"), None)

    print('Request Content Digest:')
    print()
    print(str(rcd['val']))
    print()
    print(hardwrap(str(rcd['val'])))
    print()
    print(hardwrap('Content-Digest: ' + str(rcd['val'])))
    print()
    # base response
    
    components = parse_components(exampleRequestResponseMessage)

    components = add_content_digest(components)
    cd = next((x for x in components['fields'] if x['id'] == "content-digest"), None)

    print('Response Content Digest:')
    print()
    print(str(cd['val']))
    print()
    print(hardwrap(str(cd['val'])))
    print()
    print(hardwrap('Content-Digest: ' + str(cd['val'])))
    print()

    siginput = generate_base(
        components, 
        ( # covered components list
            { 'id': "@status" },
            { 'id': "content-digest" },
            { 'id': "content-type" },
            { 'id': "@authority", 'req': True },
            { 'id': "@method", 'req': True },
            { 'id': "@path", 'req': True },
            { 'id': "content-digest", 'req': True}
        ),
        {
            'created': 1618884479,
            'keyid': 'test-key-ecc-p256'
        },
        reqComponents
    )

    base = siginput['signatureInput']
    sigparams = siginput['signatureParams']

    print("Base string:")
    print()
    print(base)
    print()
    print(hardwrap(base))
    print()
    print(softwrap(base))
    print()
    print(softwrap(exampleRequestRequestMessage.decode()))
    print()
    print(hardwrap(exampleRequestRequestMessage.decode()))
    print()
    print(softwrap(exampleRequestResponseMessage.decode()))
    print()
    print(hardwrap(exampleRequestResponseMessage.decode()))
    print()
    print(softwrap('Signature-Input: reqres=' + str(sigparams)))
    print()

    key = ECC.import_key(eccTestKeyPrivate)

    h = SHA256.new(base.encode('utf-8'))
    signer = DSS.new(key, 'fips-186-3')

    signed = http_sfv.Item(signer.sign(h))

    print("Signed:")
    print(signed)
    print()
    print(hardwrap(str(signed).strip(':'), 0))
    print()
    print(hardwrap('Signature: reqres=' + str(signed)))
    print()

    pubKey = ECC.import_key(eccTestKeyPublic)
    verifier = DSS.new(pubKey, 'fips-186-3')

    try:
        verified = verifier.verify(h, signed.value)
        print("Verified:")
        results['Request Response: Related-Response'] = 'YES'
        print(colored('> YES!', 'green'))
        print()
    except (ValueError, TypeError):
        print("Verified:")
        print(colored('> NO!', 'red'))
        results['Request Response: Related-Response'] = 'NO'
        print()



    # Add Signature to client message

    siginput = generate_base(
        reqComponents, 
        ( # covered components list
            { 'id': "@method" },
            { 'id': '@authority' },
            { 'id': "@path" }, 
            { 'id': "@query" },
            { 'id': "content-digest" },
            { 'id': "content-type" },
            { 'id': "content-length" }
        ),
        {
            'created': 1618884475,
            'keyid': 'test-key-rsa-pss'
        }
    )

    base = siginput['signatureInput']
    sigparams = siginput['signatureParams']

    print("Client Base string:")
    print()
    print(base)
    print()
    print(hardwrap(base))
    print()
    print(softwrap(base))
    print()
    print(softwrap(exampleRequestRequestMessage.decode()))
    print()
    print(hardwrap(exampleRequestRequestMessage.decode()))
    print()
    print(softwrap('Signature-Input: sig1=' + str(sigparams)))
    print()

    key = RSA.import_key(PKCS8.unwrap(PEM.decode(rsaTestKeyPssPrivate)[0])[1])

    h = SHA512.new(base.encode('utf-8'))
    signer = pss.new(key, mask_func=mgf512, salt_bytes=64)

    signed = http_sfv.Item(signer.sign(h))

    print("Client Signed:")
    print()
    print(signed)
    print()
    print(hardwrap(str(signed).strip(':'), 0))
    print()
    print(hardwrap('Signature: sig1=' + str(signed)))
    print()


    pubKey = RSA.import_key(rsaTestKeyPssPublic)
    verifier = pss.new(pubKey, mask_func=mgf512, salt_bytes=64)

    try:
        verified = verifier.verify(h, signed.value)
        print("Verified:")
        print(colored('> YES!', 'green'))
        results['Client Req'] = 'YES'
        print()
    except (ValueError, TypeError):
        print("Verified:")
        print(colored('> NO!', 'red'))
        results['Client Req'] = 'NO'
        print()

    # Add client signature
    sigfield = http_sfv.Dictionary()
    sigfield['sig1'] = signed

    cid = http_sfv.Item('Signature'.lower())
    reqComponents['fields'].append(
        {
            'id': cid.value,
            'cid': str(cid),
            'val': str(sigfield)
        }
    )
    cid = http_sfv.Item('Signature'.lower())
    cid.params['key'] = 'sig1'
    reqComponents['fields'].append(
        {
            'id': cid.value,
            'cid': str(cid),
            'key': 'sig1',
            'val': str(signed)
        }
    )

    siginputfield = http_sfv.Dictionary()
    sigin = http_sfv.InnerList()
    sigin.parse(sigparams.encode('utf-8')) # we have to re-parse because we're handed the string not the Item
    siginputfield['sig1'] = sigin

    cid = http_sfv.Item('Signature-Input'.lower())
    reqComponents['fields'].append(
        {
            'id': cid.value,
            'cid': str(cid),
            'val': str(siginputfield)
        }
    )
    cid = http_sfv.Item('Signature-Input'.lower())
    cid.params['key'] = 'sig1'
    reqComponents['fields'].append(
        {
            'id': cid.value,
            'cid': str(cid),
            'key': 'sig1',
            'val': str(sigin)
        }
    )


    # sign request-response
    
    siginput = generate_base(
        components, 
        ( # covered components list
            { 'id': "@status" },
            { 'id': "content-digest" },
            { 'id': "content-type" },
            { 'id': "@authority", 'req': True },
            { 'id': "@method", 'req': True },
            { 'id': "@path", 'req': True },
            { 'id': "@query", 'req': True },
            { 'id': "content-digest", 'req': True},
            { 'id': "content-type", 'req': True},
            { 'id': "content-length", 'req': True}
        ),
        {
            'created': 1618884479,
            'keyid': 'test-key-ecc-p256'
        },
        reqComponents
    )

    base = siginput['signatureInput']
    sigparams = siginput['signatureParams']

    print("Base string:")
    print()
    print(base)
    print()
    print(hardwrap(base))
    print()
    print(softwrap(base))
    print()
    print(softwrap(exampleRequestRequestMessage.decode()))
    print()
    print(hardwrap(exampleRequestRequestMessage.decode()))
    print()
    print(softwrap(exampleRequestResponseMessage.decode()))
    print()
    print(hardwrap(exampleRequestResponseMessage.decode()))
    print()
    print(softwrap('Signature-Input: reqres=' + str(sigparams)))
    print()

    key = ECC.import_key(eccTestKeyPrivate)

    h = SHA256.new(base.encode('utf-8'))
    signer = DSS.new(key, 'fips-186-3')

    signed = http_sfv.Item(signer.sign(h))

    print("Signed:")
    print(signed)
    print()
    print(hardwrap(str(signed).strip(':'), 0))
    print()
    print(hardwrap('Signature: reqres=' + str(signed)))
    print()

    pubKey = ECC.import_key(eccTestKeyPublic)
    verifier = DSS.new(pubKey, 'fips-186-3')

    try:
        verified = verifier.verify(h, signed.value)
        print("Verified:")
        results['Signed Res to Signed Req'] = 'YES'
        print(colored('> YES!', 'green'))
        print()
    except (ValueError, TypeError):
        print("Verified:")
        print(colored('> NO!', 'red'))
        results['Signed Res to Signed Req'] = 'NO'
        print()

if 'static' in args.target:
    
    print(colored('*' * 30, 'blue'))

    # Static signature test

    print('HTTPSig Static Test 1')
    print(colored('*' * 30, 'blue'))


    components = parse_components(exampleReverseProxyMessage)

    components = add_content_digest(components)
    cd = next((x for x in components['fields'] if x['id'] == "content-digest"), None)

    print('Content Digest:')
    print()
    print(str(cd['val']))
    print()
    print(hardwrap(str(cd['val'])))
    print()
    print(hardwrap('Content-Digest: ' + str(cd['val'])))
    print()

    siginput = generate_base(
        components, 
        ( # covered components list
            { 'id': "@method" },
            { 'id': "@authority" },
            { 'id': "@path" },
            { 'id': "content-digest"},
            { 'id': "content-length"},
            { 'id': "content-type"}
        ),
        {
            'created': 1618884473,
            'keyid': 'test-key-rsa-pss'
        }
    )

    base = siginput['signatureInput']
    sigparams = siginput['signatureParams']

    print("Base string:")
    print()
    print(base)
    print()
    print(hardwrap(base))
    print()
    print(softwrap(base))
    print()
    print(softwrap(exampleReverseProxyMessage.decode()))
    print()
    print(hardwrap(exampleReverseProxyMessage.decode()))
    print()
    print(softwrap('Signature-Input: reqres=' + str(sigparams)))
    print()

    h = SHA512.new(base.encode('utf-8'))

    signed = http_sfv.Item()

    signed.parse(':LAH8BjcfcOcLojiuOBFWn0P5keD3xAOuJRGziCLuD8r5MW9S0RoXXLzLSRfGY/3SF8kVIkHjE13SEFdTo4Af/fJ/Pu9wheqoLVdwXyY/UkBIS1M8Brc8IODsn5DFIrG0IrburbLi0uCc+E2ZIIb6HbUJ+o+jP58JelMTe0QE3IpWINTEzpxjqDf5/Df+InHCAkQCTuKsamjWXUpyOT1Wkxi7YPVNOjW4MfNuTZ9HdbD2Tr65+BXeTG9ZS/9SWuXAc+BZ8WyPz0QRz//ec3uWXd7bYYODSjRAxHqX+S1ag3LZElYyUKaAIjZ8MGOt4gXEwCSLDv/zqxZeWLj/PDkn6w==:'.encode('utf-8'))

    pubKey = RSA.import_key(rsaTestKeyPssPublic)
    verifier = pss.new(pubKey, mask_func=mgf512, salt_bytes=64)

    try:
        verified = verifier.verify(h, signed.value)
        print("Verified:")
        print(colored('> YES!', 'green'))
        results['Static 1'] = 'YES'
        print()
    except (ValueError, TypeError):
        print("Verified:")
        print(colored('> NO!', 'red'))
        results['Static 1'] = 'NO'
        print()


    print(colored('*' * 30, 'blue'))

    # Static signature test

    print('HTTPSig Static Test 3')
    print(colored('*' * 30, 'blue'))


    base = '''"@method": POST
    "@authority": example.com
    "@path": /foo
    "content-digest": sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:
    "content-length": 18
    "content-type": application/json
    "@signature-params": ("@method" "@authority" "@path" "content-digest" "content-length" "content-type");created=1618884473;keyid="test-key-rsa-pss"'''

    h = SHA512.new(base.encode('utf-8'))

    signed = http_sfv.Item()

    signed.parse(':LAH8BjcfcOcLojiuOBFWn0P5keD3xAOuJRGziCLuD8r5MW9S0RoXXLzLSRfGY/3SF8kVIkHjE13SEFdTo4Af/fJ/Pu9wheqoLVdwXyY/UkBIS1M8Brc8IODsn5DFIrG0IrburbLi0uCc+E2ZIIb6HbUJ+o+jP58JelMTe0QE3IpWINTEzpxjqDf5/Df+InHCAkQCTuKsamjWXUpyOT1Wkxi7YPVNOjW4MfNuTZ9HdbD2Tr65+BXeTG9ZS/9SWuXAc+BZ8WyPz0QRz//ec3uWXd7bYYODSjRAxHqX+S1ag3LZElYyUKaAIjZ8MGOt4gXEwCSLDv/zqxZeWLj/PDkn6w==:'.encode('utf-8'))

    pubKey = RSA.import_key(rsaTestKeyPssPublic)
    verifier = pss.new(pubKey, mask_func=mgf512, salt_bytes=64)

    try:
        verified = verifier.verify(h, signed.value)
        print("Verified:")
        print(colored('> YES!', 'green'))
        results['Static 3'] = 'YES'
        print()
    except (ValueError, TypeError):
        print("Verified:")
        print(colored('> NO!', 'red'))
        results['Static 3'] = 'NO'
        print()

    print(colored('*' * 30, 'blue'))

    ## ED 25519
    print('ed25519 signature')
    print(colored('*' * 30, 'blue'))

    components = parse_components(exampleRequestMessage)

    siginput = generate_base(
        components, 
        ( # covered components list
            { 'id': "date" },
            { 'id': "@method" },
            { 'id': "@path" },
            { 'id': "@authority" },
            { 'id': "content-type" },
            { 'id': "content-length" }
        ),
        {
            'created': 1618884473,
            'keyid': 'test-key-ed25519'
        }
    )

    base = siginput['signatureInput']
    sigparams = siginput['signatureParams']

    print("Base string:")
    print()
    print(base)
    print()
    print(hardwrap(base))
    print()
    print(softwrap(base))
    print()
    print(softwrap('Signature-Input: sig-b26=' + str(sigparams)))
    print()

    # Unpack private key, format is not supported by Cryptodomex PEM parser
    der = DerOctetString()
    der.decode(PKCS8.unwrap(PEM.decode(ed25519TestKeyPrivate)[0])[1])
    key = SigningKey(der.payload)

    h = base.encode('utf-8')
    signed = http_sfv.Item(key.sign(h).signature)

    print("Signed:")
    print(signed)
    print()
    print(hardwrap(str(signed).strip(':'), 0))
    print()
    print(hardwrap('Signature: sig-b26=' + str(signed)))
    print()

    # Unpack public key, format is not supported by Cryptodomex PEM parser

    # sequence of ID and BitString
    ds = DerSequence()
    ds.decode(PEM.decode(ed25519TestKeyPublic)[0])
    bs = DerBitString()
    bs.decode(ds[1])
    # the first byte of the bitstring is "0" for some reason??
    pubKey = VerifyKey(bs.payload[1:])

    try:
        verified = pubKey.verify(h, signed.value)
        print("Verified:")
        print(colored('> YES!', 'green'))
        results['Ed25519'] = 'YES'
        print()
    except (ValueError, TypeError):
        print("Verified:")
        print(colored('> NO!', 'red'))
        results['Ed25519'] = 'NO'
        print()

    print(colored('*' * 30, 'blue'))

    # Static HTTP test (ECC)
    print('HTTPSig Static Test 2')
    print(colored('*' * 30, 'blue'))


    base = '''"@authority": example.com
    "date": Tue, 20 Apr 2021 02:07:55 GMT
    "content-type": application/json
    "@signature-params": ("@authority" "date" "content-type");created=1618884475;keyid="test-key-p256"'''

    h = SHA256.new(base.encode('utf-8'))

    signed = http_sfv.Item()

    signed.parse(':qsAR/kVQiTST/oyJfHust6m1Z6qKTrAF7GKPPtRN7LyasFY3PW8t+0U9Fn9wNeXeZ7MVwZjw2LAxbh8gxT2LYg==:'.encode('utf-8'))

    pubKey = ECC.import_key(p256PubKey)
    verifier = DSS.new(pubKey, 'fips-186-3')

    try:
        verified = verifier.verify(h, signed.value)
        print("Verified:")
        print(colored('> YES!', 'green'))
        results['Static 2'] = 'YES'
        print()
    except (ValueError, TypeError):
        print("Verified:")
        print(colored('> NO!', 'red'))
        results['Static 2'] = 'NO'
        print()

if 'format' in args.target:
    print(colored('*' * 30, 'blue'))

    # Static Header formatting
    print(colored('*', 'blue') + ' Static header formatting')
    print(colored('*' * 30, 'blue'))

    msg = b"""GET / HTTP/1.1
Host: www.example.com
Date: Tue, 20 Apr 2021 02:07:56 GMT
X-OWS-Header:   Leading and trailing whitespace.
X-Obs-Fold-Header: Obsolete
    line folding.
Cache-Control: max-age=60
Cache-Control:    must-revalidate
Example-Dict:  a=1,    b=2;x=1;y=2,   c=(a   b   c)
"""

    components = parse_components(msg)

    siginput = generate_base(
        components, 
        ( # covered components list
            { 'id': "host" },
            { 'id': "date" },
            { 'id': "x-ows-header" },
            { 'id': "x-obs-fold-header" },
            { 'id': "cache-control" },
            { 'id': "example-dict" },
            { 'id': "example-dict", 'sf': True },
            { 'id': "example-dict", 'key': 'a' },
            { 'id': "example-dict", 'key': 'b' },
            { 'id': "example-dict", 'key': 'c' }
        ),
        {
        }
    )

    base = siginput['signatureInput']
    sigparams = siginput['signatureParams']

    print("Base string:")
    print()
    print(base)
    print()
    print(hardwrap(base))
    print()
    print(softwrap(base))
    print()

if 'queryparam' in args.target:
    print(colored('*' * 30, 'blue'))

    # Static Header formatting
    print(colored('*', 'blue') + ' Static header formatting')
    print(colored('*' * 30, 'blue'))

    msg = b"""GET /parameters?var=this%20is%20a%20big%0Amultiline%20value&bar=with+plus+whitespace&fa%C3%A7ade%22%3A%20=something HTTP/1.1
Host: www.example.com
Date: Tue, 20 Apr 2021 02:07:56 GMT
"""

    print("Message:")
    print()
    print(msg.decode('utf-8'))
    print()
    print(hardwrap(msg.decode('utf-8')))
    print()
    print(softwrap(msg.decode('utf-8')))
    print()

    components = parse_components(msg)
    
    #print(json.dumps(components, indent=4))

    siginput = generate_base(
        components, 
        ( # covered components list
            { 'id': "@query-param", 'name': 'var' },
            { 'id': "@query-param", 'name': 'bar' },
            { 'id': "@query-param", 'name': 'fa%C3%A7ade%22%3A%20' },
        ),
        {
        }
    )

    base = siginput['signatureInput']
    sigparams = siginput['signatureParams']

    print("Base string:")
    print()
    print(base)
    print()
    print(hardwrap(base))
    print()
    print(softwrap(base))
    print()

if 'transform' in args.target:
    print(colored('*' * 30, 'blue'))


    ## Transformed Messages
    print('Transformed Messages')
    print(colored('*' * 30, 'blue'))

    print('Original message:')
    print()
    print(softwrap(exampleGetRequest1.decode()))
    print()

    components = parse_components(exampleGetRequest1)

    siginput = generate_base(
        components, 
        ( # covered components list
            { 'id': "@method" },
            { 'id': "@path" },
            { 'id': "@authority" },
            { 'id': "accept" }
        ),
        {
            'created': 1618884473,
            'keyid': 'test-key-ed25519'
        }
    )

    base = siginput['signatureInput']
    sigparams = siginput['signatureParams']

    print("Base string:")
    print()
    print(base)
    print()
    print(hardwrap(base))
    print()
    print(softwrap(base))
    print()
    print(softwrap('Signature-Input: transform=' + str(sigparams)))
    print()

    # Unpack private key, format is not supported by Cryptodomex PEM parser
    der = DerOctetString()
    der.decode(PKCS8.unwrap(PEM.decode(ed25519TestKeyPrivate)[0])[1])
    key = SigningKey(der.payload)

    h = base.encode('utf-8')
    signed = http_sfv.Item(key.sign(h).signature)

    print("Signed:")
    print(signed)
    print()
    print(hardwrap(str(signed).strip(':'), 0))
    print()
    print(hardwrap('Signature: transform=' + str(signed)))
    print()

    # Unpack public key, format is not supported by Cryptodomex PEM parser

    # sequence of ID and BitString
    ds = DerSequence()
    ds.decode(PEM.decode(ed25519TestKeyPublic)[0])
    bs = DerBitString()
    bs.decode(ds[1])
    # the first byte of the bitstring is "0" for some reason??
    pubKey = VerifyKey(bs.payload[1:])

    try:
        verified = pubKey.verify(h, signed.value)
        print("Verified:")
        print(colored('> YES!', 'green'))
        results['transform1'] = 'YES'
        print()
    except (ValueError, TypeError):
        print("Verified:")
        print(colored('> NO!', 'red'))
        results['transform1'] = 'NO'
        print()


    ## now test other messages
    print('Alternate message 2:')
    print()
    print(softwrap(exampleGetRequest2.decode()))
    print()

    components = parse_components(exampleGetRequest2)

    siginput = generate_base(
        components, 
        ( # covered components list
            { 'id': "@method" },
            { 'id': "@path" },
            { 'id': "@authority" },
            { 'id': "accept" }
        ),
        {
            'created': 1618884473,
            'keyid': 'test-key-ed25519'
        }
    )

    base = siginput['signatureInput']
    h = base.encode('utf-8')

    try:
        verified = pubKey.verify(h, signed.value)
        print("Verified:")
        print(colored('> YES!', 'green'))
        results['transform2'] = 'YES'
        print()
    except (ValueError, TypeError):
        print("Verified:")
        print(colored('> NO!', 'red'))
        results['transform2'] = 'NO'
        print()

    print('Alternate message 3:')
    print()
    print(softwrap(exampleGetRequest3.decode()))
    print()

    components = parse_components(exampleGetRequest3)

    siginput = generate_base(
        components, 
        ( # covered components list
            { 'id': "@method" },
            { 'id': "@path" },
            { 'id': "@authority" },
            { 'id': "accept" }
        ),
        {
            'created': 1618884473,
            'keyid': 'test-key-ed25519'
        }
    )

    base = siginput['signatureInput']
    h = base.encode('utf-8')

    try:
        verified = pubKey.verify(h, signed.value)
        print("Verified:")
        print(colored('> YES!', 'green'))
        results['transform3'] = 'YES'
        print()
    except (ValueError, TypeError):
        print("Verified:")
        print(colored('> NO!', 'red'))
        results['transform3'] = 'NO'
        print()

    print('Alternate message 4:')
    print()
    print(softwrap(exampleGetRequest4.decode()))
    print()

    components = parse_components(exampleGetRequest4)

    siginput = generate_base(
        components, 
        ( # covered components list
            { 'id': "@method" },
            { 'id': "@path" },
            { 'id': "@authority" },
            { 'id': "accept" }
        ),
        {
            'created': 1618884473,
            'keyid': 'test-key-ed25519'
        }
    )

    base = siginput['signatureInput']
    h = base.encode('utf-8')

    try:
        verified = pubKey.verify(h, signed.value)
        print("Verified:")
        print(colored('> YES!', 'green'))
        results['transform4'] = 'YES'
        print()
    except (ValueError, TypeError):
        print("Verified:")
        print(colored('> NO!', 'red'))
        results['transform4'] = 'NO'
        print()

    print('Alternate message Bad 1:')
    print()
    print(softwrap(exampleGetRequest_bad1.decode()))
    print()

    components = parse_components(exampleGetRequest_bad1)

    siginput = generate_base(
        components, 
        ( # covered components list
            { 'id': "@method" },
            { 'id': "@path" },
            { 'id': "@authority" },
            { 'id': "accept" }
        ),
        {
            'created': 1618884473,
            'keyid': 'test-key-ed25519'
        }
    )

    base = siginput['signatureInput']
    h = base.encode('utf-8')

    try:
        verified = pubKey.verify(h, signed.value)
        print("Failed:")
        print(colored('> NO!', 'red'))
        results['transform bad1'] = 'NO' # this is supposed to fail
        print()
    except (ValueError, TypeError, BadSignatureError):
        print("Failed:")
        print(colored('> YES!', 'green'))
        results['transform bad1'] = 'YES' # this is supposed to fail
        print()

    print('Alternate message Bad 2:')
    print()
    print(softwrap(exampleGetRequest_bad2.decode()))
    print()

    components = parse_components(exampleGetRequest_bad2)

    siginput = generate_base(
        components, 
        ( # covered components list
            { 'id': "@method" },
            { 'id': "@path" },
            { 'id': "@authority" },
            { 'id': "accept" }
        ),
        {
            'created': 1618884473,
            'keyid': 'test-key-ed25519'
        }
    )

    base = siginput['signatureInput']
    h = base.encode('utf-8')

    try:
        verified = pubKey.verify(h, signed.value)
        print("Failed:")
        print(colored('> NO!', 'red'))
        results['transform bad2'] = 'NO' # this is supposed to fail
        print()
    except (ValueError, TypeError, BadSignatureError):
        print("Failed:")
        print(colored('> YES!', 'green'))
        results['transform bad2'] = 'YES' # this is supposed to fail
        print()


print(colored('*' * 30, 'magenta'))
print(colored('*' * 30, 'magenta'))


print()
print('Results:')
print()
print('+' + '-' * 37 + '+' + '-' * 5 + '+')
print ("| {:>35} | {:<3} |".format('Test', 'OK?'))
print('+' + '·' * 37 + '+' + '·' * 5 + '+')
for k,v in results.items():
    print ("| {:>35} | {:<3} |".format(k, v))
print('+' + '-' * 37 + '+' + '-' * 5 + '+')

print()
