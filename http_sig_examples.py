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
mgf512 = lambda x, y: MGF1(x, y, SHA512)

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

exampleReverseProxyMessage = b"""
POST /foo?param=Value&Pet=dog HTTP/1.1
Host: example.com
Date: Tue, 20 Apr 2021 02:07:55 GMT
Content-Type: application/json
Content-Length: 18
Forwarded: for=192.0.2.123
Signature-Input: sig1=("@method" "@authority" "@path" "content-digest" "content-length" "content-type");created=1618884475;keyid="test-key-rsa-pss"
Signature:  sig1=:LAH8BjcfcOcLojiuOBFWn0P5keD3xAOuJRGziCLuD8r5MW9S0RoXXLzLSRfGY/3SF8kVIkHjE13SEFdTo4Af/fJ/Pu9wheqoLVdwXyY/UkBIS1M8Brc8IODsn5DFIrG0IrburbLi0uCc+E2ZIIb6HbUJ+o+jP58JelMTe0QE3IpWINTEzpxjqDf5/Df+InHCAkQCTuKsamjWXUpyOT1Wkxi7YPVNOjW4MfNuTZ9HdbD2Tr65+BXeTG9ZS/9SWuXAc+BZ8WyPz0QRz//ec3uWXd7bYYODSjRAxHqX+S1ag3LZElYyUKaAIjZ8MGOt4gXEwCSLDv/zqxZeWLj/PDkn6w==:

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

exampleRequestResponseMessage = b"""HTTP/1.1 503 Service Unavailable
Date: Tue, 20 Apr 2021 02:07:56 GMT
Content-Type: application/json
Content-Length: 62

{"busy": true, "message": "Your call is very important to us"}
"""

structuredFields = {
    'accept': 'list',
    'accept-encoding': 'list',
    'accept-language': 'list',
    'accept-patch': 'list',
    'accept-ranges': 'list',
    'access-control-allow-credentials': 'item',
    'access-control-allow-headers': 'list',
    'access-control-allow-methods': 'list',
    'access-control-allow-origin': 'item',
    'access-control-expose-headers': 'list',
    'access-control-max-age': 'item',
    'access-control-request-headers': 'list',
    'access-control-request-method': 'item',
    'age': 'item',
    'allow': 'list',
    'alpn': 'list',
    'alt-svc': 'dict',
    'alt-used': 'item',
    'cache-control': 'dict',
    'connection': 'list',
    'content-encoding': 'list',
    'content-language': 'list',
    'content-length': 'list',
    'content-type': 'item',
    'cross-origin-resource-policy': 'item',
    'expect': 'item',
    'expect-ct': 'dict',
    'host': 'item',
    'keep-alive': 'dict',
    'origin': 'item',
    'pragma': 'dict',
    'prefer': 'dict',
    'preference-applied': 'dict',
    'retry-after': 'item',
    'surrogate-control': 'dict',
    'te': 'list',
    'timing-allow-origin': 'list',
    'trailer': 'list',
    'transfer-encoding': 'list',
    'vary': 'list',
    'x-content-type-options': 'item',
    'x-frame-options': 'item',
    'x-xss-protection': 'list',
    "cache-status": "list",
    "proxy-status": "list",
    "variant-key": "list",
    "variants": "dict",
    "signature": "dict",
    "signature-input": "dict",
    "priority": "dict",
    "x-dictionary": "dict",
    "x-list": "list",
    "x-list-a": "list",
    "x-list-b": "list",
    "accept-ch": "list",
    "example-list": "list",
    "example-dict": "dict",
    "example-integer": "item",
    "example-decimal": "item",
    "example-string": "item",
    "example-token": "item",
    "example-bytesequence": "item",
    "example-boolean": "item",
    "cdn-cache-control": "dict"
}


def hardwrap(src, space = 2, width = 68):
    lines = src.split('\n') # split existing lines
    out = [] # output buffer
    for l in lines:
        lout = [] # internal output buffer
        if len(l) > width:
            ll = l[slice(width - 1)] # leave room for a backslash
            lout.append(ll)
            l = l[slice(width - 1, len(l))]
            while len(l) > width: # the middle leaves room for spaces, too
                ll = l[slice(width - 1 - space)]
                lout.append(ll)
                l = l[slice(width - 1 - space, len(l))]
            lout.append(l) # add the last bits
        else:
            lout.append(l)
        out.append(('\\\n' + (' ' * space)).join(lout))
    return ('\n').join(out)

def softwrap(src, space = 2, width = 68, breakon = '; '):
    lines = src.split('\n') # split existing lines
    out = [] # output buffer
    for l in lines:
        lout = [] # internal output buffer
        if len(l) > width:
            ll = l[slice(width - 1)] # leave room for a backslash
            # find if there's a better place to break
            br = max(map(ll.rfind, breakon))
            if br > -1:
                if ll[br] == ' ':
                    br = br + 1 # capture the space
                ll = l[slice(br)] # re-slice
            else:
                br = width - 1 # no match found, use the default
            lout.append(ll)
            l = l[slice(br, len(l))]
            while len(l) > width: # the middle leaves room for spaces, too
                ll = l[slice(width - 1 - space)]
                # find if there's a better place to break
                br = max(map(ll.rfind, breakon))
                if br > -1:
                    if ll[br] == ' ':
                        br = br + 1 # capture the space
                    ll = l[slice(br)] # re-slice
                else:
                    br = width - 1 - space # no match found, use the default
                lout.append(ll)
                l = l[slice(br, len(l))]
            lout.append(l) # add the last bits
        else:
            lout.append(l)
        out.append(('\\\n' + (' ' * space)).join(lout))
    return ('\n').join(out)


def parse_components(msg):
    p = HttpParser()
    p.execute(msg, len(msg))
    
    response = {}
    
    response['fields'] = []
    for h in p.get_headers():
        cid = http_sfv.Item(h.lower())
        response['fields'].append(
            {
                'id': cid.value,
                'cid': str(cid),
                'val': p.get_headers()[h] # Note: this normalizes the header value for us
            }
        )
        # see if this is a known structured field
        if h and h.lower() in structuredFields:
            if structuredFields[h.lower()] == 'dict':
                sv = http_sfv.Dictionary()
                sv.parse(p.get_headers()[h].encode('utf-8'))
            
                for k in sv:
                    cid = http_sfv.Item(h.lower())
                    cid.params['key'] = k
                    response['fields'].append(
                        {
                            'id': cid.value,
                            'cid': str(cid),
                            'key': k,
                            'val': str(sv[k])
                        }
                    )
            
                cid = http_sfv.Item(h.lower())
                cid.params['sf'] = True
                response['fields'].append(
                    {
                        'id': cid.value,
                        'cid': str(cid),
                        'sf': True,
                        'val': str(sv)
                    }
                )
            elif structuredFields[h.lower()] == 'list':
                sv = http_sfv.List()
                sv.parse(p.get_headers()[h].encode('utf-8'))
            
                cid = http_sfv.Item(h.lower())
                cid.params['sf'] = True
                response['fields'].append(
                    {
                        'id': cid.value,
                        'cid': str(cid),
                        'sf': True,
                        'val': str(sv)
                    }
                )
            elif structuredFields[h.lower()] == 'item':
                sv = http_sfv.Item()
                sv.parse(p.get_headers()[h].encode('utf-8'))
        
                cid = http_sfv.Item(h.lower())
                cid.params['sf'] = True
                response['fields'].append(
                    {
                        'id': cid.value,
                        'cid': str(cid),
                        'sf': True,
                        'val': str(sv)
                    }
                )

    if p.get_status_code():
        # response
        response['derived'] = [
            {
                'id': '@status',
                'cid': str(http_sfv.Item('@status')),
                'val': str(p.get_status_code())
            }
        ]
    else:
        # request
        response['derived'] = [
            {
                'id': '@method',
                'cid': str(http_sfv.Item('@method')),
                'val': p.get_method()
            },
            {
                'id': '@target-uri',
                'cid': str(http_sfv.Item('@target-uri')),
                'val': 
                'https://' # TODO: this always assumes an HTTP connection for demo purposes
                    + p.get_headers()['host'] # TODO: this library assumes HTTP 1.1
                    + p.get_url()
            },
            {
                'id': '@authority',
                'cid': str(http_sfv.Item('@authority')),
                'val':  p.get_headers()['host'] # TODO: this library assumes HTTP 1.1
            },
            {
                'id': '@scheme',
                'cid': str(http_sfv.Item('@scheme')),
                'val':  'https' # TODO: this always assumes an HTTPS connection for demo purposes
            },
            {
                'id': '@request-target',
                'cid': str(http_sfv.Item('@request-target')),
                'val':  p.get_url()
            },
            {
                'id': '@path',
                'cid': str(http_sfv.Item('@path')),
                'val':  p.get_path()
            },
            {
                'id': '@query',
                'cid': str(http_sfv.Item('@query')),
                'val':  '?' + p.get_query_string()
            }
        ]

        qs = parse_qs(p.get_query_string())
        for q in qs:
            v = qs[q]
            if len(v) == 1:
                cid = http_sfv.Item('@query-param')
                cid.params['name'] = q
                response['derived'].append(
                    {
                        'id': cid.value,
                        'cid': str(cid),
                        'name': q,
                        'val': v[0]
                    }
                )
            elif len(v) > 1:
                # Multiple values, undefined behavior?
                for i in range(len(v)):
                    cid = http_sfv.Item('@query-param')
                    cid.params['name'] = q
                    response['derived'].append(
                        {
                            'id': cid.value,
                            'cid': str(cid),
                            'name': q,
                            'val': v[i],
                            'idx': i
                        }
                    )

    if 'signature-input' in p.get_headers():
        # existing signatures, parse the values
        siginputheader = http_sfv.Dictionary()
        siginputheader.parse(p.get_headers()['signature-input'].encode('utf-8'))
        
        sigheader = http_sfv.Dictionary()
        sigheader.parse(p.get_headers()['signature'].encode('utf-8'))
        
        siginputs = {}
        for (k,v) in siginputheader.items():
            
            existingComponents = []
            for c in v:
                cc = { # holder object
                    'id': c.value,
                    'cid': str(c)
                }
                if not cc['id'].startswith('@'):
                    # it's a header, try to get the existing value
                    fields = (f for f in response['fields'] if f['id'] == cc['id'])
                    if 'sf' in c.params:
                        cc['sf'] = c.params['sf']
                        cc['val'] = next((f['val'] for f in fields if f['sf'] == c.params['sf']), None)
                    elif 'key' in c.params:
                        cc['key'] = i.params['key']
                        cc['val'] = next((f['val'] for f in fields if f['key'] == c.params['key']), None)
                    else:
                        cc['val'] = next((f['val'] for f in fields if ('key' not in f and 'sf' not in f)), None)
                else:
                    # it's derived
                    derived = (d for d in response['derived'] if d['id'] == cc['id'])
                    
                    if cc['id'] == '@query-param' and 'name' in c.params:
                        cc['name'] = c.params['name']
                        cc['val'] = next((d['val'] for d in derived if d['name'] == c.params['name']), None)
                    else:
                        cc['val'] = next((d['val'] for d in derived if ('name' not in d)), None)

                existingComponents.append(cc)
            
            siginput = {
                'coveredComponents': existingComponents,
                'params': {p:pv for (p,pv) in v.params.items()},
                'value': str(v),
                'signature': str(sigheader[k])
            }
            siginputs[k] = siginput
            
        response['inputSignatures'] = siginputs

    # process the body
    body = p.recv_body()
    if body:
        response['body'] = body

    return response
    
def add_content_digest(components, alg='sha-512'):
    if 'body' in components:
        if alg == 'sha-512':
            h = SHA512.new(components['body'])
        elif alg == 'sha-256':
            h = SHA256.new(components['body'])
        else:
            # unknown alg, skip it
            return components
        dv = http_sfv.Item(h.digest())
        cd = http_sfv.Dictionary()
        cd[alg] = dv
        
        cid = http_sfv.Item('Content-Digest'.lower())
        components['fields'].append(
            {
                'id': cid.value,
                'cid': str(cid),
                'val': str(cd)
            }
        )
        
        # key with algorithm
        cid = http_sfv.Item('Content-Digest'.lower())
        cid.params['key'] = alg
        components['fields'].append(
            {
                'id': cid.value,
                'cid': str(cid),
                'key': alg,
                'val': str(dv)
            }
        )
        
        # structured field strict serialization
        cid = http_sfv.Item('Content-Digest'.lower())
        cid.params['sf'] = True
        components['fields'].append(
            {
                'id': cid.value,
                'cid': str(cid),
                'sf': True,
                'val': str(cd)
            }
        )
        
        return components
    else:
        return components

def generate_input(components, coveredComponents, params):
    sigparams = http_sfv.InnerList()
    base = ''

    for cc in coveredComponents:
        c = cc['id']
        if not c.startswith('@'):
            # it's a header
            i = http_sfv.Item(c.lower())

            if 'key' in cc:
                # try a dictionary header value
                i.params['key'] = cc['key']
                comp = next((x for x in components['fields'] if 'key' in x and x['id'] == c and x['key'] == cc['key']), None)
                                
                sigparams.append(i)
                base += str(i)
                base += ': '
                base += comp['val']
                base += "\n"
            elif 'sf' in cc:
                i.params['sf'] = True
                comp = next((x for x in components['fields'] if 'sf' in x and x['id'] == c and x['sf'] == cc['sf']), None)
                sigparams.append(i)
                base += str(i)
                base += ': '
                base += comp['val']
                base += "\n"
            else:
                comp = next((x for x in components['fields'] if x['id'] == c), None)
                sigparams.append(i)
                base += str(i)
                base += ': '
                base += comp['val']
                base += "\n"
        else:
            # it's a derived value
            i = http_sfv.Item(c)
            
            if 'key' in cc and c == '@request-response':
                # request-response has a 'key' field
                i.params['key'] = cc['key']
                comp = next((x for x in components['derived'] if 'key' in x and x['id'] == c and x['key'] == cc['key']), None)
                                
                sigparams.append(i)
                base += str(i)
                base += ': '
                base += comp['val']
                base += "\n"
            elif 'name' in cc and c == '@query-param':
                # query-param has a 'name' field
                i.params['name'] = cc['name']
                comp = next((x for x in components['derived'] if 'name' in x and x['id'] == c and x['name'] == cc['name']), None)
                                
                sigparams.append(i)
                base += str(i)
                base += ': '
                base += comp['val']
                base += "\n"
            else:
                comp = next((x for x in components['derived'] if x['id'] == c), None)

                sigparams.append(i)
                base += str(i)
                base += ': '
                base += comp['val']
                base += "\n"

    for pn in params:
        sigparams.params[pn] = params[pn]

    sigparamstr = ''
    sigparamstr += str(http_sfv.Item("@signature-params")) # never any parameters
    sigparamstr += ': '
    sigparamstr += str(sigparams)
    
    base += sigparamstr
    
    response = {
        'signatureInput': base,
        'signatureParams': sigparams
    }
    
    return response

print('*' * 30)
print('* Example Messages')
print('*' * 30)

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


## Base example pieces

print('*' * 30)
print('* Covered Content RSAPSS Test')
print('*' * 30)


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

siginput = generate_input(
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
    print('> YES!')
    results['Covered Content RSAPSS Test'] = 'YES'
    print()
except (ValueError, TypeError):
    print("Verified:")
    print('> NO!')
    results['Covered Content RSAPSS Test'] = 'NO'
    print()

print('*' * 30)

## reverse proxy signature
print('* Reverse Proxy Signature ')
print('*' * 30)

# Message with existing signatures and added headers
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

siginput = generate_input(
    components, 
    ( # covered components list
        { 'id': "signature", 'key': 'sig1' }, 
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

print("Signed:")
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
    print('> YES!')
    results['Reverse Proxy'] = 'YES'
    print()
except (ValueError, TypeError):
    print("Verified:")
    print('> NO!')
    results['Reverse Proxy'] = 'NO'
    print()

print('*' * 30)

## TLS reverse proxy signature
print('* TLS Reverse Proxy Signature ')
print('*' * 30)

# message with client cert header
components = parse_components(exampleClientCertMessage)

siginput = generate_input(
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
    print('> YES!')
    results['TTRP'] = 'YES'
    print()
except (ValueError, TypeError):
    print("Verified:")
    print('> NO!')
    results['TTRP'] = 'NO'
    print()

print('*' * 30)

## minimal signature
print('* Minimal Coverage')
print('*' * 30)


components = parse_components(exampleRequestMessage)

siginput = generate_input(
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
    print('> YES!')
    results['Minimal Coverage'] = 'YES'
    print()
except (ValueError, TypeError):
    print("Verified:")
    print('> NO!')
    results['TLSMinimal Coverage'] = 'NO'
    print()

print('*' * 30)

## header coverage
print('* Header Coverage')
print('*' * 30)

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

siginput = generate_input(
    components, 
    ( # covered components list
        { 'id': "@authority" },
        { 'id': "content-digest" }
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
    print('> YES!')
    results['Header Coverage'] = 'YES'
    print()
except (ValueError, TypeError):
    print("Verified:")
    print('> NO!')
    results['Header Coverage'] = 'NO'
    print()

print('*' * 30)

## full coverage
print('* Full Coverage')
print('*' * 30)

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

siginput = generate_input(
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
    print('> YES!')
    results['Full Coverage'] = 'YES'
    print()
except (ValueError, TypeError):
    print("Verified:")
    print('> NO!')
    results['Full Coverage'] = 'NO'
    print()

print('*' * 30)

## ECC
print('* ECC Response')
print('*' * 30)

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

siginput = generate_input(
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
    print('> YES!')
    results['ECC Response'] = 'YES'
    print()
except (ValueError, TypeError):
    print("Verified:")
    print('> NO!')
    results['ECC Response'] = 'NO'
    print()

print('*' * 30)

## HMAC coverage
print('* HMAC Coverage')
print('*' * 30)

components = parse_components(exampleRequestMessage)

siginput = generate_input(
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

print('*' * 30)

## Request-Response
print('* Request-Response')
print('*' * 30)

reqComponents = parse_components(exampleReverseProxyMessage)
components = parse_components(exampleRequestResponseMessage)

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

# Manually add in the request-response component from the request components

comp = next((x for x in reqComponents['fields'] if 'key' in x and x['id'] == 'signature' and x['key'] == 'sig1'), None)

comp['id'] = '@request-response'
comp['key'] = 'sig1'
comp['cid'] = '"@request-response";key="sig1"'

components['derived'].append(comp)

siginput = generate_input(
    components, 
    ( # covered components list
        { 'id': "@status" },
        { 'id': "content-length" },
        { 'id': "content-type" },
        { 'id': "@request-response", 'key': "sig1" }
    ),
    {
        'created': 1618884479,
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
print(softwrap(exampleReverseProxyMessage.decode()))
print()
print(hardwrap(exampleReverseProxyMessage.decode()))
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
    print('> YES!')
    print()
except (ValueError, TypeError):
    print("Verified:")
    print('> NO!')
    results['Request Response: Related-Response'] = 'NO'
    print()

print('*' * 30)

# Static signature test

print('HTTPSig Static Test 1')
print('*' * 30)


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

siginput = generate_input(
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
    print('> YES!')
    results['Static 1'] = 'YES'
    print()
except (ValueError, TypeError):
    print("Verified:")
    print('> NO!')
    results['Static 1'] = 'NO'
    print()

print('*' * 30)

# Static signature test

print('HTTPSig Static Test 3')
print('*' * 30)


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
    print('> YES!')
    results['Static 3'] = 'YES'
    print()
except (ValueError, TypeError):
    print("Verified:")
    print('> NO!')
    results['Static 3'] = 'NO'
    print()

print('*' * 30)

## ED 25519
print('ed25519 signature')
print('*' * 30)

components = parse_components(exampleRequestMessage)

siginput = generate_input(
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
    print('> YES!')
    results['Ed25519'] = 'YES'
    print()
except (ValueError, TypeError):
    print("Verified:")
    print('> NO!')
    results['Ed25519'] = 'YES'
    print()

print('*' * 30)

# Static HTTP test (ECC)
print('HTTPSig Static Test 2')
print('*' * 30)


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
    print('> YES!')
    results['Static 2'] = 'YES'
    print()
except (ValueError, TypeError):
    print("Verified:")
    print('> NO!')
    results['Static 2'] = 'NO'
    print()

print('*' * 30)

# Static Header formatting
print('Static header formatting')
print('*' * 30)

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

siginput = generate_input(
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


print('*' * 30)


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
