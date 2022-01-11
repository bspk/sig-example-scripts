#!/usr/bin/env python

import json
try:
    from http_parser.parser import HttpParser
except ImportError:
    from http_parser.pyparser import HttpParser

import http_sfv
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

requestTarget = "get /foo"

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

print('*' * 30)
print('* Covered Content RSAPSS Test')
print('*' * 30)


coveredContent = {
    str(http_sfv.Item("@method")): "GET",
    str(http_sfv.Item("@path")): "/foo",
    str(http_sfv.Item("@authority")): "example.org",
    str(http_sfv.Item("cache-control")): "max-age=60, must-revalidate",
    str(http_sfv.Item("x-empty-header")): "",
    str(http_sfv.Item("x-example")): "Example header with some whitespace."
}

sigparams = http_sfv.InnerList()
base = '';
for c in coveredContent:
    i = http_sfv.Item()
    i.parse(c.encode())
    sigparams.append(i)
    base += c # already serialized as an Item
    base += ': '
    base += coveredContent[c]
    base += "\n"

sigparams.params['created'] = 1618884475
sigparams.params['keyid'] = 'test-key-rsa-pss'

sigparamstr = ''
sigparamstr += str(http_sfv.Item("@signature-params"))
sigparamstr += ": "
sigparamstr += str(sigparams)

base += sigparamstr

print("Base string:")
print(base)
print()
print(softwrap(sigparamstr))
print()
print(softwrap('Signature-Input: sig1=' + str(sigparams)))

key = RSA.import_key(PKCS8.unwrap(PEM.decode(rsaTestKeyPssPrivate)[0])[1])

h = SHA512.new(base.encode('utf-8'))
signer = pss.new(key, mask_func=mgf512, salt_bytes=64)

signed = http_sfv.Item(signer.sign(h))

print("Signed:")
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

# old signatures

oldsiginput = softwrap('Signature-Input: sig1=("@method" "@path" "@authority" "cache-control" "x-empty-header" "x-example");created=1618884475;keyid="test-key-rsa-pss"', 4);
oldsig = hardwrap('Signature: sig1=:P0wLUszWQjoi54udOtydf9IWTfNhy+r53jGFj9XZuP4uKwxyJo1RSHi+oEF1FuX6O29d+lbxwwBao1BAgadijW+7O/PyezlTnqAOVPWx9GlyntiCiHzC87qmSQjvu1CFyFuWSjdGa3qLYYlNm7pVaJFalQiKWnUaqfT4LyttaXyoyZW84jS8gyarxAiWI97mPXU+OVM64+HVBHmnEsS+lTeIsEQo36T3NFf2CujWARPQg53r58RmpZ+J9eKR2CD6IJQvacn5A4Ix5BUAVGqlyp8JYm+S/CWJi31PNUjRRCusCVRj05NrxABNFv3r5S9IXf2fYJK+eyW4AiGVMvMcOg==:', 4)

sig1value = ':P0wLUszWQjoi54udOtydf9IWTfNhy+r53jGFj9XZuP4uKwxyJo1RSHi+oEF1FuX6O29d+lbxwwBao1BAgadijW+7O/PyezlTnqAOVPWx9GlyntiCiHzC87qmSQjvu1CFyFuWSjdGa3qLYYlNm7pVaJFalQiKWnUaqfT4LyttaXyoyZW84jS8gyarxAiWI97mPXU+OVM64+HVBHmnEsS+lTeIsEQo36T3NFf2CujWARPQg53r58RmpZ+J9eKR2CD6IJQvacn5A4Ix5BUAVGqlyp8JYm+S/CWJi31PNUjRRCusCVRj05NrxABNFv3r5S9IXf2fYJK+eyW4AiGVMvMcOg==:'

sig1hd = http_sfv.Item('signature')
sig1hd.params['key'] = 'sig1'

coveredContent = {}

coveredContent[str(sig1hd)] = str(sig1value)
coveredContent[str(http_sfv.Item("forwarded"))] = "for=192.0.2.123"


sigparams = http_sfv.InnerList()
base = '';
for c in coveredContent:
    i = http_sfv.Item()
    i.parse(c.encode())
    sigparams.append(i)
    base += c # already serialized as an Item
    base += ': '
    base += coveredContent[c]
    base += "\n"

sigparams.params['created'] = 1618884480
sigparams.params['keyid'] = 'test-key-rsa'
sigparams.params['alg'] = 'rsa-v1_5-sha256'

sigparamstr = ''
sigparamstr += str(http_sfv.Item("@signature-params"))
sigparamstr += ": "
sigparamstr += str(sigparams)

base += sigparamstr

print("Base string:")
print(base)
print()
print(softwrap(base))
print()
print(softwrap(sigparamstr))
print()
print(hardwrap(str(sig1hd) + ': ' + str(sig1value)))
print()
print(oldsiginput + ', \\')
print(softwrap('  proxy_sig=' + str(sigparams), 4))


key = RSA.import_key(rsaTestKeyPrivate)

h = SHA256.new(base.encode('utf-8'))
signer = pkcs1_15.new(key)

signed = http_sfv.Item(signer.sign(h))

print("Signed:")
print(signed)
print()
print(hardwrap(str(signed).strip(':'), 0))
print()
print(oldsig + ', \\')
print(hardwrap('  proxy_sig=' + str(signed), 4))
print()

pubKey = RSA.import_key(rsaTestKeyPublic)
verifier = pkcs1_15.new(key)

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

coveredContent = {
    str(http_sfv.Item("@path")): "/foo",
    str(http_sfv.Item("@query")): "Param=value&pet=Dog",
    str(http_sfv.Item("@method")): "POST",
    str(http_sfv.Item("@authority")): "service.internal.example",
    str(http_sfv.Item("client-cert")): ":MIIBqDCCAU6gAwIBAgIBBzAKBggqhkjOPQQDAjA6MRswGQYDVQQKDBJMZXQncyBBdXRoZW50aWNhdGUxGzAZBgNVBAMMEkxBIEludGVybWVkaWF0ZSBDQTAeFw0yMDAxMTQyMjU1MzNaFw0yMTAxMjMyMjU1MzNaMA0xCzAJBgNVBAMMAkJDMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8YnXXfaUgmnMtOXU/IncWalRhebrXmckC8vdgJ1p5Be5F/3YC8OthxM4+k1M6aEAEFcGzkJiNy6J84y7uzo9M6NyMHAwCQYDVR0TBAIwADAfBgNVHSMEGDAWgBRm3WjLa38lbEYCuiCPct0ZaSED2DAOBgNVHQ8BAf8EBAMCBsAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwHQYDVR0RAQH/BBMwEYEPYmRjQGV4YW1wbGUuY29tMAoGCCqGSM49BAMCA0gAMEUCIBHda/r1vaL6G3VliL4/Di6YK0Q6bMjeSkC3dFCOOB8TAiEAx/kHSB4urmiZ0NX5r5XarmPk0wmuydBVoU4hBVZ1yhk=:"
}

print(hardwrap('Client-Cert: ' + coveredContent['"client-cert"']))
print()

sigparams = http_sfv.InnerList()
base = '';
for c in coveredContent:
    i = http_sfv.Item()
    i.parse(c.encode())
    sigparams.append(i)
    base += c # already serialized as an Item
    base += ': '
    base += coveredContent[c]
    base += "\n"

sigparams.params['created'] = 1618884475
sigparams.params['keyid'] = 'test-key-ecc-p256'

sigparamstr = ''
sigparamstr += str(http_sfv.Item("@signature-params"))
sigparamstr += ": "
sigparamstr += str(sigparams)

base += sigparamstr

print("Base string:")
print(base)
print()
print(hardwrap(base))
print()
print(softwrap(sigparamstr))
print()
print(softwrap('Signature-Input: ttrp=' + str(sigparams)))


key = ECC.import_key(eccTestKeyPrivate)

h = SHA256.new(base.encode('utf-8'))
signer = DSS.new(key, 'fips-186-3')

signed = http_sfv.Item(signer.sign(h))

print("Signed:")
print(signed)
print()
print(hardwrap(str(signed).strip(':'), 0))
print()
print(hardwrap('Signature: ttrp=' + str(signed)))
print()

pubKey = ECC.import_key(eccTestKeyPublic)
verifier = DSS.new(key, 'fips-186-3')

try:
    verified = verifier.verify(h, signed.value)
    print("Verified:")
    print('> YES!')
    print()
except (ValueError, TypeError):
    print("Verified:")
    print('> NO!')
    print()

print('*' * 30)

## minimal signature
print('* Minimal Coverage')
print('*' * 30)


sigparams = http_sfv.InnerList()
base = '';

sigparams.params['created'] = 1618884475
sigparams.params['keyid'] = 'test-key-rsa-pss'
sigparams.params['alg'] = 'rsa-pss-sha512'

sigparamstr = ''
sigparamstr += str(http_sfv.Item("@signature-params"))
sigparamstr += ": "
sigparamstr += str(sigparams)

base += sigparamstr

print("Base string:")
print(base)
print()
print(softwrap(sigparamstr))
print()
print(softwrap('Signature-Input: sig1=' + str(sigparams)))

key = RSA.import_key(PKCS8.unwrap(PEM.decode(rsaTestKeyPssPrivate)[0])[1])

h = SHA512.new(base.encode('utf-8'))
signer = pss.new(key, mask_func=mgf512, salt_bytes=64)

signed = http_sfv.Item(signer.sign(h))

print("Signed:")
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
    print('> YES!')
    results['TLS Reverse Proxy'] = 'YES'
    print()
except (ValueError, TypeError):
    print("Verified:")
    print('> NO!')
    results['TLS Reverse Proxy'] = 'NO'
    print()

print('*' * 30)


## header coverage
print('* Header Coverage')
print('*' * 30)

coveredContent = {
    str(http_sfv.Item("@authority")): "example.com",
    str(http_sfv.Item("content-type")): "application/json",
}

sigparams = http_sfv.InnerList()
base = '';
for c in coveredContent:
    i = http_sfv.Item()
    i.parse(c.encode())
    sigparams.append(i)
    base += c # already serialized as an Item
    base += ': '
    base += coveredContent[c]
    base += "\n"

sigparams.params['created'] = 1618884475
sigparams.params['keyid'] = 'test-key-rsa-pss'

sigparamstr = ''
sigparamstr += str(http_sfv.Item("@signature-params"))
sigparamstr += ": "
sigparamstr += str(sigparams)

base += sigparamstr

print("Base string:")
print(base)
print()
print(softwrap(sigparamstr))
print()
print(softwrap('Signature-Input: sig1=' + str(sigparams)))


key = RSA.import_key(PKCS8.unwrap(PEM.decode(rsaTestKeyPssPrivate)[0])[1])

h = SHA512.new(base.encode('utf-8'))
signer = pss.new(key, mask_func=mgf512, salt_bytes=64)

signed = http_sfv.Item(signer.sign(h))

print("Signed:")
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

coveredContent = {
    str(http_sfv.Item("date")): "Tue, 20 Apr 2021 02:07:56 GMT",
    str(http_sfv.Item("@method")): "POST",
    str(http_sfv.Item("@path")): "/foo",
    str(http_sfv.Item("@query")): "?param=value&pet=dog",
    str(http_sfv.Item("@authority")): "example.com",
    str(http_sfv.Item("content-type")): "application/json",
    str(http_sfv.Item("digest")): "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=",
    str(http_sfv.Item("content-length")): "18"
}

sigparams = http_sfv.InnerList()
base = '';
for c in coveredContent:
    i = http_sfv.Item()
    i.parse(c.encode())
    sigparams.append(i)
    base += c # already serialized as an Item
    base += ': '
    base += coveredContent[c]
    base += "\n"

sigparams.params['created'] = 1618884475
sigparams.params['keyid'] = 'test-key-rsa-pss'

sigparamstr = ''
sigparamstr += str(http_sfv.Item("@signature-params"))
sigparamstr += ": "
sigparamstr += str(sigparams)

base += sigparamstr

print("Base string:")
print(base)
print()
print(softwrap(sigparamstr))
print()
print(softwrap('Signature-Input: sig1=' + str(sigparams)))

key = RSA.import_key(PKCS8.unwrap(PEM.decode(rsaTestKeyPssPrivate)[0])[1])

h = SHA512.new(base.encode('utf-8'))
signer = pss.new(key, mask_func=mgf512, salt_bytes=64)

signed = http_sfv.Item(signer.sign(h))

print("Signed:")
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

coveredContent = {
    str(http_sfv.Item("@status")): "200",
    str(http_sfv.Item("content-type")): "application/json",
    str(http_sfv.Item("digest")): "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=",
    str(http_sfv.Item("content-length")): "18"
}

sigparams = http_sfv.InnerList()
base = '';
for c in coveredContent:
    i = http_sfv.Item()
    i.parse(c.encode())
    sigparams.append(i)
    base += c # already serialized as an Item
    base += ': '
    base += coveredContent[c]
    base += "\n"

sigparams.params['created'] = 1618884475
sigparams.params['keyid'] = 'test-key-ecc-p256'

sigparamstr = ''
sigparamstr += str(http_sfv.Item("@signature-params"))
sigparamstr += ": "
sigparamstr += str(sigparams)

base += sigparamstr

print("Base string:")
print(base)
print()
print(softwrap(sigparamstr))
print()
print(softwrap('Signature-Input: sig1=' + str(sigparams)))

key = ECC.import_key(eccTestKeyPrivate)

h = SHA256.new(base.encode('utf-8'))
signer = DSS.new(key, 'fips-186-3')

signed = http_sfv.Item(signer.sign(h))

print("Signed:")
print(signed)
print()
print(hardwrap(str(signed).strip(':'), 0))
print()
print(hardwrap('Signature: sig1=' + str(signed)))
print()

pubKey = ECC.import_key(eccTestKeyPublic)
verifier = DSS.new(key, 'fips-186-3')

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

coveredContent = {
    str(http_sfv.Item("@authority")): "example.com",
    str(http_sfv.Item("date")): "Tue, 20 Apr 2021 02:07:55 GMT",
    str(http_sfv.Item("content-type")): "application/json",
}

sigparams = http_sfv.InnerList()
base = '';
for c in coveredContent:
    i = http_sfv.Item()
    i.parse(c.encode())
    sigparams.append(i)
    base += c # already serialized as an Item
    base += ': '
    base += coveredContent[c]
    base += "\n"

sigparams.params['created'] = 1618884475
sigparams.params['keyid'] = 'test-shared-secret'

sigparamstr = ''
sigparamstr += str(http_sfv.Item("@signature-params"))
sigparamstr += ": "
sigparamstr += str(sigparams)

base += sigparamstr

print("Base string:")
print(base)
print()
print(softwrap(sigparamstr))
print()
print(softwrap('Signature-Input: sig1=' + str(sigparams)))


key = base64.b64decode(sharedSecret)

signer = HMAC.new(key, digestmod=SHA256)
signer.update(base.encode('utf-8'))

signed = http_sfv.Item(signer.digest())

print("Signed:")
print(signed)
print()
print(hardwrap(str(signed).strip(':'), 0))
print()
print(hardwrap('Signature: sig1=' + str(signed)))
print()

results['HMAC'] = 'YES' # this is silly but ...

print('*' * 30)


## Request-Response
print('* Request-Response')
print('*' * 30)

coveredContent = {
    str(http_sfv.Item("@authority")): "example.com",
    str(http_sfv.Item("content-type")): "application/json",
}

sigparams = http_sfv.InnerList()
base = '';
for c in coveredContent:
    i = http_sfv.Item()
    i.parse(c.encode())
    sigparams.append(i)
    base += c # already serialized as an Item
    base += ': '
    base += coveredContent[c]
    base += "\n"

sigparams.params['created'] = 1618884475
sigparams.params['keyid'] = 'test-key-rsa-pss'

sigparamstr = ''
sigparamstr += str(http_sfv.Item("@signature-params"))
sigparamstr += ": "
sigparamstr += str(sigparams)

base += sigparamstr

print("Base string:")
print(base)
print()
print(softwrap(sigparamstr))
print()
print(softwrap('Signature-Input: sig1=' + str(sigparams)))


key = RSA.import_key(PKCS8.unwrap(PEM.decode(rsaTestKeyPssPrivate)[0])[1])

h = SHA512.new(base.encode('utf-8'))
signer = pss.new(key, mask_func=mgf512, salt_bytes=64)

signed = http_sfv.Item(signer.sign(h))

print("Signed:")
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
    print('> YES!')
    results['Request Response: Request'] = 'YES'
    print()
except (ValueError, TypeError):
    print("Verified:")
    print('> NO!')
    results['Request Response: Request'] = 'NO'
    print()

coveredContent = {
    str(http_sfv.Item("content-type")): "application/json",
    str(http_sfv.Item("content-length")): "62",
    str(http_sfv.Item("@status")): "200"
}

rr = http_sfv.Item("@request-response")
rr.params["key"] = "sig1"
coveredContent[str(rr)] = str(signed)

sigparams = http_sfv.InnerList()
base = '';
for c in coveredContent:
    i = http_sfv.Item()
    i.parse(c.encode())
    sigparams.append(i)
    base += c # already serialized as an Item
    base += ': '
    base += coveredContent[c]
    base += "\n"

sigparams.params['created'] = 1618884475
sigparams.params['keyid'] = 'test-key-ecc-p256'

sigparamstr = ''
sigparamstr += str(http_sfv.Item("@signature-params"))
sigparamstr += ": "
sigparamstr += str(sigparams)

base += sigparamstr

print("Base string:")
print(base)
print()
print(hardwrap(str(rr) + ': ' + str(signed)))
print()
print(softwrap(sigparamstr))
print()
print(softwrap('Signature-Input: sig1=' + str(sigparams)))

key = ECC.import_key(eccTestKeyPrivate)

h = SHA256.new(base.encode('utf-8'))
signer = DSS.new(key, 'fips-186-3')

signed = http_sfv.Item(signer.sign(h))

print("Signed:")
print(signed)
print()
print(hardwrap(str(signed).strip(':'), 0))
print()
print(hardwrap('Signature: sig1=' + str(signed)))
print()

pubKey = ECC.import_key(eccTestKeyPublic)
verifier = DSS.new(key, 'fips-186-3')

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


print('HTTPSig Static Test')
print('*' * 30)


base = '''"@method": GET
"@path": /foo
"@authority": example.org
"cache-control": max-age=60, must-revalidate
"x-empty-header": 
"x-example": Example header with some whitespace.
"@signature-params": ("@method" "@path" "@authority" "cache-control" "x-empty-header" "x-example");created=1618884475;keyid="test-key-rsa-pss"'''

h = SHA512.new(base.encode('utf-8'))

signed = http_sfv.Item()

signed.parse(':P0wLUszWQjoi54udOtydf9IWTfNhy+r53jGFj9XZuP4uKwxyJo1RSHi+oEF1FuX6O29d+lbxwwBao1BAgadijW+7O/PyezlTnqAOVPWx9GlyntiCiHzC87qmSQjvu1CFyFuWSjdGa3qLYYlNm7pVaJFalQiKWnUaqfT4LyttaXyoyZW84jS8gyarxAiWI97mPXU+OVM64+HVBHmnEsS+lTeIsEQo36T3NFf2CujWARPQg53r58RmpZ+J9eKR2CD6IJQvacn5A4Ix5BUAVGqlyp8JYm+S/CWJi31PNUjRRCusCVRj05NrxABNFv3r5S9IXf2fYJK+eyW4AiGVMvMcOg==:'.encode('utf-8'))

#signed.parse(':Gu5RuUzQ1R3tAs9RbgsMfhnrRaNiJ6IbxLmu2wSvjntnlaEwUrJIU8zazmbxbqx5+ioz/rAgICAIjOtOfRnynJwCX2cVmXcQsVvsYpnlUYR2ChnNIThgRj5WoVGpvzs91KsPhP2cn7a92ZLhfNsfd7jbTGS6GgZUvc8GW8EHwN5hQ10PIu7EwSeIiKDOpGWbsErEeg46rM2VxtJD+pObC82+E+hgdBPzWOCgOCmZex02OPOr/6UBO0Sb8TQ5XT3dG0QOiNzRPEN2e3gKkwhGMPFuPeHj1Sminnb/A+7L6o2KmT2d/cRmR5TN44WADCpQiqzxJHp/tSVW328pDjxCEQ==:'.encode('utf-8'))

pubKey = RSA.import_key(rsaTestKeyPssPublic)
verifier = pss.new(pubKey, mask_func=mgf512, salt_bytes=64)

try:
    verified = verifier.verify(h, signed.value)
    print("Verified:")
    print('> YES!')
    results['Static'] = 'YES'
    print()
except (ValueError, TypeError):
    print("Verified:")
    print('> NO!')
    results['Static'] = 'NO'
    print()

print('*' * 30)


## ED 25519
print('ed25519 signature')
print('*' * 30)

coveredContent = {
    str(http_sfv.Item("date")): "Tue, 20 Apr 2021 02:07:56 GMT",
    str(http_sfv.Item("@method")): "POST",
    str(http_sfv.Item("@path")): "/foo",
    str(http_sfv.Item("@authority")): "example.com",
    str(http_sfv.Item("content-type")): "application/json",
    str(http_sfv.Item("content-length")): "18"
}

sigparams = http_sfv.InnerList()
base = '';
for c in coveredContent:
    i = http_sfv.Item()
    i.parse(c.encode())
    sigparams.append(i)
    base += c # already serialized as an Item
    base += ': '
    base += coveredContent[c]
    base += "\n"

sigparams.params['created'] = 1618884475
sigparams.params['keyid'] = 'test-key-ed25519'

sigparamstr = ''
sigparamstr += str(http_sfv.Item("@signature-params"))
sigparamstr += ": "
sigparamstr += str(sigparams)

base += sigparamstr

print("Base string:")
print(base)
print()
print(softwrap(sigparamstr))
print()
print(softwrap('Signature-Input: sig1=' + str(sigparams)))


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
print(hardwrap('Signature: sig1=' + str(signed)))
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


print('Results:')
print()
print('+' + '-' * 37 + '+' + '-' * 5 + '+')
print ("| {:>35} | {:<3} |".format('Test', 'OK?'))
print('+' + '·' * 37 + '+' + '·' * 5 + '+')
for k,v in results.items():
    print ("| {:>35} | {:<3} |".format(k, v))
print('+' + '-' * 37 + '+' + '-' * 5 + '+')

print()
