#!/usr/bin/env python

import http_sfv
import M2Crypto
import hashlib

rsaTestKey = b"""
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAhAKYdtoeoy8zcAcR874L8cnZxKzAGwd7v36APp7Pv6Q2jdsPBRrw
WEBnez6d0UDKDwGbc6nxfEXAy5mbhgajzrw3MOEt8uA5txSKobBpKDeBLOsdJKFq
MGmXCQvEG7YemcxDTRPxAleIAgYYRjTSd/QBwVW9OwNFhekro3RtlinV0a75jfZg
kne/YiktSvLG34lw2zqXBDTC5NHROUqGTlML4PlNZS5Ri2U4aCNx2rUPRcKIlE0P
uKxI4T+HIaFpv8+rdV6eUgOrB2xeI1dSFFn/nnv5OoZJEIB+VmuKn3DCUcCZSFlQ
PSXSfBDiUGhwOw76WuSSsf1D4b/vLoJ10wIDAQAB
-----END RSA PUBLIC KEY-----

-----BEGIN RSA PRIVATE KEY-----
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

rsaTestKeyPublic = b"""
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAhAKYdtoeoy8zcAcR874L8cnZxKzAGwd7v36APp7Pv6Q2jdsPBRrw
WEBnez6d0UDKDwGbc6nxfEXAy5mbhgajzrw3MOEt8uA5txSKobBpKDeBLOsdJKFq
MGmXCQvEG7YemcxDTRPxAleIAgYYRjTSd/QBwVW9OwNFhekro3RtlinV0a75jfZg
kne/YiktSvLG34lw2zqXBDTC5NHROUqGTlML4PlNZS5Ri2U4aCNx2rUPRcKIlE0P
uKxI4T+HIaFpv8+rdV6eUgOrB2xeI1dSFFn/nnv5OoZJEIB+VmuKn3DCUcCZSFlQ
PSXSfBDiUGhwOw76WuSSsf1D4b/vLoJ10wIDAQAB
-----END RSA PUBLIC KEY-----
"""

rsaTestKeyPss = str.encode("""
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr4tmm3r20Wd/PbqvP1s2
+QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry53mm+
oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7OyrFAHq
gDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUAAN5W
Utzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw9lq4
aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oyc6XI
2wIDAQAB
-----END PUBLIC KEY-----

-----BEGIN PRIVATE KEY-----
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
""")

rsaTestKeyPssPublic = b"""
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr4tmm3r20Wd/PbqvP1s2
+QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry53mm+
oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7OyrFAHq
gDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUAAN5W
Utzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw9lq4
aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oyc6XI
2wIDAQAB
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

coveredContent = {
    str(http_sfv.Item("@request-target")): "get /foo",
    str(http_sfv.Item("host")): "example.org",
    str(http_sfv.Item("date")): "Tue, 20 Apr 2021 02:07:55 GMT",
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

key = M2Crypto.RSA.load_key_string(rsaTestKeyPss)

signed = http_sfv.Item(key.sign_rsassa_pss(str.encode(base), algo='sha512'))

print("Signed:")
print(signed)
print()
print(hardwrap(str(signed).strip(':'), 0))
print()
print(hardwrap('Signature: sig1=' + str(signed)))
print()

# publicKey = M2Crypto.RSA.load_key_string(rsaTestKeyPssPublic)

verified = key.verify_rsassa_pss(str.encode(base), signed.value, algo='sha512')

print("Verified:")
print('> YES!' if verified else '> NO!')
print()

print('*' * 30)


## reverse proxy signature

# old signatures

oldsiginput = softwrap('Signature-Input: sig1=' + str(sigparams), 4)
oldsig = hardwrap('Signature: sig1=' + str(signed), 4)

sig1value = signed

sig1hd = http_sfv.Item('signature')
sig1hd.params['key'] = 'sig1'

coveredContent = {}

coveredContent[str(sig1hd)] = str(sig1value)
coveredContent[str("x-forwarded-for")] = "192.0.2.123"


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
print(softwrap(sigparamstr))
print()
print(softwrap(str(sig1hd) + ': ' + str(sig1value)))
print()
print(oldsiginput + ', \\')
print(softwrap('  proxy_sig=' + str(sigparams), 4))


key = M2Crypto.RSA.load_key_string(rsaTestKey)

hashed = hashlib.new('sha256', str.encode(base)).digest()

signed = http_sfv.Item(key.sign(hashed, algo='sha256'))

print("Signed:")
print(signed)
print()
print(hardwrap(str(signed).strip(':'), 0))
print()
print(oldsig + ', \\')
print(hardwrap('  proxy_sig=' + str(signed), 4))
print()

# publicKey = M2Crypto.RSA.load_key_string(rsaTestKeyPublic)

verified = key.verify(hashed, signed.value, algo='sha256')

print("Verified:")
print('> YES!' if verified else '> NO!')
print()



print('*' * 30)


## minimal signature


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

key = M2Crypto.RSA.load_key_string(rsaTestKeyPss)

signed = http_sfv.Item(key.sign_rsassa_pss(str.encode(base), algo='sha512'))

print("Signed:")
print(signed)
print()
print(hardwrap(str(signed).strip(':'), 0))
print()
print(hardwrap('Signature: sig1=' + str(signed)))

print()

verified = key.verify_rsassa_pss(str.encode(base), signed.value, algo='sha512')

print("Verified:")
print('> YES!' if verified else '> NO!')
print()


print('*' * 30)


## header coverage

coveredContent = {
    str(http_sfv.Item("host")): "example.com",
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


key = M2Crypto.RSA.load_key_string(rsaTestKeyPss)

signed = http_sfv.Item(key.sign_rsassa_pss(str.encode(base), algo='sha512'))

print("Signed:")
print(signed)
print()
print(hardwrap(str(signed).strip(':'), 0))
print()
print(hardwrap('Signature: sig1=' + str(signed)))
print()

verified = key.verify_rsassa_pss(str.encode(base), signed.value, algo='sha512')

print("Verified:")
print('> YES!' if verified else '> NO!')
print()




print('*' * 30)


## full coverage

coveredContent = {
    str(http_sfv.Item("@request-target")): "post /foo?param=value&pet=dog",
    str(http_sfv.Item("host")): "example.com",
    str(http_sfv.Item("date")): "Tue, 20 Apr 2021 02:07:55 GMT",
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


key = M2Crypto.RSA.load_key_string(rsaTestKeyPss)

signed = http_sfv.Item(key.sign_rsassa_pss(str.encode(base), algo='sha512'))

print("Signed:")
print(signed)
print()
print(hardwrap(str(signed).strip(':'), 0))
print()
print(softwrap('Signature: sig1=' + str(signed)))
print()

verified = key.verify_rsassa_pss(str.encode(base), signed.value, algo='sha512')

print("Verified:")
print('> YES!' if verified else '> NO!')
print()




print('*' * 30)
