#!/usr/bin/env python

import http_sfv
import M2Crypto
import hashlib
import jose
import base64
import jose.jws
import json

rsajwk = {
    "kid": "gnap-rsa",
    "p": "xS4-YbQ0SgrsmcA7xDzZKuVNxJe3pCYwdAe6efSy4hdDgF9-vhC5gjaRki1wWuERSMW4Tv44l5HNrL-Bbj_nCJxr_HAOaesDiPn2PnywwEfg3Nv95Nn-eilhqXRaW-tJKEMjDHu_fmJBeemHNZI412gBnXdGzDVo22dvYoxd6GM",
    "kty": "RSA",
    "q": "rVdcT_uy-CD0GKVLGpEGRR7k4JO6Tktc8MEHkC6NIFXihk_6vAIOCzCD6LMovMinOYttpRndKoGTNdJfWlDFDScAs8C5n2y1STCQPRximBY-bw39-aZqJXMxOLyPjzuVgiTOCBIvLD6-8-mvFjXZk_eefD0at6mQ5qV3U1jZt88",
    "d": "FHlhdTF0ozTliDxMBffT6aJVKZKmbbFJOVNten9c3lXKB3ux3NAb_D2dB7inp9EV23oWrDspFtvCvD9dZrXgRKMHofkEpo_SSvBZfgtH-OTkbY_TqtPFFLPKAw0JX5cFPnn4Q2xE4n-dQ7tpRCKl59vZLHBrHShr90zqzFp0AKXU5fjb1gC9LPwsFA2Fd7KXmI1drQQEVq9R-o18Pnn4BGQNQNjO_VkcJTiBmEIVT_KJRPdpVJAmbgnYWafL_hAfeb_dK8p85yurEVF8nCK5oO3EPrqB7IL4UqaEn5Sl3u0j8x5or-xrrAoNz-gdOv7ONfZY6NFoa-3f8q9wBAHUuQ",
    "e": "AQAB",
    "qi": "ogpNEkDKg22Rj9cDV_-PJBZaXMk66Fp557RT1tafIuqJRHEufSOYnstobWPJ0gHxv1gVJw3gm-zYvV-wTMNgr2wVsBSezSJjPSjxWZtmT2z68W1DuvKkZy15vz7Jd85hmDlriGcXNCoFEUsGLWkpHH9RwPIzguUHWmTt8y0oXyI",
    "dp": "dvCKGI2G7RLh3WyjoJ_Dr6hZ3LhXweB3YcY3qdD9BnxZ71mrLiMQg4c_EBnwqCETN_5sStn2cRc2JXnvLP3G8t7IFKHTT_i_TSTacJ7uT04MSa053Y3RfwbvLjRNPR0UKAE3ZxROUoIaVNuU_6-QMf8-2ilUv2GIOrCN87gP_Vk",
    "alg": "RS256",
    "dq": "iMZmELaKgT9_W_MRT-UfDWtTLeFjIGRW8aFeVmZk9R7Pnyt8rNzyN-IQM40ql8u8J6vc2GmQGfokLlPQ6XLSCY68_xkTXrhoU1f-eDntkhP7L6XawSKOnv5F2H7wyBQ75HUmHTg8AK2B_vRlMyFKjXbVlzKf4kvqChSGEz4IjQ",
    "n": "hYOJ-XOKISdMMShn_G4W9m20mT0VWtQBsmBBkI2cmRt4Ai8BfYdHsFzAtYKOjpBR1RpKpJmVKxIGNy0g6Z3ad2XYsh8KowlyVy8IkZ8NMwSrcUIBZGYXjHpwjzvfGvXH_5KJlnR3_uRUp4Z4Ujk2bCaKegDn11V2vxE41hqaPUnhRZxe0jRETddzsE3mu1SK8dTCROjwUl14mUNo8iTrTm4n0qDadz8BkPo-uv4BC0bunS0K3bA_3UgVp7zBlQFoFnLTO2uWp_muLEWGl67gBq9MO3brKXfGhi3kOzywzwPTuq-cVQDyEN7aL0SxCb3Hc4IdqDaMg8qHUyObpPitDQ"
}

rsajwkpublic = {
    "kid": "gnap-rsa",
    "kty": "RSA",
    "e": "AQAB",
    "alg": "RS256",
    "n": "hYOJ-XOKISdMMShn_G4W9m20mT0VWtQBsmBBkI2cmRt4Ai8BfYdHsFzAtYKOjpBR1RpKpJmVKxIGNy0g6Z3ad2XYsh8KowlyVy8IkZ8NMwSrcUIBZGYXjHpwjzvfGvXH_5KJlnR3_uRUp4Z4Ujk2bCaKegDn11V2vxE41hqaPUnhRZxe0jRETddzsE3mu1SK8dTCROjwUl14mUNo8iTrTm4n0qDadz8BkPo-uv4BC0bunS0K3bA_3UgVp7zBlQFoFnLTO2uWp_muLEWGl67gBq9MO3brKXfGhi3kOzywzwPTuq-cVQDyEN7aL0SxCb3Hc4IdqDaMg8qHUyObpPitDQ"
}

rsacert = """
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCFg4n5c4ohJ0wx
KGf8bhb2bbSZPRVa1AGyYEGQjZyZG3gCLwF9h0ewXMC1go6OkFHVGkqkmZUrEgY3
LSDpndp3ZdiyHwqjCXJXLwiRnw0zBKtxQgFkZheMenCPO98a9cf/komWdHf+5FSn
hnhSOTZsJop6AOfXVXa/ETjWGpo9SeFFnF7SNERN13OwTea7VIrx1MJE6PBSXXiZ
Q2jyJOtObifSoNp3PwGQ+j66/gELRu6dLQrdsD/dSBWnvMGVAWgWctM7a5an+a4s
RYaXruAGr0w7duspd8aGLeQ7PLDPA9O6r5xVAPIQ3tovRLEJvcdzgh2oNoyDyodT
I5uk+K0NAgMBAAECggEAFHlhdTF0ozTliDxMBffT6aJVKZKmbbFJOVNten9c3lXK
B3ux3NAb/D2dB7inp9EV23oWrDspFtvCvD9dZrXgRKMHofkEpo/SSvBZfgtH+OTk
bY/TqtPFFLPKAw0JX5cFPnn4Q2xE4n+dQ7tpRCKl59vZLHBrHShr90zqzFp0AKXU
5fjb1gC9LPwsFA2Fd7KXmI1drQQEVq9R+o18Pnn4BGQNQNjO/VkcJTiBmEIVT/KJ
RPdpVJAmbgnYWafL/hAfeb/dK8p85yurEVF8nCK5oO3EPrqB7IL4UqaEn5Sl3u0j
8x5or+xrrAoNz+gdOv7ONfZY6NFoa+3f8q9wBAHUuQKBgQDFLj5htDRKCuyZwDvE
PNkq5U3El7ekJjB0B7p59LLiF0OAX36+ELmCNpGSLXBa4RFIxbhO/jiXkc2sv4Fu
P+cInGv8cA5p6wOI+fY+fLDAR+Dc2/3k2f56KWGpdFpb60koQyMMe79+YkF56Yc1
kjjXaAGdd0bMNWjbZ29ijF3oYwKBgQCtV1xP+7L4IPQYpUsakQZFHuTgk7pOS1zw
wQeQLo0gVeKGT/q8Ag4LMIPosyi8yKc5i22lGd0qgZM10l9aUMUNJwCzwLmfbLVJ
MJA9HGKYFj5vDf35pmolczE4vI+PO5WCJM4IEi8sPr7z6a8WNdmT9558PRq3qZDm
pXdTWNm3zwKBgHbwihiNhu0S4d1so6Cfw6+oWdy4V8Hgd2HGN6nQ/QZ8We9Zqy4j
EIOHPxAZ8KghEzf+bErZ9nEXNiV57yz9xvLeyBSh00/4v00k2nCe7k9ODEmtOd2N
0X8G7y40TT0dFCgBN2cUTlKCGlTblP+vkDH/PtopVL9hiDqwjfO4D/1ZAoGAAIjG
ZhC2ioE/f1vzEU/lHw1rUy3hYyBkVvGhXlZmZPUez58rfKzc8jfiEDONKpfLvCer
3NhpkBn6JC5T0Oly0gmOvP8ZE164aFNX/ng57ZIT+y+l2sEijp7+Rdh+8MgUO+R1
Jh04PACtgf70ZTMhSo121Zcyn+JL6goUhhM+CI0CgYEAogpNEkDKg22Rj9cDV/+P
JBZaXMk66Fp557RT1tafIuqJRHEufSOYnstobWPJ0gHxv1gVJw3gm+zYvV+wTMNg
r2wVsBSezSJjPSjxWZtmT2z68W1DuvKkZy15vz7Jd85hmDlriGcXNCoFEUsGLWkp
HH9RwPIzguUHWmTt8y0oXyI=
-----END PRIVATE KEY-----
"""




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




## Detached JWS Example

body = """
{
    "access_token": {
        "access": [
            "dolphin-metadata"
        ]
    },
    "interact": {
        "start": ["redirect"],
        "finish": {
            "method": "redirect",
            "uri": "https://client.foo/callback",
            "nonce": "VJLO6A4CAYLBXHTR0KRO"
        }
    },
    "client": {
      "proof": "jwsd",
      "key": {
        "jwk": {
            "kid": "gnap-rsa",
            "kty": "RSA",
            "e": "AQAB",
            "alg": "RS256",
            "n": "hYOJ-XOKISdMMShn_G4W9m20mT0VWtQBsmBBkI2cmRt4Ai8BfYdHsFzAtYKOjpBR1RpKpJmVKxIGNy0g6Z3ad2XYsh8KowlyVy8IkZ8NMwSrcUIBZGYXjHpwjzvfGvXH_5KJlnR3_uRUp4Z4Ujk2bCaKegDn11V2vxE41hqaPUnhRZxe0jRETddzsE3mu1SK8dTCROjwUl14mUNo8iTrTm4n0qDadz8BkPo-uv4BC0bunS0K3bA_3UgVp7zBlQFoFnLTO2uWp_muLEWGl67gBq9MO3brKXfGhi3kOzywzwPTuq-cVQDyEN7aL0SxCb3Hc4IdqDaMg8qHUyObpPitDQ"
        }
      }
      "display": {
        "name": "My Client Display Name",
        "uri": "https://client.foo/"
      },
    }
}
"""
print(hardwrap(body))
print()

jwsHeader = {
    "alg": rsajwk['alg'],
    "kid": rsajwk['kid'],
    "uri": "https://server.example.com/gnap",
    "htm": "POST",
    "typ": "gnap-binding+jwsd",
    "created": 1618884475
}

print('Header:')
print(jwsHeader)
print()
print(json.dumps(jwsHeader, indent=4))
print()

hashed = hashlib.new('sha256', str.encode(body)).digest()
print('Hashed:')
print(base64.urlsafe_b64encode(hashed).decode('utf-8').replace('=', ''))
print()

signed = jose.jws.sign(hashed, rsajwk, headers=jwsHeader, algorithm=rsajwk['alg'])

print('Signed:')
print(signed)
print()
print(hardwrap('Detached-JWS: ' + signed))

print('*' * 30)

## Attached JWS Example

body = """
{
    "access_token": {
        "access": [
            "dolphin-metadata"
        ]
    },
    "interact": {
        "start": ["redirect"],
        "finish": {
            "method": "redirect",
            "uri": "https://client.foo/callback",
            "nonce": "VJLO6A4CAYLBXHTR0KRO"
        }
    },
    "client": {
      "proof": "jws",
      "key": {
        "jwk": {
            "kid": "gnap-rsa",
            "kty": "RSA",
            "e": "AQAB",
            "alg": "RS256",
            "n": "hYOJ-XOKISdMMShn_G4W9m20mT0VWtQBsmBBkI2cmRt4Ai8BfYdHsFzAtYKOjpBR1RpKpJmVKxIGNy0g6Z3ad2XYsh8KowlyVy8IkZ8NMwSrcUIBZGYXjHpwjzvfGvXH_5KJlnR3_uRUp4Z4Ujk2bCaKegDn11V2vxE41hqaPUnhRZxe0jRETddzsE3mu1SK8dTCROjwUl14mUNo8iTrTm4n0qDadz8BkPo-uv4BC0bunS0K3bA_3UgVp7zBlQFoFnLTO2uWp_muLEWGl67gBq9MO3brKXfGhi3kOzywzwPTuq-cVQDyEN7aL0SxCb3Hc4IdqDaMg8qHUyObpPitDQ"
        }
      }
      "display": {
        "name": "My Client Display Name",
        "uri": "https://client.foo/"
      },
    }
}
"""
print(hardwrap(body))
print()

jwsHeader = {
    "alg": rsajwk['alg'],
    "kid": rsajwk['kid'],
    "uri": "https://server.example.com/gnap",
    "htm": "POST",
    "typ": "gnap-binding+jwsd",
    "created": 1618884475
}

print('Header:')
print(jwsHeader)
print()
print(json.dumps(jwsHeader, indent=4))
print()

signed = jose.jws.sign(body.encode('UTF-8'), rsajwk, headers=jwsHeader, algorithm=rsajwk['alg'])

print('Signed:')
print(signed)
print()
print(hardwrap(signed, 0))

print('*' * 30)