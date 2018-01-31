#!/usr/bin/python

import os
import binascii
import ecdsa
import hashlib
import simplejson
import urllib2
import time

class Address(object):

    @classmethod
    def from_secret(cls, secret):
        if len(secret) == 64:
            return Address(binascii.unhexlify(secret))
        elif len(secret) == 32:
            return Address(secret)
        else:
            raise Exception("Secret has to be exactly 32 bytes")

    @classmethod
    def from_passphrase(cls, passphrase):
        secret = passphrase.encode('utf8')
        for i in range(1): # just one round
            secret = shash(secret)
        return Address(secret)

    @classmethod
    def from_privkey(cls, privkey):
        secret = base58_check_decode(privkey, 0x80)
        return Address(secret)

    @classmethod
    def from_electrum_seed(cls, seed, idx):
        raise NotImplementedError

    def __init__(self, secret = None):
        if not secret:
            secret = os.urandom(32)
        self.secret = ecdsa.util.string_to_number(secret)
        self.pubkey = ecdsa.ecdsa.Public_key(ecdsa.ecdsa.generator_secp256k1, ecdsa.ecdsa.generator_secp256k1 * self.secret)
        self.privkey = ecdsa.ecdsa.Private_key(self.pubkey, secret)
        pubhex = ('04' + '%064x' % self.pubkey.point.x() + '%064x' % self.pubkey.point.y()).decode('hex')
        self.pub = base58_check_encode(rhash(pubhex))
        if self.pubkey.point.y() % 2:
            pubhex = ('03' + '%064x' % self.pubkey.point.x()).decode('hex')
        else:
            pubhex = ('02' + '%064x' % self.pubkey.point.x()).decode('hex')
        self.pubc = base58_check_encode(rhash(pubhex))
        self.priv = base58_check_encode(self.privkey.secret_multiplier, 0x80)

def shash(s):
    return hashlib.sha256(s).digest()

def dhash(s):
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()

def rhash(s):
    try:
        md = hashlib.new('ripemd160')
        md.update(hashlib.sha256(s).digest())
        return md.digest()
    except:
        import ripemd
        md = ripemd.new(hashlib.sha256(s).digest())
        return md.digest()
		
base58_digits = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def base58_encode(n):
    l = []
    while n > 0:
        n, r = divmod(n, 58)
        l.insert(0,(base58_digits[r]))
    return ''.join(l)

def base58_decode(s):
    n = 0
    for ch in s:
        n *= 58
        digit = base58_digits.index(ch)
        n += digit
    return n

def base58_encode_padded(s):
    res = base58_encode(int('0x' + s.encode('hex'), 16))
    pad = 0
    for c in s:
        if c == chr(0):
            pad += 1
        else:
            break
    return base58_digits[0] * pad + res

def base58_decode_padded(s):
    pad = 0
    for c in s:
        if c == base58_digits[0]:
            pad += 1
        else:
            break
    h = '%x' % base58_decode(s)
    if len(h) % 2:
        h = '0' + h
    res = h.decode('hex')
    return chr(0) * pad + res

def base58_check_encode(s, version = 0):
    vs = chr(version) + s
    check = dhash(vs)[:4]
    return base58_encode_padded(vs + check)

def base58_check_decode(s, version = 0):
    k = base58_decode_padded(s)
    v0, data, check0 = k[0], k[1:-4], k[-4:]
    check1 = dhash(v0 + data)[:4]
    if check0 != check1:
        raise BaseException('checksum error')
    if version != ord(v0):
        raise BaseException('version mismatch')
    return data


class WebApi(object):

    @classmethod
    def balance_bci(cls, address):
        h = urllib2.urlopen('http://blockchain.info/rawaddr/%s' % address)
        json = simplejson.load(h)
        h.close()
        f = float(json['final_balance'])/100000000
        return f

    @classmethod
    def balance_bec(cls, address):
        h = urllib2.urlopen('http://blockexplorer.com/q/addressbalance/%s' % address)
        f = float(h.read())
        h.close()
        return f

    @classmethod
    def fullbalance_bci(cls, address):
        h = urllib2.urlopen('http://blockchain.info/rawaddr/%s' % address)
        json = simplejson.load(h)
        h.close()
        r = float(json['total_received'])/100000000
        s = -float(json['total_sent'])/100000000
        f = float(json['final_balance'])/100000000
        return (f, r, s)

    @classmethod
    def fullbalance_bec(cls, address):
        h = urllib2.urlopen('http://blockexplorer.com/q/getreceivedbyaddress/%s' % address)
        r = float(h.read())
        h.close()
        h = urllib2.urlopen('http://blockexplorer.com/q/getsentbyaddress/%s' % address)
        s = -float(h.read())
        h.close()
        h = urllib2.urlopen('http://blockexplorer.com/q/addressbalance/%s' % address)
        f = float(h.read())
        h.close()
        return (f, r, s)

print '-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-'
print '-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-'
print '-*-*                                                                 *-*-'
print '-*-*                     Bitcoin address checker                     *-*-'
print '-*-*                       2017  Arthur Serck                        *-*-'
print '-*-*                    (Uses public coinkit code)                   *-*-'
print '-*-*                                                                 *-*-'
print '-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-'
print '-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-'
print

while True:
    try:
        a = Address()
        # use blockexplorer.com
        # balance = WebApi.balance_bec(a.pub)
        # use blockchain.info
        balance = WebApi.balance_bci(a.pub)
        print a.pub, a.priv, balance
        if balance > 0:
            break
        time.sleep(5)
    except:
	    pass
		
    else:
	    print ' Found empty balance. Generating new address...'

print 'Hurray! Balance found, import private key into compatible software at your own discretion.'
time.sleep(500000)
time.sleep(500000)