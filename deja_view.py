# Copyright (C) 2022 Alyssa Rahman, Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

# viewgen is under the MIT License
# Licensed under the MIT License (the "MIT License");
#  you may not use this file except in compliance with the MIT License.
# You may obtain a copy of the MIT License at: [package root]/viewgen_LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the MIT License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the MIT License for the specific language governing permissions and limitations under the MIT License.

META = {}
META[
	"TITLE"
] = """\n    ____         _          _    ___             
   / __ \___    (_)___ _   | |  / (_)__ _      __
  / / / / _ \  / / __ `/   | | / / / _ \ | /| / /
 / /_/ /  __/ / / /_/ /    | |/ / /  __/ |/ |/ / 
/_____/\___/_/ /\__,_/     |___/_/\___/|__/|__/  
		  /___/                                  \n"""
META["AUTHOR"] = "Alyssa Rahman @ramen0x3f"
META["CREATED"] = "2022-03-29"
META["LASTUPDATED"] = "2022-03-29"

META["DESCRIPTION"] = """Simple wrapper to read in ViewStates from event logs and bulk decrypt them using viewgen. Note: I renamed viewgen to viewgen.py for this to work."""
META["EXAMPLES"] = """python3 deja_view.py -h"""

from argparse import ArgumentParser, RawTextHelpFormatter
from base64 import b64decode
from binascii import unhexlify
from csv import DictWriter
from hashlib import md5
from sys import stderr
from viewgen import read_webconfig, ViewGen

def decrypt_all(args):
	viewgen = ViewGen(unhexlify(args.vkey), args.valg, unhexlify(args.dkey), args.dalg, args.modifier, True)
	results = []

	if args.logs:
		results.extend(get_events(args.logs))
		for e in results:
			e['Decrypted ViewState'] = viewgen.decrypt(e['ViewState'])[0].decode('ascii')
			e['Payload File Hash'] = get_executable(e['Decrypted ViewState'])
			
	if args.payload:
		results.append({
			"Server Hostname": "N/A",
			"Server Username": "N/A",
			"Requested Page": "N/A",
			"Source IP": "N/A",
			"User-Agent": "N/A",
			"ViewState": args.payload,
			"Decrypted ViewState": viewgen.decrypt(args.payload).decode('ascii'),
			"Payload File Hash": get_executable(viewgen.decrypt(args.payload).decode('ascii'))
		})

	return results

def get_events(log_path):
	events = []

	with open(log_path, "r") as logs:
		for l in logs.readlines():
			if l[0:71] == "1316 | Information | Event code: 4009-++-Viewstate verification failed.":
				request = l.split("-++-")
				events.append({
					"Server Hostname": request[12],
					"Server Username": request[16],
					"Requested Page": request[18],
					"Source IP": request[19],
					"User-Agent": request[27],
					"ViewState": request[28]
				})

	return events

def get_executable(viewstate):
	decoded = b64decode(viewstate)
	offset = decoded.find(b'\x4d\x5a\x90')

	if offset != -1:
		exe = decoded[offset:]
		exe_hash = md5(exe).hexdigest()
		with open(exe_hash, "wb") as exe_out:
			exe_out.write(exe)

		return exe_hash
	else:
		return None

def parse_arguments() -> ArgumentParser:
	# Setting up argparser
	parser = ArgumentParser(
		description=f"{META['TITLE']}By: {META['AUTHOR']}\tLast Updated: {META['LASTUPDATED']}\n\n{META['DESCRIPTION']}",
		formatter_class=RawTextHelpFormatter,
		epilog=f"examples: \n{META['EXAMPLES']}",
	)

	parser.add_argument("--webconfig", help="automatically load keys and algorithms from a web.config file", required=False)
	parser.add_argument("-m", "--modifier", help="VIEWSTATEGENERATOR value", required=False, default="00000000")
	parser.add_argument("--vkey", help="validation key", required=False, default="")
	parser.add_argument("--valg", help="validation algorithm", required=False, default="")
	parser.add_argument("--dkey", help="decryption key", required=False, default="")
	parser.add_argument("--dalg", help="decryption algorithm", required=False, default="")
	parser.add_argument("--logs", help="line delimited file of 1316 / 4009 event logs with ViewState requests", required=False, default="")
	parser.add_argument("-o", "--output", help="filename for TSV output", required=True)
	parser.add_argument("-p", "--payload", help="ViewState payload (base 64 encoded)", required=False, nargs="?")
	args = parser.parse_args()

	if args.webconfig:
		args.vkey, args.valg, args.dkey, args.dalg, args.encrypted = read_webconfig(args.webconfig)

	if "" in [args.vkey, args.valg, args.dkey, args.dalg]:
		print("[!] ERROR: Missing required validation/decryption key and algorithm options.")
		exit()

	if not (args.logs or args.payload):
		print("[!] ERROR: Must provide either an event log file or a payload string.", file=stderr)
		exit()

	return args

if __name__ == "__main__":    
	# Set up arguments and options
	args = parse_arguments()
	decrypted = decrypt_all(args)

	# Error handling
	if len(decrypted) == 0:
		print("[!] ERROR: Did not decrypt/find any ViewStates from provided input.", file=stderr)
		exit()

	# Stats 
	success = len([x for x in decrypted if x['Decrypted ViewState'] is not None])
	exes = len([x for x in decrypted if x['Payload File Hash'] is not None])
	print(f"[+] Stats\n\tTotal ViewStates: {len(decrypted)}\n\tDecrypted ViewStates: {success}\n\tDecryption Errors: {len(decrypted)-success}\n\tExecutables: {exes}")

	# Output
	with open(args.output, "w") as out:
		dict_writer = DictWriter(out, decrypted[0].keys(), delimiter='\t')
		dict_writer.writeheader()
		dict_writer.writerows(decrypted)

	print(f"[+] All done! Output written as a TSV to {args.output}")
