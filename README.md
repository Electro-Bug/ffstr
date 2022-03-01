# ffstr

!!! WARNING BETA VERSION !!!
	
	Usage python3 ffstr.py options
	
	Options:
	
	BINARY          Link to the chall either as a path ./chall or url 127.0.0.1:1337
	ELF             Link to the supporting elf file, path only
	BITS            32 or 64 bits
	
	Examples:
	
	python3 ffstr.py BINARY=127.0.0.1:1337 BITS=64 ELF=./ffstr64
	python3 ffstr.py BINARY=127.0.0.1:1337 BITS=32 ELF=./ffstr32
	python3 ffstr.py BINARY=./ffstr64 BITS=64 ELF=./ffstr64
	python3 ffstr.py BINARY=./ffstr32 BITS=32 ELF=./ffstr32
