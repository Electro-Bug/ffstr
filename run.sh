

gcc  -m32 -fno-stack-protector -z execstack -z norelro -g -no-pie ./lab/ffstr.c -o ./lab/ffstrlab32
gcc  -fno-stack-protector -z execstack -z norelro -g -no-pie ./lab/ffstr.c -o ./lab/ffstrlab64

socat TCP-LISTEN:1337,reuseaddr,fork EXEC:"./lab/ffstrlab32" &
socat TCP-LISTEN:31337,reuseaddr,fork EXEC:"./lab/ffstrlab64" &

