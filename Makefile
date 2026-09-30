default: program

FILE=wlanmoncap

program: $(FILE).c Makefile
	gcc $(FILE).c -o $(FILE) -lpcap
