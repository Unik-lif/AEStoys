objs = AES_Process.o AES_Round.o Base_change.o AES_trivial.o
aes : $(objs)
	gcc -o aes $(objs)

AES_Process.o: AES_Process.c aes.h
	gcc -c AES_Process.c
AES_Round.o: AES_Round.c AES_Process.c aes.h
	gcc -c AES_Round.c AES_Process.c
Base_change.o: Base_change.c aes.h
	gcc -c Base_change.c 
AES_trivial.o: AES_trivial.c AES_Round.c Base_change.c aes.h
	gcc -c AES_trivial.c AES_Round.c Base_change.c
clean:
	rm aes $(objs)
