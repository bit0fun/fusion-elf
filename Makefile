CC=gcc
LDFLAGS= -lncurses 
CFLAGS= -g #-std=c99
OBJ= fusion-elf.o elf_read.o
DEPS= fusion-elf.h elf_read.h 


fusion-elf: $(OBJ)
	mv *.o ./obj/
		
%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<
clean:
	rm -rf *.o *.gch
	rm -rf ./obj/*.o

distclean:
	rm -rf *.o *.gch 
	rm -rf ./obj/*.o
