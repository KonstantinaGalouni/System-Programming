OBJS = main.o readfile.o
OBJ1 = main.o
OBJ2 = readfile.o
EXEC1 = picodb
EXEC2 = readfile
GCCC = gcc -c 
GCCO = gcc -o 

all: $(OBJS)
	$(GCCO) $(EXEC1) $(OBJ1)
	$(GCCO) $(EXEC2) $(OBJ2)
main.o: main.c
	$(GCCC) main.c 
readfile.o: readfile.c
	$(GCCC) readfile.c 
clean:
	rm -rf $(OBJ1) $(EXEC1)
	rm -rf $(OBJ2) $(EXEC2)
