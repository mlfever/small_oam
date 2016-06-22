objects = main.o telnetd.o
src = main.c telnetd.c
target: $(objects)
	gcc -g -o soam $(objects) -lpthread
$(objects):
	gcc -g -c telnetd.c -lpthread
	gcc -g -c main.c
clean:
	rm soam $(objects)
	
