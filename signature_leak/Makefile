main:
	mkdir -p build
	gcc -c src/rps.c -I ../include -L ../. -lrbc -o build/rps.o
	gcc -c src/main.c -I ../include -L ../. -lrbc -o build/main.o
	gcc build/main.o build/rps.o -I ../include -L ../. -lrbc -o build/main

clean:
	rm build/*
