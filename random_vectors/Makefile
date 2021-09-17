main:
	mkdir -p build
	gcc -c src/main.c -I ../include -L ../. -lrbc -o build/main.o
	gcc build/main.o -I ../include -L ../. -lrbc -o build/main

clean:
	rm build/*
