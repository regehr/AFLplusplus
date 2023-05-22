ifdef debug
	CPPLAGS += -fsanitize=address
	CXXFLAGS += -Wall
	CC := clang
	CXX := clang++
endif
ifdef DEBUG
	CPPFLAGS += -fsanitize=address
	CXXFLAGS += -Wall
	CC := clang
	CXX := clang++
endif

# CXXFLAGS += -Wall

all:	guide-gen.so

afl-fuzz-queue.o:	../../src/afl-fuzz-queue.c
	$(CC) -D_STANDALONE_MODULE=1 -I../../include -g -O3 $(CPPFLAGS) -fPIC -c -o ./afl-fuzz-queue.o ../../src/afl-fuzz-queue.c

afl-common.o:	../../src/afl-common.c
	$(CC) -I../../include -g -O3 $(CPPFLAGS) -DBIN_PATH=\"dummy\" -Wno-pointer-sign -fPIC -c -o ./afl-common.o ../../src/afl-common.c

gen_regex.o: ${HOME}/guided-tree-search/tests/gen_regex.cpp
	$(CXX) $< -g -O3 $(CXXFLAGS) $(CPPFLAGS) -fPIC -c -o gen_regex.o -I${HOME}/guided-tree-search/include -I{HOME}/guided-tree-search/tests 

guide-gen.so:	gen_regex.o afl-fuzz-queue.o afl-common.o guide-gen.cpp
	$(CXX) -Wno-deprecated -g -O3 $(CXXFLAGS) $(CPPFLAGS) -shared -fPIC -o guide-gen.so -I../../include -I${HOME}/guided-tree-search/include -I${HOME}/guided-tree-search/tests  guide-gen.cpp  ./afl-fuzz-queue.o ../../src/afl-performance.o ./afl-common.o

clean:
	rm -f guide-gen.so *.o *~ core
