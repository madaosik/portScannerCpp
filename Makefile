COMPILER=g++
EXE=ipk-scan
FLAGS=-Wall -Wextra -pedantic -std=c++11

SDIR =./src
ODIR=./obj

_OBJ=Argparser.o Logger.o main.o Scanner.o TcpScanner.o UdpScanner.o
OBJ=$(patsubst %,$(ODIR)/%,$(_OBJ))


$(EXE): $(OBJ)
	$(COMPILER) $(FLAGS) $^ -o $@ -lpcap

$(ODIR)/%.o: $(SDIR)/%.cpp $(SDIR)/%.h
	@mkdir -p $(ODIR)
	$(COMPILER) $(FLAGS) -c -o $@ $< -lpcap

run: $(EXE)
	sudo ./$(EXE) -pu 40-48 -pt 35,53225 localhost

.PHONY: clean run

pack:
	tar -zcvf xlanic04.tar src/* Makefile README.md

clean:
	rm -f -r $(EXE) $(ODIR)
