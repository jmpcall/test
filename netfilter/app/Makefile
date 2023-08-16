BASE_DIR := $(shell pwd)
INSTALL_DIR=$(BASE_DIR)/lib3rd
BUILD_DIR=$(BASE_DIR)/build
BUILD_INSTALL_DIR=$(BUILD_DIR)$(INSTALL_DIR)

nf_test : nf_test.o
	gcc -o nf_test nf_test.o -L$(BUILD_INSTALL_DIR)/lib -lnetfilter_queue -lnfnetlink -lpthread

nf_test.o : nf_test.c
	gcc -c nf_test.c -I$(BUILD_INSTALL_DIR)/include -g -Wall

prepare :
	tar -jxf 3rd/libmnl*.tar.bz2 && mv libmnl* libmnl
	cd libmnl && ./configure --prefix=$(INSTALL_DIR) && make && make DESTDIR=$(BUILD_DIR) install
	tar jxf 3rd/libnfnetlink-*.tar.bz2 && mv libnfnetlink-* libnfnetlink
	cd libnfnetlink && ./configure --prefix=$(INSTALL_DIR) && make && make DESTDIR=$(BUILD_DIR) install
	tar jxf 3rd/libnetfilter_queue-*.tar.bz2 && mv libnetfilter_queue-* libnetfilter_queue
	cd libnetfilter_queue && LIBNFNETLINK_CFLAGS="-I$(BUILD_INSTALL_DIR)/include/" LIBNFNETLINK_LIBS="-L$(BUILD_INSTALL_DIR)/lib -lnfnetlink" LIBMNL_CFLAGS="-I$(BUILD_INSTALL_DIR)/include" LIBMNL_LIBS="-L$(BUILD_INSTALL_DIR)/lib -lmnl" ./configure --prefix=$(INSTALL_DIR) && make && make DESTDIR=$(BUILD_DIR) install

clean :
	rm nf_test nf_test.o -f

deep_clean : clean
	rm build lib* -fr
