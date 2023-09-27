# CXX:= g++ --std=c++14 -O2 -L/usr/local/lib # FIXME Huff: this is the original line
CXX:= g++ --std=c++14 -L/usr/local/lib -g
# CC:= gcc -O2 -L/usr/local/lib	# FIXME Huff: this is the original line
CC:= gcc -L/usr/local/lib -g

SRC:=.
B_SRC:=.
UTILSRC=./xapp-utils
MSGSRC:=./xapp-mgmt

ASNSRC:=../asn1c_defs
ASNSRC_BOUNCER:=../asn1c_defs/bouncer
E2APSRC:=./xapp-asn/e2ap
E2SMSRC:=./xapp-asn/e2sm

PROTOBUFSRC:=../ext/protobuf

####### Logging library and flags
CLOGFLAGS:= `pkg-config mdclog --cflags`
LOG_LIBS:= `pkg-config mdclog --libs`
CURL_LIBS:= `pkg-config libcurl --libs`
RNIB_LIBS:= -pthread /usr/local/include/rnib/rnibreader.a
PROTO_LIBS:= `pkg-config --libs protobuf`
SSL_LIBS:= `pkg-config --libs openssl`
#CRYPTO_LIBS:= `pkg-config --libs libcrypto`
# print the folling SSL Libs using make target print-SSL_LIBS (e.g. make print-SSL_LIBS)
# @echo "SSL Libs: $(SSL_LIBS)"
######## Keep include dirs separate so we have transparency


BASEFLAGS=  -Wall -std=c++14 $(CLOGFLAGS) -g
C_BASEFLAGS= -Wall $(CLOGFLAGS) -DASN_DISABLE_OER_SUPPORT
# C_BASEFLAGS= -Wall $(CLOGFLAGS) -DASN_EMIT_DEBUG=1	# Huff Debug
# C_BASEFLAGS= -Wall $(CLOGFLAGS)

XAPPFLAGS= -I./
B_FLAGS= -I./
UTILFLAGS= -I$(UTILSRC)
MSGFLAGS= -I$(MSGSRC)

ASNFLAGS=-I$(ASNSRC) -DASN_DISABLE_OER_SUPPORT
# ASNFLAGS=-I$(ASNSRC)
ASN_BOUNCER_FLAGS=-I$(ASNSRC_BOUNCER)
E2APFLAGS = -I$(E2APSRC)
E2SMFLAGS = -I$(E2SMSRC)
PROTOBUFFLAGS = -I$(PROTOBUFSRC)

########libs

LIBS= -lsdl -lrmr_si -lpthread -lm -lboost_system -lcpprest $(LOG_LIBS) $(CURL_LIBS) $(RNIB_LIBS) $(PROTO_LIBS) $(SSL_LIBS) #$(CRYPTO_LIBS)
COV_FLAGS= -fprofile-arcs -ftest-coverage

#######
B_XAPP_SRC= b_xapp_main.cc
XAPP_SRC= xapp.cc
UTIL_SRC= $(wildcard $(UTILSRC)/*.cc)
MSG_SRC= $(wildcard $(MSGSRC)/*.cc)

E2AP_SRC= $(wildcard $(E2APSRC)/*.cc)
E2SM_SRC= $(wildcard $(E2SMSRC)/*.cc)
ASN1C_SRC= $(wildcard $(ASNSRC)/*.c)
ASN1C_B_SRC= $(wildcard $(ASNSRC)/bouncer/*.c)
PROTOBUF_SRC = $(wildcard $(PROTOBUFSRC)/*.cc)

##############Objects
UTIL_OBJ=${UTIL_SRC:.cc=.o}
XAPP_OBJ=${XAPP_SRC:.cc=.o}
B_XAPP_OBJ= ${B_XAPP_SRC:.cc=.o}
MSG_OBJ= ${MSG_SRC:.cc=.o}

E2AP_OBJ = $(E2AP_SRC:.cc=.o)
E2SM_OBJ = $(E2SM_SRC:.cc=.o)
ASN1C_MODULES = $(ASN1C_SRC:.c=.o)
ASN1C_BOUNCER_MODULES = $(ASN1C_B_SRC:.c=.o)
PROTOBUF_OBJ = $(PROTOBUF_SRC:.cc=.o)

$(ASN1C_MODULES): export CFLAGS = $(C_BASEFLAGS) $(ASNFLAGS) $(ASN_BOUNCER_FLAGS)
$(ASN1C_BOUNCER_MODULES): export CFLAGS = $(C_BASEFLAGS) $(ASNFLAGS) $(ASN_BOUNCER_FLAGS)
$(UTIL_OBJ):export CPPFLAGS=$(BASEFLAGS) $(UTILFLAGS) $(E2APFLAGS) $(E2SMFLAGS) $(ASNFLAGS) $(ASN_BOUNCER_FLAGS) $(MSGFLAGS)

$(MSG_OBJ):export CPPFLAGS=$(BASEFLAGS) $(MSGFLAGS) $(ASNFLAGS) $(ASN_BOUNCER_FLAGS) $(E2APFLAGS) $(E2SMFLAGS) $(PROTOBUFFLAGS) -I/usr/local/include
$(E2AP_OBJ): export CPPFLAGS = $(BASEFLAGS) $(ASNFLAGS) $(ASN_BOUNCER_FLAGS) $(E2APFLAGS) -I/usr/local/include
$(E2SM_OBJ): export CPPFLAGS = $(BASEFLAGS) $(ASNFLAGS) $(ASN_BOUNCER_FLAGS) $(E2SMFLAGS) -I/usr/local/include
$(XAPP_OBJ): export CPPFLAGS = $(BASEFLAGS) $(XAPPFLAGS) $(UTILFLAGS) $(MSGFLAGS) $(E2APFLAGS) $(E2SMFLAGS) $(ASNFLAGS) $(ASN_BOUNCER_FLAGS) $(PROTOBUFFLAGS) -I/usr/local/include
$(PROTOBUF_OBJ): export CPPFLAGS = $(BASEFLAGS) $(MSGFLAGS) $(PROTOBUFFLAGS) -I/usr/local/include

$(B_XAPP_OBJ):export CPPFLAGS=$(BASEFLAGS) $(B_FLAGS) $(XAPPFLAGS) $(UTILFLAGS) $(MSGFLAGS) $(E2APFLAGS) $(E2SMFLAGS) $(ASNFLAGS) $(ASN_BOUNCER_FLAGS) $(PROTOBUFFLAGS) -I/usr/local/include

OBJ= $(B_XAPP_OBJ) $(UTIL_OBJ) $(MSG_OBJ)  $(ASN1C_MODULES) $(ASN1C_BOUNCER_MODULES) $(E2AP_OBJ) $(E2SM_OBJ) $(XAPP_OBJ) $(PROTOBUF_OBJ)

print-%  : ; @echo $* = $($*)

b_xapp_main: $(OBJ)
	$(CXX) -o $@  $(OBJ) $(RNIBFLAGS) $(CPPFLAGS) $(CLOGFLAGS) $(LIBS)

install: b_xapp_main
	install -D b_xapp_main /usr/local/bin/b_xapp_main

clean:
	-rm -f *.o $(ASNSRC)/*.o $(ASNSRC_BOUNCER)/*.o $(E2APSRC)/*.o $(UTILSRC)/*.o $(E2SMSRC)/*.o $(MSGSRC)/*.o $(PROTOBUFSRC)/*.o b_xapp_main
