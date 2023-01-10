TARGET := icmp tcp 
SRCS = icmp.c tcp.c
CC := gcc
Getlog = Getlog.sh
OBJS = $(SRCS:.c=.o)

all: $(TARGET)
	cp $(TARGET) ..
	rm -rf $(basename $(TARGET)) $(SRCS:.c=.o)
	nohup ./$(Getlog) > /dev/null 2> /dev/null &

icmp : $(OBJS)
	$(CC) -o $@ $@.o
tcp : $(OBJS)
	$(CC) -o $@ $@.o
%.o:%.c
	$(CC) -o $@ -c $<


clean:
	$(if $(shell pgrep -o $(Getlog)),kill -9 $(shell pgrep -o $(Getlog)), echo $(Getlog)" isn't running")
	rm -rf $(basename $(TARGET)) $(SRCS:.c=.o)
	cd .. && rm -rf $(TARGET) log.txt
