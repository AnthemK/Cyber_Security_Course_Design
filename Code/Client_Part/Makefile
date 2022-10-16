TARGET := client
INCLUDES := -I. -I../Common_Part
SRCS = message.c deal_response.c main.c
CC := gcc
OBJS = $(SRCS:.c=.o)

$(TARGET):$(OBJS)
	$(CC) -o $@ $^
	rm -rf $(SRCS:.c=.o)
%.o:%.c
	$(CC) $(INCLUDES) -o $@ -c $<

install:
	cp $(TARGET) ..
	rm -f $(TARGET)

clean:
	rm -rf $(basename $(TARGET)) $(SRCS:.c=.o)
	rm -rf ../$(TARGET)
