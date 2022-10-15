TARGET := app
SRCS = message.c deal_response.c main.c
CC := gcc
OBJS = $(SRCS:.c=.o)

$(TARGET):$(OBJS)
	$(CC) -o $@ $^
%.o:%.c
	$(CC) -o $@ -c $<

clean:
	rm -rf $(basename $(TARGET)) $(SRCS:.c=.o)
	rm -f app
