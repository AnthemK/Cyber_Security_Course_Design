#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include <linux/ip.h>
#include <assert.h>
typedef long long ll;
const int max_packet_num = 1000;
const int max_bytestream_len = 1000000;

// TODO: unfinished work ,read from the bytestram of legal message, and form a array of struct iphdr for further analysis.
// Not in Makefile 

int BF(char* str, char* sub)//str代表主串，sub代表子串
{
	assert(str&&sub);//断言
	if (str == NULL || sub == NULL)//串为空值时直接返回-1
	{
		return -1;
	}
	int lenstr = strlen(str);
	int lensub = strlen(sub);

	int i = 0;//遍历主串
	int j = 0;//遍历子串
	while ((i < lenstr) && (j < lensub))//当子串遍历结束或主串遍历结束时，跳出循环
	{
		if (str[i] == sub[j])//匹配成功
		{
			i++;
			j++;
		}
		else//匹配失败
		{
			i = i - j + 1;
			j = 0;
		}
	}
	if (j >= lensub)//如果是因为子串遍历结束而跳出循环，说明匹配成功，返回下标
	{
		return i - j;
	}
	else//匹配失败，返回-1
		return -1;
}

int main(int argc,char* argv[])
{

	char streamstr[1000000];
	char bytestreamfile[20];
	int move_len, tot_len;
	strcpy(bytestreamfile, "./log.txt");
	if(argc>=2) strcpy(bytestreamfile, argv[1]);
	printf("%s\n",bytestreamfile);
	struct iphdr *ip_packet[max_packet_num];
	FILE* fp=fopen(bytestreamfile,"r+");
	if(fp == NULL) { printf("Open File %s Error!!\n", bytestreamfile); return 0;}
	while(1){
		fscanf(fp,"%[^\n]s",streamstr);
		printf("%s", streamstr);
		move_len=BF(streamstr, "Start Captured message");
		if(move_len == -1) continue;
		printf("%s, %d %d", streamstr,move_len, strlen(streamstr));
	
		

	}
	return 0;
}
