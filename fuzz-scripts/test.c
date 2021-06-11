#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#define PASSWORD "bamboofuzz"  //写入静态密码

int verify_password(char *password)//确认密码是否输入正确
{
	int authenticated;
	char buffer[10];
	authenticated=strcmp(password,PASSWORD);  
	strcpy(buffer,password);  //存在栈溢出的函数
	return authenticated;
}

char * get_env(char * env_name){
    /*do some check*/
    return "bamboofuzz";
}

void main()
{
	int valid_flag=0;
	char *password;
	password = get_env("password"); //模拟cgi环境变量获取密码
	valid_flag=verify_password(password);
	if(valid_flag) //返回0代表正确，返回1代表错误
	{
		printf("incorrect password!\n");
	}
	else
	{
		printf("success\n");
	}
}