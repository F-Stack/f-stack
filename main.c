#include <stdio.h>
#include <stdlib.h>
#include<conio.h>
void push();
void pop();
void print();
void MultiPush();
void MultiDelete();

int stk[4],n=4,top=-1;
void main()
{
    int ch;
    while(1)
    {
    printf("1.To insert a number \n");
    printf("2.To delete a number \n");
    printf("3.To print stack elements \n");
    printf("4.To insert multiple number \n");
    printf("5.To delete multiple number \n");
    printf("6.Exit \n");
    printf("Enter your choice = ");
    scanf("%d",&ch);
    switch(ch)
     {
     case 1: push();
             break;
     case 2: pop();
             break;
     case 3 : print();
             break;
     case 4 : MultiPush();
             break;
     case 5 : MultiDelete();
             break;
     case 6 : exit(1);
             break;

     }
getch();
system("cls");
    }

}

void push()
{
    int item;
    printf("Enter the digit \n");
    scanf("%d",&item);
    if(top==n-1)
    {
        printf("Overflow");

    }
    else
    {
      top=top+1;
      stk[top]=item;
    }

}

void pop()
{
int temp;
 if (top==-1)
 {
     printf("Underflow");
 }
 else
 {
     temp=stk[top];
     top=top-1;
 }
}

void print()
{
    int i;
    for(i=top;i>=0;i--)
    {
        printf(" stk[%d]= %d \n ",i,stk[i]);
    }

}

void MultiPush()
{
    int num,i;
    printf("Enter the number of elements to be inserted = ");
    scanf("%d",&num);
    for(i=0;i<num;i++)
    {
        push();
    }
}
void MultiDelete()
{
    int num,i;
    printf("Enter the number of elements to be deleted = ");
    scanf("%d",&num);
    for(i=0;i<num;i++)
    {
        pop();
    }
}
