#include<stdio.h>
int top=0;

struct {
  char  book_name[50];
  int book_id;
  int book_price;
}new_book[3];
void push()
{
  if(top>3)
  {
    printf("Overflow\n");
  }
  else
  {
    printf("Enter book name :");
    scanf("%s",new_book[top].book_name);
    printf("Enter book id :");
    scanf("%d",&new_book[top].book_id);
    printf("Enter book price :");
    scanf("%d",&new_book[top].book_price);
    printf("\n");
    top=top+1;
  }
}
void pop()
{
  if(top==-1)
  {
    printf("underflow");
  }
  else
  {
    top=top-1;
  }
}
void peep()
{
  printf("Previous book name : %s\n",new_book[top-1].book_name);
  printf("Previous book id : %d\n",new_book[top-1].book_id);
  printf("Previous book price : %d\n",new_book[top-1].book_price);
}

int main()
{
  int n;
  printf("Select any one you want\n");
  printf("1. push\n");
  printf("2. pop\n");
  printf("3. peep\n");
  printf("4. exit\n");


do {
  printf("Enter choice :");
  scanf("%d",&n);
  printf("\n");
  switch (n) {
    case 1 : push();
    break;

    case 2 : pop();
    break;

    case 3 : peep();
    break;

    case 4 :
    break;

    default: " invalid choice";
    break;}
}while (n!=4);
  return 0;
}
