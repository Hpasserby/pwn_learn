#include <cstdio>
#include <cstdlib>

struct shell
{
	void (*getshell)();
};

struct data
{
	int data;
};

void test_getshell()
{
	printf("hello world\n");
}

int main()
{
	shell *p;
	p = (shell*)malloc(sizeof(shell));
	p->getshell = test_getshell;
	free(p);
	data *q;
	q = (data*)malloc(sizeof(data));
	q->data = 1234;
	p->getshell();
	return 0;
}

