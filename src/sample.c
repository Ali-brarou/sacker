#include <stdio.h> 

#define STUB_SEC_NAME ".test_stub"
#define STUB_SEC_SIZE 200

//creating a packer section 
__attribute__((section(STUB_SEC_NAME)))
const char stub_section[STUB_SEC_SIZE] = {0};

int main(void)
{
    printf("meow meow :3\n"); 
    return 0; 
}

