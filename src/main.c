#include <elf.h> 
#include <stdlib.h> 
#include <stdio.h> 
#include <string.h> 
#include <inttypes.h> 
#include <stdint.h> 
#include <unistd.h> 
#include <sys/mman.h> 

#define MAX_FILENAME 100
#define PACKED_EXTENSION "_packed"
#define STUB_SEC_NAME ".test_stub"

#define IS_ELF(header) (memcmp(header->e_ident, ELFMAG, SELFMAG) == 0)

uint8_t* elf_buff; 
size_t elf_buff_size; 

//mapped elf
Elf64_Ehdr* elf_header; 

Elf64_Shdr* elf_shdrs; 
Elf64_Phdr* elf_phdrs; 
Elf64_Shdr* elf_shstrtab_hdr; 
uint8_t*    elf_shstrtab;  

Elf64_Shdr* text_sec; 
Elf64_Shdr* stub_sec; 
Elf64_Phdr* stub_seg; 

uint8_t* text; 
size_t text_size; 
uint8_t* stub; 
size_t stub_size; 


void elf_parse(const char* elf_path)
{
    FILE* elf_file = fopen(elf_path, "rb"); 

    if (!elf_file)
    {
        perror(elf_path); 
        exit(EXIT_FAILURE); 
    }

    fseek(elf_file, 0, SEEK_END); 

    elf_buff_size = ftell(elf_file); 
    if (elf_buff_size <= 0)
    {
        fprintf(stderr, "%s: Invalid file size\n", elf_path);
        goto cleanup; 
    }

    rewind(elf_file); 

    elf_buff = malloc(elf_buff_size); 
    if(!elf_buff)
    {
        perror("malloc"); 
        goto cleanup; 
    }

    if(fread(elf_buff, 1, elf_buff_size, elf_file) != elf_buff_size)
    {
        fprintf(stderr, "%s: Failed reading file\n", elf_path); 
        goto cleanup; 
    }
    fclose(elf_file); 
    elf_file = NULL; 
    
    if (elf_buff_size < sizeof(Elf64_Ehdr)) {
        fprintf(stderr, "%s: Input too small to be valid ELF\n", elf_path);
        goto cleanup;
    }

    //mapping elf
    elf_header =        (Elf64_Ehdr*)elf_buff; 
    elf_shdrs =         (Elf64_Shdr*)(elf_buff + elf_header->e_shoff); 
    elf_phdrs =         (Elf64_Phdr*)(elf_buff + elf_header->e_phoff); 
    elf_shstrtab_hdr =  &elf_shdrs[elf_header -> e_shstrndx]; 
    elf_shstrtab =      elf_buff + elf_shstrtab_hdr->sh_offset; 

    if (!IS_ELF(elf_header))
    {
        fprintf(stderr, "%s: Not a proper ELF file\n", elf_path); 
        goto cleanup; 
    }

    if (elf_header->e_shoff + (elf_header->e_shnum * sizeof(Elf64_Shdr)) > (size_t)elf_buff_size) 
    {
        fprintf(stderr, "%s: Invalid section header table\n", elf_path);
        goto cleanup;
    }

        

    for (size_t i = 0; i < elf_header->e_shnum; i++) {
        const char* section_name = (const char *)elf_shstrtab + elf_shdrs[i].sh_name; 
        if (!strcmp(section_name, ".text"))
        {
            text_sec = &elf_shdrs[i]; 
        }
        if (!strcmp(section_name, STUB_SEC_NAME))
        {
            stub_sec = &elf_shdrs[i]; 
        }
    }

    if (!text_sec)
    {
        fprintf(stderr, "%s: No text section in this binary\n", elf_path);
        goto cleanup; 
    }

    if (!stub_sec)
    {
        fprintf(stderr, "%s: No stub section (Try adding it manually)\n", elf_path);
        goto cleanup; 
    }

    //search for the segment that conatains the stub section 

    for (size_t i = 0; i < elf_header->e_phnum; i++)
    {
        Elf64_Phdr* phdr = &elf_phdrs[i]; 
        if (stub_sec->sh_offset >= phdr->p_offset && 
                (stub_sec->sh_offset + stub_sec->sh_size) <= (phdr->p_offset + phdr->p_filesz))
        {
            stub_seg = phdr; 
            break; 
        }
    }

    if (!stub_seg)
    {
        fprintf(stderr, "%s: Failed finding the segment that contains the stub section\n", elf_path);
        goto cleanup; 

    }

    text = elf_buff + text_sec -> sh_offset; 
    text_size = text_sec -> sh_size; 
    stub = elf_buff + stub_sec -> sh_offset; 
    stub_size = stub_sec -> sh_size; 

    return; 

cleanup: 
    if (elf_file)
        fclose(elf_file); 
    free(elf_buff); 
    exit(EXIT_FAILURE); 
}

void elf_pack()
{
    Elf64_Addr old_entry = elf_header -> e_entry; 
    Elf64_Addr new_entry = stub_sec -> sh_addr; 

    //first make the segment that contains the stub executable    
    stub_seg->p_flags |= PF_X; 

    //fill the stub with the payload (an inf loop for now)
    stub[0] = '\xeb'; 
    stub[1] = '\xfe'; 

    //change the entry 
    elf_header -> e_entry = (Elf64_Addr)new_entry;     
}

const char* get_filename(const char* path)
{
    const char *last_slash = strrchr(path, '/');
    return last_slash ? last_slash + 1 : path; 
}

void elf_dump(const char* orig_elf_path)
{
    char new_filename[MAX_FILENAME+1]; 
    const char* orig_filename = get_filename(orig_elf_path);  
    snprintf(new_filename, sizeof(new_filename), "%s%s", orig_filename, PACKED_EXTENSION); 


    FILE* out_elf_file = fopen(new_filename, "wb"); 
    if (!out_elf_file)
    {
        perror(new_filename); 
        return; 
    }

    fwrite(elf_buff, 1, elf_buff_size, out_elf_file); 
}

void elf_clean()
{
    free(elf_buff); 
}

int main(int argc, char* argv[])
{
    if (argc != 2)
    {
        printf("usage : %s <elf_binary>\n", argv[0]); 
        return EXIT_FAILURE; 
    }

    elf_parse(argv[1]); 

    printf("Shdr address : %#" PRIx64 "\n", elf_header -> e_shoff); 
    printf("Entry point address : %#" PRIx64 "\n", elf_header -> e_entry); 
    printf("Number of sections : %d\n", elf_header -> e_shnum); 
    printf("Size of stub section : %ld\n", stub_size); 

    //fflush(stdout); 
    //write(1, text, text_size);  
     
    elf_pack(); 
    elf_dump(argv[1]); 

    elf_clean(); 

    return EXIT_SUCCESS; 
}
