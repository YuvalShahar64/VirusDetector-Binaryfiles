#include <stdio.h> 
#include <stdlib.h> 
#include <string.h>
#include <stdbool.h>
///1a
typedef struct virus {
    unsigned short SigSize;
    char virusName[16];
    unsigned char* sig;
} virus;
//1b
typedef struct link {
    struct link *nextVirus;
    virus *vir;
} link;

struct fun_desc {
    char *name; 
    void (*fun)(link**); 
} fun_desc;



bool littleEndian;
//1a
virus* readVirus(FILE* file) {
    virus* v = (virus*)malloc(sizeof(virus)); 
    if (v == NULL) { 
        perror("Failed to allocate memory for virus"); 
        exit(1); 
    }
    if (fread(v, 1, 18, file) != 18) { 
        free(v); 
        return NULL;
    }
    if (!littleEndian) { 
        v->SigSize = (v->SigSize >> 8) | (v->SigSize << 8); 
    }
    v->sig = (unsigned char*)malloc(v->SigSize); 
    if (v->sig == NULL) { 
        perror("Failed to allocate memory for virus signature"); 
        free(v); 
        exit(1); 
    }
    if (fread(v->sig, 1, v->SigSize, file) != v->SigSize) {
        perror("Error reading virus signature (incomplete file)");
        free(v->sig); 
        free(v); 
        return NULL; 
    } 
    return v;
}    

void printVirus(virus* v, FILE* output) {
    fprintf(output, "Virus name: %s\n", v->virusName);
    fprintf(output, "Virus size: %d\n", v->SigSize);
    fprintf(output, "signature:\n ");
    for (int i = 0; i < v->SigSize; i++) {
        fprintf(output, "%02X ", v->sig[i]);
    }
    fprintf(output, "\n");
}
//1b
void list_print(link *virus_list, FILE *output) {
    link *current = virus_list; 
    while (current != NULL) { 
        virus *v = current->vir; 
        printVirus(v, output);
        fprintf(output, "\n"); 
        current = current->nextVirus; 
    } 
} 

link* list_append(link* virus_list, virus* data) {
    link *new_link = malloc(sizeof(link));
    if (!new_link) {
        perror("Failed to allocate memory");
        exit(1);
    }
    new_link->vir = data;
    new_link->nextVirus = NULL;
       if (virus_list == NULL) {
        return new_link; // New link becomes the first link in the list
    } else {
        // Add at the end of the list
        link *current = virus_list;
        while (current->nextVirus != NULL) {
            current = current->nextVirus;
        }
        current->nextVirus = new_link;
        return virus_list; // Return the head of the list
    }
}

void list_free(link *virus_list) {
    while (virus_list != NULL) {
        link *next = virus_list->nextVirus;
        free(virus_list->vir->sig); // Free the signature memory
        free(virus_list->vir); // Free the virus structure
        free(virus_list); // Free the link structure
        virus_list = next;
    }
}

void load_signatures(link **virus_list) { 
    char filename[256]; 
    printf("Enter signature file name: "); 
    if (fgets(filename, sizeof(filename), stdin) == NULL) {
         printf("\nEOF detected. Exiting...\n"); 
         return;
    }
    filename[strcspn(filename, "\n")] = '\0'; // Remove newline character 
    FILE *file = fopen(filename, "rb"); 
    if (!file) { 
        perror("Error opening file"); 
        return;
    }
    char magic[4]; // checking the magic number
    if (fread(magic, 1, 4, file) != 4) {
        perror("Error reading magic number");
        fclose(file);
        return;
    }
    if (strncmp(magic, "VIRL", 4) == 0) {
        littleEndian = true;
        fprintf(stdout, "File format: Little-Endian\n");
    } else if (strncmp(magic, "VIRB", 4) == 0) {
        littleEndian = false;
        fprintf(stdout, "File format: Big-Endian\n");
    } else {
        fprintf(stderr, "Error: invalid magic number\n");
        fclose(file);
        return;
    }
    virus* v;
    while ((v = readVirus(file)) != NULL) { // Reading viruses and adding them to the linked list
    *virus_list = list_append(*virus_list, v);
    }
    fclose(file);
}

void print_signatures(link **virus_list) {
    list_print(*virus_list, stdout);
}
//1c
void detect_virus(char *buffer, unsigned int size, link *virus_list) { 
    link *current = virus_list; 
    while (current != NULL) { 
        virus *v = current->vir; 
        for (unsigned int i = 0; i < size - v->SigSize + 1; i++) { 
            if (memcmp(buffer + i, v->sig, v->SigSize) == 0) { 
                printf("Virus detected!\n"); 
                printf("Starting byte location: %u\n", i); 
                printf("Virus name: %s\n", v->virusName); 
                printf("Virus signature size: %d\n", v->SigSize); 
            } 
        } 

        current = current->nextVirus; 
    } 
}

void detect_viruses(link **virus_list) { 
    char filename[256]; 
    printf("Enter suspected file name: "); 
    if (fgets(filename, sizeof(filename), stdin) == NULL) { 
        printf("\nEOF detected. Exiting...\n"); 
        return;
    } 
    filename[strcspn(filename, "\n")] = '\0'; // Remove newline character 
    FILE *file = fopen(filename, "rb"); 
    if (!file) { 
        perror("Error opening file"); 
        return; 
    }
    char buffer[10000]; 
    unsigned int size = fread(buffer, 1, sizeof(buffer), file); 
    fclose(file); 
    detect_virus(buffer, size, *virus_list); 
}

void neutralize_virus(char *fileName, int signatureOffset) { 
    FILE *file = fopen(fileName, "r+b");  
    if (!file) { 
        perror("Error opening file"); 
        return; 
    }
    fseek(file, signatureOffset, SEEK_SET); 
    unsigned char ret = 0xC3; 
    fwrite(&ret, 1, 1, file);  
    fclose(file); 
}

void fix_file(link **virus_list) { 
    char filename[256]; 
    printf("Enter suspected file name: "); 
    if (fgets(filename, sizeof(filename), stdin) == NULL) { 
        printf("\nEOF detected. Exiting...\n"); 
        return; 
    } 
    filename[strcspn(filename, "\n")] = '\0';
    FILE *file = fopen(filename, "rb"); 
    if (!file) { 
        perror("Error opening file"); 
        return; 
    } 
    char buffer[10000]; 
    unsigned int size = fread(buffer, 1, sizeof(buffer), file);  
    fclose(file); 
    link *current = *virus_list; 
    while (current != NULL) { 
        virus *v = current->vir; 
        for (unsigned int i = 0; i < size - v->SigSize + 1; i++) { 
            if (memcmp(buffer + i, v->sig, v->SigSize) == 0) { 
                printf("Neutralizing virus at byte location: %u\n", i); 
                neutralize_virus(filename, i); 
            } 
        } 
        current = current->nextVirus;
    }
}
//1b
void quit(link **virus_list) { 
    list_free(*virus_list); 
    printf("Exiting...\n"); 
    exit(0); 
}



int main(int argc, char* argv[]) { 
    //part 1a
    // if (argc != 2) { 
    //     fprintf(stderr, "Usage: %s <signatures-file>\n", argv[0]); 
    //     return 1; 
    // } 
    // FILE* file = fopen(argv[1], "rb"); 
    // if (!file) { 
    //     perror("Error opening file"); 
    //     return 1;
    // }
    // char magic[4]; 
    // if (fread(magic, 1, 4, file) != 4) { 
    //     perror("Error reading magic number"); 
    //     fclose(file); 
    //     return 1;
    // }
    // if (strncmp(magic, "VIRL", 4) == 0) { 
    //     littleEndian = true; 
    //     fprintf(stdout, "File format: Little-Endian\n");
    // } else if (strncmp(magic, "VIRB", 4) == 0) { 
    //     littleEndian = false;
    //     fprintf(stdout, "File format: Big-Endian\n"); 
    // } else { 
    //     fprintf(stderr, "Error: invalid magic number\n"); 
    //     fclose(file); 
    //     return 1; 
    // }
    // virus* v; 
    // while ((v = readVirus(file)) != NULL) { 
    //     printVirus(v, stdout); 
    //     free(v->sig); 
    //     free(v);
    // }
    //  fclose(file);
    link *virus_list =NULL;
    struct fun_desc menu[] = { 
        {"Load signatures", load_signatures}, 
        {"Print signatures", print_signatures}, 
        {"Detect viruses", detect_viruses},
        {"Fix file", fix_file}, 
        {"Quit", quit}, 
        {NULL, NULL} 
    };
    int menu_size= sizeof(menu)/ sizeof(menu[0])-1;
    while (1) { 
        printf("Select operation from the following menu:\n"); 
        for (int i = 0; menu[i].name != NULL; i++) { 
            printf("%d) %s\n", i+1 , menu[i].name); 
        } 
        printf("Option: "); 
        char input[10]; 
        if (fgets(input, sizeof(input),stdin)==NULL) {
                printf("\nEOF detected. Exiting...\n");
                break;
        } 
        int option;
        if (sscanf(input, "%d", &option) != 1) { 
            option = -1; 
        } 
        if (option < 1 || option > menu_size) { 
            printf("Not within bounds\n"); 
            continue; 
        } 
        printf("Within bounds\n"); 
        menu[option - 1].fun(&virus_list);
    }
    return 0;
}