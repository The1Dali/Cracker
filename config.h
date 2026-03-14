#ifndef CONFIG_H   
#define CONFIG_H
typedef enum 
{
    HASH_MD5    = 0,
    HASH_SHA256 = 1,
    HASH_SHA512 = 2,
    HASH_NTLM   = 3,
} HashAlgo;

typedef struct {
    HashAlgo    algo;           
    char        hashfile[512];  
    char        wordlist[512];  
    char        outfile[512];  
    int         verbose;      
} Config;

#endif 