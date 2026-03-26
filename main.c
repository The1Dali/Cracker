#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"
#include "hashfile.h"
#include "hash.h"
#include "attack.h"

static void print_usage(const char *prog_name)
{
    fprintf(stderr,
        "Usage: %s [options] <hashfile>\n"
        "\nAttack modes (-a):\n"
        "  0 = Dictionary attack (default)\n"
        "  1 = Brute force\n"
        "\nHash types (-m):\n"
        "  0 = MD5 (default)\n"
        "  1 = SHA-256\n"
        "  2 = SHA-512\n"
        "  3 = NTLM\n"
        "\nOptions:\n"
        "  -w <path>     Wordlist path (dictionary mode)\n"
        "  -c <charset>  Charset for brute force. Presets:\n"
        "                  lower  = a-z\n"
        "                  upper  = A-Z\n"
        "                  digits = 0-9\n"
        "                  alnum  = a-z A-Z 0-9\n"
        "                  all    = alnum + symbols\n"
        "                Or supply any custom string: -c 'abc123'\n"
        "  --min-len <n> Minimum length for brute force (default: 1)\n"
        "  --max-len <n> Maximum length for brute force (default: 4)\n"
        "  -o <path>     Write cracked pairs to file\n"
        "  -v            Verbose — show live progress\n"
        "  -h            Print this help and exit\n"
        "\nExamples:\n"
        "  %s -m 0 -w rockyou.txt hashes.txt\n"
        "  %s -a 1 -m 0 -c digits --min-len 4 --max-len 6 hashes.txt\n",
        prog_name, prog_name, prog_name);
}

static const char *resolve_charset(const char *input)
{
    if (strcmp(input, "lower")  == 0) return CHARSET_LOWER;
    if (strcmp(input, "upper")  == 0) return CHARSET_UPPER;
    if (strcmp(input, "digits") == 0) return CHARSET_DIGITS;
    if (strcmp(input, "alnum")  == 0) return CHARSET_ALNUM;
    if (strcmp(input, "all")    == 0) return CHARSET_ALL;
    return input;
}

int main(int argc, char *argv[])
{
    Config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.algo    = HASH_MD5;
    cfg.mode    = ATTACK_DICTIONARY;
    cfg.min_len = 1;
    cfg.max_len = 4;
    cfg.verbose = 0;

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-m") == 0)
        {
            if (i + 1 >= argc) { fprintf(stderr, "Error: -m requires a value\n"); return 1; }
            cfg.algo = (HashAlgo)atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "-a") == 0)
        {
            if (i + 1 >= argc) { fprintf(stderr, "Error: -a requires a value\n"); return 1; }
            cfg.mode = (AttackMode)atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "-w") == 0)
        {
            if (i + 1 >= argc) { fprintf(stderr, "Error: -w requires a value\n"); return 1; }
            strncpy(cfg.wordlist, argv[++i], sizeof(cfg.wordlist) - 1);
        }
        else if (strcmp(argv[i], "-c") == 0)
        {
            if (i + 1 >= argc) { fprintf(stderr, "Error: -c requires a value\n"); return 1; }
            strncpy(cfg.charset, resolve_charset(argv[++i]), sizeof(cfg.charset) - 1);
        }
        else if (strcmp(argv[i], "--min-len") == 0)
        {
            if (i + 1 >= argc) { fprintf(stderr, "Error: --min-len requires a value\n"); return 1; }
            cfg.min_len = atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "--max-len") == 0)
        {
            if (i + 1 >= argc) { fprintf(stderr, "Error: --max-len requires a value\n"); return 1; }
            cfg.max_len = atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "-o") == 0)
        {
            if (i + 1 >= argc) { fprintf(stderr, "Error: -o requires a value\n"); return 1; }
            strncpy(cfg.outfile, argv[++i], sizeof(cfg.outfile) - 1);
        }
        else if (strcmp(argv[i], "-v") == 0)
        {
            cfg.verbose = 1;
        }
        else if (strcmp(argv[i], "-h") == 0)
        {
            print_usage(argv[0]);
            return 0;
        }
        else
        {
            strncpy(cfg.hashfile, argv[i], sizeof(cfg.hashfile) - 1);
        }
    }

    if (cfg.hashfile[0] == '\0')
    {
        fprintf(stderr, "Error: no hash file specified\n");
        print_usage(argv[0]);
        return 1;
    }

    if (cfg.mode == ATTACK_DICTIONARY && cfg.wordlist[0] == '\0')
    {
        fprintf(stderr, "Error: dictionary mode requires a wordlist (-w)\n");
        print_usage(argv[0]);
        return 1;
    }

    if (cfg.mode == ATTACK_BRUTEFORCE && cfg.charset[0] == '\0')
    {
        strncpy(cfg.charset, CHARSET_LOWER, sizeof(cfg.charset) - 1);
        fprintf(stderr, "[*] No charset specified, defaulting to lowercase\n");
    }

    Target *targets   = NULL;
    size_t  n_targets = 0;

    if (hashfile_load(cfg.hashfile, &targets, &n_targets) != 0)
    {
        fprintf(stderr, "Error: could not load hash file\n");
        return 1;
    }

    fprintf(stderr, "[*] Loaded %zu target hash(es)\n", n_targets);

    int cracked = 0;

    if (cfg.mode == ATTACK_DICTIONARY)
    {
        fprintf(stderr, "[*] Starting dictionary attack...\n");
        cracked = run_dictionary(&cfg, targets, n_targets);
    }
    else if (cfg.mode == ATTACK_BRUTEFORCE)
    {
        fprintf(stderr, "[*] Starting brute force attack (len %d-%d, charset: %s)...\n",
                cfg.min_len, cfg.max_len, cfg.charset);
        cracked = run_bruteforce(&cfg, targets, n_targets);
    }

    fprintf(stderr, "[*] Done. %d/%zu cracked.\n", cracked, n_targets);

    free(targets);
    return 0;
}