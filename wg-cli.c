#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdbool.h>

struct flags
{
    bool quiet;
    bool verbose;
} f1;

/**
 * Creates a new peer file using template.conf as a template
 * 
 * @param source Template file
 * @param dest Destination/peer file
 * @param private_key Private key to be inserted in destination
 * @param address IP address to be inserted in destination
*/
void create_config(char *source, char *dest, char *private_key, char *address)
{
    FILE *source_file, *dest_file;
    char line[1024];

    // Open template and peer files
    source_file = fopen(source, "r");
    if (source_file == NULL)
    {
        printf("Error: Failed to read template configuration\n");
        exit(0);
    }
    dest_file = fopen(dest, "w");
    if (dest_file == NULL)
    {
        printf("Error: Failed to write new peer configuration\n");
        exit(0);
    }

    // Copy template file and write private key and address
    while (fgets(line, sizeof(line), source_file) != NULL)
    {
        if (strstr(line, "PrivateKey") != NULL)
        {
            strtok(line, "\n");
            fprintf(dest_file, "PrivateKey = %s\n", private_key);
        }
        else if (strstr(line, "Address") != NULL)
        {
            strtok(line, "\n");
            fprintf(dest_file, "Address = %s/24\n", address);
        }
        else
        {
            fprintf(dest_file, "%s", line);
        }
    }

    fclose(source_file);
    fclose(dest_file);
}

/** 
 * Calls a command in the shell and prints stdout
 * 
 * @param command Shell command to be executed
*/
void command_print(char *command)
{
    FILE *fp;
    int size_line;
    char line[1024];

    if (command != NULL)
    {
        fp = popen(command, "r");
        if (fp != NULL)
        {
            while (fgets(line, size_line = sizeof(line), fp) != NULL)
            {
                printf("%s", line);
            }
        }
        pclose(fp);
    }
}

/**
 * Executes a shell command and returns stdout
 * 
 * @param command Shell command to be executed
 * @return Returns stdout as char array
 */
char *get_key_string(char *command)
{
    FILE *file;
    int size_key = 45; // Size of key
    char *key = (char *)malloc(1024 * sizeof(char));
    file = popen(command, "r");
    if (file != NULL)
    {
        fgets(key, size_key, file);
    }
    pclose(file);
    strtok(key, "\n");
    return key;
}

/**
 * Generate a new Wireguard peer file and insert key into interface configuration file
 */
int create_peer(int argc, char *argv[], struct flags f1)
{
    // Create wireguard/peers/ directory if not already exists
    struct stat st = {0};
    char peers_dir[FILENAME_MAX] = "/etc/wireguard/peers/";
    if (stat(peers_dir, &st) == -1)
    {
        mkdir(peers_dir, 0700);
    }

    // Generate private key
    char *private_key = get_key_string("wg genkey");
    if (f1.verbose)
    {
        printf("Private Key = %s\n", private_key);
    }

    // Create new peer configuration file in wireguard/peers/
    strcat(peers_dir, argv[2]);
    strcat(peers_dir, "-");
    strcat(peers_dir, argv[3]);
    strcat(peers_dir, ".conf");

    // Check if configuration file with filename = argv[3] already exists
    FILE *peer;
    if ((peer = fopen(peers_dir, "r")))
    {
        fclose(peer);
        free(private_key);
        printf("Aborted: Configuration with filename \"%s-%s.conf\" already exists\n", argv[2], argv[3]);
        return 1;
    }

    // Check if Wireguard interface exists
    char wg_dir[FILENAME_MAX] = "/etc/wireguard/";
    strcat(wg_dir, argv[2]);
    strcat(wg_dir, ".conf");
    FILE *wg;
    if (!(wg = fopen(wg_dir, "r")))
    {
        free(private_key);
        printf("Aborted: Interface \"%s\" not found\n", argv[2]);
        return 1;
    }

    // Copy template file to peers directory and replace private key and address
    char template_dir[FILENAME_MAX] = "/etc/wg-cli/template.conf";
    create_config(template_dir, peers_dir, private_key, argv[4]);

    // Generate public key using private key
    char pubkey_command[100] = "bash -c \'wg pubkey <<< ";
    strcat(pubkey_command, private_key);
    strcat(pubkey_command, "\'");
    char *public_key = get_key_string(pubkey_command);
    if (f1.verbose)
    {
        printf("Public Key = %s\n", public_key);
        printf("Create new peer file in: %s\n", peers_dir);
    }

    // Open Wireguard interface configuration file named in argv[2]
    wg = fopen(wg_dir, "a");
    fprintf(wg, "\n[Peer]\nPublicKey = %s\nAllowedIPs = %s/32\n", public_key, argv[4]);
    fclose(wg);

    free(private_key);
    free(public_key);

    // Print QR code
    char qrencode[FILENAME_MAX] = "qrencode -t ansiutf8 < ";
    strcat(qrencode, peers_dir);
    if (!f1.quiet)
    {
        printf("\nNew peer successfully generated:\n");
        command_print(qrencode);
    }

    return 0;
}

void print_help_string()
{
    char *help_string = "Usage: wg-cli <cmd> [<args>]\n\n"
                        "Available commands:\n"
                        "  create-peer: Create a new peer and add to an existing configuration\n";
    printf("%s", help_string);
}

int main(int argc, char *argv[])
{
    // Check argument flags
    f1.quiet = false;
    f1.verbose = false;
    for (int i = 0; i < argc; i++)
    {
        if (!strcmp(argv[i], "-q"))
        {
            f1.quiet = true;
            for (int j = i; j < argc - 1; j++)
            {
                argv[j] = argv[j + 1];
            }
            argc--;
            i--;
        }
        else if (!strcmp(argv[i], "-v"))
        {
            f1.verbose = true;
            for (int j = i; j < argc - 1; j++)
            {
                argv[j] = argv[j + 1];
            }
            argc--;
            i--;
        }
    }

    // If arguments empty or help
    if (argc == 1 || !strcmp(argv[1], "help") || !strcmp(argv[1], "-h") || !strcmp(argv[1], "--help"))
    {
        print_help_string();
        return 0;
    }

    if (!strcmp(argv[1], "create-peer"))
    {
        if (argc < 5 || !strcmp(argv[2], "help") || !strcmp(argv[2], "-h") || !strcmp(argv[2], "--help"))
        {
            fprintf(stderr, "Usage: wg-cli create-peer <Interface> <Peer Name> <Address>\n");
            return 1;
        }
        create_peer(argc, argv, f1);
        return 0;
    }

    printf("Invalid command: '%s'\n", argv[1]);
    print_help_string();
    return 1;
}