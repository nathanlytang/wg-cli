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
};

struct directories
{
    char peers_dir[FILENAME_MAX];
    char wg_dir[FILENAME_MAX];
    char template_dir[FILENAME_MAX];
};

/**
 * Creates a new peer file using template.conf as a template
 * 
 * @param source Template file
 * @param dest Destination/peer file
 * @param private_key Private key to be inserted in destination
 * @param address IP address to be inserted in destination in CIDR notation
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
            fprintf(dest_file, "Address = %s\n", address);
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
 * 
 * @param argc Number of arguments
 * @param argv Array of arguments
 * @param dir1 Directory locations
 * @param f1 Argument flags
 */
int create_peer(int argc, char *argv[], struct directories dir1, struct flags f1)
{
    // Create wireguard/peers/ directory if not already exists
    struct stat st = {0};
    if (stat(dir1.peers_dir, &st) == -1)
    {
        mkdir(dir1.peers_dir, 0700);
    }

    // Generate private key
    char *private_key = get_key_string("wg genkey");
    if (f1.verbose)
    {
        printf("Private Key = %s\n", private_key);
    }

    // Create new peer configuration file in wireguard/peers/
    strcat(dir1.peers_dir, argv[2]);
    strcat(dir1.peers_dir, "-");
    strcat(dir1.peers_dir, argv[3]);
    strcat(dir1.peers_dir, ".conf");

    // Check if configuration file with filename = argv[3] already exists
    FILE *peer;
    if ((peer = fopen(dir1.peers_dir, "r")))
    {
        fclose(peer);
        free(private_key);
        printf("Aborted: Configuration with filename \"%s-%s.conf\" already exists\n", argv[2], argv[3]);
        return 1;
    }

    // Check if Wireguard interface exists
    strcat(dir1.wg_dir, argv[2]);
    strcat(dir1.wg_dir, ".conf");
    FILE *wg;
    if (!(wg = fopen(dir1.wg_dir, "r")))
    {
        free(private_key);
        printf("Aborted: Interface \"%s\" not found\n", argv[2]);
        return 1;
    }

    // Copy template file to peers directory and replace private key and address
    create_config(dir1.template_dir, dir1.peers_dir, private_key, argv[4]);

    // Generate public key using private key
    char pubkey_command[100] = "bash -c \'wg pubkey <<< ";
    strcat(pubkey_command, private_key);
    strcat(pubkey_command, "\'");
    char *public_key = get_key_string(pubkey_command);
    if (f1.verbose)
    {
        printf("Public Key = %s\n", public_key);
        printf("Create new peer file in: %s\n", dir1.peers_dir);
    }

    // Remove CIDR notation from IP address
    char address[20];
    memcpy(address, argv[4], 20);
    for (int i = 0; i < 3; i++) {
        address[strlen(address)-1] = '\0';
    }

    // Open Wireguard interface configuration file named in argv[2]
    wg = fopen(dir1.wg_dir, "a");
    fprintf(wg, "\n[Peer]\nPublicKey = %s\nAllowedIPs = %s/32\n", public_key, address);
    fclose(wg);

    free(private_key);
    free(public_key);

    // Print QR code
    char qrencode[FILENAME_MAX] = "qrencode -t ansiutf8 < ";
    strcat(qrencode, dir1.peers_dir);
    if (!f1.quiet)
    {
        printf("\nNew peer successfully generated:\n");
        command_print(qrencode);
    }

    return 0;
}

/**
 * Remove Wireguard peer from the interface configuration and delete the peer configuration file
 * 
 * @param argc Number of arguments
 * @param argv Array of arguments
 * @param dir1 Directory locations
 * @param f1 Argument flags
 */
int remove_peer(int argc, char *argv[], struct directories dir1, struct flags f1)
{
    char temp_dir[FILENAME_MAX];
    strcpy(temp_dir, dir1.wg_dir);

    // Check if Wireguard interface exists
    strcat(dir1.wg_dir, argv[2]);
    strcat(dir1.wg_dir, ".conf");
    FILE *wg;
    if (!(wg = fopen(dir1.wg_dir, "r")))
    {
        printf("Aborted: Interface \"%s\" not found\n", argv[2]);
        return 1;
    }

    // Find peer configuration file
    strcat(dir1.peers_dir, argv[2]);
    strcat(dir1.peers_dir, "-");
    strcat(dir1.peers_dir, argv[3]);
    strcat(dir1.peers_dir, ".conf");
    FILE *peer;
    if (!(peer = fopen(dir1.peers_dir, "r")))
    {
        printf("Aborted: Peer configuration file \"%s\" not found\n", argv[3]);
        return 1;
    }

    // Grab privatekey from peer configuration file
    char line[1024];
    char *private_key;
    while (fgets(line, sizeof(line), peer) != NULL)
    {
        if (strstr(line, "PrivateKey") != NULL)
        {
            private_key = strtok(line, " = ");
            private_key = strtok(NULL, " = ");
            strcat(private_key, "=");
            if (f1.verbose)
            {
                printf("Private key = %s\n", private_key);
            }
            break;
        }
    }
    fclose(peer);

    // Convert private key to public key
    char pubkey_command[100] = "bash -c \'wg pubkey <<< ";
    strcat(pubkey_command, private_key);
    strcat(pubkey_command, "\'");
    char *public_key = get_key_string(pubkey_command);
    if (f1.verbose)
    {
        printf("Public key = %s\n", public_key);
    }

    // Find peer in interface configuration file from public key and delete peer
    FILE *temp, *wg2;
    strcat(temp_dir, "temp");
    temp = fopen(temp_dir, "w");
    wg = fopen(dir1.wg_dir, "r");
    int counter = 0;
    int skip_lines = 3;
    char temp_line[1024];
    bool found = false;
    while (fgets(line, sizeof(line), wg) != NULL)
    {
        if (found && (skip_lines != 0))
        {
            skip_lines--;
        }
        else if (!found)
        {
            counter++;
            if (strstr(line, "[Peer]") != NULL)
            {
                wg2 = fopen(dir1.wg_dir, "r");
                for (int i = 0; i < counter + 1; i++)
                {
                    fgets(temp_line, sizeof(temp_line), wg2);
                }
                if (strstr(temp_line, public_key) != NULL)
                {
                    found = true;
                    if (f1.verbose)
                    {
                        printf("Found peer in interface: %s", temp_line);
                    }
                }
                else
                {
                    fprintf(temp, "%s", line);
                }
                fclose(wg2);
            }
            else
            {
                fprintf(temp, "%s", line);
            }
        }
        else if (found && (skip_lines == 0))
        {
            fprintf(temp, "%s", line);
        }
    }
    if (!found && !f1.quiet)
    {
        printf("Error: Peer \"%s\" not found in interface \"%s\"\n", argv[3], argv[2]);
        remove(temp_dir);
        return 1;
    }
    free(public_key);
    fclose(wg);
    fclose(temp);

    // Rename temporary file and delete old interface file
    int delete_old = remove(dir1.wg_dir);
    int rename_temp = rename(temp_dir, dir1.wg_dir);
    if (!delete_old && !rename_temp && !f1.quiet)
    {
        printf("Interface \"%s\" sucessfully updated\n", argv[2]);
    }
    else if (!f1.quiet)
    {
        printf("Error: Unable to update interface \"%s\"\n", argv[2]);
    }

    // Delete peer configuration file
    int delete_peer = remove(dir1.peers_dir);
    if (!delete_peer && !f1.quiet)
    {
        printf("Peer configuration file for \"%s\" deleted successfully\n", argv[3]);
    }
    else if (!f1.quiet)
    {
        printf("Error: Unable to delete peer configuration file for \"%s\"", argv[3]);
    }

    return 0;
}

/**
 * Shows peers belonging to an existing interface
 * 
 * @param argc Number of arguments
 * @param argv Array of arguments
 * @param dir1 Directory locations
 * @param f1 Argument flags
 */
int show(int argc, char *argv[], struct directories dir1, struct flags f1)
{
    return 0;
}

/**
 * Prints the help string to stdout
 */
void print_help_string(char *PROG_NAME)
{
    printf("Usage: %s <cmd> [<args>]\n\n", PROG_NAME);
    char *help_string = "Available commands:\n"
                        "  show: Show existing peers\n"
                        "  create-peer: Create a new peer and add to an existing interface configuration file\n"
                        "  remove-peer: Remove an existing peer from the interface configuration file\n\n"
                        "Flags:\n"
                        "-q quiet -v verbose\n";
    printf("%s", help_string);
}

/**
 * Main
 */
int main(int argc, char *argv[])
{
    char *PROG_NAME = argv[0];
    // Directories
    struct directories dir1;
    strcpy(dir1.peers_dir, "/etc/wireguard/peers/");
    strcpy(dir1.wg_dir, "/etc/wireguard/");
    strcpy(dir1.template_dir, "/etc/wg-cli/template.conf");

    // Check argument flags
    struct flags f1;
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
        print_help_string(PROG_NAME);
        return 0;
    }

    if (!strcmp(argv[1], "show"))
    {
        if ((argc == 3 && (!strcmp(argv[2], "help") || !strcmp(argv[2], "-h") || !strcmp(argv[2], "--help"))) || argc > 3)
        {
            fprintf(stderr, "Usage: %s show [<interface>]\n", PROG_NAME);
            return 1;
        }
        show(argc, argv, dir1, f1);
        return 0;
    }

    if (!strcmp(argv[1], "create-peer"))
    {
        if (argc != 5 || !strcmp(argv[2], "help") || !strcmp(argv[2], "-h") || !strcmp(argv[2], "--help"))
        {
            fprintf(stderr, "Usage: %s create-peer <Interface> <Peer Name> <CIDR IP>\n", PROG_NAME);
            return 1;
        }
        create_peer(argc, argv, dir1, f1);
        return 0;
    }

    if (!strcmp(argv[1], "remove-peer"))
    {
        if (argc != 4 || !strcmp(argv[2], "help") || !strcmp(argv[2], "-h") || !strcmp(argv[2], "--help"))
        {
            fprintf(stderr, "Usage: %s remove-peer <Interface> <Peer Name>\n", PROG_NAME);
            return 1;
        }
        remove_peer(argc, argv, dir1, f1);
        return 0;
    }

    printf("Invalid command: '%s'\n", argv[1]);
    print_help_string(PROG_NAME);
    return 1;
}