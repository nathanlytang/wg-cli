#define _GNU_SOURCE
#include <dirent.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

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
 * Generate a new Wireguard peer file and insert key into interface
 * configuration file
 *
 * @param argc Number of arguments
 * @param argv Array of arguments
 * @param dir1 Directory locations
 * @param f1 Argument flags
 */
int create_peer(int argc, char *argv[], struct directories dir1,
                struct flags f1)
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
        printf("Aborted: Configuration with filename \"%s-%s.conf\" already "
               "exists\n",
               argv[2], argv[3]);
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
    for (int i = 0; i < 3; i++)
    {
        address[strlen(address) - 1] = '\0';
    }

    // Open Wireguard interface configuration file named in argv[2]
    wg = fopen(dir1.wg_dir, "a");
    fprintf(wg, "\n[Peer]\nPublicKey = %s\nAllowedIPs = %s/32\n", public_key,
            address);
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

    // Restart wg
    char restart[FILENAME_MAX] = "systemctl restart wg-quick@";
    strcat(restart, argv[2]);
    command_print(restart);

    return 0;
}

/**
 * Remove Wireguard peer from the interface configuration and delete the peer
 * configuration file
 *
 * @param argc Number of arguments
 * @param argv Array of arguments
 * @param dir1 Directory locations
 * @param f1 Argument flags
 */
int remove_peer(int argc, char *argv[], struct directories dir1,
                struct flags f1)
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
        printf("Error: Peer \"%s\" not found in interface \"%s\"\n", argv[3],
               argv[2]);
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

    if (!delete_old && !rename_temp)
    {
        // Restart wg
        char restart[FILENAME_MAX] = "systemctl restart wg-quick@";
        strcat(restart, argv[2]);
        command_print(restart);
    }

    // Delete peer configuration file
    int delete_peer = remove(dir1.peers_dir);
    if (!delete_peer && !f1.quiet)
    {
        printf("Peer configuration file for \"%s\" deleted successfully\n",
               argv[3]);
    }
    else if (!f1.quiet)
    {
        printf("Error: Unable to delete peer configuration file for \"%s\"",
               argv[3]);
    }

    return 0;
}

/**
 * Shows peers for a specific interface.
 *
 * Iterates over /etc/wireguard/peers/ for files matching the pattern:
 * <interface_name>-<peer_name>.conf
 *
 * If a matching file is found, it extracts and displays the peer name and
 * AllowedIPs.
 *
 * @param interface_name The name of the WireGuard interface (e.g., "wg0").
 * @param dir1 Directory locations.
 * @param f1 Argument flags.
 */
void show_interface(char *interface_name, struct directories dir1,
                    struct flags f1)
{
    // Construct the interface configuration file path
    char interface_config_path[FILENAME_MAX];
    snprintf(interface_config_path, sizeof(interface_config_path), "%s%s.conf", dir1.wg_dir, interface_name);

    // Check if the interface configuration file exists
    if (access(interface_config_path, F_OK) == -1) {
        printf("Interface: %s does not exist\n", interface_name);
        return;
    }

    DIR *d;
    struct dirent *dir;
    d = opendir(dir1.peers_dir);

    if (d)
    {
        printf("Interface: %s\n", interface_name);
        while ((dir = readdir(d)) != NULL)
        {
            // Check if the file is a regular file and matches the pattern
            if (dir->d_type == DT_REG)
            {
                char peer_name[FILENAME_MAX];
                char file_interface_name[FILENAME_MAX];
                int matches = sscanf(dir->d_name, "%[^-]-%[^.].conf",
                                     file_interface_name, peer_name);

                if (matches == 2 &&
                    strcmp(file_interface_name, interface_name) == 0)
                {
                    // Construct the full file path
                    char file_path[FILENAME_MAX];
                    snprintf(file_path, sizeof(file_path), "%s%s",
                             dir1.peers_dir, dir->d_name);

                    // Open the peer configuration file
                    FILE *peer_file = fopen(file_path, "r");
                    if (peer_file)
                    {
                        char line[1024];
                        char allowed_ips[256] =
                            ""; // Initialize to empty string

                        while (fgets(line, sizeof(line), peer_file) != NULL)
                        {
                            if (strstr(line, "AllowedIPs") != NULL)
                            {
                                // Extract AllowedIPs
                                char *temp = strstr(line, "=");
                                if (temp != NULL)
                                {
                                    temp++; // move past the = sign
                                    while (*temp == ' ')
                                        temp++; // remove any spaces
                                    strcpy(allowed_ips, temp);
                                    strtok(allowed_ips, "\n");
                                }
                            }
                        }
                        fclose(peer_file);

                        // Print peer information
                        printf("  Peer Name: %s\n", peer_name);
                        printf("  Allowed IPs: %s\n", allowed_ips);
                        printf("\n");
                    }
                    else
                    {
                        fprintf(stderr,
                                "Error opening peer configuration file: %s\n",
                                file_path);
                    }
                }
            }
        }
        closedir(d);
    }
    else
    {
        perror("Error opening peers directory");
    }
}

/**
 * Shows peers belonging to an existing interface
 *
 * @param argc Number of arguments
 * @param argv Array of arguments
 * @param dir1 Directory locations
 * @param f1 Argument flags
 */
int show(int argc, char *argv[], struct directories dir1, struct flags f1) {
    if (argc == 2) {
        // If no interface is specified, show all interfaces and their peers
        DIR *d;
        struct dirent *dir;
        d = opendir(dir1.wg_dir);
        if (d) {
            while ((dir = readdir(d)) != NULL) {
                // Check if the file is a .conf file and not a directory
                if (dir->d_type == DT_REG) {
                    size_t len = strlen(dir->d_name);
                    if (len > 5 && strcmp(dir->d_name + len - 5, ".conf") == 0) { // Correctly check for .conf at the end
                        // Extract interface name
                        char interface_name[FILENAME_MAX];
                        strcpy(interface_name, dir->d_name);
                        interface_name[len - 5] = '\0'; // Remove ".conf"

                        // Show peers for this interface
                        show_interface(interface_name, dir1, f1);
                    }
                }
            }
            closedir(d);
        } else {
            perror("Error opening /etc/wireguard directory");
            return 1;
        }

    } else if (argc == 3) {
        show_interface(argv[2], dir1, f1);
    }
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
                        "  create-peer: Create a new peer and add to an "
                        "existing interface configuration file\n"
                        "  remove-peer: Remove an existing peer from the "
                        "interface configuration file\n\n"
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
    if (argc == 1 || !strcmp(argv[1], "help") || !strcmp(argv[1], "-h") ||
        !strcmp(argv[1], "--help"))
    {
        print_help_string(PROG_NAME);
        return 0;
    }

    if (!strcmp(argv[1], "show"))
    {
        if ((argc == 3 && (!strcmp(argv[2], "help") || !strcmp(argv[2], "-h") ||
                           !strcmp(argv[2], "--help"))) ||
            argc > 3)
        {
            fprintf(stderr, "Usage: %s show [<interface>]\n\n",
                    PROG_NAME);

            fprintf(stderr, "Arguments:\n");
            fprintf(stderr,
                    "  [<interface>]: The name of the WireGuard interface "
                    "(e.g., wg0). If omitted, all interfaces are "
                    "shown.\n\n");

            fprintf(stderr, "Description:\n");
            fprintf(stderr, "  Displays information about WireGuard peers "
                            "for the specified interface, or all "
                            "interfaces if none is provided.\n");
            fprintf(stderr, "  The output includes peer public keys, "
                            "allowed IPs, and other relevant details.\n\n");

            fprintf(stderr, "Example:\n");
            fprintf(stderr, "  %s show wg0\n",
                    PROG_NAME);
            fprintf(stderr, "  This shows the peers configured for "
                            "interface 'wg0'.\n\n");
            fprintf(stderr, "  %s show\n",
                    PROG_NAME);
            fprintf(stderr, "  This shows all configured WireGuard "
                            "interfaces and their peers.\n");

            return 1;
        }
        show(argc, argv, dir1, f1);
        return 0;
    }

    if (!strcmp(argv[1], "create-peer"))
    {
        if (argc != 5 || !strcmp(argv[2], "help") || !strcmp(argv[2], "-h") ||
            !strcmp(argv[2], "--help"))
        {
            fprintf(stderr,
                    "Usage: %s create-peer <interface> <peer-name> "
                    "<allowed-ips>\n\n",
                    PROG_NAME);

            fprintf(stderr, "Creates a new WireGuard peer configuration.\n\n");

            fprintf(stderr, "Arguments:\n");
            fprintf(stderr, "  <interface>:   The name of the WireGuard "
                            "interface (e.g., wg0).\n");
            fprintf(stderr, "  <peer-name>:   A descriptive name for the "
                            "peer (e.g., phone, laptop).\n");
            fprintf(stderr,
                    "  <allowed-ips>: The IP address(es) or CIDR block(s) "
                    "that the peer will be allowed to access\n");
            fprintf(stderr, "                 through the tunnel (e.g., "
                            "192.168.2.10/32 or 10.0.0.0/24. Use 0.0.0.0/0 "
                            "for all).\n\n");

            fprintf(stderr, "This command does the following:\n");
            fprintf(stderr, "1. Generates a new private and public key "
                            "pair for the peer.\n");
            fprintf(stderr,
                    "2. Creates a new peer configuration file named "
                    "<interface>-<peer-name>.conf in /etc/wireguard/peers/.\n");
            fprintf(stderr, "3. Adds the peer's public key and allowed IPs "
                            "to the interface configuration file "
                            "(/etc/wireguard/<interface>.conf).\n");
            fprintf(stderr, "4. Displays a QR code of the peer "
                            "configuration for easy mobile setup.\n");
            fprintf(stderr, "5. Restarts the WireGuard interface to apply "
                            "the changes.\n\n");

            fprintf(stderr, "Example:\n");
            fprintf(stderr, "  %s create-peer wg0 phone 192.168.2.10/32\n",
                    PROG_NAME);
            fprintf(stderr, "  This creates a peer named 'phone' on interface "
                            "'wg0', allowing access to 192.168.2.10.\n");

            return 1;
        }
        create_peer(argc, argv, dir1, f1);
        return 0;
    }

    if (!strcmp(argv[1], "remove-peer"))
    {
        if (argc != 4 || !strcmp(argv[2], "help") || !strcmp(argv[2], "-h") ||
            !strcmp(argv[2], "--help"))
        {
            fprintf(stderr, "Usage: %s remove-peer <interface> <peer-name>\n\n",
                    PROG_NAME);

            fprintf(stderr, "Removes a WireGuard peer configuration.\n\n");

            fprintf(stderr, "Arguments:\n");
            fprintf(stderr, "  <interface>: The name of the WireGuard "
                            "interface (e.g., wg0).\n");
            fprintf(stderr, "  <peer-name>: The descriptive name of the "
                            "peer to remove (e.g., phone, laptop).\n\n");
            fprintf(stderr, "This command does the following:\n");
            fprintf(stderr,
                    "1. Removes the peer's entry from the interface "
                    "configuration file (/etc/wireguard/<interface>.conf).\n");
            fprintf(stderr, "2. Deletes the peer's configuration file "
                            "(named <interface>-<peer-name>.conf) from "
                            "/etc/wireguard/peers/.\n");
            fprintf(stderr, "3. Restarts the WireGuard interface to apply "
                            "the changes.\n\n");

            fprintf(stderr, "Example:\n");
            fprintf(stderr, "  %s remove-peer wg0 phone\n", PROG_NAME);
            fprintf(stderr, "  This removes the peer named 'phone' from "
                            "the interface 'wg0'.\n");

            return 1;
        }
        remove_peer(argc, argv, dir1, f1);
        return 0;
    }

    printf("Invalid command: '%s'\n", argv[1]);
    print_help_string(PROG_NAME);
    return 1;
}