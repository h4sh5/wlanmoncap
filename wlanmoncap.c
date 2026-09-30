#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <signal.h>

pcap_t *handle = NULL;
pcap_dumper_t *dumper = NULL;

// Handle Ctrl+C to clean up and exit safely
void sig_handler(int signo) {
    if (signo == SIGINT) {
        printf("\n[!] Stopping capture...\n");
        if (dumper) pcap_dump_close(dumper);
        if (handle) pcap_close(handle);
        exit(0);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <interface> <channel> <output_file.pcap>\n", argv[0]);
        fprintf(stderr, "Example: %s wlan0 6 capture.pcap\n", argv[0]);
        return 1;
    }

    char *dev = argv[1];
    char *channel = argv[2];
    char *filename = argv[3];
    char errbuf[PCAP_ERRBUF_SIZE];

    signal(SIGINT, sig_handler);

    // 1. Create the pcap handle
    handle = pcap_create(dev, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "[-] Couldn't create handle for %s: %s\n", dev, errbuf);
        return 2;
    }

    // 2. Enable Monitor Mode
    if (pcap_set_rfmon(handle, 1) != 0) {
        fprintf(stderr, "[-] Warning: Failed to set monitor mode (or not supported).\n");
    }

    // Set snapshot length and promiscuous mode
    pcap_set_snaplen(handle, 65535);
    pcap_set_promisc(handle, 1);
    pcap_set_timeout(handle, 1000); // 1 second timeout

    // 3. Activate the capture handle
    int status = pcap_activate(handle);
    if (status < 0) {
        fprintf(stderr, "[-] Activation failed: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 2;
    }

    // 4. Set the Channel via system call (libpcap doesn't handle tuning)
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "sudo iw dev %s set channel %s", dev, channel);
    printf("[*] Setting channel: %s\n", cmd);
    if (system(cmd) != 0) {
        fprintf(stderr, "[-] Failed to set channel. Ensure you have root/sudo privileges.\n");
    }

    // Verify we are getting 802.11 Link Layer headers
    int link_type = pcap_datalink(handle);
    if (link_type != DLT_IEEE802_11 && link_type != DLT_IEEE802_11_RADIO) {
        printf("[!] Warning: Datalink type is %s, not native 802.11. Packet parsing might differ.\n", 
               pcap_datalink_val_to_name(link_type));
    }

    // 5. Open the output PCAP file
    dumper = pcap_dump_open(handle, filename);
    if (dumper == NULL) {
        fprintf(stderr, "[-] Error opening output file: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 2;
    }

    printf("[+] Capturing on %s (Channel %s) -> Saving to %s\n", dev, channel, filename);
    printf("[*] Press Ctrl+C to stop.\n");

    // 6. Enter the packet loop (-1 means loop indefinitely)
    // pcap_dump writes directly to our dumper handle
    pcap_loop(handle, -1, pcap_dump, (u_char *)dumper);

    // Cleanup (Should only hit if pcap_loop naturally breaks)
    pcap_dump_close(dumper);
    pcap_close(handle);
    return 0;
}
