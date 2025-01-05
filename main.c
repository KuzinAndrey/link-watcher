/*
///////////////////////////////////////////////////////

link-watcher - automatically select active link between two routers

Author: kuzinandrey@yandex.ru
URL: https://www.github.com/KuzinAndrey/link-watcher
License: MIT

///////////////////////////////////////////////////////

History:
   2025-01-05 - Initial version
*/
#define _XOPEN_SOURCE 600
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <time.h>
#include <sys/select.h>
#include <openssl/evp.h>
#include "shared_secret.h"

#define PROC_NET_ROUTE_PATH "/proc/net/route"

int quit = 0;
unsigned int opt_portno = 46721;
const char *opt_mdalgo = "sha256";
clock_t opt_clock = CLOCK_MONOTONIC;
int opt_dryrun = 1;
int opt_verbose = 1;
int opt_autoswitch = 1;
float opt_keepalive = 5.0; // time beetween messages

char header_magic[] = "\xFD\x10\xDE\xAD\xBE\xEF\xAA\xBB";

EVP_MD_CTX *mdctx = NULL;
const EVP_MD *md = NULL;
unsigned char md_value[EVP_MAX_MD_SIZE];
unsigned int md_len;

const char *ip_bin = NULL;
const char *ip_search[] = {
	"/usr/local/sbin/ip",
	"/usr/local/bin/ip",
	"/usr/sbin/ip",
	"/usr/bin/ip",
	"/sbin/ip",
	"/usr/ip",
	NULL };

char *get_default_gateway(char *ipaddr, char *ifname, unsigned int *metric) {
	char skip_header[128];
	struct in_addr route_net;
	struct in_addr route_mask;
	struct in_addr route_gw;
	unsigned int no;

	FILE *net_route = fopen(PROC_NET_ROUTE_PATH, "r");
	if (!net_route) {
		fprintf(stderr, "ERROR: Can't open file %s\n", PROC_NET_ROUTE_PATH);
		goto error;
	}

	if (!fgets(skip_header, sizeof(skip_header), net_route)) {
		fprintf(stderr, "ERROR: Can't skip header of %s\n", PROC_NET_ROUTE_PATH);
		goto error;
	}

	while (!feof(net_route)) {
		if (11 != fscanf(net_route, "%s\t%X\t%X\t%X\t%u\t%u\t%u\t%X\t%u\t%u\t%u",
			ifname, &route_net.s_addr, &route_gw.s_addr, &no, &no, &no, metric,
			&route_mask.s_addr, &no, &no, &no)) break;

		if (route_net.s_addr == 0 && route_mask.s_addr == 0) {
			sprintf(ipaddr, "%s", inet_ntoa(route_gw));
			fclose(net_route);
			return ipaddr;
		}
	}

error:
	sprintf(ipaddr, "%s", "");
	sprintf(ifname, "%s", "");
	if (net_route) fclose(net_route);
	return NULL;
} // get_default_gateway()

int make_sign(char *data, size_t datalen) {
	if (!EVP_DigestInit_ex(mdctx, md, NULL)) {
		fprintf(stderr, "ERROR: Can't init digest %s\n", opt_mdalgo);
		return 1;
	}
	if (data && datalen) {
		if (!EVP_DigestUpdate(mdctx, data, datalen)) {
			fprintf(stderr, "ERROR: Can't update digest\n");
			return 1;
		}
	}
	if (!EVP_DigestUpdate(mdctx, shared_secret, strlen(shared_secret))) {
		fprintf(stderr, "ERROR: Can't update digest\n");
		return 1;
	}
	if (!EVP_DigestFinal_ex(mdctx, md_value, &md_len)) {
		fprintf(stderr, "ERROR: Can't digest final\n");
		return 1;
	}
	return 0;
} // make_sign()

int run_command(const char *fmt, ...) {
	char *com = NULL;
	int comret = 0;
	int ret = -1; // default error

	va_list arg_list;
	va_start(arg_list, fmt);
	ret = vasprintf(&com, fmt, arg_list);
	va_end(arg_list);
	if (ret == -1) goto defer;

	printf("%s %s", opt_dryrun ? "*" : "+", com);
	if (!opt_dryrun) comret = system(com);
	printf(" = %d\n", comret);
	if (comret == -1) {
		fprintf(stderr, "Can't run command: \"%s\" - %s\n", com, strerror(errno));
	} else if (comret != 0) {
		fprintf(stderr, "Command \"%s\" return not zero code %d\n", com, comret);
	} else ret = comret;
defer:
	if (com) free(com);
	return ret;
} // run_command()

int delete_all_routes_via_ip(const char *ifname, const struct in_addr remote_point) {
	int ret = 0;
	char skip_header[128];
	char proc_ifname[IF_NAMESIZE + 1];
	int filled = 0;
	struct in_addr route_net[10];
	struct in_addr route_mask[10];
	unsigned int metric[10];
	char buf_net[50];
	char buf_mask[50];
	char buf_remote[50];
	char buf_metric[50];
	struct in_addr route_gw;
	unsigned int no;
	FILE *net_route = NULL;

	if (opt_verbose) printf("Delete routes via %s dev %s\n", inet_ntoa(remote_point), ifname);
	sprintf(buf_remote, "%s", inet_ntoa(remote_point));
	while (1) {
		filled = 0;

		net_route = fopen(PROC_NET_ROUTE_PATH, "r");
		if (!net_route) {
			fprintf(stderr, "ERROR: Can't open file %s\n", PROC_NET_ROUTE_PATH);
			ret = 1;
			goto error;
		}

		if (!fgets(skip_header, sizeof(skip_header), net_route)) {
			fprintf(stderr, "ERROR: Can't skip header of %s\n", PROC_NET_ROUTE_PATH);
			ret = 2;
			goto error;
		}

		while (!feof(net_route)) {
			if (11 != fscanf(net_route, "%s\t%X\t%X\t%X\t%u\t%u\t%u\t%X\t%u\t%u\t%u",
				proc_ifname, &route_net[filled].s_addr, &route_gw.s_addr, &no, &no, &no, 
				&metric[filled], &route_mask[filled].s_addr, &no, &no, &no)) break;

			if (0 == strcmp(proc_ifname, ifname) && route_gw.s_addr == remote_point.s_addr) {
				filled++;
				if (filled >= sizeof(route_net)/sizeof(route_net[0])) break;
			}
		}

		for (int i = 0; i < filled; i++) {
			sprintf(buf_net, "%s", inet_ntoa(route_net[i]));
			sprintf(buf_mask, "%s", inet_ntoa(route_mask[i]));
			if (metric[i] != 0)
				sprintf(buf_metric, " metric %u", metric[i]);
			else
				sprintf(buf_metric, "%s", "");
			if (0 != run_command("%s route del %s/%s via %s dev %s%s",
				ip_bin, buf_net, buf_mask, buf_remote, ifname, buf_metric)
			) {
				fprintf(stderr, "ERROR: Can't delete route %s/%s via %s",
					buf_net, buf_mask, buf_remote);
			}
		}

		fclose(net_route);
#ifndef PROD
		if (opt_dryrun) break; // break forever loop in debug mode (dryrun routes don't deleted really)
#endif
		if (filled == 0) break;
	} // while

	return 0;
error:
	if (net_route) fclose(net_route);
	if (opt_verbose) printf("delete_all_routes_via_ip return %d\n", ret);
	return ret;
} // delete_all_routes_via_ip()

char *append_routes(const char ifaces[10][IF_NAMESIZE], const int ifaces_count, char *buffer) {
	int ret = 0;
	char skip_header[128];
	char proc_ifname[IF_NAMESIZE + 1];
	struct in_addr route_net;
	struct in_addr route_mask;
	struct in_addr route;
	uint32_t bitmask;
	char buf_net[50];
	unsigned int no;
	FILE *net_route = NULL;
	char *p = buffer;

	net_route = fopen(PROC_NET_ROUTE_PATH, "r");
	if (!net_route) {
		fprintf(stderr, "ERROR: Can't open file %s\n", PROC_NET_ROUTE_PATH);
		ret = 1;
		goto error;
	}

	if (!fgets(skip_header, sizeof(skip_header), net_route)) {
		fprintf(stderr, "ERROR: Can't skip header of %s\n", PROC_NET_ROUTE_PATH);
		ret = 2;
		goto error;
	}

	while (!feof(net_route)) {
		if (11 != fscanf(net_route, "%s\t%X\t%X\t%X\t%u\t%u\t%u\t%X\t%u\t%u\t%u",
			proc_ifname, &route_net.s_addr, &route.s_addr, &no, &no, &no, 
			&no, &route_mask.s_addr, &no, &no, &no)) break;

		no = 0; // skip flag
		for (int i = 0; i < ifaces_count; i++) {
			if (
				!strncmp(proc_ifname, ifaces[i], IF_NAMESIZE)
				|| !strncmp(proc_ifname, "lo", IF_NAMESIZE)
				|| !strncmp(proc_ifname, "tun", 3)
				|| !strncmp(proc_ifname, "tap", 3)
			) {
				no = 1;
				break;
			}
		}
		if (no) continue;

		no = 32; // mask bitcount
		bitmask = ntohl(route_mask.s_addr);
		while (no > 0 && (bitmask & 1) == 0) {
			no--;
			bitmask >>= 1;
		}
		buffer += sprintf(buffer, "\t%s/%d", inet_ntoa(route_net), no);
	}

	fclose(net_route);
	return buffer;
error:
	if (net_route) fclose(net_route);
	return p;
} // append_routes()

int main(int argc, char **argv) {
	char dgw_ifname[IF_NAMESIZE];
	char dgw_ip[50];
	unsigned int metric;
	struct ifaddrs *iface_addr_list = NULL;

	size_t active_count = 0;
	char active_ifaces[10][IF_NAMESIZE] = {};
	struct in_addr local_point[10] = {};
	struct in_addr remote_point[10] = {};
	int checked[10] = {};
	int sock[10] = {};
	struct sockaddr_in serveraddr[10] = {};
	struct sockaddr_in clientaddr[10] = {};
	struct timespec last_syn[10] = {};
	struct timespec last_ack[10] = {};
	struct timespec timestamp = {};
	int active_path = -1;

	fd_set sock_rfds;
	int max_fdnum = 0;
	struct timeval tv = {};
	char udp_packet[0xFFFF];
	size_t udp_packet_len = 0;

	int ret = 0;
	int mode = 1; // 0 - client, 1 - server
	int current_gw = -1;

#ifdef CLIENT
	// DEBUG client
	mode = 0;
	sprintf(active_ifaces[0],"%s","eth1");
	sprintf(active_ifaces[1],"%s","eth2");
	sprintf(active_ifaces[2],"%s","eth0.7");
	inet_aton("10.248.248.1", &remote_point[0]);
	inet_aton("10.248.249.1", &remote_point[1]);
	inet_aton("10.248.250.1", &remote_point[2]);
#else
	// DEBUG server
	mode = 1;
	sprintf(active_ifaces[0],"%s","eth3");
	sprintf(active_ifaces[1],"%s","eth4");
	sprintf(active_ifaces[2],"%s","eth1.7");
	inet_aton("10.248.248.2", &remote_point[0]);
	inet_aton("10.248.249.2", &remote_point[1]);
	inet_aton("10.248.250.2", &remote_point[2]);
#endif
	active_count = 3;

	if (active_count < 2) {
		fprintf(stderr, "ERROR: You must use at least two interfaces / remote addresses for this program\n");
		return 1;
	}

	// Search /bin/ip command binary
	for (const char **t = ip_search; *t; t++) {
		if (0 == access(*t, R_OK | X_OK)) { ip_bin = *t; break; }
	}
	if (!ip_bin) {
		fprintf(stderr,"Can't found 'ip' executable !\n");
		return 1;
	}

	// Prepare digest in OpenSSL
	md = EVP_get_digestbyname(opt_mdalgo);
	if (!md) {
		fprintf(stderr, "ERROR: Unknown digest type: %s\n", opt_mdalgo);
		return 1;
	}
	mdctx = EVP_MD_CTX_new();
	if (!mdctx) {
		fprintf(stderr, "ERROR: Can't create digest %s\n", opt_mdalgo);
		return 1;
	}

	// Echo current secret key hash
	if (0 != make_sign(NULL, 0)) { ret = 1; goto exitprog; }
	printf("Secret hash(%s): ", opt_mdalgo);
	for (int i = 0; i < md_len; i++) {
		printf("%02x", md_value[i]);
	}
	printf("\n");

	if (get_default_gateway(dgw_ip, dgw_ifname, &metric)) {
		printf("Default GW: default via %s dev %s metric %u\n", dgw_ip, dgw_ifname, metric);
	}

	for (int i = 0; i < sizeof sock / sizeof sock[0]; i++) sock[i] = -1;

	// Get interfaces info
	if (getifaddrs(&iface_addr_list) != 0) {
		fprintf(stderr, "ERROR: Can't get ifaces address list - %s \n", strerror(errno));
		return 1;
	}
	for (struct ifaddrs *l = iface_addr_list; l; l = l->ifa_next) {
		if (!l->ifa_addr || !l->ifa_name) continue;
		if (l->ifa_addr->sa_family == AF_INET) {
			struct sockaddr_in *iface_ip = (struct sockaddr_in *)l->ifa_addr;
			struct sockaddr_in *iface_netmask = (struct sockaddr_in *)l->ifa_netmask;
			int found = 0;

			for (int i = 0; i < active_count; i++) {
				if (checked[i]) continue;
				if ((iface_ip->sin_addr.s_addr & iface_netmask->sin_addr.s_addr) ==
				    (remote_point[i].s_addr & iface_netmask->sin_addr.s_addr)) {
					local_point[i].s_addr = iface_ip->sin_addr.s_addr;
					checked[i] = 1;
					found = 1;
					if (strlen(dgw_ifname) > 0 && !strncmp(dgw_ifname, l->ifa_name, IF_NAMESIZE)) {
						active_path = i;
					}
				}
			}

			printf("iface: %s", l->ifa_name);
			printf(", ip: %s", inet_ntoa(iface_ip->sin_addr));
			printf(", mask: %s", inet_ntoa(iface_netmask->sin_addr));
			if (found) printf(" *");
			printf("\n");
		}
	}
	if (iface_addr_list) {
		freeifaddrs(iface_addr_list);
		iface_addr_list = NULL;
	}

	for (int i = 0; i < active_count; i++) {
		if (!checked[i]) {
			fprintf(stderr, "ERROR: Wrong remote point %s for interface %s\n",
				inet_ntoa(remote_point[i]), active_ifaces[i]);
			goto exitprog;
		}
	}

#ifdef PROD
	if (daemon(0, 0) != 0) {
		fprintf(stderr,"Can't daemonize process!\n");
		goto exitprog;
	}
	opt_verbose = 0;
	opt_dryrun = 0;
#endif

	///////////////////////////////////////////////////////////////
	if (mode == 0) { // mode client
		if (opt_verbose) printf("Prepare UDP sockets for remote points:\n");
		for (int i = 0; i < active_count; i++) {
			sock[i] = socket(AF_INET, SOCK_DGRAM, 0);
			if (sock[i] < 0) {
				fprintf(stderr, "ERROR: Can't create UDP(%d) socket - %s\n", i, strerror(errno));
				ret = 1;
				goto exitprog;
			}

			memset(&clientaddr[i], 0, sizeof(clientaddr[i]));
			clientaddr[i].sin_family = AF_INET;
			clientaddr[i].sin_addr = local_point[i];
			clientaddr[i].sin_port = htons((unsigned short)opt_portno);

			if (checked[i] && opt_verbose)
				printf("\t%d - %s = %s\n", i + 1, active_ifaces[i], inet_ntoa(remote_point[i]));
		}

		// Forever client cycle
		while (!quit) {
			int s;
			for (int i = 0; i < active_count; i++) {
				// Get current time
				if (-1 == clock_gettime(CLOCK_MONOTONIC, &timestamp)) {
					fprintf(stderr, "ERROR: can't get monotonic clock\n");
					continue;
				}

				// Send message to server every keepalive period
				if ((timestamp.tv_sec + timestamp.tv_nsec/1000000000.0) -
				    (last_syn[i].tv_sec + last_syn[i].tv_nsec/1000000000.0) > opt_keepalive)
				{
					FILE *proc_routes = NULL;
					char *payload = NULL, *p = NULL;
					struct sockaddr_in remote_addr;
					socklen_t remote_addr_len = sizeof remote_addr;

					remote_addr.sin_family = AF_INET;
					remote_addr.sin_addr.s_addr = remote_point[i].s_addr;
					remote_addr.sin_port = htons((unsigned short)opt_portno);

					memcpy(udp_packet, &header_magic, sizeof(header_magic));
					payload = p = udp_packet + sizeof(header_magic);
					p += sprintf(p, "%" PRIu64 ".%" PRIu64 "\t%s\t%s",
						timestamp.tv_sec, timestamp.tv_nsec,
						active_path == i ? "A":"*",
						(timestamp.tv_sec + timestamp.tv_nsec/1000000000.0) -
						(last_ack[i].tv_sec + last_ack[i].tv_nsec/1000000000.0)
						<= (opt_keepalive * 2) ? "+":"-");

					// Dump routes from other ifaces (not active)
					p = append_routes(active_ifaces, active_count, p);
					p++; // skip \0
					if (0 != make_sign(payload, p - payload - 1))
						continue;
					*(p++) = 0; // add more 0 for safe strsep
					*(p++) = (char)md_len;
					memcpy(p, md_value, md_len);
					p += md_len;
					if (-1 != sendto(sock[i], udp_packet, p - udp_packet, 0,
						(struct sockaddr *) &remote_addr, remote_addr_len))
					{
						if (opt_verbose) printf("SEND to server %s = %s\n", active_ifaces[i], payload);
						memcpy(&last_syn[i], &timestamp, sizeof(struct timespec));
					} else {
						fprintf(stderr, "ERROR: Can't sendto(%s) - %s\n",
							inet_ntoa(remote_point[i]), strerror(errno));
					}
				}
			} // for i=active

			// Read ack answers from server side 
			FD_ZERO(&sock_rfds);
			max_fdnum = 0;
			for (int i = 0; i < active_count; i++) {
				FD_SET(sock[i], &sock_rfds);
				if (max_fdnum < sock[i]) max_fdnum = sock[i];
			}

			tv.tv_sec = 1; tv.tv_usec = 0;
			s = select(max_fdnum + 1, &sock_rfds, NULL, NULL, &tv);
			if (s == -1) { // error
				fprintf(stderr, "ERROR: select error %s\n", strerror(errno));
				continue;

			// read packet timeout
			} else if (s == 0) {
				if (-1 == clock_gettime(CLOCK_MONOTONIC, &timestamp)) {
					fprintf(stderr, "ERROR: can't get monotonic clock\n");
					continue;
				}

				// Check current path state
				if (active_path != -1 && ((timestamp.tv_sec + timestamp.tv_nsec/1000000000.0) -
					    (last_ack[active_path].tv_sec + last_ack[active_path].tv_nsec/1000000000.0) > opt_keepalive * 2))
				{
					if (get_default_gateway(dgw_ip, dgw_ifname, &metric)) {
						char metric_val[50] = "";
						if (metric != 0) sprintf(metric_val, " metric %u", metric);

						if (0 != run_command("%s route del default via %s dev %s%s", ip_bin, dgw_ip, dgw_ifname, metric_val)) {
							fprintf(stderr, "ERROR: delete default gw failed\n");
						} else {
							if (opt_verbose) printf("Reset current path %d (last ack expired)\n", active_path);
							active_path = -1;
						}
					}
				}

				// Try to find new path
				if (active_path == -1) {
					for (int i = 0; i < active_count; i++) {
						if ((timestamp.tv_sec + timestamp.tv_nsec/1000000000.0) -
						    (last_ack[i].tv_sec + last_ack[i].tv_nsec/1000000000.0) <= opt_keepalive)
						{
							if (0 != run_command("%s route add default via %s dev %s", ip_bin,
								inet_ntoa(remote_point[i]), active_ifaces[i])) {
								fprintf(stderr, "ERROR: add default gw failed\n");
							} else {
								if (opt_verbose) printf("Select %d connection as active\n", i);
								active_path = i;
							}
							break;
						}
					}
				}
			
			// Analyze received packet
			} else for (int i = 0; i < active_count; i++) {
				struct sockaddr_in remote_addr;
				socklen_t remote_addr_len = sizeof remote_addr;
				char *payload = NULL, *p = NULL;
				size_t payload_len;
				if (!FD_ISSET(sock[i], &sock_rfds)) continue;

				// Read UDP packet
				s = recvfrom(sock[i], udp_packet, sizeof(udp_packet), 0,
					(struct sockaddr *) &remote_addr, &remote_addr_len);
				if (s < 0) {
					fprintf(stderr, "ERROR: recvfrom error %s\n", strerror(errno));
					continue;
				} else if (s == 0) continue;

				if (remote_addr.sin_family != AF_INET
					|| remote_addr_len != sizeof(struct sockaddr_in)
					|| s < sizeof(header_magic)
					|| 0 != memcmp(udp_packet, &header_magic, sizeof(header_magic))
					|| NULL == memchr(udp_packet + sizeof(header_magic), '\0',
						sizeof(udp_packet) - sizeof(header_magic))
				) {
					fprintf(stderr, "ERROR: recieve bogus packet\n");
					continue;
				}

				if (remote_addr.sin_addr.s_addr != remote_point[i].s_addr) {
					fprintf(stderr, "ERROR: recieve packet from bad address: %s\n",
						inet_ntoa(remote_addr.sin_addr));
					continue;
				}

				payload = udp_packet + sizeof(header_magic);
				payload_len = strlen(payload);
				if (payload_len + sizeof(header_magic) > s) {
					fprintf(stderr, "ERROR: bad payload len\n");
					continue;
				}

				// check sign
				if (0 != make_sign(payload, payload_len))
					continue;

				p = payload + payload_len + 1;
				if (*p != (char) md_len) {
					fprintf(stderr, "ERROR: Bad sign len %u (want %hhu)\n", md_len, (unsigned char)(*p));
					continue;
				} else p++;
				if (0 != memcmp(p, md_value, md_len)) {
					fprintf(stderr, "ERROR: Bad sign message\n");
					continue;
				}

				if (opt_verbose) printf("RECV from server (%s): %s\n", inet_ntoa(remote_addr.sin_addr), payload);

				if (2 != sscanf(payload, "%ld.%ld", &timestamp.tv_sec, &timestamp.tv_nsec)) {
					fprintf(stderr, "ERROR: Bad timespec value\n");
					continue;
				}
				if (0 != memcmp(&last_syn[i], &timestamp, sizeof(struct timespec))) {
					fprintf(stderr, "ERROR: Not last timestamp recieved\n");
					// TODO something ?!
				}

				if (-1 == clock_gettime(CLOCK_MONOTONIC, &last_ack[i])) {
					fprintf(stderr, "ERROR: can't get monotonic clock\n");
					continue;
				}

				// Activate more priority link if it makes alive
				if (active_path != -1 && i < active_path && opt_autoswitch) {

					if (get_default_gateway(dgw_ip, dgw_ifname, &metric)) {
						char metric_val[50] = "";
						if (metric != 0) sprintf(metric_val, " metric %u", metric);

						if (0 != run_command("%s route del default via %s dev %s%s", ip_bin, dgw_ip, dgw_ifname, metric_val)) {
							fprintf(stderr, "ERROR: delete default gw failed\n");
						} else {
							if (opt_verbose) printf("Reset current path %d (last ack expired)\n", active_path);
							active_path = -1;
						}
					}
					/*
					if (0 != run_command("%s route del default via %s dev %s", ip_bin,
						inet_ntoa(remote_point[active_path]), active_ifaces[active_path])) {
						fprintf(stderr, "ERROR: delete default gw failed\n");
					}
					*/
					if (0 != run_command("%s route add default via %s dev %s", ip_bin,
						inet_ntoa(remote_point[i]), active_ifaces[i])) {
						fprintf(stderr, "ERROR: add default gw failed\n");
					} else {
						if (opt_verbose) printf("Switch current path %d to more priority %d\n", active_path, i);
						active_path = i;
					}
				}
			} // for

			if (opt_verbose) fflush(stdout);
		} // while (!quit)
///////////////////////////////////////////////////////////////
	} else { // mode server
		char *current_client_routes = NULL;
		char *new_client_routes = NULL;

		for (int i = 0; i < active_count; i++) {
			sock[i] = socket(AF_INET, SOCK_DGRAM, 0);
			if (sock[i] < 0) {
				fprintf(stderr, "ERROR: Can't create UDP(%d) socket - %s\n", i, strerror(errno));
				ret = 1;
				goto exitprog;
			}

			memset(&serveraddr[i], 0, sizeof serveraddr[i]);
			serveraddr[i].sin_family = AF_INET;
			serveraddr[i].sin_addr = local_point[i];
			serveraddr[i].sin_port = htons((unsigned short)opt_portno);

			if (0 > bind(sock[i], (struct sockaddr *)&serveraddr[i], sizeof serveraddr[i])) {
				fprintf(stderr, "ERROR: Can't bind UDP socket on %s %s:%d - %s\n", active_ifaces[i],
					inet_ntoa(local_point[i]), opt_portno, strerror(errno));
				ret = 1;
				goto exitprog;
			}

			if (0 != delete_all_routes_via_ip(active_ifaces[i], remote_point[i])) {
				fprintf(stderr, "ERROR: Can't clean route table via %s iface\n",
					active_ifaces[i]);
			}
		} // for

		// Forever server cycle
		while (!quit) {
			int s;

			FD_ZERO(&sock_rfds);
			max_fdnum = 0;
			for (int i = 0; i < active_count; i++) {
				FD_SET(sock[i], &sock_rfds);
				if (max_fdnum < sock[i]) max_fdnum = sock[i];
			}

			tv.tv_sec = 1; tv.tv_usec = 0;
			s = select(max_fdnum + 1, &sock_rfds, NULL, NULL, &tv);
			if (s == -1) { // error
				fprintf(stderr, "ERROR: select error %s\n", strerror(errno));
				continue;
			} else if (s == 0) { // timeout
				if (-1 == clock_gettime(CLOCK_MONOTONIC, &timestamp)) {
					fprintf(stderr, "ERROR: can't get monotonic clock\n");
					continue;
				}

				// Check current path state
				if (active_path != -1 && ((timestamp.tv_sec + timestamp.tv_nsec/1000000000.0) -
					    (last_ack[active_path].tv_sec + last_ack[active_path].tv_nsec/1000000000.0) > opt_keepalive * 2))
				{
					if (0 == delete_all_routes_via_ip(active_ifaces[active_path], remote_point[active_path])) {
						if (opt_verbose) printf("Reset current path %d (last ack expired)\n", active_path);
						active_path = -1;
					}
				}
			} else for (int i = 0; i < active_count; i++) { // work
				struct sockaddr_in remote_addr;
				socklen_t remote_addr_len = sizeof remote_addr;
				char *payload = NULL, *p = NULL;
				size_t payload_len;
				char *token;
				int token_num = 0;
				int rebuild_routes = 0;
				int new_active = -1;

				if (!FD_ISSET(sock[i], &sock_rfds)) continue;

				s = recvfrom(sock[i], udp_packet, sizeof(udp_packet), 0,
					(struct sockaddr *) &remote_addr, &remote_addr_len);
				if (s < 0) {
					fprintf(stderr, "ERROR: recvfrom error %s\n", strerror(errno));
					continue;
				} else if (s == 0) continue;

				if (remote_addr.sin_family != AF_INET
					|| remote_addr_len != sizeof(struct sockaddr_in)
					|| s < sizeof(header_magic)
					|| 0 != memcmp(udp_packet, &header_magic, sizeof(header_magic))
					|| NULL == memchr(udp_packet + sizeof(header_magic), '\0',
						sizeof(udp_packet) - sizeof(header_magic))
				) {
					fprintf(stderr, "ERROR: recieve bogus packet\n");
					continue;
				}

				if (remote_addr.sin_addr.s_addr != remote_point[i].s_addr) {
					fprintf(stderr, "ERROR: recieve packet from bad address: %s\n",
						inet_ntoa(remote_addr.sin_addr));
					continue;
				}

				payload = udp_packet + sizeof(header_magic);
				payload_len = strlen(payload);
				if (payload_len + sizeof(header_magic) > s) {
					fprintf(stderr, "ERROR: bad payload len\n");
					continue;
				}

				// check packet sign
				if (0 != make_sign(payload, payload_len))
					continue;

				p = payload + payload_len + 2; // skip additional '0'
				if (*p != (char) md_len) {
					fprintf(stderr, "ERROR: Bad sign len %u (want %hhu)\n", md_len, (unsigned char)(*p));
					continue;
				} else p++;
				if (0 != memcmp(p, md_value, md_len)) {
					fprintf(stderr, "ERROR: Bad sign message\n");
					continue;
				}

				if (opt_verbose) printf("RECV from client (%s:%d): %s\n", inet_ntoa(remote_addr.sin_addr), 
					ntohs(remote_addr.sin_port), payload);

				p = payload;
				token_num = 0;
				while ((token = strsep(&p,"\t")) != NULL) {
					token_num++;
					if (1 == token_num) { // timestamp on client side
						if (2 != sscanf(token, "%ld.%ld", &timestamp.tv_sec, &timestamp.tv_nsec)) {
							fprintf(stderr, "ERROR: Bad timespec value\n");
							rebuild_routes = -1; // break analyze
							break;
						}
					} else if (2 == token_num) { // link mode on client side (A - active, * - passive)
						if ((i != active_path && 0 == strcmp(token,"A")) // link become active
							|| (i == active_path && 0 == strcmp(token,"*")) // link become passive
						) {
							if (-1 != active_path && 0 == delete_all_routes_via_ip(
								active_ifaces[active_path], remote_point[active_path])) {
								if (opt_verbose) printf("Clean routes for %s via %s\n",
									active_ifaces[active_path], inet_ntoa(remote_point[active_path]));
							}
							if (i == active_path) new_active = -1; else new_active = i;
							rebuild_routes = 1;
						}
					} else if (3 == token_num) { // ack state on client side ("+" - ack ok, "-" - ack fail)
						// skip ack flag
						// TODO if we need something do with ack flag value

						if ( // check active path new subnet list with current
							0 == rebuild_routes &&
							1 == strlen(token) &&
							i == active_path &&
							current_client_routes &&
							0 != strcmp(token + 2, current_client_routes)
						) {
							if (opt_verbose) printf("Detect new subnet list on active iface\n");
							if (0 != delete_all_routes_via_ip(active_ifaces[active_path], remote_point[active_path])) {
								fprintf(stderr, "ERROR: Can't clean route table via %s iface\n",
									active_ifaces[active_path]);
							}
							new_active = i;
							rebuild_routes = 1;
						}

						// If rebuild mode then save subnet list
						if (rebuild_routes == 1) {
							new_client_routes = strdup(token + 2);
							if (!new_client_routes) {
								fprintf(stderr, "ERROR: Can't strdup new routes list");
							}
						}
					} else if (4 <= token_num) { // subnet via link on client side
						if (rebuild_routes == 1 && -1 != new_active) {
							// Add route from token
							if (0 != run_command("%s route add %s via %s dev %s",
								ip_bin, token, inet_ntoa(remote_point[i]), active_ifaces[i])
							) {
								fprintf(stderr, "ERROR: Fail add route %s via %s dev %s\n",
									token, inet_ntoa(remote_point[i]), active_ifaces[i]);
							}
						} else break;
					}
				} // while strsep
				if (rebuild_routes == -1) continue;

				if (rebuild_routes == 1) {
					if (current_client_routes) {
						free(current_client_routes);
						current_client_routes = NULL;
					}
					if (new_client_routes) {
						current_client_routes = new_client_routes;
						new_client_routes = NULL;
					}
					if (opt_verbose) printf("Set active_path=%d to %d (routes %s)\n", active_path, new_active,
						current_client_routes ? current_client_routes : "NULL");
					active_path = new_active;
				}

				if (-1 == clock_gettime(CLOCK_MONOTONIC, &last_ack[i])) {
					fprintf(stderr, "ERROR: can't get monotonic clock\n");
					continue;
				}

				// Send ACK to client with parsed timestamp
				p = payload;
				p += sprintf(p, "%" PRIu64 ".%" PRIu64, timestamp.tv_sec, timestamp.tv_nsec);
				p++; // skip \0
				if (0 != make_sign(payload, p - payload - 1))
					continue;
				*(p++) = (char)md_len;
				memcpy(p, md_value, md_len);
				p += md_len;
				if (-1 != sendto(sock[i], udp_packet, p - udp_packet, 0,
					(struct sockaddr *) &remote_addr, sizeof(struct sockaddr_in)))
				{
					if (opt_verbose) printf("SEND to client %s = %s\n", active_ifaces[i], payload);
					memcpy(&last_syn[i], &timestamp, sizeof(struct timespec));
				} else {
					fprintf(stderr, "ERROR: Can't sendto(%s) - %s\n",
						inet_ntoa(remote_point[i]), strerror(errno));
				}
			} // if
			fflush(stdout);
		} // while
	} // server

exitprog:
	for (int i = 0; i < active_count; i++) {
		if (sock[i] != -1) {
			shutdown(sock[i], 2);
			close(sock[i]);
		}
	}

	if (mdctx) EVP_MD_CTX_free(mdctx);

	if (iface_addr_list) freeifaddrs(iface_addr_list);
	return ret;
}
