// Include files
#include <cstring>
#include <getopt.h>

#include <resolv.h>
#include <arpa/nameser.h>

#include <iostream>

#include "common.h"
#include "DNSProxy.h"

// Defaults for command line options.
#define DFLT_LISTEN_ADDR		"127.0.0.1"
#define DFLT_LISTEN_PORT		9000
#define DFLT_UPSTREAM_PORT		NS_DEFAULTPORT

#define DFLT_REQUEST_TIMEOUT		15
#define DFLT_MAX_REQUESTS		250
#define DFLT_MAX_PORTS			50
#define DFLT_MAX_PORT_LIFETIME		10
#define DFLT_MIN_GC_TIME		5

// Expand @x and return it stringified (eg. 5 -> "5")..
#define QQ(x)				#x
#define Q(x)				QQ(x)

// Command line option descriptions for getopt_long().
static struct option const options[] =
{
	{ "help",		no_argument,		NULL, 'h' },
	{ "debug",		no_argument,		NULL, 'D' },
	{ "seed",		required_argument,	NULL, 'S' },

	{ "listen",		required_argument,	NULL, 'l' },
	{ "port",		required_argument,	NULL, 'p' },

	{ "timeout",		required_argument,	NULL, 't' },
	{ "max-requests",	required_argument,	NULL, 'r' },
	{ "min-gc-time",	required_argument,	NULL, 'T' },

	{ "max-ports",		required_argument,	NULL, 'n' },
	{ "max-port-lifetime",	required_argument,	NULL, 'N' },
};

// Program code
// Print the help to @out.
static void help(std::ostream &out)
{
	// @program_invocation_short_name is the basename of main()'s
	// @argv[0].
	out <<
"Usage: " << program_invocation_short_name
	  << " [options] <upstream-address> [<upstream-port>]\n"
"\n"
"Simple but secure UDP-to-UDP DNS forwarder.\n"
"\n"
"Options:\n"
"  --help, -h				Print this help and exit.\n"
"  --debug, -D				Print debug logs including the\n"
"					queried domains and enable extra\n"
"					internal sanity checks.\n"
"  --seed, -S <number>     		Initialize the pseudo-random number\n"
"					generator with this seed.  Useful to\n"
"					reproduce a previous run of the\n"
"					program in case a bug is found.\n"
"					If not specified the PRNG is seeded\n"
"					based on the current time.  The seed\n"
"					is printed with the debug logs.\n"
"\n"
"  --listen, -l <address>		Listen for DNS queries on this IPv4\n"
"					address.  The default is "
					DFLT_LISTEN_ADDR ".\n"
"  --port, -p <port>			Listen for DNS queries on this UDP\n"
"					port.  The default is "
					Q(DFLT_LISTEN_PORT) ".\n"
"\n"
"  --timeout, -t <seconds>		Maximum time to wait for a response\n"
"					from the upstream DNS server.\n"
"					The default is " Q(DFLT_REQUEST_TIMEOUT)
					" seconds.  The system\n"
"					resolver's default is " Q(RES_TIMEOUT)
					" seconds.\n"
"					Specifying 0 disables query expiration.\n"
"  --max-requests, -r <number>		Maximum number of forwarded queries\n"
"					to handle at the same time.  This\n"
"					option influences the maximum memory\n"
"					usage of the program.  The default is\n"
"					" Q(DFLT_MAX_REQUESTS) ".  "
					"Specifying 0 disables the limit.\n"
"					In practice the maximum is "
					<< Requests::MAX_POSSIBLE_QUERIES << ",\n"
"					because of the limited size of query ID\n"
"					in DNS messages.\n"
"  --min-gc-time, -T <seconds>		Usually queries are expired as soon as\n"
"					they time out.  However, if there are\n"
"					many of them in quick succession, it is\n"
"					impractical to wake up the program\n"
"					for each one in a short period of time.\n"
"					Instead this case queries are expired \n"
"					in batches, every <seconds> "
					"(" Q(DFLT_MIN_GC_TIME) " being\n"
"					the default).  Specifying 0 causes\n"
"					timed out queries to be expired exactly\n"
"					on time always.\n"
"\n"
"  --max-ports, -n <number>		Maximum number of source ports to use\n"
"					for forwarding, " Q(DFLT_MAX_PORTS) " "
					"by default.  Queries\n"
"					are forwarded through randomly chosen\n"
"					source ports for security.  If <number>\n"
"					is 0, a new port is opened every time,\n"
"					until the system runs out of them.\n"
"					Then one of the already open ports\n"
"					is selected for forwarding.\n"
"  --max-port-lifetime, -N <number>	Close a source port after this many\n"
"					queries have been forwarded through it.\n"
"					This increases security by varying the\n"
"					source ports over time.  Specifying 0\n"
"					allows a port to be reused any number\n"
"					of times.\n"
"\n"
"<upstream-address>:<upstream-port> (default " Q(DFLT_UPSTREAM_PORT) ") "
"is the IPv4 address of the DNS\n"
"server to forward queries to.  Queries are forwarded with randomized ID and\n"
"source port, and responses are strictly validated against blind spoofing\n"
"attacks.\n";
}

int main(int argc, char *const *argv)
{
	// Set defaults for command line options.
	bool debug = false;
	unsigned rnd_seed = 0;

	const char *local_addr	= DFLT_LISTEN_ADDR;
	unsigned local_port	= DFLT_LISTEN_PORT;

	// There's no reasonable default for @upstream.
	const char *upstream;
	unsigned upstream_port	= DFLT_UPSTREAM_PORT;

	struct DNSProxy::config_st config =
	{
		DFLT_REQUEST_TIMEOUT,
		DFLT_MAX_REQUESTS,
		DFLT_MAX_PORTS,
		DFLT_MAX_PORT_LIFETIME,
		DFLT_MIN_GC_TIME,
	};

	// Parse the command line.
	int optchar;
	while ((optchar = getopt_long(argc, argv,
				      "hDS:l:p:t:r:T:n:N:", options,
				      NULL)) != -1)
		switch (optchar)
		{
		case '?': // Invalid option
			return 1;

		case 'h':
			help(std::cout);
			return 0;
		case 'D':
			debug = true;
			break;
		case 'S':
			rnd_seed = atoi(optarg);
			break;

		case 'l':
			local_addr = optarg;
			break;
		case 'p':
			local_port = atoi(optarg);
			break;

		case 't':
			config.request_timeout = atoi(optarg);
			break;
		case 'r':
			config.max_requests = atoi(optarg);
			break;
		case 'T':
			config.min_gc_time = atoi(optarg);
			break;

		case 'n':
			config.max_ports = atoi(optarg);
			break;
		case 'N':
			config.max_port_lifetime = atoi(optarg);
			break;
		}

	argv += optind;
	if (!*argv)
	{	// @upstream is a required argument.
		help(std::cerr);
		return 1;
	}

	upstream = *argv++;
	if (*argv)
		upstream_port = atoi(*argv++);

	// Log the configuration.
	common::Init(debug, rnd_seed);
	common::Log_debug("Request timeout:              %us",
			  config.request_timeout);
	common::Log_debug("Max. outstanding requests:    %u",
			  config.max_requests);
	common::Log_debug("Max. number of ports:         %u",
			  config.max_ports);
	common::Log_debug("Max. port lifetime:           %u",
			  config.max_port_lifetime);
	common::Log_debug("Min. garbage collection time: %us",
			  config.min_gc_time);
	common::Log_info("Upstream server: %s:%u", upstream, upstream_port);

	// Run the proxy.
	DNSProxy app(config);
	if (!app.Init(local_addr, local_port, upstream, upstream_port))
		return 1;
	app.Run();

	return 0;
}

// End of main.cc
