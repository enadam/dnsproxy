#ifndef DNS_PROXY_H
#define DNS_PROXY_H

#include <vector>

#include <netinet/in.h>
#include <arpa/nameser.h>

#include "Requests.h"

// Forward declarations
class Requests;
class Upstream;

// Class taking DNS queries from clients, forwarding them to the upstream
// server and returning the response to the appropriate client.
class DNSProxy
{
public:
	struct config_st
	{
		unsigned request_timeout;
		unsigned max_requests;
		unsigned max_ports;
		unsigned max_port_lifetime;
		unsigned min_gc_time;
	};

protected:
	typedef HEADER dns_header_st;

	// Config options for the Requests and Upstream classes.
	const struct config_st config;

	// @serverfd is a socket receiving queries from clients.
	// @pollfd is an epoll fd used in the main loop.
	// @timerfd is used to call Requests::Gc() at the appropriate time.
	int serverfd = -1, pollfd = -1, timerfd = -1;

	// The upstream server address is used in log messages.
	struct sockaddr_in upstream;

	Requests *requests = NULL;
	Upstream *sockets  = NULL;

public:
	DNSProxy(const struct config_st &config);
	~DNSProxy();

	// Creates @serverfd, @pollfd and @timerfd.
	// @serverfd is bound to @local_addr:@local_port.
	// On error false is returned and the object must be destroyed.
	bool Init(const char *local_addr, unsigned local_port,
		  const char *upstream_addr, unsigned upstream_port);

	// Runs the main loop.  It never ends actually.
	void Run();

protected:
	bool str2addr(struct sockaddr_in *saddr,
		      const char *addr, unsigned port) const;

	char *receive_message(int fd, int *smsgp,
			      struct sockaddr_in *sender = NULL) const;
	void discard_message(int fd) const;
	const dns_header_st *parse_message(const struct sockaddr_in &sender,
					   const char *msg, size_t smsg,
					   Requests::query_id_t *query_idp,
					   std::vector<char> &question) const;

	bool forward_query() const;
	bool return_response(int upstream_fd) const;
};

#endif // ! DNS_PROXY_H
