#ifndef UPSTREAM_H
#define UPSTREAM_H

#include <netinet/in.h>
#include <unordered_map>

// Class to create, select and dispose of socket file descriptors connected to
// the upstream DNS server.
class Upstream
{
public:
	// Usage information of an upstream socket.
	struct socket_usage_st
	{
		// Number of requests awaiting response via this socket.
		// Used as a reference counter.
		unsigned outstanding;

		// Total number of requests forwarded through this socket.
		// When it reaches @MAX_PORT_LIFETIME the socket is moved
		// to @end_of_life.
		unsigned lifetime;
	};

protected:
	// Socket fd -> socket usage map.  Sockets in this map can be selected
	// for forwarding by Get().
	std::unordered_map<int, struct socket_usage_st> available;

	// Socket fd -> # of outstanding requests map.  Sockets in this map
	// are closed as soon as the outstanding requests are answered or
	// time out.
	std::unordered_map<int, unsigned> end_of_life;

protected:
	// Initialized from command line options.
	const unsigned MAX_PORTS;
	const unsigned MAX_PORT_LIFETIME;

	// The epoll file descriptor used in the main loop.
	int pollfd;

	// Address of the upstream DNS server where sockets will be
	// connected to.
	struct sockaddr_in upstream;

public:
	Upstream(unsigned max_ports, unsigned max_port_lifetime,
		 int pollfd, const struct sockaddr_in &upstream);
	~Upstream();

	// Return a random @available upstream socket or create a new one
	// if @MAX_PORTS allows it.  If it doesn't or socket creation failed,
	// logs and error and returns NULL.
	struct socket_usage_st *Get(int *sfdp);

	// Called when a request is forwarded through @sfd.  Does the
	// accounting and moves it to @end_of_life if it has been reached.
	void Put(int sfd, struct socket_usage_st *socket);

	// Called when a response is received through @sfd or if a query
	// forwarded through it has timed out.
	void Done(int sfd);

protected:
	int new_upstream_socket() const;
};

#endif // ! UPSTREAM_H
