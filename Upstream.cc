// Include files
#include <cassert>
#include <unistd.h>

#include <sys/epoll.h>
#include <arpa/inet.h>

#include <random>
#include <iterator>

#include "common.h"
#include "Upstream.h"

// Program code
Upstream::Upstream(unsigned max_ports, unsigned max_port_lifetime,
		   int pollfd, const struct sockaddr_in &upstream):
	MAX_PORTS(max_ports),
	MAX_PORT_LIFETIME(max_port_lifetime),
	pollfd(pollfd),
	upstream(upstream)
{
	// NOP
}

Upstream::~Upstream()
{	// close() all the file descriptors we were managing.
	for (const auto &i: this->available)
		close(i.first);
	for (const auto &i: this->end_of_life)
		close(i.first);
}

// Create a socket bound to a random local port, connect it to the @upstream
// and add it to @pollfd.  On failure logs the error and returns -1.
int Upstream::new_upstream_socket() const
{
	int sfd;

	// connect() will also bind() the socket.
	// We rely on the kernel chosing a random local port.
	if ((sfd = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
	{
		common::Log_error("socket(upstream_fd): %m");
		return -1;
	} else if (connect(sfd,
			   reinterpret_cast<const sockaddr *>
					   (&this->upstream),
			   sizeof(this->upstream)) < 0)
	{
		common::Log_error("connect(%s:%u): %m",
				  inet_ntoa(this->upstream.sin_addr),
				  ntohs(this->upstream.sin_port));
		close(sfd);
		return -1;
	}

	struct epoll_event event = { EPOLLIN };
	event.data.fd = sfd;
	if (epoll_ctl(this->pollfd, EPOLL_CTL_ADD, sfd, &event) < 0)
	{
		common::Log_error("epoll_ctl(add): %m");
		close(sfd);
		return -1;
	}

	return sfd;
}

struct Upstream::socket_usage_st *Upstream::Get(int *sfdp)
{
	// @open_new_port if we can afford it, otherwise choose an
	// @available one.
	bool open_new_port = !MAX_PORTS
		|| this->available.size() + this->end_of_life.size()
			< MAX_PORTS;
	if (!open_new_port && this->available.empty())
	{
		common::Log_error("Maximum number of bound ports reached.");
		return NULL;
	} else if (open_new_port && (*sfdp = new_upstream_socket()) >= 0)
	{	// The new *@sfdp must be unique.
		auto ret = this->available.emplace(*sfdp,
						   socket_usage_st { 0, 0 });
		assert(ret.second == true);
		return &ret.first->second;
	} else if (!this->available.empty())
	{	// Either we didn't want to @open_new_port or we couldn't,
		// but there are @available ones.  Choose one randomly.
		auto n = std::uniform_int_distribution<unsigned>
				(0, this->available.size()-1)
				(common::Rnd);

		// Too bad there's no standard function to select a random
		// entry in an unordered_map.
		auto i = this->available.begin();
		std::advance(i, n);

		*sfdp = i->first;
		return &i->second;
	} else	// Couldn't @open_new_port.
		return NULL;
}

void Upstream::Put(int sfd, struct socket_usage_st *socket)
{
	socket->outstanding++;
	if (MAX_PORT_LIFETIME && ++socket->lifetime >= MAX_PORT_LIFETIME)
	{	// @MAX_PORT_LIFETIME reached, move @sfd to @end_of_life.
		auto i = this->available.find(sfd);
		assert(i != this->available.end());

		auto ret = this->end_of_life.emplace(sfd,
						     socket->outstanding);
		assert(ret.second == true);

		this->available.erase(i);
	}
}

void Upstream::Done(int sfd)
{
	// @sfd must be either @available ...
	auto i = this->available.find(sfd);
	if (i != this->available.end())
	{
		struct socket_usage_st *socket = &i->second;
		assert(socket->outstanding > 0);
		socket->outstanding--;
		return;
	}

	// ... or @end_of_life.
	auto o = this->end_of_life.find(sfd);
	assert(o != this->end_of_life.end());

	// Decrease the reference counter.
	assert(o->second > 0);
	o->second--;

	if (!o->second)
	{	// @sfd doesn't have outstanding requests anymore, close it.
		this->end_of_life.erase(o);

		// Don't call inet_ntoa() if we're not in debug mode.
		if (common::Debug)
		{
			struct sockaddr_in saddr;
			if (common::GetSockName(sfd, &saddr))
				common::Log_debug("%s:%u socket end of life, "
						  "closing",
						  inet_ntoa(saddr.sin_addr),
						  ntohs(saddr.sin_port));
		}

		// close() also removes @sfd from @this->pollfd.
		close(sfd);
	}
}

// End of Upstream.cc
