// Include files
#include <cassert>
#include <cerrno>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/ioctl.h>

#include <arpa/inet.h>
#include <arpa/nameser.h>

#include "common.h"
#include "Requests.h"
#include "Upstream.h"
#include "DNSProxy.h"

// Program code
DNSProxy::DNSProxy(const struct config_st &config):
	config(config)
{
	// NOP
}

DNSProxy::~DNSProxy()
{
	delete this->sockets;
	delete this->requests;

	if (this->timerfd >= 0)
		close(this->timerfd);
	if (this->serverfd >= 0)
		close(this->serverfd);
	if (this->pollfd >= 0)
		close(this->pollfd);
}

// Parse @addr and @port and put them info @saddr.
bool DNSProxy::str2addr(struct sockaddr_in *saddr,
			const char *addr, unsigned port) const
{
	saddr->sin_family = AF_INET;
	if (!inet_aton(addr, &saddr->sin_addr))
	{
		common::Log_error("%s: invalid IPv4 address", addr);
		return false;
	} else if (port > std::numeric_limits<uint16_t>::max())
	{
		common::Log_error("port %u is out of range", port);
		return false;
	} else
	{
		saddr->sin_port = htons(port);
		return true;
	}
}

bool DNSProxy::Init(const char *local_addr, unsigned local_port,
		    const char *upstream_addr, unsigned upstream_port)
{
	struct sockaddr_in listen_addr;

	// Before anything else parse the addresses we're given.
	if (!str2addr(&listen_addr, local_addr, local_port))
		return false;
	if (!str2addr(&this->upstream, upstream_addr, upstream_port))
		return false;

	if ((this->pollfd = epoll_create(1)) < 0)
	{
		common::Log_error("epoll_create(): %m");
		return false;
	}

	// Let's not close fd:s on error, the destructor will do it anyway.
	if ((this->serverfd = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
	{
		common::Log_error("socket(serverfd): %m");
		return false;
	} else if (bind(this->serverfd,
			reinterpret_cast<const sockaddr *>(&listen_addr),
			sizeof(listen_addr)) < 0)
	{
		common::Log_error("bind(%s:%u): %m", local_addr, local_port);
		return false;
	} else
		common::Log_info("Listening on %s:%u",
				 local_addr, local_port);

	struct epoll_event event = { EPOLLIN };
	event.data.fd = this->serverfd;
	if (epoll_ctl(this->pollfd, EPOLL_CTL_ADD, this->serverfd,
		      &event) < 0)
	{
		common::Log_error("epoll_ctl(add): %m");
		return false;
	}

	if ((this->timerfd = timerfd_create(CLOCK_MONOTONIC, 0)) < 0)
	{
		common::Log_error("timerfd_create(): %m");
		return false;
	}

	event.data.fd = this->timerfd;
	if (epoll_ctl(this->pollfd, EPOLL_CTL_ADD, this->timerfd, &event) < 0)
	{
		common::Log_error("epoll_ctl(add): %m");
		return false;
	}

	this->sockets = new Upstream(this->config.max_ports,
				     this->config.max_port_lifetime,
				     this->pollfd, this->upstream);
	this->requests = new Requests(this->config.max_requests,
				      this->config.request_timeout,
				      this->config.min_gc_time,
				      this->timerfd);

	return true;
}

// Read an UDP message from @fd, returning its size in *@smsgp.
// If @sender is not NULL it is filled.  On failure returns NULL.
char *DNSProxy::receive_message(int fd, int *smsgp,
				struct sockaddr_in *sender) const
{
	char *msg;
	socklen_t addrlen;

	// First try to determine the size of the message.
	// If we can't, assume it's no larger than NS_MAXMSG.
	if (ioctl(fd, FIONREAD, smsgp) < 0)
	{
		common::Log_error("ioctl(FIONREAD): %m");
		*smsgp = NS_MAXMSG;
	} else if (*smsgp < 0 || *smsgp > NS_MAXMSG)
	{
		common::Log_error("ioctl(FIONREAD): "
				  "unexpected incoming message size "
				  "(%d bytes)", *smsgp);
		*smsgp = NS_MAXMSG;
	}

	struct sockaddr_in tmp_sender;
	if (!sender)
		sender = &tmp_sender;

	// Receive @msg.
	msg = new char[*smsgp];
	addrlen = sizeof(*sender);
	*smsgp = recvfrom(fd, msg, *smsgp, 0,
			  reinterpret_cast<struct sockaddr *>(sender),
			  &addrlen);
	if (*smsgp < 0)
	{
		common::Log_error("recvfrom(): %m");
		delete[] msg;
		return NULL;
	}

	if (common::Debug)
		common::Log_debug("Message received from %s:%u: %d bytes",
				  inet_ntoa(sender->sin_addr),
				  ntohs(sender->sin_port), *smsgp);
	return msg;
}

// Pop the next UDP message from @fd without reading it.
// It is used when we know we won't be able to process it.
void DNSProxy::discard_message(int fd) const
{
	char msg;
	socklen_t addrlen;
	struct sockaddr_in sender;

	addrlen = sizeof(sender);
	if (recvfrom(fd, &msg, sizeof(msg), 0,
		     reinterpret_cast<struct sockaddr *>(&sender),
		     &addrlen) < 0)
		common::Log_error("recv(discard): %m");

	if (common::Debug)
		common::Log_debug("Discarding message from %s:%u",
				  inet_ntoa(sender.sin_addr),
				  ntohs(sender.sin_port));
}

// Parse @msg and extract the query ID and the question section.
// Returns a pointer to the DNS header (which is the first byte of @msg)
// or NULL if the message is not valid.
const DNSProxy::dns_header_st *
DNSProxy::parse_message(const struct sockaddr_in &sender,
			const char *msg, size_t smsg,
			Requests::query_id_t *query_idp,
			std::vector<char> &question) const
{
	const dns_header_st *header;
	const char *top, *p;
	size_t left;

	if (smsg < NS_HFIXEDSZ)
	{
		common::Log_error("%s: incomplete header (%zu bytes)",
				  inet_ntoa(sender.sin_addr), smsg);
		return NULL;
	}

	header = reinterpret_cast<const dns_header_st *>(msg);
	*query_idp = ntohs(header->id);

	// Parse the question section of @msg.  There can be multiple
	// questions in a DNS query, or none at all (eg. when doing a
	// dynamic DNS update).
	p = top = &msg[NS_HFIXEDSZ];
	left = smsg - NS_HFIXEDSZ;
	for (unsigned i = ntohs(header->qdcount); i > 0; i--)
	{
		std::string qname;

		// Parse one @qname.  A QNAME is a sequence of labels,
		// terminated by the root label (which is the empty string).
		for (;;)
		{	// A label is a string, preceded by a single byte
			// representing the label's length.
			//
			// NOTE: I'm not sure whether message compression
			//       can be applied to the names appearing in
			//       the question section.  If so, the worst
			//       case we'll log a bogus QNAME.
			//
			// (And of course international names aren't decoded.)
			if (left < 1)
			{
				common::Log_error("%s[%u]: "
						  "unterminated QNAME",
						  inet_ntoa(sender.sin_addr),
						  *query_idp);
				return NULL;
			}

			unsigned llabel = *reinterpret_cast<const uint8_t *>
					   (p);
			p++;
			left--;

			if (llabel == 0)
				// We've reached the root label.
				break;

			if (left < llabel)
			{
				common::Log_error("%s[%u]: truncated QNAME",
						  inet_ntoa(sender.sin_addr),
						  *query_idp);
				return NULL;
			}

			if (common::Debug)
			{	// Add the label to @qname.
				if (!qname.empty())
					qname.append(1, '.');
				qname.append(p, llabel);
			}

			p += llabel;
			left -= llabel;
		}

		// The QNAME is followed by the query class and type,
		// without padding.  Skip them.
		if (left < NS_QFIXEDSZ)
		{
			common::Log_error("%s[%u]: "
					  "truncated QUESTION section",
					  inet_ntoa(sender.sin_addr),
					  *query_idp);
			return NULL;
		}
		p += NS_QFIXEDSZ;
		left -= NS_QFIXEDSZ;

		if (common::Debug)
		{
			common::Log_debug("%s[%u]: QNAME: %s",
					  inet_ntoa(sender.sin_addr),
					  *query_idp,
					  qname.empty() ? ".":qname.c_str());
			qname.clear();
		}
	}

	// Save the entire @question.
	question.assign(top, p);

	return header;
}

// Read a message from @serverfd, replace its query ID with a random one,
// forward it on a random upstream socket and save the query in the internal
// data structures.  Returns false if there was a problem with receiving the
// message (which could indicate some uncontrollable transient error, like
// out of kernel memory).
bool DNSProxy::forward_query() const
{
	char *msg;
	int smsg, upstream_fd;
	struct sockaddr_in client;
	dns_header_st *header;
	std::vector<char> question;
	Requests::query_id_t received_query_id, proxied_query_id;
	struct Upstream::socket_usage_st *upstream_socket;

	// Do we have a free query ID to forward a query with?
	// If not, discard the message without reading it.
	if (!this->requests->Get_query_id(&proxied_query_id))
	{
		discard_message(this->serverfd);
		return true;
	}

	if (!(msg = receive_message(this->serverfd, &smsg, &client)))
		return false;

	if (!(header = const_cast<dns_header_st *>(parse_message(
						client, msg, smsg,
						&received_query_id,
						question))))
		goto out;

	if (header->qr)
	{
		common::Log_error("%s[%u]: message is not a query",
				  inet_ntoa(client.sin_addr),
				  received_query_id);
		goto out;
	}

	if (!(upstream_socket = this->sockets->Get(&upstream_fd)))
		goto out;

	header->id = htons(proxied_query_id);
	if (send(upstream_fd, msg, smsg, 0) < 0)
	{
		common::Log_error("send(upstream): %m");
		goto out;
	} else if (common::Debug)
	{
		struct sockaddr_in saddr;
		if (common::GetSockName(upstream_fd, &saddr))
			common::Log_debug("%u -> %s:%u -> %u",
					  received_query_id,
					  inet_ntoa(saddr.sin_addr),
					  ntohs(saddr.sin_port),
					  proxied_query_id);
	}

	this->sockets->Put(upstream_fd, upstream_socket);
	this->requests->Put(proxied_query_id, upstream_fd, client,
			    question, received_query_id);

out:
	delete[] msg;
	return true;
}

// Read a message from @upstream_fd, validate it as a DNS response,
// replace its query ID and return it to the appropriate client.
// Returns false if there was a problem with receiving the message.
bool DNSProxy::return_response(int upstream_fd) const
{
	int smsg;
	char *msg;
	dns_header_st *header;
	std::vector<char> question;
	Requests::query_id_t proxied_query_id;
	const struct Requests::request_st *request;

	if (!(msg = receive_message(upstream_fd, &smsg)))
		return false;
	// Since @upstream_fd is connected to the upstream DNS server,
	// this @msg must have the proper source address and port.

	if (!(header = const_cast<dns_header_st *>(parse_message(
						this->upstream,
						msg, smsg,
						&proxied_query_id,
						question))))
		goto out;
	proxied_query_id = ntohs(header->id);

	// Validate @msg.
	if (!header->qr)
	{
		common::Log_error("%s[%u]: message is not a response",
				  inet_ntoa(this->upstream.sin_addr),
				  proxied_query_id);
		goto out;
	} else if (!(request = this->requests->Find(proxied_query_id)))
	{
		if (common::Debug)
			common::Log_debug("%s[%u]: request not found",
					  inet_ntoa(this->upstream.sin_addr),
					  proxied_query_id);
		goto out;
	} else if (upstream_fd != request->upstream_fd)
	{	// @msg arrived through a different port than we had
		// forwarded it throug, which can be a sign of spoofing.
		if (common::Debug)
			common::Log_debug("%s[%u]: response on wrong port",
					  inet_ntoa(this->upstream.sin_addr),
					  proxied_query_id);
		goto out;
	} else if (question != request->question)
	{	// The response has to contain the exact same @question
		// as the query.
		//
		// XXX RFC5452 9.1 says we should validate the QTYPE and
		//     QCLASS too.
		if (common::Debug)
			common::Log_debug("%s[%u]: "
					  "response to wrong question",
					  inet_ntoa(this->upstream.sin_addr),
					  proxied_query_id);
		goto out;
	}

	header->id = htons(request->original_query_id);
	if (sendto(this->serverfd, msg, smsg, 0,
		   reinterpret_cast<const struct sockaddr *>
				   (&request->client),
		   sizeof(request->client)) < 0)
	{	// inet_ntoa() might change @errno.
		auto serrno = errno;
		const char *addr = inet_ntoa(request->client.sin_addr);
		errno = serrno;
		common::Log_error("sendto(%s:%u): %m",
				  addr, ntohs(request->client.sin_port));
	} else if (common::Debug)
		common::Log_debug("%u <- %s:%u <- %u",
				  request->original_query_id,
				  inet_ntoa(request->client.sin_addr),
				  ntohs(request->client.sin_port),
				  proxied_query_id);

	this->sockets->Done(upstream_fd);
	this->requests->Done(proxied_query_id, request);

out:
	delete[] msg;
	return true;
}

void DNSProxy::Run()
{
	// Make sure we've been Init()ialized.
	assert(this->requests != NULL);
	assert(this->sockets  != NULL);

	// Run the event loop.
	common::Log_info("Ready to accept requests.");
	for (;;)
	{
		struct epoll_event event;

		// Process one event at a time.
		if (epoll_wait(this->pollfd, &event, 1, -1) < 0)
		{
			if (errno != EINTR)
			{
				common::Log_error("epoll_wait(): %m");
				goto snooze;
			} else
				continue;
		} else
			assert(event.events & EPOLLIN);

		// Dispatch the event.
		if (event.data.fd == this->serverfd)
		{
			if (!forward_query())
				goto snooze;
		} else if (event.data.fd == this->timerfd)
		{
			uint64_t n;

			if (read(this->timerfd, &n, sizeof(n)) < 0)
			{
				common::Log_error("read(timerfd): %m");
				goto snooze;
			} else
			{
				common::Log_debug("Deleting "
						  "expired requests...");
				this->requests->Gc(
					[this]
					(const struct Requests::request_st *request)
					{ this->sockets->Done(request->upstream_fd); });
			}
		} else if (!return_response(event.data.fd))
			goto snooze;

		continue;

snooze:		// We have experienced an unaccountable error.
		// Let's sleep a bit to prevent busy-looping.
		sleep(1);
	}
}

// End of DNSProxy.cc
