#ifndef REQUESTS_H
#define REQUESTS_H

#include <netinet/in.h>

#include <limits>
#include <chrono>
#include <vector>
#include <set>
#include <map>
#include <functional>

// Class holding the ongoing forwarded DNS queries.
class Requests
{
public:
	// Type of the ID field of a DNS message ...
	typedef uint16_t query_id_t;

	// ... whose size determines how many @requests can be forwarded
	// in parallel.
	static const size_t MAX_POSSIBLE_QUERIES =
		std::numeric_limits<query_id_t>::max() + 1;

	// Information on a forwarded request needed to validate and return
	// the response to the client.
	struct request_st
	{
		// The socket fd through which we expect the response.
		int upstream_fd;

		// The time when the query will expire.  Used for garbage
		// collection.
		std::chrono::steady_clock::time_point expiration;

		// Where to return the response.
		struct sockaddr_in client;

		// The client's original question, which must be included
		// as it was in the response.  Used for validation.
		const std::vector<char> question;

		// The ID with which the client originally sent the query.
		// When forwarding we replace it with a random one.
		query_id_t original_query_id;
	};

protected:
	// Initialized from command line options.
	const unsigned MAX_OUTSTANDING_REQUESTS;
	const unsigned REQUEST_TIMEOUT;
	const unsigned MIN_GC_TIME;

	// A timerfd used to tick when a garbage collection is due.
	int gc_timer;

	// The state of @gc_timer.
	enum
	{
		// The timer is not active.  This is the state when there are
		// no outstanding @requests or there is no @REQUEST_TIMEOUT.
		DISARMED,

		// The timer is set to tick every @MIN_GC_TIME.  This is the
		// state when the oldest request would time out sooner than
		// this time.
		PERIODIC,

		// The timer is set to tick exactly when the oldest request
		// will time out.
		EXACT,
	} timer_state;

	// Map of proxied query ID -> forwarded request.  Used to identify
	// incoming responses.  Needs to be ordered for Get_query_id().
	std::map<query_id_t, struct request_st> requests;

	// Set of <expiration time, proxied query ID>s.  Used for garbage
	// collection.
	std::set<std::pair<std::chrono::steady_clock::time_point, query_id_t>>
		expirations;

public:
	Requests(unsigned max_requests,
		 unsigned request_timeout,
		 unsigned min_gc_time,
		 int timerfd);
	~Requests();

	// Find a random query ID not used by any ongoing @requests.
	// Returns false if none could be found.
	bool Get_query_id(query_id_t *query_idp) const;

	// Called when a request is actually forwarded with the allocated
	// @query_id.  The parameters are used to construct a request_st.
	void Put(query_id_t query_id, int upstream_fd,
		 const struct sockaddr_in &client,
		 std::vector<char> &question,
		 query_id_t orig_query_id);

	// Return the outstanding request identified by @query_id or NULL.
	const struct request_st *Find(query_id_t query_id) const;

	// Called when a @request is done and can be removed from the
	// internal data structures.
	void Done(query_id_t query_id, const struct request_st *request);

	// Called when @gc_timer ticks to remove expired requests from the
	// internal data structures.  @callback is called for each one.
	void Gc(std::function<void(const struct request_st *)> callback);

protected:
	void update_gc_timer();
};

#endif // ! REQUESTS_H
