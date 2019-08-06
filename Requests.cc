// Include files
#include <cassert>
#include <sys/timerfd.h>

#include <limits>
#include <chrono>
#include <utility>

#include "common.h"
#include "Requests.h"

// Program code
Requests::Requests(unsigned max_requests,
		   unsigned request_timeout,
		   unsigned min_gc_time,
		   int timerfd):
	MAX_OUTSTANDING_REQUESTS(max_requests),
	REQUEST_TIMEOUT(request_timeout),
	MIN_GC_TIME(min_gc_time),
	gc_timer(timerfd),
	timer_state(DISARMED)
{
	// NOP
}

Requests::~Requests()
{	// Make sure @gc_timer is stopped.
	this->requests.clear();
	this->expirations.clear();
	update_gc_timer();
}

bool Requests::Get_query_id(query_id_t *query_idp) const
{
	if (MAX_OUTSTANDING_REQUESTS
	    && this->requests.size() >= MAX_OUTSTANDING_REQUESTS)
	{
		common::Log_error("Maximum number of outstanding requests "
				  "reached.");
		return NULL;
	}

	assert(this->requests.size() <= MAX_POSSIBLE_QUERIES);
	if (this->requests.size() >= MAX_POSSIBLE_QUERIES)
	{
		common::Log_error("Out of free query IDs.");
		return false;
	}

	// Find the @nth free query ID from the ongoing @requests.
	const size_t max_query_id = std::numeric_limits<query_id_t>::max();
	auto nth = std::uniform_int_distribution<query_id_t>
			(0, max_query_id-this->requests.size())
			(common::Rnd);
	*query_idp = nth;

	// @next_free is the next possibly free query ID.
	query_id_t next_free = 0;
	for (const auto &i: this->requests)
	{	// It is useful to remember that @requests is ordered by
		// the used query IDs.  This algorithm is best followed on
		// paper with pencil.
		assert(next_free <= i.first);
		query_id_t nfree = i.first - next_free;
		if (*query_idp < nfree)
			break;
		*query_idp -= nfree;
		next_free = i.first + 1;
	}
	*query_idp += next_free;

	if (common::Debug)
	{
		// The new query ID must not be in @requests yet.
		assert(this->requests.find(*query_idp)
		       == this->requests.end());

		// Verify that the selected query ID is indeed the @nth free.
		for (const auto i: this->requests)
			if (i.first < *query_idp)
				nth++;
			else
				break;
		assert(nth == *query_idp);
	}

	return true;
}

void Requests::Put(query_id_t query_id, int upstream_fd,
		   const struct sockaddr_in &client,
		   std::vector<char> &question,
		   query_id_t orig_query_id)
{
	auto expiration = std::chrono::steady_clock::now()
			+ std::chrono::seconds(REQUEST_TIMEOUT);
	auto ret = this->requests.emplace(query_id,
					  request_st{ upstream_fd,
						      std::move(expiration),
					  	      client,
						      std::move(question),
						      orig_query_id });
	assert(ret.second == true);

	if (!REQUEST_TIMEOUT)
		return;

	// Since this request is the newest, it will be added at the end
	// of @expirations.
	auto nprev = this->expirations.size();
	auto i = this->expirations.emplace_hint(this->expirations.end(),
						std::make_pair(expiration,
							       query_id));
	assert(this->expirations.size() > nprev);
	assert(++i == this->expirations.end());

	if (!nprev)
		// Start the @gc_timer.
		update_gc_timer();
}

const struct Requests::request_st *Requests::Find(query_id_t query_id) const
{
	const auto i = this->requests.find(query_id);
	return i != this->requests.cend() ? &i->second : NULL;
}

void Requests::Done(query_id_t query_id, const struct request_st *request)
{
	bool is_oldest = false;

	if (REQUEST_TIMEOUT)
	{	// Remove @query_id from @expirations.
		auto i = this->expirations.find(std::make_pair(
					request->expiration, query_id));
		assert(i != this->expirations.end());
		if (i == this->expirations.begin())
			is_oldest = true;
		this->expirations.erase(i);
	}

	auto nremoved = this->requests.erase(query_id);
	assert(nremoved == 1);

	if (is_oldest)
		// The removed @request is the oldest one, determine the
		// next time for garbage collection.
		update_gc_timer();
}

void Requests::Gc(std::function<void(const struct request_st *)> callback)
{
	bool update_timer = false;
	assert(REQUEST_TIMEOUT > 0);

	auto i = this->expirations.begin();
	auto now = std::chrono::steady_clock::now();
	while (i != this->expirations.end() && i->first <= now)
	{	// The request pointed to by @i is too old, remove it.
		auto o = this->requests.find(i->second);
		assert(o != this->requests.end());

		common::Log_debug("Request %u timed out", o->first);
		callback(&o->second);
		this->requests.erase(o);

		// rease() returns an iterator pointing at the next element.
		i = this->expirations.erase(i);
		update_timer = true;
	}

	if (update_timer)
		update_gc_timer();
}

void Requests::update_gc_timer()
{
	if (this->expirations.empty())
	{
		if (this->timer_state == DISARMED)
			return;
		assert(REQUEST_TIMEOUT > 0);

		struct itimerspec stop { { 0, 0 }, { 0, 0 } };
		if (timerfd_settime(this->gc_timer, 0, &stop, NULL) < 0)
			common::Log_error("timerfd_settime(stop): %m");
		else
			this->timer_state = DISARMED;
		return;
	} else	// If there is no @REQUEST_TIMEOUT, @expirations is not used.
		assert(REQUEST_TIMEOUT > 0);

	// @oldest can be expired already, but it will be garbage collected
	// eventually.
	auto oldest = this->expirations.begin()->first;
	if (MIN_GC_TIME
	    && oldest < std::chrono::steady_clock::now()
		      + std::chrono::seconds(MIN_GC_TIME))
	{
		if (this->timer_state == PERIODIC)
			return;

		struct itimerspec periodic =
		{
			{ MIN_GC_TIME, 0 },
			{ MIN_GC_TIME, 0 },
		};

		if (timerfd_settime(this->gc_timer, 0,
				    &periodic, NULL) < 0)
			common::Log_error("timerfd_settime(MIN_GC_TIME): %m");
		else
			this->timer_state = PERIODIC;
	} else
	{
		const auto t = oldest.time_since_epoch();

		struct itimerspec ts_expiry = { { 0, 0 } };
		ts_expiry.it_value.tv_sec = t.count()
			* decltype(t)::period::num
			/ decltype(t)::period::den;
		ts_expiry.it_value.tv_nsec = 
			common::XsofT<std::chrono::nanoseconds>(t);

		if (timerfd_settime(this->gc_timer,
				    TFD_TIMER_ABSTIME,
				    &ts_expiry, NULL) < 0)
			common::Log_error("timerfd_settime(): %m");
		else
			this->timer_state = EXACT;
	}
}

// End of Requests.cc
