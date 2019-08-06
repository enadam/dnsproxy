#ifndef COMMON_H
#define COMMON_H

#include <ratio>
#include <random>

namespace common
{
	// Whether Log_debug() will be effective.
	extern bool Debug;

	// Random number engine shared between classes.
	extern std::default_random_engine Rnd;

	// @rnd_seed can be specified to reproduce a random sequence.
	// Otherwise @Rnd will be seeded with the current time.
	extern void Init(bool debugging = false, unsigned rnd_seed = 0);

	// Return the milliseconds/microseconds/nanoseconds/... part
	// of a std::chrono::duration.
	template<typename to_duration, typename from_duration>
	typename to_duration::rep XsofT(from_duration d)
	{
		typedef std::ratio_divide<typename from_duration::period,
					  typename to_duration::period> div;
		return ((d.count() * div::num / div::den)
			% to_duration::period::den);
	}

	// Logging functions
	extern void
	__attribute__((format(printf, 1, 2)))
	Log_error(const char *fmt, ...);

	extern void
	__attribute__((format(printf, 1, 2)))
	Log_info(const char *fmt, ...);

	extern void
	__attribute__((format(printf, 1, 2)))
	Log_debug(const char *fmt, ...);

	// Return the local address of a socket.
	extern bool GetSockName(int sfd, struct sockaddr_in *saddr);
};

#endif // ! COMMON_H
