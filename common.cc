// Include files
#include <cstdarg>
#include <cerrno>
#include <cstdio>
#include <ctime>

#include <chrono>

#include <sys/socket.h>
#include <netinet/in.h>

#include "common.h"

// Everything defined in this file is in the "common" namespace.
namespace common {

// Global variable definitions
bool Debug = false;
std::default_random_engine Rnd;

// Program code
void Init(bool debugging, unsigned seed)
{
	// Line-buffering must be set before using @stdout.
	std::setvbuf(stdout, NULL, _IOLBF, 0);

	Debug = debugging;

	if (!seed)
		// Seed with the microseconds part of the current time.
		seed = common::XsofT<std::chrono::microseconds>(
			std::chrono::system_clock::now().time_since_epoch());
	Rnd.seed(seed);
	Log_debug("Random seed: %u", seed);
}

static void logit(FILE *out, const char *level,
		  const char *fmt, va_list args)
{
	// Save @errno and restore it right before vfprintf() for %m
	// to work reliably.
	auto serrno = errno;

	auto now = std::chrono::system_clock::now();
	auto t = std::chrono::system_clock::to_time_t(now);

	// Print the timestamp and @level.
	char timestamp[32];
	strftime(timestamp, sizeof(timestamp),
		 "%Y-%m-%d %H:%M:%S", std::localtime(&t));
	std::fprintf(out, "%s.%03ld %-5s ", timestamp,
		     common::XsofT<std::chrono::milliseconds>(
						now.time_since_epoch()),
		     level);

	// Print the actual log message.
	errno = serrno;
	std::vfprintf(out, fmt, args);
	std::fputc('\n', out);
}

void Log_error(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	logit(stderr, "ERROR", fmt, args);
	va_end(args);
}

void Log_info(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	logit(stdout, "INFO", fmt, args);
	va_end(args);
}

void Log_debug(const char *fmt, ...)
{
	va_list args;

	if (!Debug)
		return;

	va_start(args, fmt);
	logit(stdout, "DEBUG", fmt, args);
	va_end(args);
}

bool GetSockName(int sfd, struct sockaddr_in *saddr)
{
	socklen_t addrlen = sizeof(*saddr);
	if (getsockname(sfd,
			reinterpret_cast<struct sockaddr *>(saddr),
			&addrlen) < 0)
	{
		Log_error("getsockname(): %m");
		return false;
	} else
		return true;
}

} /* namespace */

// End of common.cc
