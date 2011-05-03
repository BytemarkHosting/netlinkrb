LIBDIR = File.expand_path(File.join(File.dirname(__FILE__), '..', 'lib'))
$LOAD_PATH.unshift LIBDIR

require 'pp'
require 'netlink/route'

# Example of use of high-level API for NETLINK_ROUTE socket.
# The data is memoized - that is, it's downloaded from the kernel once
# and then manipulated internally.

nl = Netlink::Route::Socket.new
pp nl.if["eth0"]
pp nl.if.addrs["eth0"]

# Find the route with the shortest prefix len (probably default route)
pp nl.rt[Socket::AF_INET].min_by { |route| route.dst_len }
