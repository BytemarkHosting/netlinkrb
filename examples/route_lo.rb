LIBDIR = File.expand_path(File.join(File.dirname(__FILE__), '..', 'lib'))
$LOAD_PATH.unshift LIBDIR

require 'pp'
require 'netlink/route'

# Example of use of low-level API for NETLINK_ROUTE socket.
# Each of these method calls performs a netlink protocol exchange.

nl = Netlink::Route::Socket.new
puts "*** links ***"
pp nl.if.read_links
puts "*** addrs ***"
pp nl.if.read_addrs(:family => Socket::AF_INET)
puts "*** routes ***"
pp nl.rt.read_routes(:family => Socket::AF_INET)
