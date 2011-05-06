LIBDIR = File.expand_path(File.join(File.dirname(__FILE__), '..', 'lib'))
$LOAD_PATH.unshift LIBDIR

require 'pp'
require 'linux/netlink/route'

# Example of use of low-level API for NETLINK_ROUTE socket.
# Each of these method calls performs a netlink protocol exchange.

ip = Linux::Netlink::Route::Socket.new
puts "*** links ***"
pp ip.link.read_link
puts "*** addrs ***"
pp ip.addr.read_addr
puts "*** routes ***"
pp ip.route.read_route
