LIBDIR = File.expand_path(File.join(File.dirname(__FILE__), '..', 'lib'))
$LOAD_PATH.unshift LIBDIR

require 'pp'
require 'netlink/route'

# Example of use of low-level API for NETLINK_ROUTE socket.
# Each of these method calls performs a netlink protocol exchange.

rt = Netlink::Route::Socket.new
puts "*** links ***"
pp rt.links.read_links
puts "*** addrs ***"
pp rt.addrs.read_addrs
puts "*** routes ***"
pp rt.routes.read_routes
