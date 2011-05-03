LIBDIR = File.expand_path(File.join(File.dirname(__FILE__), '..', 'lib'))
$LOAD_PATH.unshift LIBDIR

require 'pp'
require 'netlink/route'

# Example of use of high-level API for NETLINK_ROUTE socket.
# The data is memoized - that is, it's downloaded from the kernel once
# and then manipulated internally.

rt = Netlink::Route::Socket.new

puts "\nInterface eth0:"
pp rt.links["eth0"]

puts "\nAddresses on interface eth0:"
pp rt.addrs.list(:index=>"eth0").to_a

puts "\nAll v4 routes in main routing table:"
pp rt.routes.list(:family=>Socket::AF_INET, :table=>Netlink::RT_TABLE_MAIN).to_a

puts "\nDefault route is probably:"
pp rt.routes.list(:family=>Socket::AF_INET, :table=>Netlink::RT_TABLE_MAIN).
  min_by { |route| route.dst_len }

puts "\nTraffic to 192.168.1.1 goes out via:"
puts rt.ifname(rt.routes.get(:dst=>"192.168.1.1").oif)
