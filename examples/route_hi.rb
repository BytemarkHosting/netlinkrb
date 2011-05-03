LIBDIR = File.expand_path(File.join(File.dirname(__FILE__), '..', 'lib'))
$LOAD_PATH.unshift LIBDIR

require 'pp'
require 'netlink/route'

# Example of use of high-level API for NETLINK_ROUTE socket.
# The data is memoized - that is, it's downloaded from the kernel once
# and then manipulated internally.

ip = Netlink::Route::Socket.new

puts "\nInterface eth0:"
pp ip.link["eth0"]

puts "\nAddresses on interface eth0:"
pp ip.addr.list(:index=>"eth0").to_a

puts "\nAll routes in main routing table:"
pp ip.route.list(:table=>Netlink::RT_TABLE_MAIN).to_a

puts "\nV4 default route is probably:"
pp ip.route.list(:family=>Socket::AF_INET, :table=>Netlink::RT_TABLE_MAIN).
  min_by { |route| route.dst_len }

puts "\nTraffic to 192.168.1.1 goes out via:"
puts ip.ifname(ip.route.get(:dst=>"192.168.1.1").oif)
