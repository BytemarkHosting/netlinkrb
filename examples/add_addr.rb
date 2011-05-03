LIBDIR = File.expand_path(File.join(File.dirname(__FILE__), '..', 'lib'))
$LOAD_PATH.unshift LIBDIR

require 'netlink/route'

nl = Netlink::Route::Socket.new
puts "\n*** Before adding address"
nl.if.addrs["lo"][Socket::AF_INET].each { |x| puts x.address }

puts "\n*** After adding address"
begin
  nl.if.add_addr(:index=>"lo", :local=>"1.2.3.4", :prefixlen=>32)
rescue Errno::EEXIST
  puts "Already exists"
end
nl.if.addrs["lo"][Socket::AF_INET].each { |x| puts x.address }

puts "\n*** After deleting address"
nl.if.delete_addr(:index=>"lo", :local=>"1.2.3.4", :prefixlen=>32)
nl.if.addrs["lo"][Socket::AF_INET].each { |x| puts x.address }

