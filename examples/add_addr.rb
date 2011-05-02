LIBDIR = File.expand_path(File.join(File.dirname(__FILE__), '..', 'lib'))
$LOAD_PATH.unshift LIBDIR

require 'netlink/route'

nl = Netlink::Route::Socket.new
puts "\n*** Before adding address"
nl.addrs["lo"][Socket::AF_INET].each { |x| puts x.address }

begin
  nl.add_addr(:index=>"lo", :local=>"1.2.3.4", :prefixlen=>32)
rescue Errno::EEXIST
end
puts "\n*** After adding address"
nl.addrs["lo"][Socket::AF_INET].each { |x| puts x.address }

nl.delete_addr(:index=>"lo", :local=>"1.2.3.4", :prefixlen=>32)
puts "\n*** After deleting address"
nl.addrs["lo"][Socket::AF_INET].each { |x| puts x.address }

