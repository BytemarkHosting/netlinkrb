LIBDIR = File.expand_path(File.join(File.dirname(__FILE__), '..', 'lib'))
$LOAD_PATH.unshift LIBDIR

require 'netlink/route'

nl = Netlink::Route::Socket.new
puts "\n*** Before adding address"
nl.addrs.list(:index=>"lo", :family=>Socket::AF_INET) { |x| puts x.address }

puts "\n*** After adding address"
begin
  nl.addrs.add(:index=>"lo", :local=>"1.2.3.4", :prefixlen=>32)
rescue Errno::EEXIST
  puts "Already exists"
end
nl.addrs.list(:index=>"lo", :family=>Socket::AF_INET) { |x| puts x.address }

puts "\n*** After deleting address"
nl.addrs.delete(:index=>"lo", :local=>"1.2.3.4", :prefixlen=>32)
nl.addrs.list(:index=>"lo", :family=>Socket::AF_INET) { |x| puts x.address }

