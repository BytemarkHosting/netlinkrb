LIBDIR = File.expand_path(File.join(File.dirname(__FILE__), '..', 'lib'))
$LOAD_PATH.unshift LIBDIR

require 'linux/netlink/route'

ip = Linux::Netlink::Route::Socket.new
puts "\n*** Before adding address"
ip.addr.list(:index=>"lo", :family=>Socket::AF_INET) { |x| puts x.address }

puts "\n*** After adding address"
begin
  ip.addr.add(:index=>"lo", :local=>"1.2.3.4", :prefixlen=>32)
rescue Errno::EEXIST
  puts "Already exists"
end
ip.addr.list(:index=>"lo", :family=>Socket::AF_INET) { |x| puts x.address }

puts "\n*** After deleting address"
ip.addr.delete(:index=>"lo", :local=>"1.2.3.4", :prefixlen=>32)
ip.addr.list(:index=>"lo", :family=>Socket::AF_INET) { |x| puts x.address }

