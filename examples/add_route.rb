LIBDIR = File.expand_path(File.join(File.dirname(__FILE__), '..', 'lib'))
$LOAD_PATH.unshift LIBDIR

require 'netlink/route'

ip = Netlink::Route::Socket.new
puts "\n*** Before adding route"
ip.route.list(:family=>Socket::AF_INET, :table=>Netlink::RT_TABLE_MAIN) { |x| p x }

puts "\n*** After adding route"
begin
  ip.route.add(:oif=>"lo", :dst=>"1.2.3.4", :dst_len=>32, :gateway=>"127.0.0.1")
rescue Errno::EEXIST
  puts "Already exists"
end
ip.route.list(:family=>Socket::AF_INET, :table=>Netlink::RT_TABLE_MAIN) { |x| p x }

puts "\n*** After deleting route"
ip.route.delete(:oif=>"lo", :dst=>"1.2.3.4", :dst_len=>32, :gateway=>"127.0.0.1")
ip.route.list(:family=>Socket::AF_INET, :table=>Netlink::RT_TABLE_MAIN) { |x| p x }

