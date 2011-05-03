LIBDIR = File.expand_path(File.join(File.dirname(__FILE__), '..', 'lib'))
$LOAD_PATH.unshift LIBDIR

require 'netlink/route'

nl = Netlink::Route::Socket.new
puts "\n*** Before adding route"
nl.routes.list(:family=>Socket::AF_INET, :table=>Netlink::RT_TABLE_MAIN) { |x| p x }

puts "\n*** After adding route"
begin
  nl.routes.add(:oif=>"lo", :dst=>"1.2.3.4", :dst_len=>32, :gateway=>"127.0.0.1")
rescue Errno::EEXIST
  puts "Already exists"
end
nl.routes.list(:family=>Socket::AF_INET, :table=>Netlink::RT_TABLE_MAIN) { |x| p x }

puts "\n*** After deleting route"
nl.routes.delete(:oif=>"lo", :dst=>"1.2.3.4", :dst_len=>32, :gateway=>"127.0.0.1")
nl.routes.list(:family=>Socket::AF_INET, :table=>Netlink::RT_TABLE_MAIN) { |x| p x }

