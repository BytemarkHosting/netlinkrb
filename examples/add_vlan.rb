LIBDIR = File.expand_path(File.join(File.dirname(__FILE__), '..', 'lib'))
$LOAD_PATH.unshift LIBDIR

require 'netlink/route'
require 'pp'

nl = Netlink::Route::Socket.new
puts "\n*** Before adding VLAN"
pp nl.if.select { |lnk| lnk.kind?("vlan") }

puts "\n*** After adding VLAN on lo"
begin
  nl.if.add_link(:link=>"lo",
    :linkinfo=>Netlink::LinkInfo.new(
    :kind=>"vlan", :data=>Netlink::VlanInfo.new(
      :id=>1234,  #:flags => Netlink::VlanFlags.new(:flags=>Netlink::VLAN_FLAG_LOOSE_BINDING, :mask=>0xffffffff)
  )))
rescue Errno::EEXIST
  puts "Already present"
end
pp nl.if.select { |lnk| lnk.kind?("vlan") }

puts "\n*** After deleting VLANs from lo"
nl.if.each do |lnk|
  if lnk.kind?('vlan') && nl.if.name(lnk.link) == 'lo'
    nl.if.delete_link(lnk.index)
  end
end
pp nl.if.select { |lnk| lnk.kind?("vlan") }

