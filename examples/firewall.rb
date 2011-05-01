LIBDIR = File.expand_path(File.join(File.dirname(__FILE__), '..', 'lib'))
$LOAD_PATH.unshift LIBDIR

require 'pp'
require 'netlink/firewall'

# Example of using Netlink::Firewall to capture all outbound packets
# to TCP port 7551. Use "telnet 127.0.0.1 7551" to test.

#system("modprobe ip_queue")
#system("modprobe iptable_filter")
#system("iptables -I OUTPUT -j QUEUE -p tcp --destination-port 7551")
nl = Netlink::Firewall::Socket.new
nl.set_mode(Netlink::IPQ_COPY_PACKET, 128)
nl.dequeue_packets do |pkt|
  p pkt
  Netlink::NF_ACCEPT  # Netlink::NF_DROP
end
