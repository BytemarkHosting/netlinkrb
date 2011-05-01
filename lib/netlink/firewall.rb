# This file implements the messages and methods for the NETLINK_FIREWALL
# protocol.
#
# TODO: implement multiple queue support (NFQUEUE)

require 'netlink/nlsocket'
require 'netlink/message'

module Netlink
  # struct ipq_packet_msg
  class IPQPacket < Message
    code IPQM_PACKET
    
    field :packet_id, :ulong
    field :mark, :ulong
    field :timestamp_sec, :long
    field :timestamp_usec, :long
    field :hook, :uint
    field :indev_name, :pattern => "Z#{IFNAMSIZ}", :default => EMPTY_STRING
    field :outdev_name, :pattern => "Z#{IFNAMSIZ}", :default => EMPTY_STRING
    field :hw_protocol, :ns
    field :hw_type, :ushort
    field :hw_addrlen, :uchar
    field :hw_addr, :pattern => "a8", :default => EMPTY_STRING
    field :data_len, :size_t
    field :payload, :binary 		# TODO: clip to data_len
  end

  # struct ipq_verdict_msg
  class IPQVerdict < Message
    code IPQM_VERDICT
    
    field :value, :uint			# NF_*
    field :id, :ulong
    field :data_len, :size_t		# TODO: auto set from payload.bytesize
    field :payload, :binary		# optional replacement packet
  end

  # struct ipq_mode_msg
  class IPQMode < Message
    code IPQM_MODE
    
    field :value, :uchar		# IPQ_*
    field :range, :size_t
    # NOTE! Kernel enforced that IPQM_MODE messages must be at least
    # as large as IPQM_VERDICT messages (otherwise you get EINVAL)
    field_pad IPQVerdict.bytesize - bytesize
  end
  
  module Firewall
    class Socket < NLSocket
      def initialize(opt={})
        super(opt.merge(:protocol => Netlink::NETLINK_FIREWALL))
      end

      # Set mode to IPQ_COPY_META to receive metadata only, IPQ_COPY_PACKET
      # to get packet content, or IPQ_COPY_NONE to disable receipt of packets.
      # size=0 means copy whole packet, but you can specify a limit instead.
      def set_mode(mode, size=0)
        send_request IPQM_MODE, IPQMode.new(:value=>mode, :range=>size)
      end
      
      # As packets are received they are yielded to the block. The block
      # must return one of the NF_* values, e.g. NF_ACCEPT/NF_DROP.
      # nil is treated as NF_ACCEPT.
      def dequeue_packets #:yields: pkt
        receive_stream(IPQM_PACKET) do |pkt|
          verdict = (yield pkt) || NF_ACCEPT
          send_request IPQM_VERDICT, IPQVerdict.new(
            :value => verdict,
            :id => pkt.packet_id
          )
        end
      end
    end
  end
end
