# Patchup to add Socket#sendmsg and Socket#recvmsg for ruby 1.8

if BasicSocket.instance_methods.grep(/^sendmsg$/).empty?
  begin
    require 'ffi'
  rescue LoadError
    require('rubygems') ? retry : raise
  end

    
  class BasicSocket
    module FFIExt
      extend FFI::Library
      ffi_lib FFI::Library::LIBC
      attach_function :sendmsg, [:int, :buffer_in, :int], :ssize_t
      attach_function :recvmsg, [:int, :buffer_inout, :int], :ssize_t
    end
    
    class Msghdr < FFI::Struct
      layout :name, :pointer,
        :namelen, :socklen_t,
        :iov, :pointer,
        :iovlen, :size_t,
        :control, :pointer,
        :controllen, :socklen_t,
        :flags, :int
    end
    
    class IOVec < FFI::Struct
      layout :base, :pointer,
        :len, :size_t
    end

    def sendmsg(mesg, flags=0, dest_sockaddr=nil, *controls)
      data = FFI::MemoryPointer.new(mesg.bytesize, 1, false)
      data.put_bytes(0, mesg)

      iov = IOVec.new
      iov[:base] = data
      iov[:len] = mesg.bytesize
      
      header = Msghdr.new
      if dest_sockaddr
        dest_sockaddr = dest_sockaddr.to_sockaddr if dest_sockaddr.respond_to?(:to_sockaddr)
        nbuf = FFI::MemoryPointer.new(dest_sockaddr.bytesize, 1, false)
        nbuf.put_bytes(0, dest_sockaddr)
        header[:name] = nbuf
        header[:namelen] = dest_sockaddr.bytesize
      end
      header[:iov] = iov
      header[:iovlen] = 1
      header[:control] = nil  # TODO: controls
      header[:controllen] = 0 # controls
      header[:flags] = flags
      
      Kernel.select(nil, [self])
      res = FFIExt.sendmsg(fileno, header, flags)
      raise "sendmsg error: #{res}" if res < 0  # FIXME: read errno
      # return numbytes_sent
      res
    end
    
    def recvmsg(maxmesglen=nil, flags=0, maxcontrollen=nil, opts={})
      data = FFI::MemoryPointer.new(maxmesglen || 4096, 1, false)
      namebuf = FFI::MemoryPointer.new(64, 1, false)
      
      iov = IOVec.new
      iov[:base] = data
      iov[:len] = data.size
      
      header = Msghdr.new
      header[:name] = namebuf
      header[:namelen] = namebuf.size
      header[:iov] = iov
      header[:iovlen] = 1
      header[:flags] = flags
      
      Kernel.select([self])
      res = FFIExt.recvmsg(fileno, header, flags)
      raise "recvmsg error: #{res}" if res < 0  # FIXME: read errno
      # return [mesg, sender_addrinfo, rflags, *controls]
      return [
        data.get_bytes(0, res),
        namebuf.get_bytes(0, header[:namelen]),
        header[:flags]
        # TODO: controls
      ]
    end
  end
end
