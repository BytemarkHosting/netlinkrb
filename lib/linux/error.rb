module Linux
  ERRNO_MAP = {}  #:nodoc:
  Errno.constants.each do |k|
    klass = Errno.const_get(k)
    next unless klass.is_a?(Class) and klass.const_defined?(:Errno)
    ERRNO_MAP[klass::Errno] = klass
  end

  # Raise an Errno exception if the given rc is negative
  def self.check_error(rc)
    if rc < 0
      raise ERRNO_MAP[-rc] || "System error #{-rc}"
    end
  end
end
