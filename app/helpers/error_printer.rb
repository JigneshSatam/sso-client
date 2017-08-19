module ErrorPrinter
  def self.print_error(msg, flash_msg = nil)
    msg = "\e[31m#{msg}\e[0m"
    msg = "\e[1m#{msg}\e[22m"
    flash_msg ||= "Follow the below instructions"
    flash_msg = "\e[36m#{flash_msg}\e[0m"
    flash_msg = "\e[1m#{flash_msg}\e[22m"
    flash_msg = "\e[5m#{flash_msg}\e[25m"
    print "\n"
    Rails.logger.info(flash_msg)
    Rails.logger.info(msg)
    print "\n"
  end

  module ClassMethods

  end

  module InstanceMethods

  end

  def self.included(receiver)
    receiver.extend         ClassMethods
    receiver.send :include, InstanceMethods
  end
end
