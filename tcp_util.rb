require 'timeout'
require 'socket'
require 'eis_cmds/utils/exit_codes'

module EISCmds
  module Utils
    # A Network utility class for testing port connectivity on a remote node.
    #
    # @example
    #     node = EISCmds::Net_utils.new(nil, TEST_PORT)
    #     result = node.connect?(2, 10)
    #
    #     puts 'Connected: ' << result.to_s << ', Status: ' << node.error_status.to_s
    #     puts 'retries: ' << node.count.to_s << ', total time: ' << node.running_time.to_s << 's'
    #
    class TCPUtil
      PORT_WINRM=5985
      PORT_SSH=22

      # @return[Boolean] show_messages, prints debugging messages
      attr_accessor :debug

      # @return[Object] hostname, Read/Write remote host name or ip.
      attr_accessor :hostname

      # @return[Integer] port, Read/Write remote host port
      attr_accessor :port

      # @return[Object] error_status, Error code of last connect attempt
      attr_reader :error_status

      # @return[Integer] count, number of completed attempts(successes and failures), excluding timeout errors
      attr_reader :completion_count

      # @return[Integer] confirmed_count, number of positive connect confirmations required to be considered
      #   successful overall
      attr_reader :confirmed_count

      # @return[Object] running_time, attribute returns time taken to connect
      #  with given retry and interval constraints
      attr_reader :running_time

      # @return[Object] failed_attempts, attribute returns number of failed attempts
      #  with given retry and interval constraints
      attr_reader :failed_count

      # @param[Object] hostname, the IP address or Node alias. Nil defaults to localhost.
      # @param[Integer] port, a valid TCP port on hostname
      def initialize(hostname=nil, port)
        raise ArgumentError, "port (#{port}) must be a valid integer." unless port.is_a?(Fixnum)
        @hostname = (hostname.nil?)? '127.0.0.1': hostname
        @port = port
        @confirmed_count = 0
        @failed_count = 0
        @debug = false
      end

      def debug=(value)
        raise ArgumentError, 'debug expected a boolean value' unless value.is_a?(TrueClass) || value.is_a?(FalseClass)
        @debug = value
      end

      # Attempts a TCP connection with on Hostname:port.
      # @param[Integer] retries, how many attempts to perform
      # @param[Integer] interval_seconds, desired time between attempts.
      # @param[Integer] confirmation_threshold, number of consecutive successful attempts to be considered a success
      def connect?(retries=6, interval_seconds=10, confirmation_threshold = 0)
        raise ArgumentError, 'retries must be a valid integer' unless retries.is_a?(Fixnum)
        raise ArgumentError, 'interval_seconds must be a valid integer' unless interval_seconds.is_a?(Fixnum)
        raise ArgumentError, 'interval_seconds must be a valid integer' unless confirmation_threshold.is_a?(Fixnum)

        start_time = Time.now
        @confirmed_count = 0
        @failed_count = 0
        @completion_count = 0

        (1..retries).each do |x|
          begin
            @error_status = EISCmds::ExitCodes::UNDEFINED
            Timeout::timeout(interval_seconds) {
              @error_status = connect
              @completion_count += 1

              if @error_status == EISCmds::ExitCodes::SUCCESS
                @confirmed_count += 1
                return true if @confirmed_count >= confirmation_threshold
              else
                @confirmed_count = 0
                @failed_count += 1
              end

              sleep interval_seconds unless x == retries
            }

          rescue TimeoutError => e
            # Timing out generally means ready to begin next connect retry.
            #  ignore timeout unless error_status is in an undefined state.
            if @error_status == EISCmds::ExitCodes::UNDEFINED
              # Timing out while in an error state of UNDEFINED means a
              # timeout occurred before connect could return success/failure.
              puts "TCPUtil=> #{e.message}" if @debug
              @confirmed_count = 0
              @failed_count += 1
              @error_status = e
            end
          end
        end

        return false

      ensure
        @running_time = Time.now - start_time unless start_time.nil?
      end


      private

      # Creates a TCP connection on hostname and port.
      # @return[Integer], exit code 0 on success, or the errno of the TCPSocket attempt.
      def connect
        begin
          socket = TCPSocket.new(@hostname, @port)
          socket.close unless socket.nil?

        rescue SystemCallError => e
          puts "TCPUtil=> (#{@hostname}:#{@port})#{e.message}" if @debug
          return e.class

        end

        return EISCmds::ExitCodes::SUCCESS

      ensure

      end

    end
  end
end
