module EISCmds
  module Utils

    # RetryBlock is a utility class. RetryBlock will execute a block of ruby code for a maximum
    # number of retries, waiting a predefined sleep interval between retries.
    #
    # Should a desired exit condition be reached, before the last retry, the code block can
    # issue a Ruby 'break' command to exit the RetryBlock early.
    #
    # @example Exec a block of code, 3 max_retries, 5s sleep btw retries, breaks loop on 2nd retry
    #     block = EISCmds::Exec_utils::RetryBlock.new(3,5)
    #     block.run {
    #       puts 'attempt #' + block.count.to_s
    #       break if block.count == 2
    #     }
    #     puts 'Block Retries: ' << block.count.to_s << ', Block Time: ' << block.running_time.to_s << 's'
    #
    class LoopBlock
      # @return[Integer] max_retries, maximum number of attempts to make executing a code block
      attr_accessor :max_count
      # @return[Integer] interval_seconds, seconds to sleep between code block retries.
      attr_accessor :interval_seconds
      # @return[Integer] count, number of completed attempts at code block execution
      attr_reader :count
      # @return[Object] running_time, complete time taken to execute code block including retries
      #  and sleep interval
      attr_reader :running_time

      # Create a retry block that will execute a block of code
      # for a specific number of retries, waiting the specified interval_seconds
      # between retries.
      # @param [Object] max_count
      # @param [Object] interval_seconds
      def initialize (max_count=10, interval_seconds=120)
        raise ArgumentError, 'max_retries must be a valid integer' unless max_count.is_a?(Fixnum)
        raise ArgumentError, 'interval_seconds must be a valid integer' unless interval_seconds.is_a?(Fixnum)

        @count = 0
        @running_time = 0
        @max_count = max_count
        @interval_seconds = interval_seconds
      end

      # Executes the given code block for given number of retries and
      # waiting interval_seconds between retries.
      #
      # Use the Ruby 'break' command within the code block, if desired
      # conditions have been met and no additional retries are require.
      # 'break' will terminate the retry loop.
      #
      # @return [Object] running time in seconds
      def run (&code_block)
        raise ArgumentError, 'run requires a code block to execute.' unless block_given?
        @count=0

        start_time = Time.now

        (1..@max_count).each do |x|
          @count = x
          code_block.call

          sleep @interval_seconds unless @count == @max_count
        end

      ensure
        @running_time = Time.now - start_time unless start_time.nil?
      end


    end

  end
end
