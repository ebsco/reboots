require 'eis_delivery/steps/step_base'

require 'eis_cmds/knife_cmd/remote_command/commands/remote_chef_client'

require 'eis_cmds/knife_cmd/remote_command/shells/protocol'
require 'eis_cmds/knife_cmd/remote_command/commands/knife_results/remote_chef_client_results'

require 'eis_cmds/knife_cmd/remote_command/shells/remote_shell_ssh'
require 'eis_cmds/knife_cmd/remote_command/shells/remote_shell_winrm'
require 'eis_cmds/knife_cmd/remote_command/commands/remote_chef_client_attributes/format_attribute'
require 'eis_cmds/knife_cmd/remote_command/commands/remote_chef_client_attributes/log_level_attribute'
require 'eis_cmds/knife_cmd/remote_command/commands/remote_chef_client_attributes/enable_reporting_attribute'

require 'eis_delivery/steps/node_subcmd/node_chef_client_result'
require 'eis_delivery/steps/node_subcmd/node_chef_client_exception'
require 'eis_delivery/steps/node_subcmd/idempotent_attr'


module EISDelivery
  module Steps
    module NodeSubCmd


      # NodeChefClient Invokes EIS ChefClient Knife command.  Chef Client is responsible for
      # deploying resources on Ebsco nodes.
      class NodeChefClient < EISDelivery::Steps::StepBase
        SUCCESS = 'SUCCESS'
        FAILURE = 'FAILURE'
        NO_EVENT = 'NO EVENT'


        attr_accessor :port

        # ---- RemoteShell related parameters ----
        attr_accessor :remote_ip
        attr_accessor :shell_protocol
        attr_accessor :port
        attr_accessor :remote_platform

        attr_accessor :knifecfg
        attr_accessor :linux_user
        attr_accessor :linux_identity_file
        attr_accessor :windows_user
        attr_accessor :windows_password
        attr_accessor :enable_reporting
        attr_accessor :log_level
        attr_accessor :format

        attr_accessor :warn_on_idempotency_reboot
        attr_accessor :warn_on_idempotency_violation
        attr_accessor :run_cycles
        attr_accessor :run_interval_sec
        attr_accessor :reboot_detect_retries
        attr_accessor :reboot_detect_interval_sec
        attr_accessor :reboot_detect_confirm_threshold

        attr_accessor :error_retry
        attr_accessor :error_retry_interval

        def run(remote_ip, shell_protocol=EISCmds::EISKnife::Remote::Shells::Protocol::AUTO, port=nil, remote_platform=Gem::Platform.local.os)
          log_step_start("chef_client.#{__method__.to_s}")

          process_params(remote_ip, shell_protocol, port, remote_platform)

          case @warn_on_idempotency_violation
          when EISDelivery::Steps::NodeSubCmd::IdempotentAttr::OFF
            return do_run_cycle(
                          @run_cycles,
                          @run_interval_sec,
                          @reboot_detect_retries,
                          @reboot_detect_interval_sec,
                          @reboot_detect_confirm_threshold
            )

          else
            return do_run_cycle_idempotent(
                          @run_cycles,
                          @run_interval_sec,
                          @reboot_detect_retries,
                          @reboot_detect_interval_sec,
                          @reboot_detect_confirm_threshold
            )
          end
        ensure
          log_step_end("chef_client.#{__method__.to_s}")
        end

        def cmd_to_s(remote_ip, shell_protocol=EISCmds::EISKnife::Remote::Shells::Protocol::AUTO, port=nil, remote_platform=Gem::Platform.local.os)
          process_params(remote_ip, shell_protocol, port, remote_platform)
          create_chef_client_shell.chef_cmd_to_s
        end


        private

        def process_params(remote_ip, shell_protocol, port, remote_platform)
          @remote_ip = remote_ip
          @shell_protocol = shell_protocol
          @port = port
          @remote_platform = (remote_platform == 'windows')? 'mingw32': remote_platform
        end

        # Performs a loop executing a chef-client run, waiting for reboot to complete if necessary.
        #
        # @param[Integer] run_cycles, number of times to perform chef-client run and wait for reboot cycle
        # @param[Integer] run_interval_sec, desired time to wait between loop cycles
        # @param[Integer] reboot_detect_retries, how many connect attempts to perform waiting for reboot completion
        # @param[Integer] reboot_detect_interval_sec, desired time between connect attempts.
        # @param[Integer] reboot_detect_confirmation_threshold, number of consecutive successful attempts to be considered a successful reboot
        # @param[boolean] is_idempotency_run_cycle, is true if do_run_cycle is being run as part of idempotency validation
        def do_run_cycle (run_cycles, run_interval_sec, reboot_detect_retries, reboot_detect_interval_sec, reboot_detect_confirmation_threshold, is_idempotency_run_cycle=false)
          @chef_client_shell = create_chef_client_shell
          @reboot_detector = create_reboot_detector(@chef_client_shell)

          loop_block = EISCmds::Utils::LoopBlock.new(run_cycles, run_interval_sec)
          EISDelivery::LOG.info("BEGIN RUN_CYCLE. Cycles: #{run_cycles}, intvl_secs: #{run_interval_sec}s, max_cycle_time: #{calc_max_retry_wait(run_cycles, run_interval_sec)}s")
          loop_block.run {

            # --- Chef client run Phase --- #
            # Check the exit of chef_client, the block will terminate
            #  on any exit code other than 250
            knife_result = @chef_client_shell.run

            run_result = process_run_cycle(knife_result, nil, reboot_detect_confirmation_threshold, loop_block.count)
            unless run_result.chef_exit_code == EISCmds::ExitCodes::CHEF_REBOOT
              raise NodeChefClientBadExitCodeException.new(run_result) unless run_result.chef_exit_code == 0
              return run_result
            end

            # --- Reboot Detection Phase (Wait for reboot completion)--- #
            if is_idempotency_run_cycle
              # Flag a problem if we've rebooted during a idempotency run cycle
              do_warn_on_idempotency_reboot(run_result)
              return run_result
            end

            # Attempt a number of node connections equal to connect_retries, sleeping connect_interval between
            #  retries.  If the number of successful connections meets or exceeds confirmation_threshold then
            #  then the connect is judged successful, otherwise the connection is considered failed.
            EISDelivery::LOG.info("BEGIN wait for re-start (retries: #{reboot_detect_retries}, intvl_secs=#{reboot_detect_interval_sec}s, max_wait_secs: #{calc_max_retry_wait(reboot_detect_retries, reboot_detect_interval_sec)}s)...")
            connect_result = @reboot_detector.connect?(reboot_detect_retries, reboot_detect_interval_sec, reboot_detect_confirmation_threshold)

            do_warn_on_reboot_detection_interval_exceeded(reboot_detect_retries, reboot_detect_interval_sec) unless connect_result == true

            run_result = process_run_cycle(knife_result, connect_result, reboot_detect_confirmation_threshold, loop_block.count)
            EISDelivery::LOG.info("END wait for restart: #{@reboot_detector.inspect}")

            raise NodeChefClientConfirmationException.new(run_result) if (run_result.reboot_detect_retries < reboot_detect_confirmation_threshold)


          }


          # If we get here, then our run cycle has taken too long. Bail on the run cycle, and Flag a problem.
          raise NodeChefClientException.new("Quit chef-client, Maximum run_cycles exceeded '#{run_cycles}'")

        ensure
           EISDelivery::LOG.info("END RUN_CYCLE. Statistics: #{loop_block.inspect}")

        end

        # Performs 2 consecutive runs. See #run method. If after the second run the number of updated
        # resources exceeds 0, an idempotency exception is fired.
        def do_run_cycle_idempotent(run_cycles, run_interval_sec, reboot_detect_retries, reboot_detect_interval_sec, reboot_detect_confirmation_threshold)
          result = do_run_cycle(run_cycles, run_interval_sec, reboot_detect_retries, reboot_detect_interval_sec,
                                reboot_detect_confirmation_threshold)
          if result.chef_resources_updated != 0
            EISDelivery::LOG.info('BEGIN IDEMPOTENCY CHECKS ...')
            result = do_run_cycle(run_cycles, run_interval_sec, reboot_detect_retries, reboot_detect_interval_sec,
                                  reboot_detect_confirmation_threshold, true)

            do_warn_on_idempotency_violation(result)
          end

          return result
        end

        def create_chef_client_shell
          shell = nil

          #TODO: EIS_CMD update: RemoteShell needs support for non-default port assignments, other than 5985(WINRM), 22(SSH).
          #TODO: EIS_CMD update: RemoteShell should expose the port number in use.
          case @shell_protocol
            when EISCmds::EISKnife::Remote::Shells::Protocol::AUTO
              shell = EISCmds::EISKnife::Remote::RemoteShell.create(@knifecfg, nil)
              shell.error_retry = @error_retry
              shell.error_retry_interval = @error_retry_interval

              #TODO: This is a Hack, have RemoteShell expose the protocol it is running. Instead of checking class type.
              if shell.is_a?(EISCmds::EISKnife::Remote::Shells::RemoteShellSsh)
                shell.remote_user = @linux_user
                shell.identity_file = @linux_identity_file
                shell.remote_ip = @remote_ip
              else
                shell.remote_user = @windows_user
                shell.remote_password =@windows_password
                shell.remote_ip = @remote_ip
              end
            when EISCmds::EISKnife::Remote::Shells::Protocol::SSH
              shell =  EISCmds::EISKnife::Remote::RemoteShell.ssh(@knifecfg, {:remote_user=>@linux_user,
                                                                              :identity_file=>@linux_identity_file,
                                                                              :remote_ip=>@remote_ip,
                                                                              :error_retry => @error_retry,
                                                                              :error_retry_interval => @error_retry_interval
              })
            when EISCmds::EISKnife::Remote::Shells::Protocol::WINRM
              shell =  EISCmds::EISKnife::Remote::RemoteShell.winrm(@knifecfg, {:remote_user=>@windows_user,
                                                                                :remote_password=>@windows_password,
                                                                                :remote_ip=>@remote_ip,
                                                                                :error_retry => @error_retry,
                                                                                :error_retry_interval => @error_retry_interval
              })
          end

          raise RuntimeError, "RemoteShell, unsupported protocol '#{@shell_protocol}'" if shell.nil?

          shell.remote_command = EISCmds::EISKnife::Remote::RemoteChefClient.new(@remote_platform, {:enable_reporting=>@enable_reporting,
                                                                                                    :log_level=>@log_level,
                                                                                                    :format=>@format})

          return shell
        end

        def create_reboot_detector(shell)
          #TODO: EIS_CMD update: TCPUtil should validate that against the port used in RemoteShell.
          case
            when shell.is_a?(EISCmds::EISKnife::Remote::Shells::RemoteShellSsh)
              return EISCmds::Utils::TCPUtil.new(@remote_ip, (@port.nil?)? EISCmds::Utils::TCPUtil::PORT_SSH: @port)
            when shell.is_a?(EISCmds::EISKnife::Remote::Shells::RemoteShellWinrm)
              return EISCmds::Utils::TCPUtil.new(@remote_ip, (@port.nil?)? EISCmds::Utils::TCPUtil::PORT_WINRM: @port)
            else
              raise RuntimeError, "Unable to instantiate a node validator for use with remote shell #{@shell.class.inspect}"
          end
        end

        def process_run_cycle(knife_result, connection_result, confirmation_threshold, last_run_cycle = 0)

           raise NodeChefClientException.new("Bad node validator '#{@reboot_detector.class.inspect}'") unless
                @reboot_detector.is_a?(EISCmds::Utils::TCPUtil)

           raise NodeChefClientException.new("Bad remote shell '#{@chef_client_shell.class.inspect}'") unless
               @chef_client_shell.is_a?(EISCmds::EISKnife::Remote::RemoteShell)


          run_result = NodeChefClientResultStruct.new
          run_result.command_str = @chef_client_shell.chef_cmd_to_s
          run_result.last_run_cycle = last_run_cycle

          if (knife_result.is_a?(EISCmds::EISKnife::Remote::KnifeResults::RemoteChefClientResults))
            #TODO: EIS_CMD bug: Negative Chef Exit Code isn't getting passed up into knife results.
            #TODO: EIS_CMD bug: Add a general error exit code with a value of 1
            run_result.chef_exit_code = (knife_result.chef_exitcode.nil?)? 1: knife_result.chef_exitcode
            run_result.chef_resources_updated = knife_result.resources_updated
          else
            raise NodeChefClientException.new("Bad knife result '#{knife_result.class.inspect}'")
          end

          run_result.hostname = @reboot_detector.hostname
          run_result.port = @reboot_detector.port

          if (connection_result.nil?)
            # connection_result is initialized when chef reboot occurs.
            # If a reboot never occurred, node_validation was unnecessary and therefore @node_validation
            # result cannot be initialized.
            # This code is unnecessary if the following bug is addressed
            run_result.reboot_result = NO_EVENT
            run_result.reboot_detect_retries = 0
            run_result.reboot_detect_threshold = 0
            run_result.reboot_error_msg = 'No reboot detect occurred'
         else
            run_result.reboot_result = (connection_result)? SUCCESS: FAILURE
            run_result.reboot_detect_retries = @reboot_detector.completion_count - @reboot_detector.failed_count
            run_result.reboot_detect_threshold = confirmation_threshold
            run_result.reboot_error_msg = (run_result.reboot_detect_retries < confirmation_threshold)?
                "Reboot detect retries exceeded confirmation threshold Error: #{@reboot_detector.error_status}. Total Attempts: #{@reboot_detector.completion_count}, Failures: #{@reboot_detector.failed_count}" :
                @reboot_detector.error_status
          end

          return run_result
        end

        def do_warn_on_idempotency_reboot(result)
          # don't overwrite a previously detected failure
          return if result.reboot_result == FAILURE

          result.reboot_result = FAILURE
          result.reboot_error_msg = 'Reboot occurred during Idempotency Validation!'

          case @warn_on_idempotency_reboot
            when EISDelivery::Steps::NodeSubCmd::IdempotentAttr::LOG
              EISDelivery::LOG.warn(result.reboot_error_msg)
            when EISDelivery::Steps::NodeSubCmd::IdempotentAttr::FAIL
              raise NodeChefClientIdempotencyException.new(result)
          end
        end

        def do_warn_on_idempotency_violation(result)
          return if result.chef_resources_updated == 0

          # don't overwrite a previously detected failure
          return if result.reboot_result == FAILURE

          result.reboot_result = FAILURE
          result.reboot_error_msg = "Idempotency violation, detected #{result.chef_resources_updated} resources updated."

          case @warn_on_idempotency_violation
            when EISDelivery::Steps::NodeSubCmd::IdempotentAttr::LOG
              EISDelivery::LOG.warn(result.reboot_error_msg)
            else
              raise NodeChefClientIdempotencyException.new(result)
          end
        end

        def do_warn_on_reboot_detection_interval_exceeded(retries, interval_sec)
          raise ArgumentError, 'retries must be a valid integer' unless retries.is_a?(Fixnum)
          raise ArgumentError, 'interval_seconds must be a valid integer' unless interval_sec.is_a?(Fixnum)

          total_detection_interval = calc_max_retry_wait(retries, interval_sec)
          unless @reboot_detector.nil?
            if total_detection_interval <= @reboot_detector.running_time
              EISDelivery::LOG.warn("Long reboot detection cycle, waited for reboot #{@reboot_detector.running_time}s, exceeds max wait time cut-off time of #{total_detection_interval}s!! Consider Increasing your reboot_detect_retries or reboot_detect_interval_sec, see Environment configuration.")
            end
          end
        end

        def calc_max_retry_wait(retries, retry_interval)
          # The reason this is not a straight multiplication (retries*retry_interval), is
          #  the last retry returns immediately after a success or fail, we do not wait the retry_interval
          #  before exiting.
          return (retries-1) * retry_interval
        end
      end

    end
  end
end
