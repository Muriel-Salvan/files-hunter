module FilesHunter

  # Decoders that are based on begin patterns (sucha as Magic Numbers) inherit from this class.
  # They then have to implement the following methods:
  # * *get_begin_pattern*: To give the begin pattern and eventual options
  # * *decode*: To decode data starting a given offset that matches the begin pattern
  # * *check_begin_pattern*: Provide a quick check of the begin pattern when found [optional]
  # They can then use the following DSL in the decode method:
  # * *found_relevant_data*: Indicate that we are certain the beginning of data of the given extension has been found
  # * *invalid_data*: Indicate the data read is invalid for our Decoder
  # * *truncated_data*: Indicate the data should have continued beyond @end_offset if it were to be complete
  # * *progress*: Indicate the progression of the scan: everything before the progression is considered valid for the given extension (if found_relevant_data was called previously)
  # * *metadata*: Set metadata properties
  class BeginPatternDecoder < Decoder

    class TruncatedDataError < RuntimeError
    end

    class InvalidDataError < RuntimeError
    end

    # Find segments from a given data
    def find_segments
      @begin_pattern, options = get_begin_pattern
      log_debug "Pattern to find: #{@begin_pattern.inspect}"
      @has_to_check_begin_pattern = self.respond_to?(:check_begin_pattern)
      # Parse options
      @max_regexp_size = 32
      @offset_inc = 1
      @begin_pattern_offset_in_segment = 0
      if (options != nil)
        @max_regexp_size = options[:max_regexp_size] if (options[:max_regexp_size] != nil)
        @offset_inc = options[:offset_inc] if (options[:offset_inc] != nil)
        @begin_pattern_offset_in_segment = options[:begin_pattern_offset_in_segment] if (options[:begin_pattern_offset_in_segment] != nil)
      end
      @metadata = {}
      @missing_previous_data = false
      foreach_begin_pattern do |begin_pattern_offset|
        next decode(begin_pattern_offset)
      end
    end

    protected

    # Mark the current decoding as being valid.
    # This is called when the decoder knows that it has valid data matching its specification.
    # Before calling this method, decoded data might still be junk.
    #
    # Parameters::
    # * *extension* (_Symbol_ or <em>list<Symbol></em>): Extension(s) this data belongs to
    def found_relevant_data(extension)
      @extension = extension
    end

    # Indicate that the data is invalid.
    # This will stop the decoding by raising an exception.
    #
    # Parameters::
    # * *message* (_String_): Message to give with the exception [default = '']
    def invalid_data(message = '')
      raise InvalidDataError.new(message)
    end

    # Indicate that the data is truncated.
    # This will stop the decoding by raising an exception.
    #
    # Parameters::
    # * *message* (_String_): Message to give with the exception [default = '']
    def truncated_data(message = '')
      raise TruncatedDataError.new(message)
    end

    # Indicate that the data is missing previous data.
    def missing_previous_data
      @missing_previous_data = true
    end

    # Indicate progression in the decoding
    #
    # Parameters::
    # * *offset_to_be_decoded* (_Fixnum_): Next to be decoded
    def progress(offset_to_be_decoded)
      @last_offset_to_be_decoded = offset_to_be_decoded
      raise TruncatedDataError.new("Progression @#{offset_to_be_decoded} is over limit (#{@end_offset})") if (@last_offset_to_be_decoded > @end_offset)
      keep_alive
    end

    # Set metadata properties
    #
    # Parameters::
    # * *properties* (<em>map<Symbol,Object></em>): The properties to be set
    def metadata(properties)
      #log_debug "Add metadata: #{properties.inspect}"
      @metadata.merge!(properties)
    end

    private

    # Find a starting pattern and call a client block when it matches.
    # Client block decodes data, and calls the following methods to give progress on its decoding:
    # * *found_relevant_data*: Indicate that there is valid data to be decoded. If a TruncatedDataError occurs before this method is called, the data is ignored ; otherwise it will be marked as decoded but truncated to the end of the current segment.
    # * *progress*: Indicate progression
    # * *truncated_data*: Indicate that the data is truncated
    # * *invalid_data*: Indicate that the data is invalid
    #
    # Parameters::
    # * _Block_: Client code called when such a pattern matches. Its goal is to decode correctly at the given offset.
    #   * Parameters::
    #   * *begin_pattern_offset* (_Fixnum_): The offset of the pattern
    #   * *pattern_index* (_Fixnum_): The pattern index that matched the search. Always nil if begin_pattern is not a list.
    #   * Result::
    #   * *end_offset* (_Fixnum_): The ending offset (nil if could not be decoded). If the ending offset returned is greater than end_offset, segment will be considered as truncated.
    def foreach_begin_pattern
      # Loop to the end
      current_offset = @begin_offset
      while (current_offset < @end_offset)
        # Find the begin pattern
        log_debug "Find begin_pattern starting #{current_offset}..."
        begin_pattern_offset, pattern_index = @data.index(@begin_pattern, current_offset, @max_regexp_size)
        if ((begin_pattern_offset == nil) or
            (begin_pattern_offset >= @end_offset))
          # No match
          current_offset = @end_offset
          log_debug "No more pattern."
        else
          if (begin_pattern_offset >= @begin_offset + @begin_pattern_offset_in_segment)
            begin_pattern_offset -= @begin_pattern_offset_in_segment
            log_debug "Found begin_pattern at #{begin_pattern_offset}."
            # We have a candidate
            # Try to decode it
            decoded_end_offset = nil
            truncated = false
            @missing_previous_data = false
            @extension = nil
            @last_offset_to_be_decoded = nil
            begin
              # If the decoder can perform additional tests, call them
              begin_pattern_valid = (@has_to_check_begin_pattern) ? check_begin_pattern(begin_pattern_offset, pattern_index) : true
              if begin_pattern_valid
                # Call the Decoder
                decoded_end_offset = yield(begin_pattern_offset, pattern_index)
              else
                log_debug 'Invalid pattern returned by the check.'
              end
            rescue InvalidDataError
              # If data was already validated, it means that the segment is truncated.
              log_debug "Got an invalid data exception while decoding data: #{$!}"
              #log_debug $!.backtrace.join("\n")
              # If not, drop everything.
              if ((@extension != nil) and
                  (@last_offset_to_be_decoded != nil))
                truncated = true
                # Use the last decoded offset as the truncated limit.
                decoded_end_offset = @last_offset_to_be_decoded
              else
                decoded_end_offset = nil
              end
            rescue TruncatedDataError, AccessAfterDataError
              # Data is truncated
              log_debug "Got a truncation exception while decoding data: #{$!}"
              #log_debug $!.backtrace.join("\n")
              # If we already got relevant data, mark it as truncated
              if (@extension != nil)
                truncated = true
                decoded_end_offset = @end_offset
              else
                decoded_end_offset = nil
              end
            rescue
              #log_err "Error while decoding data: #{$!}\n#{$!.backtrace.join("\n")}"
              #decoded_end_offset = nil
              raise
            end
            if ((decoded_end_offset == nil) or
                (@extension == nil))
              log_debug 'Invalid segment.'
              # Try searching from further: maybe another BEGIN_PATTERN might be found
              current_offset = begin_pattern_offset + @begin_pattern_offset_in_segment + @offset_inc
            else
              log_debug "Decoded segment in offsets [ #{begin_pattern_offset} - #{decoded_end_offset} ]"
              if (decoded_end_offset > @end_offset)
                log_debug "Decoded segment ends at #{decoded_end_offset} which is greater than #{@end_offset} => truncated"
                decoded_end_offset = @end_offset
                truncated = true
              end
              # Extract the segment and go on to the next
              found_segment(begin_pattern_offset, decoded_end_offset, @extension, truncated, @missing_previous_data, @metadata)
              current_offset = decoded_end_offset
            end
          else
            # Try searching from further: maybe another BEGIN_PATTERN might be found
            current_offset = begin_pattern_offset + @offset_inc
          end
        end
      end
    end

  end

end
