module FilesHunter

  # Generic Decode class
  # All Decoders inherit from this class and have to implement the find_segments method, using @data, @begin_offset and @end_offset instance variables to parse data.
  # Here is the DSL Decoders can use in their find_segments method:
  # * *@data* (_IOBlockReader_): The data to be accessed
  # * *@begin_offset* (_Fixnum_): The begin offset
  # * *@end_offset* (_Fixnum_): The end offset
  # * *found_segment*: Method used to indicate a Segment was successfully parsed
  # * *progress*: Method used to indicate progression among the data offsets
  class Decoder

    # Prepare for new search
    #
    # Parameters:
    # * *data* (_IOBlockReader_): Data being analyzed
    # * *begin_offset* (_Fixnum_): The begin offset
    # * *end_offset* (_Fixnum_): The end offset
    def setup(data, begin_offset, end_offset)
      @data = data
      @begin_offset = begin_offset
      @end_offset = end_offset
      @segments = []
      @last_offset_to_be_decoded = @begin_offset
      @cancel_parsing = false
    end

    # Return found segments since last setup
    #
    # Result::
    # * <em>list<Segment></em>: The list of segments
    def segments_found
      return @segments
    end

    protected

    # Callback called by decoders to notify a Segment has been found successfully
    #
    # Parameters::
    # * *begin_offset* (_Fixnum_): The begin offset
    # * *end_offset* (_Fixnum_): The end offset
    # * *extension* (_Symbol_ or <em>list<Symbol></em>): The extension (can be a list of possible extensions)
    # * *truncated* (_Boolean_): Is the data truncated in this segment?
    # * *metadata* (<em>map<Symbol,Object></em>): Metadata associated to this segment (Decoder dependent) [default = {}]
    def found_segment(segment_begin_offset, segment_end_offset, extension, truncated, metadata)
      raise "Segment begin offset (#{segment_begin_offset}) is lower than data begin offset (#{@begin_offset})" if (segment_begin_offset < @begin_offset)
      if (segment_end_offset > @end_offset)
        log_debug "Segment end offset (#{segment_end_offset}) is greater than data end offset (#{@end_offset}). Mark Segment as truncated."
        @segments << Segment.new(segment_begin_offset, @end_offset, extension, true, metadata)
      else
        @segments << Segment.new(segment_begin_offset, segment_end_offset, extension, truncated, metadata)
      end
    end

    # Indicate progression in the decoding
    #
    # Parameters::
    # * *offset_to_be_decoded* (_Fixnum_): Next to be decoded
    def progress(offset_to_be_decoded)
      @last_offset_to_be_decoded = offset_to_be_decoded
      raise CancelParsingError.new("Parsing cancelled while decoding @#{offset_to_be_decoded}") if @cancel_parsing
      raise AccessAfterDataError.new("Progression @#{offset_to_be_decoded} is over limit (#{@end_offset})") if (@last_offset_to_be_decoded > @end_offset)
    end

  end

end
