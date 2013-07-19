module FilesHunter

  # Generic Decode class
  # All Decoders inherit from this class and have to implement the find_segments method, using @data, @begin_offset and @end_offset instance variables to parse data.
  # Here is the DSL Decoders can use in their find_segments method:
  # * *@data* (_IOBlockReader_): The data to be accessed
  # * *@begin_offset* (_Fixnum_): The begin offset
  # * *@end_offset* (_Fixnum_): The end offset
  # * *found_segment*: Method used to indicate a Segment was successfully parsed
  # * *keep_alive*: Method used to indicate progression
  class Decoder

    # Prepare for new search
    #
    # Parameters::
    # * *segments_analyzer* (_SegmentsAnalyzer_): The segments analyzer for which this Decoder is working
    # * *data* (_IOBlockReader_): Data being analyzed
    # * *begin_offset* (_Fixnum_): The begin offset
    # * *end_offset* (_Fixnum_): The end offset
    def setup(segments_analyzer, data, begin_offset, end_offset)
      @segments_analyzer = segments_analyzer
      @data = data
      @begin_offset = begin_offset
      @end_offset = end_offset
      @segments = []
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
    # * *missing_previous_data* (_Boolean_): Is some data missing before?
    # * *metadata* (<em>map<Symbol,Object></em>): Metadata associated to this segment (Decoder dependent) [default = {}]
    def found_segment(segment_begin_offset, segment_end_offset, extension, truncated, missing_previous_data, metadata)
      raise "Segment begin offset (#{segment_begin_offset}) is lower than data begin offset (#{@begin_offset})" if (segment_begin_offset < @begin_offset)
      if (segment_end_offset > @end_offset)
        log_debug "Segment end offset (#{segment_end_offset}) is greater than data end offset (#{@end_offset}). Mark Segment as truncated."
        segment_end_offset = @end_offset
        truncated = true
      end
      @segments << Segment.new(segment_begin_offset, segment_end_offset, extension, truncated, missing_previous_data, metadata)
      @segments_analyzer.add_bytes_decoded(segment_end_offset - segment_begin_offset)
    end

    # Indicate progression in the decoding
    # This is used to eventually cancel the parsing
    def keep_alive
      raise CancelParsingError.new('Parsing cancelled while decoding') if (@segments_analyzer.parsing_cancelled)
    end

  end

end
