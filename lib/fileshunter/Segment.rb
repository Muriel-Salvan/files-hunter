module FilesHunter

  # A segment represents a chunk of data
  class Segment

    # Begin offset of the segment
    #   Fixnum
    attr_reader :begin_offset

    # End offset of the segment (equals the begin offset of the next segment)
    #   Fixnum
    attr_reader :end_offset

    # Extension guessed (:mkv, :dll ...). :unknown used to unknown data.
    #   Symbol
    attr_reader :extension

    # Is this segment truncated? This means that for the given extension, data should have continued beyond this segment.
    #   Boolean
    attr_reader :truncated

    # Constructor
    #
    # Parameters::
    # * *begin_offset* (_Fixnum_): Specify begin offset
    # * *end_offset* (_Fixnum_): Specify end offset
    # * *extension* (_Symbol_): Specify extension
    # * *truncated* (_Boolean_): Specify truncated flag [default = false]
    def initialize(begin_offset, end_offset, extension, truncated = false)
      @begin_offset = begin_offset
      @end_offset = end_offset
      @extension = extension
      @truncated = truncated
    end

  end

end
