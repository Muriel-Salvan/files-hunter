module FilesHunter

  # A segment represents a chunk of data
  class Segment

    # Begin offset of the segment
    #   Fixnum
    attr_reader :begin_offset

    # End offset of the segment (equals the begin offset of the next segment)
    #   Fixnum
    attr_reader :end_offset

    # List of extensions guessed (sort by descending probability) (:mkv, :dll ...). :unknown used to unknown data.
    #   list<Symbol>
    attr_reader :extensions

    # Is this segment truncated? This means that for the given extension, data should have continued beyond this segment.
    #   Boolean
    attr_reader :truncated

    # Is this segment missing previous data? This means that for the given extension, data should have been present already before this segment.
    #   Boolean
    attr_reader :missing_previous_data

    # Metadata associated to this Segment (Decoder dependent)
    #   map< Symbol, Object >
    attr_reader :metadata

    # Constructor
    #
    # Parameters::
    # * *begin_offset* (_Fixnum_): Specify begin offset
    # * *end_offset* (_Fixnum_): Specify end offset
    # * *extension* (_Symbol_ or <em>list<Symbol></em>): Specify extension
    # * *truncated* (_Boolean_): Specify truncated flag
    # * *missing_previous_data* (_Boolean_): Do we lack data before this segment?
    # * *metadata* (<em>map<Symbol,Object></em>): Metadata (Decoder dependent)
    def initialize(begin_offset, end_offset, extension, truncated, missing_previous_data, metadata)
      @begin_offset = begin_offset
      @end_offset = end_offset
      @extensions = (extension.is_a?(Symbol)) ? [ extension ] : extension
      @truncated = truncated
      @missing_previous_data = missing_previous_data
      @metadata = metadata
    end

  end

end
