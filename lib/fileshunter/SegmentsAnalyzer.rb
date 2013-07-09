require 'bindata'
require 'ioblockreader'
require 'rUtilAnts/Plugins'
require 'fileshunter/Segment'
require 'fileshunter/Decoder'
require 'fileshunter/BeginPatternDecoder'

module IOBlockReader

  # Extend class IOBlockReader to raise exceptions when accessing off limits
  class IOBlockReader

    # Set limits that will trigger exceptions
    def set_limits(begin_offset, end_offset)
      @begin_offset = begin_offset
      @end_offset = end_offset
    end

    alias_method :old_squares, :[]
    def [](range)
      if (range.is_a?(Range))
        raise FilesHunter::AccessAfterDataError.new("Index out of range: #{range}") if (range.last >= @end_offset)
        raise FilesHunter::AccessBeforeDataError.new("Index out of range: #{range}") if (range.first < @begin_offset)
        result = self.old_squares(range)
      else
        raise FilesHunter::AccessAfterDataError.new("Index out of range: #{range}") if (range >= @end_offset)
        raise FilesHunter::AccessBeforeDataError.new("Index out of range: #{range}") if (range < @begin_offset)
        result = self.old_squares(range)
      end
      return result
    end

  end

end

module FilesHunter

  class AccessDataError < RuntimeError
  end

  class AccessAfterDataError < AccessDataError
  end

  class AccessBeforeDataError < AccessDataError
  end

  class CancelParsingError < RuntimeError
  end

  class SegmentsAnalyzer

    # Is the parsing being cancelled?
    #   Boolean
    attr_reader :parsing_cancelled

    # Constructor
    #
    # Parameters::
    # * *options* (<em>map<Symbol,Object></em>): Options [default = {}]
    #   * *:block_size* (_Fixnum_): Block size in bytes to read from the file at once [default = 134217728]
    def initialize(options = {})
      @block_size = (options[:block_size] || 134217728)
      @plugins = RUtilAnts::Plugins::PluginsManager.new
      @plugins.parse_plugins_from_dir(:Decoders, "#{File.dirname(__FILE__)}/Decoders", 'FilesHunter::Decoders')
      # Following are variables that may be accessed in a multithreaded environment
      @parsing_cancelled = false
      @nbr_bytes = nil
      @nbr_bytes_decoded = nil
    end

    # Get segments by analyzing a given file
    #
    # Parameters::
    # * *file_name* (_String_): File to analyze
    # Result::
    # * <em>list<Segment></em>: List of segments for this file
    def get_segments(file_name)
      segments = []

      @parsing_cancelled = false

      File.open(file_name, 'rb') do |file|
        content = IOBlockReader.init(file, :block_size => @block_size)

        @nbr_bytes = File.size(file_name)
        @nbr_bytes_decoded = 0
        log_debug "File size: #{@nbr_bytes}"
        segments << Segment.new(0, @nbr_bytes, :unknown, false, {})

        begin
          # Get decoders in a given order
          # This is important as some containers can include segments of other containers
          [
            'CFBF', # includes Thumbs.db, DOC, XLS, PPT
            'ASF', # includes WMV
            'EXE', # includes DLL, EXE, OCX, OBJ. Cannot detect data concatenated after some EXE files. Detects DRV and SYS as EXE/DLL.
            'MPG_Video', # not generic enough
            'EBML', # includes MKV, WEBM
            'MP4', # include 3GP, MOV, M4A and many others
            'OGG',
            'RIFF', # includes AVI, WAV
            'FLAC',
            'BMP',
            'ICO', # includes ICO, CUR
            'Text', # includes TXT, SRT, RTF (both ASCII-8BIT and UTF-16)
            'JPEG',
            'MP3'
          ].each do |decoder_name|
            @plugins.access_plugin(:Decoders, decoder_name) do |decoder|
              log_debug "[#{file_name}] - Try #{decoder_name}"
              segments = foreach_unknown_segment(segments) do |begin_offset, end_offset|
                log_debug "[#{file_name}] - Try #{decoder_name} for segment [#{begin_offset}, #{end_offset}]"
                content.set_limits(begin_offset, end_offset)
                decoder.setup(self, content, begin_offset, end_offset)
                begin
                  decoder.find_segments
                rescue AccessDataError
                  log_err "Decoder #{decoder_name} exceeded data ranges: #{$!}.\n#{$!.backtrace.join("\n")}"
                end
                next decoder.segments_found
              end
            end
          end
        rescue CancelParsingError
          log_info "[#{file_name}] - Parsing cancelled"
        end
      end

      return segments
    end

    # Cancel the parsing.
    # This method has to be called from a different thread than the one who is currently calling get_segments.
    def cancel_parsing
      @parsing_cancelled = true
    end

    # Add some bytes as being decoded
    #
    # Parameters::
    # * *nbr_bytes* (_Fixnum_): Number of bytes just being decoded
    def add_bytes_decoded(nbr_bytes)
      @nbr_bytes_decoded = nbr_bytes
      #puts "Progression: #{@nbr_bytes_decoded} / #{@nbr_bytes}"
    end

    # Get the current progression
    #
    # Result::
    # * _Fixnum_: Total number of bytes
    # * _Fixnum_: Total number of bytes decoded
    def progression
      return @nbr_bytes, @nbr_bytes_decoded
    end

    private

    # Call the block for each unknown segments.
    # Blocks have to return a list of segments they managed to decode.
    # Return the list of segments splitted.
    #
    # Parameters::
    # * *lst_segments* (<em>list<Segment></em>): The list of current segments to loop on
    # * _Block_: Code called for each unknown segment found. This code is responsible for splitting each segment with decoded segments if possible.
    #   * Parameters::
    #   * *begin_offset* (_Fixnum_): Begin offset of the unknown segment
    #   * *end_offset* (_Fixnum_): End offset of the unknown segment
    #   * Result::
    #   * <em>list<Segment></em>: List of decoded segments (can be empty if none have been decoded)
    # Result::
    # * <em>list<Segment></em>: The resulting list of segments
    def foreach_unknown_segment(lst_segments)
      result_segments = []

      # Split segments that can be decoded
      splitted_segments = []
      lst_segments.each do |segment|
        if (segment.extensions == [:unknown])
          log_debug "Try to find segments in #{segment.begin_offset}..#{segment.end_offset}"
          decoded_segments = yield(segment.begin_offset, segment.end_offset)
          log_debug "Decoded #{decoded_segments.size} new segments: #{decoded_segments.map { |decoded_segment| "[#{decoded_segment.extensions.join(',')}#{decoded_segment.truncated ? '(truncated)' : ''}:#{decoded_segment.begin_offset}..#{decoded_segment.end_offset}]" }}"
          if (decoded_segments.empty?)
            splitted_segments << segment
          else
            last_written_offset = segment.begin_offset
            decoded_segments.each do |decoded_segment|
              splitted_segments << Segment.new(last_written_offset, decoded_segment.begin_offset, :unknown, false, {}) if (decoded_segment.begin_offset > last_written_offset)
              splitted_segments << decoded_segment
              last_written_offset = decoded_segment.end_offset
            end
            splitted_segments << Segment.new(last_written_offset, segment.end_offset, :unknown, false, {}) if (segment.end_offset > last_written_offset)
          end
        else
          splitted_segments << segment
        end
      end

      # Merge consecutives :unknown segments
      nbr_consecutive_unknown = 0
      splitted_segments.each_with_index do |segment, iIdx|
        if (segment.extensions == [:unknown])
          nbr_consecutive_unknown += 1
        else
          if (nbr_consecutive_unknown == 1)
            # Just 1 unknown segment previously encountered
            result_segments << splitted_segments[iIdx-1]
          elsif (nbr_consecutive_unknown > 1)
            # Several consecutive segments encountered: merge them
            result_segments << Segment.new(splitted_segments[iIdx-nbr_consecutive_unknown].begin_offset, splitted_segments[iIdx-1].end_offset, :unknown, false, {})
          end
          result_segments << segment
          nbr_consecutive_unknown = 0
        end
      end
      if (nbr_consecutive_unknown == 1)
        # Just 1 unknown segment previously encountered
        result_segments << splitted_segments[-1]
      elsif (nbr_consecutive_unknown > 1)
        # Several consecutive segments encountered
        result_segments << Segment.new(splitted_segments[-nbr_consecutive_unknown].begin_offset, splitted_segments[-1].end_offset, :unknown, false, {})
      end

      return result_segments
    end

  end

end
