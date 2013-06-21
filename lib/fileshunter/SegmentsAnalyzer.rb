require 'bindata'
require 'ioblockreader'
require 'rUtilAnts/Plugins'
RUtilAnts::Plugins::install_plugins_on_object
require 'fileshunter/Segment'
require 'fileshunter/BeginPatternDecoder'

module IOBlockReader

  # Extend class IOBlockReader to raise TruncatedDataError exceptions when accessing off limits
  class IOBlockReader

    # Set limits that will trigger TruncatedDataError exceptions
    def set_limits(begin_offset, end_offset)
      @begin_offset = begin_offset
      @end_offset = end_offset
    end

    alias_method :old_squares, :[]
    def [](range)
      if (range.is_a?(Range))
        raise FilesHunter::TruncatedDataError.new("Index out of range: #{range}") if ((range.first < @begin_offset) or (range.last >= @end_offset))
        result = self.old_squares(range)
        raise FilesHunter::TruncatedDataError.new("Index out of range: #{range}") if ((result == nil) or (result.size != range.last - range.first + 1))
      else
        raise FilesHunter::TruncatedDataError.new("Index out of range: #{range}") if ((range < @begin_offset) or (range >= @end_offset))
        result = self.old_squares(range)
        raise FilesHunter::TruncatedDataError.new("Index out of range: #{range}") if (result == nil)
      end
      return result
    end

  end

end

module FilesHunter

  class TruncatedDataError < RuntimeError
  end

  class InvalidDataError < RuntimeError
  end

  class SegmentsAnalyzer

    # Constructor
    #
    # Parameters::
    # * *options* (<em>map<Symbol,Object></em>): Options [default = {}]
    #   * *:block_size* (_Fixnum_): Block size in bytes to read from the file at once [default = 134217728]
    def initialize(options = {})
      @block_size = (options[:block_size] || 134217728)

      parse_plugins_from_dir(:Decoders, "#{File.dirname(__FILE__)}/Decoders", 'FilesHunter::Decoders')
    end

    # Get segments by analyzing a given file
    #
    # Parameters::
    # * *file_name* (_String_): File to analyze
    # Result::
    # * <em>list<Segment></em>: List of segments for this file
    def get_segments(file_name)
      segments = []

      File.open(file_name, 'rb') do |file|
        content = IOBlockReader.init(file, :block_size => @block_size)

        log_debug "File size: #{File.size(file_name)}"
        segments << Segment.new(0, File.size(file_name), :unknown)

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
          access_plugin(:Decoders, decoder_name) do |decoder|
            log_debug "[#{file_name}] - Try #{decoder_name}"
            segments = foreach_unknown_segment(segments) do |begin_offset, end_offset|
              log_debug "[#{file_name}] - Try #{decoder_name} for segment [#{begin_offset}, #{end_offset}]"
              content.set_limits(begin_offset, end_offset)
              next decoder.find_segments(content, begin_offset, end_offset)
            end
          end
        end
      end

      return segments
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
        if (segment.extension == :unknown)
          log_debug "Try to find segments in #{segment.begin_offset}..#{segment.end_offset}"
          decoded_segments = yield(segment.begin_offset, segment.end_offset)
          log_debug "Decoded #{decoded_segments.size} new segments: #{decoded_segments.map { |decoded_segment| "[#{decoded_segment.extension.to_s}#{decoded_segment.truncated ? '(truncated)' : ''}:#{decoded_segment.begin_offset}..#{decoded_segment.end_offset}]" }}"
          if (decoded_segments.empty?)
            splitted_segments << segment
          else
            last_written_offset = segment.begin_offset
            decoded_segments.each do |decoded_segment|
              splitted_segments << Segment.new(last_written_offset, decoded_segment.begin_offset, :unknown) if (decoded_segment.begin_offset > last_written_offset)
              splitted_segments << decoded_segment
              last_written_offset = decoded_segment.end_offset
            end
            splitted_segments << Segment.new(last_written_offset, segment.end_offset, :unknown) if (segment.end_offset > last_written_offset)
          end
        else
          splitted_segments << segment
        end
      end

      # Merge consecutives :unknown segments
      nbr_consecutive_unknown = 0
      splitted_segments.each_with_index do |segment, iIdx|
        if (segment.extension == :unknown)
          nbr_consecutive_unknown += 1
        else
          if (nbr_consecutive_unknown == 1)
            # Just 1 unknown segment previously encountered
            result_segments << splitted_segments[iIdx-1]
          elsif (nbr_consecutive_unknown > 1)
            # Several consecutive segments encountered: merge them
            result_segments << Segment.new(splitted_segments[iIdx-nbr_consecutive_unknown].begin_offset, splitted_segments[iIdx-1].end_offset, :unknown)
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
        result_segments << Segment.new(splitted_segments[-nbr_consecutive_unknown].begin_offset, splitted_segments[-1].end_offset, :unknown)
      end

      return result_segments
    end

  end

end
