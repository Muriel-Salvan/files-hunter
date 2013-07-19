module FilesHunter

  module Decoders

    class OGG < BeginPatternDecoder

      BEGIN_PATTERN_OGG = "OggS\x00".force_encoding(Encoding::ASCII_8BIT)

      # Sorted by the least dominating extension first
      KNOWN_EXTENSIONS = {
        'vorbis'.force_encoding(Encoding::ASCII_8BIT) => :oga,
        'theora'.force_encoding(Encoding::ASCII_8BIT) => :ogv
      }

      def get_begin_pattern
        return BEGIN_PATTERN_OGG, { :offset_inc => 5 }
      end

      def decode(offset)
        ending_offset = nil

        cursor = offset
        extensions = [ :ogg, :ogx ] # By default
        nbr_pages = 0
        bitstreams = []
        while (ending_offset == nil)
          version = @data[cursor+4].ord
          header_type = @data[cursor+5].ord
          invalid_data("@#{cursor} - Invalid header type: #{header_type}") if (header_type > 7)
          granule_position = @data[cursor+6..cursor+13]
          bitstream_sn = BinData::Uint32le.read(@data[cursor+14..cursor+17])
          page_sequence_idx = BinData::Uint32le.read(@data[cursor+18..cursor+21])
          checksum = @data[cursor+22..cursor+25]
          # Read the number of segments
          nbr_segments = @data[cursor+26].ord
          # Compute the total size of the payload
          size = 0
          @data[cursor+27..cursor+26+nbr_segments].bytes.each do |segment_size|
            size += segment_size
          end
          log_debug("@#{cursor} - [ Bitstream ##{bitstream_sn} / Page ##{page_sequence_idx} ]: Type #{header_type}, having #{nbr_segments} (total size of #{size})")
          cursor += 27 + nbr_segments
          found_relevant_data(extensions)
          if ((header_type & 0b00000010) != 0)
            # Page of type BOS: Beginning of Stream
            invalid_data("@#{cursor} - Stream #{bitstream_sn} was already marked as begun.") if (bitstreams.include?(bitstream_sn))
            # We can find whether it is a video file or an audio one
            KNOWN_EXTENSIONS.each do |token, extension|
              extensions.unshift(extension) if (@data[cursor..cursor+size-1].index(token) != nil)
              extensions.delete(:oga) if (extensions.include?(:ogv))
              found_relevant_data(extensions)
            end
            bitstreams << bitstream_sn
          elsif ((header_type & 0b00000100) == 0)
            # This is a packet in the middle of a stream
            missing_previous_data if (!bitstreams.include?(bitstream_sn))
            #invalid_data("@#{cursor} - Stream #{bitstream_sn} has not been declared previously.") if (!bitstreams.include?(bitstream_sn))
          end
          cursor += size
          progress(cursor)
          nbr_pages += 1
          # Check if a subsequent page is present
          ending_offset = cursor if ((cursor == @end_offset) or (@data[cursor..cursor+4] != BEGIN_PATTERN_OGG))
        end
        metadata( :nbr_pages => nbr_pages )

        return ending_offset
      end

    end

  end

end
