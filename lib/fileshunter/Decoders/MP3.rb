module FilesHunter

  module Decoders

    class MP3 < BeginPatternDecoder

      BEGIN_PATTERN_MP3 = /\xFF[\xE2-\xFF][\x00-\xEF]/
      BEGIN_PATTERN_ID3V1 = 'TAG'.force_encoding('ASCII-8BIT')
      BEGIN_PATTERN_ID3V2 = 'ID3'.force_encoding('ASCII-8BIT')

      BITRATE_INDEX = [
        [ 32,  32,  32,  32,  8 ],
        [ 64,  48,  40,  48,  16 ],
        [ 96,  56,  48,  56,  24 ],
        [ 128, 64,  56,  64,  32 ],
        [ 160, 80,  64,  80,  40 ],
        [ 192, 96,  80,  96,  48 ],
        [ 224, 112, 96,  112, 56 ],
        [ 256, 128, 112, 128, 64 ],
        [ 288, 160, 128, 144, 80 ],
        [ 320, 192, 160, 160, 96 ],
        [ 352, 224, 192, 176, 112 ],
        [ 384, 256, 224, 192, 128 ],
        [ 416, 320, 256, 224, 144 ],
        [ 448, 384, 320, 256, 160 ]
      ]
      SAMPLE_RATE_INDEX = [
        [ 44100, 22050, 11025 ],
        [ 48000, 24000, 12000 ],
        [ 32000, 16000, 8000 ]
      ]

      MIN_ACCEPTABLE_TIME_MS = 1000

      def get_begin_pattern
        return [ BEGIN_PATTERN_MP3, BEGIN_PATTERN_ID3V1, BEGIN_PATTERN_ID3V2 ], { :max_regexp_size => 3 }
      end

      def check_begin_pattern(begin_pattern_offset, pattern_index)
        if (pattern_index == 0)
          header_bytes = @data[begin_pattern_offset+1..begin_pattern_offset+3].bytes.to_a
          return (((header_bytes[0] & 24) != 16) and
                  ((header_bytes[0] & 6) != 0) and
                  ((header_bytes[1] & 12) != 12) and
                  ((header_bytes[2] & 3) != 2))
        else
          return true
        end
      end

      def decode(offset)
        ending_offset = nil

        cursor = offset
        nbr_ms = 0
        while (ending_offset == nil)
          log_debug "=== @#{cursor} - Reading what's here"
          c_0_2 = @data[cursor..cursor+2]
          if (c_0_2 == BEGIN_PATTERN_ID3V1)
            # Just met an ID3v1 tag: skip 128 bytes
            log_debug "=== @#{cursor} - Found ID3v1 tag"
            cursor += 128
          elsif (c_0_2 == BEGIN_PATTERN_ID3V2)
            # Just met an ID3v2 tag
            log_debug "=== @#{cursor} - Found ID3v2 tag"
            invalid_data("@#{cursor} - Invalid ID3v2 header") if ((@data[cursor+3].ord == 255) or (@data[cursor+4].ord == 255))
            # Compute the tag's size
            size = 10 # Header
            @data[cursor+6..cursor+9].bytes.each_with_index do |iByte, iIdx|
              invalid_data("@#{cursor} - Invalid ID3v2 header in size specification (#{iIdx})") if (iByte >= 128)
              size += (iByte << ((8*(3-iIdx))-3+iIdx))
            end
            # Is there a footer?
            size += 10 if ((@data[cursor+5].ord & 16) == 16)
            cursor += size
          else
            # Real MP3 data
            log_debug "=== @#{cursor} - Found MP3 data"
            # Check the header's values
            header_bytes = @data[cursor..cursor+3].bytes.to_a
            invalid_data("@#{cursor} - Invalid MP3 header") if ((header_bytes[0] != 255) or
                                                                ((header_bytes[1] & 224) != 224) or
                                                                ((header_bytes[1] & 24) == 16) or
                                                                ((header_bytes[1] & 6) == 0) or
                                                                ((header_bytes[2] & 240) == 240) or
                                                                ((header_bytes[2] & 12) == 12) or
                                                                ((header_bytes[3] & 3) == 2))
            invalid_data("@#{cursor} - Invalid MP3 header: can't compute size of free bitrates") if ((header_bytes[2] & 240) == 0)
            # Read header values to compute the size
            version = nil
            case ((header_bytes[1] & 24) >> 3)
            when 0
              version = 3
            when 2
              version = 2
            when 3
              version = 1
            else
              invalid_data("@#{cursor} - Unknown version in header: #{((header_bytes[1] & 24) >> 3)}")
            end
            layer = 4 - ((header_bytes[1] & 6) >> 1)
            bit_rate = BITRATE_INDEX[((header_bytes[2] & 240) >> 4)-1][(version == 1) ? layer - 1 : ((layer == 1) ? 3 : 4)] * 1000
            sample_rate = SAMPLE_RATE_INDEX[(header_bytes[2] & 12) >> 2][version - 1]
            padding = ((header_bytes[2] & 2) >> 1)
            # Compute the size
            size = (layer == 1) ? ((12 * bit_rate) / sample_rate + padding) * 4 : (144 * bit_rate) / sample_rate + padding
            log_debug "=== @#{cursor} - Read MP3: Version=#{version} Layer=#{layer} BitRate=#{bit_rate} SampleRate=#{sample_rate} Padding=#{padding} FrameLength=#{size}"
            # Go see after
            cursor += size
            # Consider we have valid data only if we have enough milliseconds
            if (nbr_ms < MIN_ACCEPTABLE_TIME_MS)
              nbr_ms += ((layer == 1) ? 384000 : 1152000) / sample_rate
              found_relevant_data(:mp3) if (nbr_ms >= MIN_ACCEPTABLE_TIME_MS)
            end
          end
          if ((nbr_ms >= MIN_ACCEPTABLE_TIME_MS) and
              (cursor == @end_offset))
            ending_offset = cursor
          end
          progress(cursor)
        end

        return ending_offset
      end

    end

  end

end
