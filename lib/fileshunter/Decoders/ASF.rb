module FilesHunter

  module Decoders

    class ASF < BeginPatternDecoder

      BEGIN_PATTERN_ASF = "\x30\x26\xB2\x75\x8E\x66\xCF\x11\xA6\xD9\x00\xAA\x00\x62\xCE\x6C".force_encoding(Encoding::ASCII_8BIT)
      ASF_DATA_GUID = "\x36\x26\xB2\x75\x8E\x66\xCF\x11\xA6\xD9\x00\xAA\x00\x62\xCE\x6C".force_encoding(Encoding::ASCII_8BIT)
      ACCEPTABLE_INDEX_GUID = [
        "\x90\x08\x00\x33\xB1\xE5\xCF\x11\x89\xF4\x00\xA0\xC9\x03\x49\xCB".force_encoding(Encoding::ASCII_8BIT),
        "\xD3\x29\xE2\xD6\xDA\x35\xD1\x11\x90\x34\x00\xA0\xC9\x03\x49\xBE".force_encoding(Encoding::ASCII_8BIT),
        "\xF8\x03\xB1\xFE\xAD\x12\x64\x4C\x84\x0F\x2A\x1D\x2F\x7A\xD4\x8C".force_encoding(Encoding::ASCII_8BIT),
        "\xD0\x3F\xB7\x3C\x4A\x0C\x03\x48\x95\x3D\xED\xF7\xB6\x22\x8F\x0C".force_encoding(Encoding::ASCII_8BIT)
      ]

      def get_begin_pattern
        return BEGIN_PATTERN_ASF, { :offset_inc => 16 }
      end

      def decode(offset)
        ending_offset = nil

        cursor = offset + BinData::Uint64le.read(@data[cursor+16..cursor+23])
        progress(cursor)
        # Should be on the DATA object
        invalid_data("@#{cursor} - Missing Data object in ASF. GUID does not match.") if (@data[cursor..cursor+15] != ASF_DATA_GUID)
        found_relevant_data(:asf)
        cursor += BinData::Uint64le.read(@data[cursor+16..cursor+23])
        progress(cursor)
        # Now cycle through optional Index objects
        while (ending_offset == nil)
          if (ACCEPTABLE_INDEX_GUID.include?(@data[cursor..cursor+15]))
            # There is an index object
            cursor += BinData::Uint64le.read(@data[cursor+16..cursor+23])
            progress(cursor)
            ending_offset = cursor if (cursor == @end_offset)
          else
            # Finished
            ending_offset = cursor
          end
        end

        return ending_offset
      end

    end

  end

end
