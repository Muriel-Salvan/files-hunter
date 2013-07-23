module FilesHunter

  module Decoders

    class EBML < BeginPatternDecoder

      BEGIN_PATTERN_MKV = "\x1A\x45\xDF\xA3".force_encoding(Encoding::ASCII_8BIT)
      DOCTYPE_ID_INT = 642
      SEGMENT_MATROSKA_ID = "\x18\x53\x80\x67".force_encoding(Encoding::ASCII_8BIT)
      ACCEPTABLE_DOCTYPES = {
        'matroska' => :mkv,
        'webm' => :webm
      }

      # List of possible elements, sorted by size.
      # Taken from http://matroska.svn.sourceforge.net/viewvc/matroska/trunk/foundation_src/spectool/specdata.xml?view=markup
      VALID_ELEMENT_IDS = {
        1 => [
          "\x80".force_encoding(Encoding::ASCII_8BIT),
          "\x83".force_encoding(Encoding::ASCII_8BIT),
          "\x85".force_encoding(Encoding::ASCII_8BIT),
          "\x86".force_encoding(Encoding::ASCII_8BIT),
          "\x88".force_encoding(Encoding::ASCII_8BIT),
          "\x89".force_encoding(Encoding::ASCII_8BIT),
          "\x8e".force_encoding(Encoding::ASCII_8BIT),
          "\x8f".force_encoding(Encoding::ASCII_8BIT),
          "\x91".force_encoding(Encoding::ASCII_8BIT),
          "\x92".force_encoding(Encoding::ASCII_8BIT),
          "\x96".force_encoding(Encoding::ASCII_8BIT),
          "\x97".force_encoding(Encoding::ASCII_8BIT),
          "\x98".force_encoding(Encoding::ASCII_8BIT),
          "\x9a".force_encoding(Encoding::ASCII_8BIT),
          "\x9b".force_encoding(Encoding::ASCII_8BIT),
          "\x9c".force_encoding(Encoding::ASCII_8BIT),
          "\x9f".force_encoding(Encoding::ASCII_8BIT),
          "\xa0".force_encoding(Encoding::ASCII_8BIT),
          "\xa1".force_encoding(Encoding::ASCII_8BIT),
          "\xa2".force_encoding(Encoding::ASCII_8BIT),
          "\xa3".force_encoding(Encoding::ASCII_8BIT),
          "\xa4".force_encoding(Encoding::ASCII_8BIT),
          "\xa5".force_encoding(Encoding::ASCII_8BIT),
          "\xa6".force_encoding(Encoding::ASCII_8BIT),
          "\xa7".force_encoding(Encoding::ASCII_8BIT),
          "\xaa".force_encoding(Encoding::ASCII_8BIT),
          "\xab".force_encoding(Encoding::ASCII_8BIT),
          "\xae".force_encoding(Encoding::ASCII_8BIT),
          "\xaf".force_encoding(Encoding::ASCII_8BIT),
          "\xb0".force_encoding(Encoding::ASCII_8BIT),
          "\xb2".force_encoding(Encoding::ASCII_8BIT),
          "\xb3".force_encoding(Encoding::ASCII_8BIT),
          "\xb5".force_encoding(Encoding::ASCII_8BIT),
          "\xb6".force_encoding(Encoding::ASCII_8BIT),
          "\xb7".force_encoding(Encoding::ASCII_8BIT),
          "\xb9".force_encoding(Encoding::ASCII_8BIT),
          "\xba".force_encoding(Encoding::ASCII_8BIT),
          "\xbb".force_encoding(Encoding::ASCII_8BIT),
          "\xbf".force_encoding(Encoding::ASCII_8BIT),
          "\xc0".force_encoding(Encoding::ASCII_8BIT),
          "\xc1".force_encoding(Encoding::ASCII_8BIT),
          "\xc4".force_encoding(Encoding::ASCII_8BIT),
          "\xc6".force_encoding(Encoding::ASCII_8BIT),
          "\xc7".force_encoding(Encoding::ASCII_8BIT),
          "\xc8".force_encoding(Encoding::ASCII_8BIT),
          "\xc9".force_encoding(Encoding::ASCII_8BIT),
          "\xca".force_encoding(Encoding::ASCII_8BIT),
          "\xcb".force_encoding(Encoding::ASCII_8BIT),
          "\xcc".force_encoding(Encoding::ASCII_8BIT),
          "\xcd".force_encoding(Encoding::ASCII_8BIT),
          "\xce".force_encoding(Encoding::ASCII_8BIT),
          "\xcf".force_encoding(Encoding::ASCII_8BIT),
          "\xd7".force_encoding(Encoding::ASCII_8BIT),
          "\xdb".force_encoding(Encoding::ASCII_8BIT),
          "\xe0".force_encoding(Encoding::ASCII_8BIT),
          "\xe1".force_encoding(Encoding::ASCII_8BIT),
          "\xe2".force_encoding(Encoding::ASCII_8BIT),
          "\xe3".force_encoding(Encoding::ASCII_8BIT),
          "\xe4".force_encoding(Encoding::ASCII_8BIT),
          "\xe5".force_encoding(Encoding::ASCII_8BIT),
          "\xe6".force_encoding(Encoding::ASCII_8BIT),
          "\xe7".force_encoding(Encoding::ASCII_8BIT),
          "\xe8".force_encoding(Encoding::ASCII_8BIT),
          "\xe9".force_encoding(Encoding::ASCII_8BIT),
          "\xea".force_encoding(Encoding::ASCII_8BIT),
          "\xeb".force_encoding(Encoding::ASCII_8BIT),
          "\xec".force_encoding(Encoding::ASCII_8BIT),
          "\xed".force_encoding(Encoding::ASCII_8BIT),
          "\xee".force_encoding(Encoding::ASCII_8BIT),
          "\xf0".force_encoding(Encoding::ASCII_8BIT),
          "\xf1".force_encoding(Encoding::ASCII_8BIT),
          "\xf7".force_encoding(Encoding::ASCII_8BIT),
          "\xfa".force_encoding(Encoding::ASCII_8BIT),
          "\xfb".force_encoding(Encoding::ASCII_8BIT),
          "\xfd".force_encoding(Encoding::ASCII_8BIT)
        ],
        2 => [
          "\x42\x54".force_encoding(Encoding::ASCII_8BIT),
          "\x42\x55".force_encoding(Encoding::ASCII_8BIT),
          "\x42\x82".force_encoding(Encoding::ASCII_8BIT),
          "\x42\x85".force_encoding(Encoding::ASCII_8BIT),
          "\x42\x86".force_encoding(Encoding::ASCII_8BIT),
          "\x42\x87".force_encoding(Encoding::ASCII_8BIT),
          "\x42\xf2".force_encoding(Encoding::ASCII_8BIT),
          "\x42\xf3".force_encoding(Encoding::ASCII_8BIT),
          "\x42\xf7".force_encoding(Encoding::ASCII_8BIT),
          "\x43\x7c".force_encoding(Encoding::ASCII_8BIT),
          "\x43\x7e".force_encoding(Encoding::ASCII_8BIT),
          "\x44\x44".force_encoding(Encoding::ASCII_8BIT),
          "\x44\x61".force_encoding(Encoding::ASCII_8BIT),
          "\x44\x7a".force_encoding(Encoding::ASCII_8BIT),
          "\x44\x84".force_encoding(Encoding::ASCII_8BIT),
          "\x44\x85".force_encoding(Encoding::ASCII_8BIT),
          "\x44\x87".force_encoding(Encoding::ASCII_8BIT),
          "\x44\x89".force_encoding(Encoding::ASCII_8BIT),
          "\x45\x0d".force_encoding(Encoding::ASCII_8BIT),
          "\x45\x98".force_encoding(Encoding::ASCII_8BIT),
          "\x45\xa3".force_encoding(Encoding::ASCII_8BIT),
          "\x45\xb9".force_encoding(Encoding::ASCII_8BIT),
          "\x45\xbc".force_encoding(Encoding::ASCII_8BIT),
          "\x45\xbd".force_encoding(Encoding::ASCII_8BIT),
          "\x45\xdb".force_encoding(Encoding::ASCII_8BIT),
          "\x45\xdd".force_encoding(Encoding::ASCII_8BIT),
          "\x46\x5c".force_encoding(Encoding::ASCII_8BIT),
          "\x46\x60".force_encoding(Encoding::ASCII_8BIT),
          "\x46\x61".force_encoding(Encoding::ASCII_8BIT),
          "\x46\x62".force_encoding(Encoding::ASCII_8BIT),
          "\x46\x6e".force_encoding(Encoding::ASCII_8BIT),
          "\x46\x75".force_encoding(Encoding::ASCII_8BIT),
          "\x46\x7e".force_encoding(Encoding::ASCII_8BIT),
          "\x46\xae".force_encoding(Encoding::ASCII_8BIT),
          "\x47\xe1".force_encoding(Encoding::ASCII_8BIT),
          "\x47\xe2".force_encoding(Encoding::ASCII_8BIT),
          "\x47\xe3".force_encoding(Encoding::ASCII_8BIT),
          "\x47\xe4".force_encoding(Encoding::ASCII_8BIT),
          "\x47\xe5".force_encoding(Encoding::ASCII_8BIT),
          "\x47\xe6".force_encoding(Encoding::ASCII_8BIT),
          "\x4d\x80".force_encoding(Encoding::ASCII_8BIT),
          "\x4d\xbb".force_encoding(Encoding::ASCII_8BIT),
          "\x50\x31".force_encoding(Encoding::ASCII_8BIT),
          "\x50\x32".force_encoding(Encoding::ASCII_8BIT),
          "\x50\x33".force_encoding(Encoding::ASCII_8BIT),
          "\x50\x34".force_encoding(Encoding::ASCII_8BIT),
          "\x50\x35".force_encoding(Encoding::ASCII_8BIT),
          "\x53\x5f".force_encoding(Encoding::ASCII_8BIT),
          "\x53\x6e".force_encoding(Encoding::ASCII_8BIT),
          "\x53\x78".force_encoding(Encoding::ASCII_8BIT),
          "\x53\x7f".force_encoding(Encoding::ASCII_8BIT),
          "\x53\xab".force_encoding(Encoding::ASCII_8BIT),
          "\x53\xac".force_encoding(Encoding::ASCII_8BIT),
          "\x53\xb8".force_encoding(Encoding::ASCII_8BIT),
          "\x53\xb9".force_encoding(Encoding::ASCII_8BIT),
          "\x54\xaa".force_encoding(Encoding::ASCII_8BIT),
          "\x54\xb0".force_encoding(Encoding::ASCII_8BIT),
          "\x54\xb2".force_encoding(Encoding::ASCII_8BIT),
          "\x54\xb3".force_encoding(Encoding::ASCII_8BIT),
          "\x54\xba".force_encoding(Encoding::ASCII_8BIT),
          "\x54\xbb".force_encoding(Encoding::ASCII_8BIT),
          "\x54\xcc".force_encoding(Encoding::ASCII_8BIT),
          "\x54\xdd".force_encoding(Encoding::ASCII_8BIT),
          "\x55\xaa".force_encoding(Encoding::ASCII_8BIT),
          "\x55\xee".force_encoding(Encoding::ASCII_8BIT),
          "\x56\x54".force_encoding(Encoding::ASCII_8BIT),
          "\x57\x41".force_encoding(Encoding::ASCII_8BIT),
          "\x58\x54".force_encoding(Encoding::ASCII_8BIT),
          "\x58\xd7".force_encoding(Encoding::ASCII_8BIT),
          "\x61\xa7".force_encoding(Encoding::ASCII_8BIT),
          "\x62\x40".force_encoding(Encoding::ASCII_8BIT),
          "\x62\x64".force_encoding(Encoding::ASCII_8BIT),
          "\x63\xa2".force_encoding(Encoding::ASCII_8BIT),
          "\x63\xc0".force_encoding(Encoding::ASCII_8BIT),
          "\x63\xc3".force_encoding(Encoding::ASCII_8BIT),
          "\x63\xc4".force_encoding(Encoding::ASCII_8BIT),
          "\x63\xc5".force_encoding(Encoding::ASCII_8BIT),
          "\x63\xc6".force_encoding(Encoding::ASCII_8BIT),
          "\x63\xc9".force_encoding(Encoding::ASCII_8BIT),
          "\x63\xca".force_encoding(Encoding::ASCII_8BIT),
          "\x65\x32".force_encoding(Encoding::ASCII_8BIT),
          "\x66\x24".force_encoding(Encoding::ASCII_8BIT),
          "\x66\xa5".force_encoding(Encoding::ASCII_8BIT),
          "\x66\xbf".force_encoding(Encoding::ASCII_8BIT),
          "\x66\xfc".force_encoding(Encoding::ASCII_8BIT),
          "\x67\xc8".force_encoding(Encoding::ASCII_8BIT),
          "\x68\xca".force_encoding(Encoding::ASCII_8BIT),
          "\x69\x11".force_encoding(Encoding::ASCII_8BIT),
          "\x69\x22".force_encoding(Encoding::ASCII_8BIT),
          "\x69\x24".force_encoding(Encoding::ASCII_8BIT),
          "\x69\x33".force_encoding(Encoding::ASCII_8BIT),
          "\x69\x44".force_encoding(Encoding::ASCII_8BIT),
          "\x69\x55".force_encoding(Encoding::ASCII_8BIT),
          "\x69\xa5".force_encoding(Encoding::ASCII_8BIT),
          "\x69\xbf".force_encoding(Encoding::ASCII_8BIT),
          "\x69\xfc".force_encoding(Encoding::ASCII_8BIT),
          "\x6d\x80".force_encoding(Encoding::ASCII_8BIT),
          "\x6d\xe7".force_encoding(Encoding::ASCII_8BIT),
          "\x6d\xf8".force_encoding(Encoding::ASCII_8BIT),
          "\x6e\x67".force_encoding(Encoding::ASCII_8BIT),
          "\x6e\xbc".force_encoding(Encoding::ASCII_8BIT),
          "\x6f\xab".force_encoding(Encoding::ASCII_8BIT),
          "\x73\x73".force_encoding(Encoding::ASCII_8BIT),
          "\x73\x84".force_encoding(Encoding::ASCII_8BIT),
          "\x73\xa4".force_encoding(Encoding::ASCII_8BIT),
          "\x73\xc4".force_encoding(Encoding::ASCII_8BIT),
          "\x73\xc5".force_encoding(Encoding::ASCII_8BIT),
          "\x74\x46".force_encoding(Encoding::ASCII_8BIT),
          "\x75\xa1".force_encoding(Encoding::ASCII_8BIT),
          "\x78\xb5".force_encoding(Encoding::ASCII_8BIT),
          "\x7b\xa9".force_encoding(Encoding::ASCII_8BIT),
          "\x7d\x7b".force_encoding(Encoding::ASCII_8BIT),
          "\x7e\x5b".force_encoding(Encoding::ASCII_8BIT),
          "\x7e\x7b".force_encoding(Encoding::ASCII_8BIT),
          "\x7e\x8a".force_encoding(Encoding::ASCII_8BIT),
          "\x7e\x9a".force_encoding(Encoding::ASCII_8BIT),
          "\x7e\xa5".force_encoding(Encoding::ASCII_8BIT),
          "\x7e\xb5".force_encoding(Encoding::ASCII_8BIT)
        ],
        3 => [
          "\x22\xb5\x9c".force_encoding(Encoding::ASCII_8BIT),
          "\x23\x31\x4f".force_encoding(Encoding::ASCII_8BIT),
          "\x23\x83\xe3".force_encoding(Encoding::ASCII_8BIT),
          "\x23\xe3\x83".force_encoding(Encoding::ASCII_8BIT),
          "\x25\x86\x88".force_encoding(Encoding::ASCII_8BIT),
          "\x26\xb2\x40".force_encoding(Encoding::ASCII_8BIT),
          "\x2a\xd7\xb1".force_encoding(Encoding::ASCII_8BIT),
          "\x2e\xb5\x24".force_encoding(Encoding::ASCII_8BIT),
          "\x2f\xb5\x23".force_encoding(Encoding::ASCII_8BIT),
          "\x3a\x96\x97".force_encoding(Encoding::ASCII_8BIT),
          "\x3b\x40\x40".force_encoding(Encoding::ASCII_8BIT),
          "\x3c\x83\xab".force_encoding(Encoding::ASCII_8BIT),
          "\x3c\xb9\x23".force_encoding(Encoding::ASCII_8BIT),
          "\x3e\x83\xbb".force_encoding(Encoding::ASCII_8BIT),
          "\x3e\xb9\x23".force_encoding(Encoding::ASCII_8BIT)
        ],
        4 => [
          "\x10\x43\xa7\x70".force_encoding(Encoding::ASCII_8BIT),
          "\x11\x4d\x9b\x74".force_encoding(Encoding::ASCII_8BIT),
          "\x12\x54\xc3\x67".force_encoding(Encoding::ASCII_8BIT),
          "\x15\x49\xa9\x66".force_encoding(Encoding::ASCII_8BIT),
          "\x16\x54\xae\x6b".force_encoding(Encoding::ASCII_8BIT),
          "\x18\x53\x80\x67".force_encoding(Encoding::ASCII_8BIT),
          "\x19\x41\xa4\x69".force_encoding(Encoding::ASCII_8BIT),
          "\x1a\x45\xdf\xa3".force_encoding(Encoding::ASCII_8BIT),
          "\x1b\x53\x86\x67".force_encoding(Encoding::ASCII_8BIT),
          "\x1c\x53\xbb\x6b".force_encoding(Encoding::ASCII_8BIT),
          "\x1f\x43\xb6\x75".force_encoding(Encoding::ASCII_8BIT)
        ]
      }

      def get_begin_pattern
        return BEGIN_PATTERN_MKV, { :offset_inc => 4 }
      end

      def decode(offset)
        ending_offset = nil

        cursor = offset
        # Read the variable int for the header size
        header_size, vint_size = decode_vint(@data[cursor+4..cursor+11])
        cursor += 4 + vint_size
        progress(cursor)
        # Here we have header_size bytes for the header data.
        # Get the DocType
        max_header_cursor = cursor + header_size
        doc_type = nil
        while ((cursor < max_header_cursor) and (doc_type == nil))
          log_debug "=== @#{cursor} - Inspecting #{@data[cursor..cursor+20].inspect}"
          # Read next EBML segment
          segment_id, vint_size = decode_vint(@data[cursor..cursor+7])
          log_debug "=== @#{cursor} - Found ID #{segment_id}"
          cursor += vint_size
          # Read its size
          segment_size, vint_size = decode_vint(@data[cursor..cursor+7])
          cursor += vint_size
          if (segment_id == DOCTYPE_ID_INT)
            doc_type = @data[cursor..cursor+segment_size-1]
            log_debug "=== @#{cursor} - Found DocType: #{doc_type.inspect}"
          end
          cursor += segment_size
          progress(cursor)
        end
        invalid_data("@#{offset} - Unable to get the DocType from the EBML file") if (doc_type == nil)
        extension = ACCEPTABLE_DOCTYPES[doc_type]
        invalid_data("@#{offset} - Unknown DocType: #{doc_type}") if (extension == nil)
        # Make sure we consumed the header completely
        cursor = max_header_cursor
        # Now read the segment
        invalid_data("@#{cursor} - Invalid Segment ID") if (@data[cursor..cursor+3] != SEGMENT_MATROSKA_ID)
        found_relevant_data(extension)
        # Read segment size
        segment_size, vint_size = decode_vint(@data[cursor+4..cursor+11])
        log_debug "=== @#{cursor} - Found segment of size #{segment_size}"
        cursor += 4 + vint_size
        if (segment_size == 127)
          # The size is unknown
          # We have to make a deep decoding
          while (ebml_id_size = decode_ebml_id(cursor))
            # Read segment size
            segment_size, vint_size = decode_vint(@data[cursor+ebml_id_size..cursor+ebml_id_size+7])
            log_debug "=== @#{cursor} - Found segment #{segment_id} (size #{ebml_id_size}) of size #{segment_size} (size #{vint_size})"
            cursor += ebml_id_size + vint_size
            if (segment_size != 127)
              cursor += segment_size
              break if (cursor == @end_offset)
            end
            progress(cursor)
          end
        else
          cursor += segment_size
        end
        progress(cursor)
        ending_offset = cursor

        return ending_offset
      end

      private

      # Take the data (as a String) and read it as a variable size integer (return also the size)
      #
      # Parameters::
      # * *data* (_String_): The data to decode
      # Result::
      # * _Fixnum_: The corresponding value
      # * _Fixnum_: The size of the vint
      def decode_vint(data)
        value = 0
        size = 1

        bytes = data.bytes.to_a
        # Size of the integer is defined in first byte only
        first_byte = bytes.first
        size = 1
        while ((first_byte & (1 << (8-size))) == 0)
          size += 1
          invalid_data("Invalid variable int encoded: #{data}") if (size > 8)
        end
        # Replace first byte with its true value
        bytes[0] = first_byte & ((1 << (8-size))-1)
        # Read all
        size.times do |idx|
          value = (value << 8) + bytes[idx]
        end

        return value, size
      end

      # Decode an EBML ID
      #
      # Parameters::
      # * *cursor* (_Fixnum_): The cursor
      # Result::
      # * _Fixnum_: Size of the decoded EBML ID, or false if not a valid EBML ID
      def decode_ebml_id(cursor)
        if (VALID_ELEMENT_IDS[1].include?(@data[cursor]))
          return 1
        elsif (VALID_ELEMENT_IDS[2].include?(@data[cursor..cursor+1]))
          return 2
        elsif (VALID_ELEMENT_IDS[3].include?(@data[cursor..cursor+2]))
          return 3
        elsif (VALID_ELEMENT_IDS[4].include?(@data[cursor..cursor+3]))
          return 4
        else
          return false
        end
      end

    end

  end

end
