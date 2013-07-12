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
          "\x80",
          "\x83",
          "\x85",
          "\x86",
          "\x88",
          "\x89",
          "\x8e",
          "\x8f",
          "\x91",
          "\x92",
          "\x96",
          "\x97",
          "\x98",
          "\x9a",
          "\x9b",
          "\x9c",
          "\x9f",
          "\xa0",
          "\xa1",
          "\xa2",
          "\xa3",
          "\xa4",
          "\xa5",
          "\xa6",
          "\xa7",
          "\xaa",
          "\xab",
          "\xae",
          "\xaf",
          "\xb0",
          "\xb2",
          "\xb3",
          "\xb5",
          "\xb6",
          "\xb7",
          "\xb9",
          "\xba",
          "\xbb",
          "\xbf",
          "\xc0",
          "\xc1",
          "\xc4",
          "\xc6",
          "\xc7",
          "\xc8",
          "\xc9",
          "\xca",
          "\xcb",
          "\xcc",
          "\xcd",
          "\xce",
          "\xcf",
          "\xd7",
          "\xdb",
          "\xe0",
          "\xe1",
          "\xe2",
          "\xe3",
          "\xe4",
          "\xe5",
          "\xe6",
          "\xe7",
          "\xe8",
          "\xe9",
          "\xea",
          "\xeb",
          "\xec",
          "\xed",
          "\xee",
          "\xf0",
          "\xf1",
          "\xf7",
          "\xfa",
          "\xfb",
          "\xfd"
        ],
        2 => [
          "\x42\x54",
          "\x42\x55",
          "\x42\x82",
          "\x42\x85",
          "\x42\x86",
          "\x42\x87",
          "\x42\xf2",
          "\x42\xf3",
          "\x42\xf7",
          "\x43\x7c",
          "\x43\x7e",
          "\x44\x44",
          "\x44\x61",
          "\x44\x7a",
          "\x44\x84",
          "\x44\x85",
          "\x44\x87",
          "\x44\x89",
          "\x45\x0d",
          "\x45\x98",
          "\x45\xa3",
          "\x45\xb9",
          "\x45\xbc",
          "\x45\xbd",
          "\x45\xdb",
          "\x45\xdd",
          "\x46\x5c",
          "\x46\x60",
          "\x46\x61",
          "\x46\x62",
          "\x46\x6e",
          "\x46\x75",
          "\x46\x7e",
          "\x46\xae",
          "\x47\xe1",
          "\x47\xe2",
          "\x47\xe3",
          "\x47\xe4",
          "\x47\xe5",
          "\x47\xe6",
          "\x4d\x80",
          "\x4d\xbb",
          "\x50\x31",
          "\x50\x32",
          "\x50\x33",
          "\x50\x34",
          "\x50\x35",
          "\x53\x5f",
          "\x53\x6e",
          "\x53\x78",
          "\x53\x7f",
          "\x53\xab",
          "\x53\xac",
          "\x53\xb8",
          "\x53\xb9",
          "\x54\xaa",
          "\x54\xb0",
          "\x54\xb2",
          "\x54\xb3",
          "\x54\xba",
          "\x54\xbb",
          "\x54\xcc",
          "\x54\xdd",
          "\x55\xaa",
          "\x55\xee",
          "\x56\x54",
          "\x57\x41",
          "\x58\x54",
          "\x58\xd7",
          "\x61\xa7",
          "\x62\x40",
          "\x62\x64",
          "\x63\xa2",
          "\x63\xc0",
          "\x63\xc3",
          "\x63\xc4",
          "\x63\xc5",
          "\x63\xc6",
          "\x63\xc9",
          "\x63\xca",
          "\x65\x32",
          "\x66\x24",
          "\x66\xa5",
          "\x66\xbf",
          "\x66\xfc",
          "\x67\xc8",
          "\x68\xca",
          "\x69\x11",
          "\x69\x22",
          "\x69\x24",
          "\x69\x33",
          "\x69\x44",
          "\x69\x55",
          "\x69\xa5",
          "\x69\xbf",
          "\x69\xfc",
          "\x6d\x80",
          "\x6d\xe7",
          "\x6d\xf8",
          "\x6e\x67",
          "\x6e\xbc",
          "\x6f\xab",
          "\x73\x73",
          "\x73\x84",
          "\x73\xa4",
          "\x73\xc4",
          "\x73\xc5",
          "\x74\x46",
          "\x75\xa1",
          "\x78\xb5",
          "\x7b\xa9",
          "\x7d\x7b",
          "\x7e\x5b",
          "\x7e\x7b",
          "\x7e\x8a",
          "\x7e\x9a",
          "\x7e\xa5",
          "\x7e\xb5"
        ],
        3 => [
          "\x22\xb5\x9c",
          "\x23\x31\x4f",
          "\x23\x83\xe3",
          "\x23\xe3\x83",
          "\x25\x86\x88",
          "\x26\xb2\x40",
          "\x2a\xd7\xb1",
          "\x2e\xb5\x24",
          "\x2f\xb5\x23",
          "\x3a\x96\x97",
          "\x3b\x40\x40",
          "\x3c\x83\xab",
          "\x3c\xb9\x23",
          "\x3e\x83\xbb",
          "\x3e\xb9\x23"
        ],
        4 => [
          "\x10\x43\xa7\x70",
          "\x11\x4d\x9b\x74",
          "\x12\x54\xc3\x67",
          "\x15\x49\xa9\x66",
          "\x16\x54\xae\x6b",
          "\x18\x53\x80\x67",
          "\x19\x41\xa4\x69",
          "\x1a\x45\xdf\xa3",
          "\x1b\x53\x86\x67",
          "\x1c\x53\xbb\x6b",
          "\x1f\x43\xb6\x75"
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
