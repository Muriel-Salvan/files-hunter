module FilesHunter

  module Decoders

    class EBML < BeginPatternDecoder

      BEGIN_PATTERN_MKV = "\x1A\x45\xDF\xA3".force_encoding('ASCII-8BIT')
      DOCTYPE_ID_INT = 642
      SEGMENT_MATROSKA_ID = "\x18\x53\x80\x67".force_encoding('ASCII-8BIT')
      ACCEPTABLE_DOCTYPES = {
        'matroska' => :mkv,
        'webm' => :webm
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
        cursor += 4 + vint_size + segment_size
        progress(cursor)
        ending_offset = cursor

        return ending_offset
      end

      private

      # Take the data (as a String) and read it as a variable size integer (return also the size)
      def decode_vint(data)
        value = 0
        size = 1

        bytes = data.bytes.to_a
        # Size of the integer is defined in first byte only
        first_byte = bytes.first
        size = 1
        while ((first_byte & (1 << (8-size))) == 0)
          size += 1
          raise "Invalid variable int encoded: #{data}" if (size > 8)
        end
        # Replace first byte with its true value
        bytes[0] = first_byte & ((1 << (8-size))-1)
        # Read all
        size.times do |idx|
          value = (value << 8) + bytes[idx]
        end

        return value, size
      end

    end

  end

end
