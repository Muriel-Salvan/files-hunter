module FilesHunter

  module Decoders

    class Text

      UTF_16BE_BOM = "\xFE\xFF".force_encoding(Encoding::ASCII_8BIT)
      UTF_16LE_BOM = "\xFF\xFE".force_encoding(Encoding::ASCII_8BIT)
      NULL_CHAR = "\x00".force_encoding(Encoding::ASCII_8BIT)
      NL_CHAR = "\n".force_encoding(Encoding::ASCII_8BIT)

      # Find segments from a given data
      #
      # Parameters:
      # * *data* (_IOBlockReader_): Data being analyzed
      # * *begin_offset* (_Fixnum_): The begin offset
      # * *end_offset* (_Fixnum_): The end offset
      # Return::
      # * <em>list<Segment></em>: List of decoded segments
      def find_segments(data, begin_offset, end_offset)
        segments = []

        current_offset = begin_offset
        while (current_offset < end_offset)
          # First find a new line character from current_offset
          newline_offset = data.index(NL_CHAR, current_offset)
          if ((newline_offset == nil) or
              (newline_offset >= end_offset))
            # No text
            current_offset = end_offset
            log_debug "Contains no more Text."
          else
            # We have a candidate
            # Get back to see the beginning of Text
            text_begin_offset = nil
            text_header_size = 0
            # Detect if it might be UTF-16 encoded
            if (((newline_offset > begin_offset) and
                 (data[newline_offset-1] == NULL_CHAR)) or
                ((newline_offset < end_offset-1) and
                 (data[newline_offset+1] == NULL_CHAR)))
              # Cursor should always be on a \x00 unless it arrived at the end
              cursor = newline_offset - 1
              while ((cursor >= begin_offset+1) and
                     (data[cursor] == NULL_CHAR) and
                     ((((c = data[cursor-1].ord) >= 32) and
                       (c != 127)) or
                      (c == 9) or
                      (c == 13)))
                cursor -= 2
              end
              # Here we several possibilities:
              # * cursor is on begin_offset-1 and data begins with \x00: UTF-16 string starts at begin_offset and is big endian,
              # * else cursor is on begin_offset and data[begin_offset+1] is \x00 but we did not check data[begin_offset] (if data[begin_offset] is ASCII then it means UTF-16 begins at begin_offset and is little endian ; otherwise it starts at begin_offset+1 and is big endian),
              # * else cursor is at least on begin_offset+1 (we have at least 2 bytes before it), and
              #   * data[cursor] is not \x00 and data[cursor+2] is \x00: we could be on the endianness marker, or out of the string already ; if not endianness marker, if data[cursor+1] is valid ASCI then UTF-16 string starts at cursor+1 and is little endian, otherwise it starts at cursor+2 and is big endian,
              #   * else data[cursor] is \x00 but preceding character is not ASCII (meaning it can't be the endianness marker either): UTF-16 string starts at cursor end is big endian
              # UTF_16BE = "\xFE\xFF\x00\x??"
              # UTF_16LE = "\xFF\xFE\x??\x00"
              # In following comments, here are the conventions:
              # * \xAA means valid ASCII character
              # * \xBB means not a valid ASCII character
              # * \x11 means a non zero character
              # * \x?? means unknown character
              # * other values represent their corresponding character
              if (cursor == begin_offset-1)
                # data[begin_offset..begin_offset+1] == \xAA\x00
                text_begin_offset = begin_offset
                encoding = Encoding::UTF_16LE
              elsif (cursor == begin_offset)
                # data[begin_offset..begin_offset+2] == \x??\xAA\x00
                if ((c = data[begin_offset].ord) == 0)
                  # data[begin_offset..begin_offset+2] == \x00\xAA\x00
                  text_begin_offset = begin_offset
                  encoding = Encoding::UTF_16BE
                elsif (((c >= 32) and
                        (c != 127)) or
                       (c == 9) or
                       (c == 13))
                  # data[begin_offset..begin_offset+2] == \xAA\xAA\x00
                  if (data[begin_offset..begin_offset+1] == UTF_16BE_BOM)
                    # data[begin_offset..begin_offset+2] == \xFE\xFF\x00
                    text_begin_offset = begin_offset
                    encoding = Encoding::UTF_16BE
                    text_header_size = 2
                  else
                    text_begin_offset = begin_offset + 1
                    encoding = Encoding::UTF_16LE
                  end
                else
                  # data[begin_offset..begin_offset+2] == \xBB\xAA\x00
                  text_begin_offset = begin_offset + 1
                  encoding = Encoding::UTF_16LE
                end
              elsif (data[cursor] == NULL_CHAR)
                # data[cursor-1..cursor+2] == \xBB\x00\xAA\x00
                text_begin_offset = cursor
                encoding = Encoding::UTF_16BE
              elsif (data[cursor-1..cursor] == UTF_16LE_BOM)
                # data[cursor-1..cursor+2] == \xFF\xFE\xAA\x00
                text_begin_offset = cursor - 1
                encoding = Encoding::UTF_16LE
                text_header_size = 2
              elsif (data[cursor..cursor+1] == UTF_16BE_BOM)
                # data[cursor-1..cursor+2] == \x??\xFE\xFF\x00
                text_begin_offset = cursor
                encoding = Encoding::UTF_16BE
                text_header_size = 2
              else
                # data[cursor-1..cursor+2] == \x??\x11\xAA\x00
                text_begin_offset = cursor + 1
                encoding = Encoding::UTF_16LE
              end
            else
              encoding = Encoding::ASCII_8BIT
              cursor = newline_offset - 1
              while ((cursor >= begin_offset) and
                     ((((c = data[cursor].ord) >= 32) and
                       (c != 127)) or
                      (c == 9) or
                      (c == 13)))
                cursor -= 1
              end
              text_begin_offset = cursor + 1
            end
            # Now find forward
            text_end_offset = nil
            truncated = false
            case encoding
            when Encoding::ASCII_8BIT
              cursor = newline_offset + 1
              while ((cursor < end_offset) and
                     ((((c = data[cursor].ord) >= 32) and
                       (c != 127)) or
                      (c == 9) or
                      (c == 10) or
                      (c == 13)))
                cursor += 1
              end
              text_end_offset = cursor
            when Encoding::UTF_16BE
              # cursor points on \x00
              cursor = newline_offset + 1
              while ((cursor < end_offset-1) and
                     (data[cursor] == NULL_CHAR) and
                     ((((c = data[cursor+1].ord) >= 32) and
                       (c != 127)) or
                      (c == 9) or
                      (c == 10) or
                      (c == 13)))
                cursor += 2
              end
              # Several possibilities:
              # * cursor is at end_offset, meaning the string ends at end_offset,
              # * else cursor is at end_offset-1, meaning the string ends at end_offset-1 or at end_offset and is truncated if data[end_offset-1] is "\x00",
              # * else the string ends at cursor
              if (cursor == end_offset-1)
                if (data[cursor] == NULL_CHAR)
                  truncated = true
                  text_end_offset = end_offset
                else
                  text_end_offset = end_offset - 1
                end
              else
                text_end_offset = cursor
              end
            when Encoding::UTF_16LE
              # cursor points on the ASCII value
              cursor = newline_offset
              while ((cursor < end_offset-1) and
                     (data[cursor+1] == NULL_CHAR) and
                     ((((c = data[cursor].ord) >= 32) and
                       (c != 127)) or
                      (c == 9) or
                      (c == 10) or
                      (c == 13)))
                cursor += 2
              end
              # Several possibilities:
              # * cursor is at end_offset, meaning the string ends at end_offset,
              # * else cursor is at end_offset-1, meaning the string ends at end_offset-1 or at end_offset and is truncated if data[end_offset-1] is a valid ASCII,
              # * else the string ends at cursor
              if (cursor == end_offset-1)
                if ((((c = data[cursor].ord) >= 32) and
                     (c != 127)) or
                    (c == 9) or
                    (c == 10) or
                    (c == 13))
                  truncated = true
                  text_end_offset = end_offset
                else
                  text_end_offset = end_offset - 1
                end
              else
                text_end_offset = cursor
              end
            end
            log_debug "@#{text_begin_offset} - Found text up to #{text_end_offset} with encoding #{encoding} and header of size #{text_header_size}"
            # Consider text files longer than a certain size only
            if (text_end_offset - text_begin_offset < 512*((encoding == Encoding::ASCII_8BIT) ? 1 : 2))
              log_debug "@#{text_begin_offset} - Text section is too short (#{text_end_offset - text_begin_offset}) to be identified as text"
            else
              # Now check some formats
              text = data[text_begin_offset+text_header_size..text_end_offset-1].clone.force_encoding(encoding)
              lines = text.split("\r\n".encode(encoding))
              lines = text.split("\n".encode(encoding)) if (lines.size == 1)
              extension = :txt # By default
              if is_text_srt?(lines, encoding)
                extension = :srt
              elsif is_text_rtf?(lines, encoding)
                extension = :rtf
              end
              segments << Segment.new(text_begin_offset, text_end_offset, extension)
            end
            current_offset = text_end_offset + 1
          end
        end

        return segments
      end

      private

      def is_text_srt?(lines, encoding)
        # TODO (Ruby bug): Replace [0-9] with \d when it will work in UTF_16LE encoding
        return ((lines[0] =~ Regexp.new('^\d+$'.encode(encoding))) and
                (lines[1] =~ Regexp.new('^[0-9][0-9]:[0-9][0-9]:[0-9][0-9],[0-9][0-9][0-9] --> [0-9][0-9]:[0-9][0-9]:[0-9][0-9],[0-9][0-9][0-9]$'.encode(encoding))))
      end

      def is_text_rtf?(lines, encoding)
        return (lines[0] =~ Regexp.new('{\\\\rtf'.encode(encoding)))
      end

    end

  end

end
