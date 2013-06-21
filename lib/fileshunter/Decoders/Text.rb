module FilesHunter

  module Decoders

    class Text

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
          newline_offset = data.index("\n", current_offset)
          if ((newline_offset == nil) or
              (newline_offset >= end_offset))
            # No text
            current_offset = end_offset
            log_debug "Contains no more Text."
          else
            # We have a candidate
            # Get back to see the beginning of Text
            cursor = newline_offset-1
            distance = 1
            while ((cursor >= begin_offset) and
                   ((((c = data[cursor].ord) >= 32) and
                     (c != 127)) or
                    (c == 9) or
                    (c == 13) or
                    ((c == 0) and
                     (distance.odd?))))
              cursor -= 1
              distance += 1
            end
            text_begin_offset = cursor + 1
            # Now find forward
            cursor = newline_offset + 1
            distance = 1
            while ((cursor < end_offset) and
                   ((((c = data[cursor].ord) >= 32) and
                     (c != 127)) or
                    (c == 9) or
                    (c == 10) or
                    (c == 13) or
                    ((c == 0) and
                     (distance.odd?))))
              cursor += 1
              distance += 1
            end
            text_end_offset = cursor
            # Check encoding
            encoding = Encoding::ASCII_8BIT
            if (text_end_offset - text_begin_offset > 1)
              if (data[text_begin_offset] == "\x00")
                encoding = Encoding::UTF_16BE
              elsif (data[text_begin_offset+1] == "\x00")
                encoding = Encoding::UTF_16LE
              end
            end
            # Consider text files longer than a certain size only
            if (text_end_offset - text_begin_offset < 512*((encoding == Encoding::ASCII_8BIT) ? 1 : 2))
              log_debug "@#{text_begin_offset} - Text section is too short (#{text_end_offset - text_begin_offset}) to be identified as ASCII text"
            else
              # Now check some formats
              text = data[text_begin_offset..text_end_offset-1].clone.force_encoding(encoding)
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
        return ((lines[0] =~ Regexp.new('^\d+$'.encode(encoding))) and
                (lines[1] =~ Regexp.new('^\d\d:\d\d:\d\d,\d\d\d --> \d\d:\d\d:\d\d,\d\d\d$'.encode(encoding))))
      end

      def is_text_rtf?(lines, encoding)
        return (lines[0] =~ Regexp.new('^\{\\rtf'.encode(encoding)))
      end

    end

  end

end
