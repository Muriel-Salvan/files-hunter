require 'fileshunter/Decoders/_FLAC'

module FilesHunter

  module Decoders

    class FLAC < BeginPatternDecoder

      BEGIN_PATTERN_FLAC = 'fLaC'.force_encoding(Encoding::ASCII_8BIT)

      def get_begin_pattern
        return BEGIN_PATTERN_FLAC, { :offset_inc => 4 }
      end

      def decode(offset)
        ending_offset = nil

        # Read all Metadata blocks
        cursor = offset+4
        metadata_finished = false
        nbr_bits_per_sample_header = nil
        while (!metadata_finished)
          c = @data[cursor].ord
          metadata_finished = (c > 128)
          metadata_type = (c & 127)
          invalid_data("@#{cursor} - Invalid Metadata type: #{c}") if (metadata_type > 6)
          if (metadata_type == 0)
            nbr_bits_per_sample_header = ((@data[cursor+16].ord & 1) << 4) + ((@data[cursor+17].ord & 240) >> 4) + 1
          end
          metadata_size = BinData::Uint24be.read(@data[cursor+1..cursor+3])
          cursor += 4 + metadata_size
          progress(cursor)
        end
        invalid_data("@#{offset} - Missing METADATA_BLOCK_STREAMINFO from headers") if (nbr_bits_per_sample_header == nil)
        found_relevant_data(:flac)
        metadata(
          :nbr_bits_per_sample_header => nbr_bits_per_sample_header
        )
        # Read frames
        while (ending_offset == nil)
          log_debug "@#{cursor} - Reading new frame"
          # Check frame header
          header_bytes = @data[cursor..cursor+4].bytes.to_a
          invalid_data("@#{cursor} - Incorrect frame header") if ((header_bytes[0] != 255) or
                                                                  ((header_bytes[1] & 254) != 248) or
                                                                  ((header_bytes[2] & 240) == 0) or
                                                                  ((header_bytes[2] & 15) == 15) or
                                                                  (header_bytes[3] >= 176) or
                                                                  ((header_bytes[3] & 14) == 6) or
                                                                  ((header_bytes[3] & 14) == 14) or
                                                                  (header_bytes[3].odd?))
          utf8_number_size = get_utf8_size(header_bytes[4])
          invalid_data("@#{cursor} - Incorrect UTF-8 size") if ((header_bytes[1].even?) and (utf8_number_size >= 7))
          cursor += 4 + utf8_number_size
          block_size = 0
          block_size_byte = ((header_bytes[2] & 240) >> 4)
          log_debug "@#{cursor} - block_size_byte=#{block_size_byte}"
          case block_size_byte
          when 1
            block_size = 192
          when 2..5
            block_size = 576 * (2**(block_size_byte-2))
          when 6
            # Blocksize is coded here on 8 bits
            block_size = @data[cursor].ord + 1
            cursor += 1
          when 7
            # Blocksize is coded here on 16 bits
            block_size = BinData::Uint16be.read(@data[cursor..cursor+1]) + 1
            cursor += 2
          else
            block_size =  256 * (2**(block_size_byte-8))
          end
          case (header_bytes[2] & 15)
          when 12
            # Sample rate is coded here on 8 bits
            cursor += 1
          when 13, 14
            # Sample rate is coded here on 16 bits
            cursor += 2
          end
          cursor += 1 # CRC
          # Decode some values needed further
          nbr_channels = ((header_bytes[3] & 240) >> 4) + 1
          # Channels encoding side (differences) always have +1 bit per sample
          bps_inc = nil
          case nbr_channels
          when 9, 11
            bps_inc = [ 0, 1 ]
          when 10
            bps_inc = [ 1, 0 ]
          else
            bps_inc = [ 0, 0 ]
          end
          nbr_channels = 2 if (nbr_channels > 8)
          nbr_bits_per_sample_frame_header = 0
          case ((header_bytes[3] & 14) >> 1)
          when 0
            nbr_bits_per_sample_frame_header = nbr_bits_per_sample_header
          when 1
            nbr_bits_per_sample_frame_header = 8
          when 2
            nbr_bits_per_sample_frame_header = 12
          when 4
            nbr_bits_per_sample_frame_header = 16
          when 5
            nbr_bits_per_sample_frame_header = 20
          when 6
            nbr_bits_per_sample_frame_header = 24
          end
          log_debug "@#{cursor} - block_size=#{block_size} nbr_channels=#{nbr_channels} nbr_bits_per_sample_frame_header=#{nbr_bits_per_sample_frame_header} bps_inc=#{bps_inc.inspect}"
          progress(cursor)
          # Here cursor is on the next byte after the frame header
          # We have nbr_channels subframes
          # !!! Starting from here, we have to track bits shifting
          cursor_bits = 0
          nbr_channels.times do |idx_channel|
            nbr_bits_per_sample = nbr_bits_per_sample_frame_header + ((bps_inc[idx_channel] == nil) ? 0 : bps_inc[idx_channel])
            log_debug "@#{cursor},#{cursor_bits} - Reading Subframe"
            nbr_encoded_partitions = 0
            # Decode the sub-frame header
            sub_header_first_byte, cursor, cursor_bits = decode_bits(cursor, cursor_bits, 8)
            invalid_data("@#{cursor},#{cursor_bits} - Invalid Sub frame header: #{sub_header_first_byte}") if ((sub_header_first_byte > 127) or
                                                                                                ((sub_header_first_byte & 124) == 4) or
                                                                                                ((sub_header_first_byte & 240) == 8) or
                                                                                                ((sub_header_first_byte & 96) == 32))
            wasted_bits = 0
            if (sub_header_first_byte.odd?)
              wasted_bits, cursor, cursor_bits = decode_unary(cursor, cursor_bits)
            end
            log_debug "@#{cursor},#{cursor_bits} - Found #{wasted_bits} wasted bits"
            cursor, cursor_bits = inc_cursor_bits(cursor, cursor_bits, wasted_bits)
            # Now decode the Subframe itself
            if ((sub_header_first_byte & 126) == 0)
              # SUBFRAME_CONSTANT
              log_debug "@#{cursor},#{cursor_bits} - Found Subframe header SUBFRAME_CONSTANT"
              cursor, cursor_bits = inc_cursor_bits(cursor, cursor_bits, nbr_bits_per_sample)
            elsif ((sub_header_first_byte & 126) == 1)
              # SUBFRAME_VERBATIM
              log_debug "@#{cursor},#{cursor_bits} - Found Subframe header SUBFRAME_VERBATIM"
              cursor, cursor_bits = inc_cursor_bits(cursor, cursor_bits, nbr_bits_per_sample * block_size)
            elsif ((sub_header_first_byte & 112) == 16)
              # SUBFRAME_FIXED
              order = ((sub_header_first_byte & 14) >> 1)
              invalid_data("@#{cursor},#{cursor_bits} - Invalid SUBFRAME_FIXED") if (order > 4)
              log_debug "@#{cursor},#{cursor_bits} - Found Subframe header SUBFRAME_FIXED of order #{order}"
              cursor, cursor_bits = inc_cursor_bits(cursor, cursor_bits, nbr_bits_per_sample * order)
              cursor, cursor_bits, nbr_encoded_partitions = decode_residual(cursor, cursor_bits, nbr_bits_per_sample, block_size, order, nbr_encoded_partitions)
            else
              # SUBFRAME_LPC
              lpc_order = ((sub_header_first_byte & 62) >> 1) + 1
              log_debug "@#{cursor},#{cursor_bits} - Found Subframe header SUBFRAME_LPC of order #{lpc_order}"
              cursor, cursor_bits = inc_cursor_bits(cursor, cursor_bits, nbr_bits_per_sample * lpc_order)
              qlpc_precision, cursor, cursor_bits = decode_bits(cursor, cursor_bits, 4)
              invalid_data("@#{cursor},#{cursor_bits} - Invalid qlpc_precision: #{qlpc_precision}") if (qlpc_precision == 15)
              qlpc_precision += 1
              log_debug "@#{cursor},#{cursor_bits} - qlpc_precision=#{qlpc_precision}"

              # DEBUG only
              # qlpc_shift, cursor, cursor_bits = decode_bits(cursor, cursor_bits, 5)
              # qlpc_shift = -((qlpc_shift - 1) ^ 31) if ((qlpc_shift & 16) != 0)
              # log_debug "@#{cursor},#{cursor_bits} - qlpc_shift=#{qlpc_shift}"
              # lpc_order.times do |idx_coeff|
              #   coeff, cursor, cursor_bits = decode_bits(cursor, cursor_bits, qlpc_precision)
              #   # Negative value
              #   coeff = -((coeff - 1) ^ ((1 << qlpc_precision) - 1)) if ((coeff & (1 << (qlpc_precision-1))) != 0)
              #   log_debug "@#{cursor},#{cursor_bits} - qlpc_coeff[#{idx_coeff}]=#{coeff}"
              # end
              # NON DEBUG only
              cursor, cursor_bits = inc_cursor_bits(cursor, cursor_bits, 5)
              cursor, cursor_bits = inc_cursor_bits(cursor, cursor_bits, qlpc_precision * lpc_order)

              cursor, cursor_bits, nbr_encoded_partitions = decode_residual(cursor, cursor_bits, nbr_bits_per_sample, block_size, lpc_order, nbr_encoded_partitions)
            end
            progress(cursor)
          end
          # We align back to byte
          cursor += 1 if (cursor_bits > 0)
          # Frame footer
          cursor += 2
          progress(cursor)
          ending_offset = cursor if (cursor == @end_offset)
        end

        return ending_offset
      end

      private

      # Get number of bytes taken by an UTF-8 character that has the given byte as the first one.
      #
      # Parameters::
      # * *first_utf8_byte* (_Fixnum_): The first UTF-8 byte
      # Result::
      # * _Fixnum_: The total size of the UTF-8 character
      def get_utf8_size(first_utf8_byte)
        return 1 if (first_utf8_byte < 128)
        raise "Invalid variable UTF-8 byte encoded: #{first_utf8_byte} (is a UTF-16 character)" if ((first_utf8_byte & 192) == 128)
        size = 2
        while ((first_utf8_byte & (1 << (7-size))) != 0)
          size += 1
          raise "Invalid variable UTF-8 byte encoded: #{first_utf8_byte}" if (size > 7)
        end
        return size
      end

      # Get position (in binary terms) of the next bit set to 1 in data.
      # Return nil if none found.
      #
      # Parameters::
      # * *data* (_String_): The data to analyze
      # * *idx_bit_begin_search* (_Fixnum_): Index of the first bit to begin search (has to be < 32)
      # Result::
      # * _Fixnum_: The position of the first 1. For example: 001 would return 2
      def find_bit(data, idx_bit_begin_search)
        data_32bits = data.unpack('N*')
        # Mask the ignored bits with 0
        data_32bits[0] = data_32bits[0] & ((1 << (32-idx_bit_begin_search))-1) if (idx_bit_begin_search > 0)
        idx_not_null = data_32bits.find_index { |v| v != 0 }
        return nil if (idx_not_null == nil)
        not_null = data_32bits[idx_not_null]
        position_in_32bits = 0
        mask = (1 << 31)
        while ((not_null & mask) == 0)
          position_in_32bits += 1
          mask = mask >> 1
        end
        return idx_not_null*32 + position_in_32bits
      end

      # Decode the next value as unary encoded (0 padding, ending with 1)
      #
      # Parameters::
      # * *cursor* (_Fixnum_): Current cursor
      # * *cursor_bits* (_Fixnum_): Current cursor_bits
      # Result::
      # * _Fixnum_: Value
      # * _Fixnum_: New cursor
      # * _Fixnum_: New cursor_bits
      def decode_unary(cursor, cursor_bits)
        # There are some wasted bits-per-sample: count them
        value = 1
        first_block = true
        @data.each_block(cursor) do |data_block|
          bit_position_in_block = find_bit(data_block, first_block ? cursor_bits : 0)
          if (bit_position_in_block == nil)
            value += 8 * data_block.size
            value -= cursor_bits if first_block
          else
            # We found it
            value += bit_position_in_block
            value -= cursor_bits if first_block
            break
          end
          first_block = false
        end
        cursor, cursor_bits = inc_cursor_bits(cursor, cursor_bits, value)

        return value, cursor, cursor_bits
      end

      # Increment cursor and cursor_bits by a given amount of bits
      #
      # Parameters::
      # * *cursor* (_Fixnum_): The cursor in bytes
      # * *cursor_bits* (_Fixnum_): The cursor in bits
      # * *nbr_bits* (_Fixnum_): The number of bits
      # Result::
      # * _Fixnum_: The new cursor
      # * _Fixnum_: The new cursor_bits
      def inc_cursor_bits(cursor, cursor_bits, nbr_bits)
        nbr_bytes, result_cursor_bits = (cursor_bits + nbr_bits).divmod(8)
        return cursor + nbr_bytes, result_cursor_bits
      end

      # Increment cursor and cursor_bits by reading a RESIDUAL section
      #
      # Parameters::
      # * *cursor* (_Fixnum_): The cursor in bytes
      # * *cursor_bits* (_Fixnum_): The cursor in bits
      # * *bits_per_sample* (_Fixnum_): Number of bits per sample
      # * *block_size* (_Fixnum_): The block size
      # * *predictor_order* (_Fixnum_): The predictor order
      # * *nbr_encoded_partitions* (_Fixnum_): The number of encoded partitions
      # Result::
      # * _Fixnum_: The new cursor
      # * _Fixnum_: The new cursor_bits
      # * _Fixnum_: The number of encoded partitions
      def decode_residual(cursor, cursor_bits, bits_per_sample, block_size, predictor_order, nbr_encoded_partitions)
        method_id, cursor, cursor_bits = decode_bits(cursor, cursor_bits, 2)

        invalid_data("@#{cursor},#{cursor_bits} - Invalid Residual method id: #{method_id}") if (method_id > 1)
        rice_parameter_size = 4 + method_id
        partition_order, cursor, cursor_bits = decode_bits(cursor, cursor_bits, 4)
        log_debug "@#{cursor},#{cursor_bits} - Found residual with method_id=#{method_id} rice_parameter_size=#{rice_parameter_size} partition_order=#{partition_order}"
        nbr_partitions = 2**partition_order
        nbr_partitions.times do |idx_partition|
          log_debug "@#{cursor},#{cursor_bits} - Decode partition"
          rice_parameter, cursor, cursor_bits = decode_bits(cursor, cursor_bits, rice_parameter_size)
          partition_bits_per_sample, cursor, cursor_bits = decode_bits(cursor, cursor_bits, 5) if (rice_parameter == 15)
          nbr_samples = nil
          if (partition_order == 0)
            nbr_samples = block_size - predictor_order
          elsif (nbr_encoded_partitions > 0)
            nbr_samples = block_size / nbr_partitions
          else
            nbr_samples = (block_size / nbr_partitions) - predictor_order
          end
          log_debug "@#{cursor},#{cursor_bits} - Begin decoding Rice samples: rice_parameter=#{rice_parameter} partition_bits_per_sample=#{partition_bits_per_sample} nbr_samples=#{nbr_samples}"
          if (partition_bits_per_sample == nil)
            # Samples encoded using Unary high values and rice_parameter length low values.
            # See http://www.hydrogenaudio.org/forums//lofiversion/index.php/t81718.html
            cursor, cursor_bits = decode_rice(cursor, cursor_bits, nbr_samples, rice_parameter)
            # Ruby version, very slow
            # nbr_samples.times do |idx_sample|

            #   # DEBUG only
            #   # value_high, cursor, cursor_bits = decode_unary(cursor, cursor_bits)
            #   # value_low, cursor, cursor_bits = decode_bits(cursor, cursor_bits, rice_parameter)
            #   # value = ((value_high-1) << (rice_parameter-1)) + (value_low >> 1)
            #   # value = -value-1 if (value_low.odd?)
            #   # log_debug "@#{cursor},#{cursor_bits} - Residual[#{idx_sample}]=#{value}"
            #   # NON DEBUG only
            #   _, cursor, cursor_bits = decode_unary(cursor, cursor_bits)
            #   _, cursor, cursor_bits = decode_bits(cursor, cursor_bits, rice_parameter)

            # end
          else
            # Fixed-size encoded samples
            cursor, cursor_bits = inc_cursor_bits(cursor, cursor_bits, nbr_samples * partition_bits_per_sample)
          end
          nbr_encoded_partitions += 1
          progress(cursor)
        end

        return cursor, cursor_bits, nbr_encoded_partitions
      end

      # Decode the next n bits and increment cursor and cursor_bits accordingly
      #
      # Parameters::
      # * *cursor* (_Fixnum_): The cursor in bytes
      # * *cursor_bits* (_Fixnum_): The cursor in bits
      # * *nbr_bits* (_Fixnum_): The number of bits to decode (has to be maximum 24)
      # Result::
      # * _Fixnum_: The decoded value
      # * _Fixnum_: The new cursor
      # * _Fixnum_: The new cursor_bits
      def decode_bits(cursor, cursor_bits, nbr_bits)
        value = nil
        nbr_bits_to_read = cursor_bits + nbr_bits
        if (nbr_bits_to_read > 24)
          # The value is split between 4 bytes
          value = (BinData::Uint32be.read(@data[cursor..cursor+3]) >> (32-nbr_bits_to_read)) & ((1 << nbr_bits)-1)
        elsif (nbr_bits_to_read > 16)
          # The value is split between 3 bytes
          value = (BinData::Uint24be.read(@data[cursor..cursor+2]) >> (24-nbr_bits_to_read)) & ((1 << nbr_bits)-1)
        elsif (nbr_bits_to_read > 8)
          # The value is split between 2 bytes
          value = (BinData::Uint16be.read(@data[cursor..cursor+1]) >> (16-nbr_bits_to_read)) & ((1 << nbr_bits)-1)
        else
          # The value is accessible through the same byte (@data[cursor])
          value = (@data[cursor].ord >> (8-nbr_bits_to_read)) & ((1 << nbr_bits)-1)
        end
        cursor, cursor_bits = inc_cursor_bits(cursor, cursor_bits, nbr_bits)

        return value, cursor, cursor_bits
      end

    end

  end

end
