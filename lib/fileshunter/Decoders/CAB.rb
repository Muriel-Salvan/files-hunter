module FilesHunter

  module Decoders

    class CAB < BeginPatternDecoder

      BEGIN_PATTERN_CAB = "MSCF\x00\x00\x00\x00".force_encoding('ASCII-8BIT')

      END_STRING_TERMINATOR = "\x00".force_encoding('ASCII-8BIT')

      AUTHENTICODE_ID = "\x30\x82".force_encoding('ASCII-8BIT')

      def get_begin_pattern
        return BEGIN_PATTERN_CAB, { :offset_inc => 4 }
      end

      def decode(offset)

        # CFHEADER
        cabinet_size = BinData::Uint32le.read(@data[offset+8..offset+11])
        invalid_data("@#{offset} - Invalid CAB header.") if (BinData::Uint32le.read(@data[offset+12..offset+15]) != 0)
        cf_file_offset = BinData::Uint32le.read(@data[offset+16..offset+19])
        invalid_data("@#{offset} - Invalid CAB header.") if (BinData::Uint32le.read(@data[offset+20..offset+23]) != 0)
        minor_version = @data[offset+24].ord
        major_version = @data[offset+25].ord
        nbr_cf_folders = BinData::Uint16le.read(@data[offset+26..offset+27])
        nbr_cf_files = BinData::Uint16le.read(@data[offset+28..offset+29])
        flags = BinData::Uint16le.read(@data[offset+30..offset+31])
        flag_prev_cabinet = ((flags & 0b00000000_00000001) != 0)
        flag_next_cabinet = ((flags & 0b00000000_00000010) != 0)
        flag_reserve_present = ((flags & 0b00000000_00000100) != 0)
        set_id = BinData::Uint16le.read(@data[offset+32..offset+33])
        idx_cabinet = BinData::Uint16le.read(@data[offset+34..offset+35])
        cursor = offset + 36
        reserve_field_size_in_folder = 0
        reserve_field_size_in_data = 0
        if flag_reserve_present
          reserve_field_size_in_header = BinData::Uint16le.read(@data[offset+36..offset+37])
          invalid_data("@#{offset} - Invalid reserve_field_size_in_header (#{reserve_field_size_in_header})") if (reserve_field_size_in_header > 60000)
          reserve_field_size_in_folder = @data[offset+38].ord
          reserve_field_size_in_data = @data[offset+39].ord
          cursor += 4 + reserve_field_size_in_header
        end
        if flag_prev_cabinet
          idx_terminator = @data.index(END_STRING_TERMINATOR, cursor)
          invalid_data("@#{cursor} - Unable to read previous cabinet name") if (idx_terminator == nil)
          cursor = idx_terminator + 1
          idx_terminator = @data.index(END_STRING_TERMINATOR, cursor)
          invalid_data("@#{cursor} - Unable to read previous disk name") if (idx_terminator == nil)
          cursor = idx_terminator + 1
        end
        if flag_next_cabinet
          idx_terminator = @data.index(END_STRING_TERMINATOR, cursor)
          invalid_data("@#{cursor} - Unable to read next cabinet name") if (idx_terminator == nil)
          cursor = idx_terminator + 1
          idx_terminator = @data.index(END_STRING_TERMINATOR, cursor)
          invalid_data("@#{cursor} - Unable to read next disk name") if (idx_terminator == nil)
          cursor = idx_terminator + 1
        end
        progress(cursor)
        found_relevant_data([:cab, :msu])
        metadata(
          :cabinet_size => cabinet_size,
          :minor_version => minor_version,
          :major_version => major_version,
          :nbr_cf_folders => nbr_cf_folders,
          :nbr_cf_files => nbr_cf_files,
          :set_id => set_id,
          :idx_cabinet => idx_cabinet,
          :flag_prev_cabinet => flag_prev_cabinet,
          :flag_next_cabinet => flag_next_cabinet,
          :flag_reserve_present => flag_reserve_present
        )

        # CFFOLDER
        data_blocks = []
        log_debug "@#{cursor} - Beginning of #{nbr_cf_folders} CFFOLDER structures"
        nbr_cf_folders.times do |idx_cf_folder|
          first_data_offset = BinData::Uint32le.read(@data[cursor..cursor+3])
          nbr_data_blocks = BinData::Uint16le.read(@data[cursor+4..cursor+5])
          data_blocks << [ first_data_offset, nbr_data_blocks ]
          compression_type = BinData::Uint16le.read(@data[cursor+6..cursor+7])
          cursor += 8 + reserve_field_size_in_folder
          progress(cursor)
        end

        # CFFILE
        log_debug "@#{cursor} - Beginning of #{nbr_cf_files} CFFILE structures"
        nbr_cf_files.times do |idx_cf_file|
          file_size = BinData::Uint32le.read(@data[cursor..cursor+3])
          file_offset = BinData::Uint32le.read(@data[cursor+4..cursor+7])
          idx_file_in_folder = BinData::Uint16le.read(@data[cursor+8..cursor+9])
          file_date = BinData::Uint16le.read(@data[cursor+10..cursor+11])
          file_time = BinData::Uint16le.read(@data[cursor+12..cursor+13])
          file_attrs = BinData::Uint16le.read(@data[cursor+14..cursor+15])
          cursor += 16
          idx_terminator = @data.index(END_STRING_TERMINATOR, cursor)
          invalid_data("@#{cursor} - Unable to read file name") if (idx_terminator == nil)
          cursor = idx_terminator + 1
          progress(cursor)
        end

        # CFDATA
        log_debug "@#{cursor} - Beginning of CFDATA"
        while (!data_blocks.empty?)
          # We should be on the first data block
          first_datablock_offset, nbr_datablocks = data_blocks.shift
          invalid_data("@#{cursor} - We should be on the next data block offset (#{offset+first_datablock_offset})") if (cursor-offset != first_datablock_offset)
          nbr_datablocks.times do |idx_datablock|
            data_crc = BinData::Uint32le.read(@data[cursor..cursor+3])
            nbr_compressed_bytes = BinData::Uint16le.read(@data[cursor+4..cursor+5])
            nbr_uncompressed_bytes = BinData::Uint16le.read(@data[cursor+6..cursor+7])
            cursor += 8 + reserve_field_size_in_data + nbr_compressed_bytes
            progress(cursor)
          end
        end
        invalid_data("@#{cursor} - We should be on at the end of the CAB file (#{offset+cabinet_size})") if (cursor-offset != cabinet_size)

        # Check if it is signed digitally using Authenticode
        if ((cursor+4 < @end_offset) and
            (@data[cursor..cursor+1] == AUTHENTICODE_ID))
          # Read the size
          authenticode_size = BinData::Uint16be.read(@data[cursor+2..cursor+3])
          log_debug "@#{cursor} - Found authenticode data of size #{authenticode_size}"
          cursor += 8 + authenticode_size
        end

        return cursor
      end

    end

  end

end
