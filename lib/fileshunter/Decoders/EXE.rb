module FilesHunter

  module Decoders

    class EXE < BeginPatternDecoder

      BEGIN_PATTERN_EXE = Regexp.new("MZ....\x00\x00.\x00.\x00..\x00\x00..\x00\x00\x00\x00\x00\x00.\x00.\x00\x00\x00....\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00....\x00\x00\x00\x00\x00\x00\x00\x00", nil, 'n')

      KNOWN_MACHINE_TYPES = [
        "\x00\x00".force_encoding(Encoding::ASCII_8BIT),
        "\xd3\x01".force_encoding(Encoding::ASCII_8BIT),
        "\x64\x86".force_encoding(Encoding::ASCII_8BIT),
        "\xc0\x01".force_encoding(Encoding::ASCII_8BIT),
        "\xc4\x01".force_encoding(Encoding::ASCII_8BIT),
        "\x64\xaa".force_encoding(Encoding::ASCII_8BIT),
        "\xbc\x0e".force_encoding(Encoding::ASCII_8BIT),
        "\x4c\x01".force_encoding(Encoding::ASCII_8BIT),
        "\x00\x02".force_encoding(Encoding::ASCII_8BIT),
        "\x41\x90".force_encoding(Encoding::ASCII_8BIT),
        "\x66\x02".force_encoding(Encoding::ASCII_8BIT),
        "\x66\x03".force_encoding(Encoding::ASCII_8BIT),
        "\x66\x04".force_encoding(Encoding::ASCII_8BIT),
        "\xf0\x01".force_encoding(Encoding::ASCII_8BIT),
        "\xf1\x01".force_encoding(Encoding::ASCII_8BIT),
        "\x66\x01".force_encoding(Encoding::ASCII_8BIT),
        "\xa2\x01".force_encoding(Encoding::ASCII_8BIT),
        "\xa3\x01".force_encoding(Encoding::ASCII_8BIT),
        "\xa6\x01".force_encoding(Encoding::ASCII_8BIT),
        "\xa8\x01".force_encoding(Encoding::ASCII_8BIT),
        "\xc2\x01".force_encoding(Encoding::ASCII_8BIT),
        "\x69\x01".force_encoding(Encoding::ASCII_8BIT)
      ]

      PE_SIGNATURE = "PE\x00\x00".force_encoding(Encoding::ASCII_8BIT)
      NE_SIGNATURE = 'NE'.force_encoding(Encoding::ASCII_8BIT)
      OPTIONAL_HEADER_ID = "\x0B".force_encoding(Encoding::ASCII_8BIT)
      PE32_ID = "\x01".force_encoding(Encoding::ASCII_8BIT)
      KNOWN_OPTIONAL_HEADER_TYPES = [
        PE32_ID,
        "\x02".force_encoding(Encoding::ASCII_8BIT)
      ]
      SECTION_TEXT_ID = ".text\x00\x00\x00".force_encoding(Encoding::ASCII_8BIT)

      def get_begin_pattern
        return BEGIN_PATTERN_EXE, { :offset_inc => 60, :max_regexp_size => 60 }
      end

      def decode(offset)
        ending_offset = nil

        # Go directly to the PE file header
        cursor = offset + BinData::Uint32le.read(@data[offset+60..offset+63])
        progress(cursor)
        # Decode PE file header
        invalid_data("@#{cursor} - Invalid PE/NE header") if ((@data[cursor..cursor+3] != PE_SIGNATURE) and (@data[cursor..cursor+1] != NE_SIGNATURE))
        if (@data[cursor..cursor+1] == NE_SIGNATURE)
          # NE format
          # Reference: http://www.fileformat.info/format/exe/corion-ne.htm
          # Reference: http://itee.uq.edu.au/~cristina/students/david/honoursThesis96/appendix.htm
          # Reference: http://www.program-transformation.org/Transform/NeFormat
          # Reference: http://www.chiark.greenend.org.uk/~sgtatham/fonts/dewinfont
          ne_offset = cursor
          cursor += 2
          #linker_major_version = @data[cursor].ord
          #linker_minor_version = @data[cursor+1].ord
          entry_table_offset = BinData::Uint16le.read(@data[cursor+2..cursor+3])
          entry_table_size = BinData::Uint16le.read(@data[cursor+4..cursor+5])
          #file_load_crc = BinData::Uint32le.read(@data[cursor+6..cursor+9])
          #program_flags = @data[cursor+10].ord
          #application_flags = @data[cursor+11].ord
          #auto_data_segment_index = BinData::Uint16le.read(@data[cursor+12..cursor+13])
          #initial_local_heap_size = BinData::Uint16le.read(@data[cursor+14..cursor+15])
          #initial_stack_size = BinData::Uint16le.read(@data[cursor+16..cursor+17])
          #entry_point = BinData::Uint32le.read(@data[cursor+18..cursor+21])
          #initial_stack_pointer = BinData::Uint32le.read(@data[cursor+22..cursor+25])
          nbr_segments = BinData::Uint16le.read(@data[cursor+26..cursor+27])
          nbr_module_reference = BinData::Uint16le.read(@data[cursor+28..cursor+29])
          non_resident_names_table_size = BinData::Uint16le.read(@data[cursor+30..cursor+31])
          segment_table_offset = BinData::Uint16le.read(@data[cursor+32..cursor+33])
          resource_table_offset = BinData::Uint16le.read(@data[cursor+34..cursor+35])
          resident_names_table_offset = BinData::Uint16le.read(@data[cursor+36..cursor+37])
          module_reference_table_offset = BinData::Uint16le.read(@data[cursor+38..cursor+39])
          imported_names_table_offset = BinData::Uint16le.read(@data[cursor+40..cursor+41])
          non_resident_names_table_offset = BinData::Uint32le.read(@data[cursor+42..cursor+45])
          #moveable_entry_point_count = BinData::Uint16le.read(@data[cursor+46..cursor+47])
          #file_alignment = BinData::Uint16le.read(@data[cursor+48..cursor+49])
          #nbr_resource_table_entries = BinData::Uint16le.read(@data[cursor+50..cursor+51])
          #target_operating_system = @data[cursor+52].ord
          #other_flags = @data[cursor+53].ord
          #return_thunks_offset = BinData::Uint16le.read(@data[cursor+54..cursor+55])
          #segment_reference_thunks_offset = BinData::Uint16le.read(@data[cursor+56..cursor+57])
          #code_swap_area_size = BinData::Uint16le.read(@data[cursor+58..cursor+59])
          #expected_win_version_minor = @data[cursor+60].ord
          #expected_win_version_major = @data[cursor+61].ord
          cursor += 62
          progress(cursor)
          log_debug "@#{cursor} - NE header: entry_table_offset=#{entry_table_offset} entry_table_size=#{entry_table_size} nbr_segments=#{nbr_segments} nbr_module_reference=#{nbr_module_reference} non_resident_names_table_size=#{non_resident_names_table_size} segment_table_offset=#{segment_table_offset} resource_table_offset=#{resource_table_offset} resident_names_table_offset=#{resident_names_table_offset} module_reference_table_offset=#{module_reference_table_offset} imported_names_table_offset=#{imported_names_table_offset} non_resident_names_table_offset=#{non_resident_names_table_offset}"
          # Segment table
          log_debug "@#{cursor} - Segment table"
          invalid_data("@#{cursor} - Segment table offset (#{segment_table_offset}) should have been set here (#{cursor-ne_offset}).") if (segment_table_offset != cursor-ne_offset)
          # map< SegmentOffset, SegmentSize >
          segment_data = {}
          nbr_segments.times do |idx_segment|
            segment_data_offset = BinData::Uint16le.read(@data[cursor..cursor+1])
            if (segment_data_offset > 0)
              segment_data_size = BinData::Uint16le.read(@data[cursor+2..cursor+3])
              segment_data_size = 65536 if (segment_data_size == 0)
              segment_data[segment_data_offset] = segment_data_size
            end
            cursor += 8
          end
          progress(cursor)
          # Now we track the maximal cursor encountered
          max_cursor = cursor
          # Resource table
          log_debug "@#{cursor} - Resource table"
          invalid_data("@#{cursor} - Resource table offset (#{resource_table_offset}) should have been set here (#{cursor-ne_offset}).") if (resource_table_offset != cursor-ne_offset)
          # Ignore nbr_resource_table_entries
          alignment_shift_count = BinData::Uint16le.read(@data[cursor..cursor+1])
          offset_factor = (1 << alignment_shift_count)
          # map< SegmentOffset, SegmentSize >
          resource_data = {}
          type_id = BinData::Uint16le.read(@data[cursor+2..cursor+3])
          cursor += 4
          while (type_id != 0)
            # If the Type ID is a string, read it
            if ((type_id & 0b10000000_00000000) == 0)
              str_offset = ne_offset + resource_table_offset + type_id
              end_str_cursor = str_offset + 1 + @data[str_offset].ord
              max_cursor = end_str_cursor if (max_cursor < end_str_cursor)
            end
            nbr_resources_for_this_type = BinData::Uint16le.read(@data[cursor..cursor+1])
            reserved = BinData::Uint32le.read(@data[cursor+2..cursor+5])
            invalid_data("@#{cursor} - Reserved data should have been null: #{reserved}") if (reserved != 0)
            cursor += 6
            nbr_resources_for_this_type.times do |idx_resource_for_this_type|
              resource_offset = BinData::Uint16le.read(@data[cursor..cursor+1])
              resource_size = BinData::Uint16le.read(@data[cursor+2..cursor+3])
              resource_flags = BinData::Uint16le.read(@data[cursor+4..cursor+5])
              resource_id = BinData::Uint16le.read(@data[cursor+6..cursor+7])
              real_offset = resource_offset * offset_factor
              real_size = resource_size * offset_factor
              log_debug "@#{cursor} - Found resource ##{resource_id} @#{real_offset} of size #{real_size} with flags #{resource_flags}"
              reserved = BinData::Uint32le.read(@data[cursor+8..cursor+11])
              invalid_data("@#{cursor} - Reserved data should have been null: #{reserved}") if (reserved != 0)
              resource_data[real_offset] = real_size
              # If the Resource ID is a string, read it
              if ((resource_id & 0b10000000_00000000) == 0)
                str_offset = ne_offset + resource_table_offset + resource_id
                end_str_cursor = str_offset + 1 + @data[str_offset].ord
                max_cursor = end_str_cursor if (max_cursor < end_str_cursor)
              end
              cursor += 12
              progress(cursor)
            end
            type_id = BinData::Uint16le.read(@data[cursor..cursor+1])
            cursor += 2
            progress(cursor)
          end
          progress(cursor)
          max_cursor = cursor if (max_cursor < cursor)
          # Resident names table
          cursor = ne_offset + resident_names_table_offset
          log_debug "@#{cursor} - Resident names table"
          next_string_length = @data[cursor].ord
          cursor += 1
          while (next_string_length > 0)
            str_name = @data[cursor..cursor+next_string_length-1]
            log_debug "@#{cursor} - Found resident name string: #{str_name.inspect}"
            cursor += next_string_length
            next_string_length = @data[cursor+2].ord
            cursor += 3
            progress(cursor)
          end
          max_cursor = cursor if (max_cursor < cursor)
          # Module reference table
          cursor = ne_offset + module_reference_table_offset
          log_debug "@#{cursor} - Module reference table"
          nbr_module_reference.times do |idx_module_reference|
            cursor += 2
          end
          progress(cursor)
          max_cursor = cursor if (max_cursor < cursor)
          # Imported name table
          cursor = ne_offset + imported_names_table_offset
          log_debug "@#{cursor} - Imported names table"
          next_string_length = @data[cursor].ord
          cursor += 1
          while (next_string_length > 0)
            str_name = @data[cursor..cursor+next_string_length-1]
            log_debug "@#{cursor} - Found imported name string: #{str_name.inspect}"
            cursor += next_string_length
            next_string_length = @data[cursor].ord
            cursor += 1
            progress(cursor)
          end
          max_cursor = cursor if (max_cursor < cursor)
          # Entry table
          cursor = ne_offset + entry_table_offset
          log_debug "@#{cursor} - Entry table"
          nbr_entries_in_bundle = @data[cursor].ord
          #segment_indicator_for_bundle = @data[cursor+1].ord
          cursor += 2
          while (nbr_entries_in_bundle > 0)
            # TODO
            invalid_data("@#{cursor} - Cannot decode entry tables from NE executable files yet. Sorry.")

            nbr_entries_in_bundle = @data[cursor].ord
          end
          invalid_data("@#{cursor} - Declared entry table size (#{entry_table_size}) is smaller than what has been read: #{cursor-ne_offset-entry_table_offset}") if (entry_table_size < cursor-ne_offset-entry_table_offset)
          # Make sure we get padding too
          cursor = ne_offset + entry_table_offset + entry_table_size
          max_cursor = cursor if (max_cursor < cursor)
          # Non resident names table
          cursor = offset + non_resident_names_table_offset
          log_debug "@#{cursor} - Non resident name table"
          next_string_length = @data[cursor].ord
          cursor += 1
          while (next_string_length > 0)
            str_name = @data[cursor..cursor+next_string_length-1]
            log_debug "@#{cursor} - Found non resident name string: #{str_name.inspect}"
            cursor += next_string_length
            next_string_length = @data[cursor+2].ord
            cursor += 3
            progress(cursor)
          end
          invalid_data("@#{cursor} - Declared non resident name table size (#{non_resident_names_table_size}) is smaller than what has been read: #{cursor-offset-non_resident_names_table_offset}") if (non_resident_names_table_size < cursor-offset-non_resident_names_table_offset)
          # Make sure we get padding too
          cursor = offset + non_resident_names_table_offset + non_resident_names_table_size
          max_cursor = cursor if (max_cursor < cursor)
          # Data and resource segments
          segment_data.merge(resource_data).each do |data_offset, data_size|
            cursor = offset + data_offset
            cursor += data_size
            max_cursor = cursor if (max_cursor < cursor)
          end
          ending_offset = max_cursor
          found_relevant_data(:fon)
        else
          # PE format
          cursor += 4
          target_machine = @data[cursor..cursor+1]
          invalid_data("@#{cursor} - Invalid machine type: #{target_machine.inspect}") if (!KNOWN_MACHINE_TYPES.include?(target_machine))
          nbr_sections = BinData::Uint16le.read(@data[cursor+2..cursor+3])
          #creation_time = BinData::Uint32le.read(@data[cursor+4..cursor+7])
          symbol_table_offset = BinData::Uint32le.read(@data[cursor+8..cursor+11])
          nbr_symbols = BinData::Uint32le.read(@data[cursor+12..cursor+15])
          optional_header_size = BinData::Uint16le.read(@data[cursor+16..cursor+17])
          characteristics = BinData::Uint16le.read(@data[cursor+18..cursor+19])
          invalid_data("@#{cursor+18} - Invalid characteristics #{characteristics}: bits should be 0") if ((characteristics & 80) != 0)
          # We can have a first guess on the extension
          file_type = ((characteristics & 8192) == 0) ? :exe : ((optional_header_size == 0) ? :obj : :dll)
          found_relevant_data((file_type == :exe) ? [ :exe, :sys ] : ((file_type == :obj) ? :obj : [ :dll, :drv, :ocx ]))
          metadata(
            :target_machine => target_machine,
            :nbr_sections => nbr_sections,
            :symbol_table_offset => symbol_table_offset,
            :nbr_symbols => nbr_symbols,
            :optional_header_size => optional_header_size,
            :characteristics => characteristics
          )
          cursor += 20
          progress(cursor)
          file_alignment = nil
          certificate_table_offset = nil
          certificate_table_size = nil
          #delay_import_table_offset = nil
          #delay_import_table_size = nil
          # Decode optional header if any
          optional_header_end_offset = cursor + optional_header_size
          if (optional_header_size > 0)
            c_1 = @data[cursor+1]
            invalid_data("@#{cursor} - Invalid optional header") if ((@data[cursor] != OPTIONAL_HEADER_ID) or (!KNOWN_OPTIONAL_HEADER_TYPES.include?(c_1)))
            mode_pe32 = (c_1 == PE32_ID)
            #linker_version_major = @data[cursor+2].ord
            #linker_version_minor = @data[cursor+3].ord
            #code_size = BinData::Uint32le.read(@data[cursor+4..cursor+7])
            #init_data_size = BinData::Uint32le.read(@data[cursor+8..cursor+11])
            #uninit_data_size = BinData::Uint32le.read(@data[cursor+12..cursor+15])
            #log_debug "@#{cursor} - code_size=#{code_size} init_data_size=#{init_data_size} uninit_data_size=#{uninit_data_size}"
            #entry_point_address = BinData::Uint32le.read(@data[cursor+16..cursor+19])
            #base_of_code = BinData::Uint32le.read(@data[cursor+20..cursor+23])
            #if mode_pe32
              #base_of_data = BinData::Uint32le.read(@data[cursor+24..cursor+27])
              #image_base = BinData::Uint32le.read(@data[cursor+28..cursor+31])
            #else
              #image_base = BinData::Uint64le.read(@data[cursor+24..cursor+31])
            #end
            #section_alignment = BinData::Uint32le.read(@data[cursor+32..cursor+35])
            file_alignment = BinData::Uint32le.read(@data[cursor+36..cursor+39])
            #os_version_major = BinData::Uint16le.read(@data[cursor+40..cursor+41])
            #os_version_minor = BinData::Uint16le.read(@data[cursor+42..cursor+43])
            #image_version_major = BinData::Uint16le.read(@data[cursor+44..cursor+45])
            #image_version_minor = BinData::Uint16le.read(@data[cursor+46..cursor+47])
            #subsystem_version_major = BinData::Uint16le.read(@data[cursor+48..cursor+49])
            #subsystem_version_minor = BinData::Uint16le.read(@data[cursor+50..cursor+51])
            win32_version = BinData::Uint32le.read(@data[cursor+52..cursor+55])
            invalid_data("@#{cursor+52} - Invalid Win32 version: #{win32_version}") if (win32_version != 0)
            #image_size = BinData::Uint32le.read(@data[cursor+56..cursor+59])
            headers_size = BinData::Uint32le.read(@data[cursor+60..cursor+64])
            #checksum = BinData::Uint32le.read(@data[cursor+64..cursor+67])
            subsystem = BinData::Uint16le.read(@data[cursor+68..cursor+69])
            if (subsystem == 1)
              case file_type
              when :dll
                file_type = :drv
                found_relevant_data(:drv)
              when :exe
                file_type = :sys
                found_relevant_data(:sys)
              end
            end
            dll_characteristics = BinData::Uint16le.read(@data[cursor+70..cursor+71])
            invalid_data("@#{cursor+70} - Invalid DLL characteristics #{dll_characteristics}: bits should be 0") if ((dll_characteristics & 4111) != 0)
            nbr_rva_and_sizes = nil
            if mode_pe32
              # stack_reserve_size = BinData::Uint32le.read(@data[cursor+72..cursor+75])
              # stack_commit_size = BinData::Uint32le.read(@data[cursor+76..cursor+79])
              # heap_reserve_size = BinData::Uint32le.read(@data[cursor+80..cursor+83])
              # heap_commit_size = BinData::Uint32le.read(@data[cursor+84..cursor+87])
              # loader_flags = BinData::Uint32le.read(@data[cursor+88..cursor+91])
              nbr_rva_and_sizes = BinData::Uint32le.read(@data[cursor+92..cursor+95])
              cursor += 96
            else
              # stack_reserve_size = BinData::Uint64le.read(@data[cursor+72..cursor+79])
              # stack_commit_size = BinData::Uint64le.read(@data[cursor+80..cursor+87])
              # heap_reserve_size = BinData::Uint64le.read(@data[cursor+88..cursor+95])
              # heap_commit_size = BinData::Uint64le.read(@data[cursor+96..cursor+103])
              # loader_flags = BinData::Uint32le.read(@data[cursor+104..cursor+107])
              nbr_rva_and_sizes = BinData::Uint32le.read(@data[cursor+108..cursor+111])
              cursor += 112
            end
            # Get some info from the Data Directories
            if (nbr_rva_and_sizes >= 5)
              certificate_table_offset = BinData::Uint32le.read(@data[cursor+32..cursor+35])
              certificate_table_size = BinData::Uint32le.read(@data[cursor+36..cursor+39])
            end
            #if (nbr_rva_and_sizes >= 14)
              #delay_import_table_offset = BinData::Uint32le.read(@data[cursor+104..cursor+107])
              #delay_import_table_size = BinData::Uint32le.read(@data[cursor+108..cursor+111])
            #end
            cursor += 8*nbr_rva_and_sizes
            progress(cursor)
            log_debug "@#{cursor} - Extended header: mode_pe32=#{mode_pe32} win32_version=#{win32_version} headers_size=#{headers_size} subsystem=#{subsystem} dll_characteristics=#{dll_characteristics} nbr_rva_and_sizes=#{nbr_rva_and_sizes}"
            # We should have reached the end of optional header
            # Sometimes optional_header_end_offset is invalid
            invalid_data("@#{cursor} - Optional headers end at #{cursor} but were supposed to end at #{optional_header_end_offset}") if (cursor != optional_header_end_offset)
            metadata(
              :mode_pe32 => mode_pe32,
              :file_alignment => file_alignment,
              :win32_version => win32_version,
              :headers_size => headers_size,
              :subsystem => subsystem,
              :dll_characteristics => dll_characteristics,
              :nbr_rva_and_sizes => nbr_rva_and_sizes,
              :certificate_table_offset => certificate_table_offset,
              :certificate_table_size => certificate_table_size
            )
          end
          log_debug "@#{cursor} - PE Header: nbr_sections=#{nbr_sections} file_alignment=#{file_alignment} symbol_table_offset=#{symbol_table_offset} nbr_symbols=#{nbr_symbols} certificate_table_offset=#{certificate_table_offset} certificate_table_size=#{certificate_table_size}"
          # Now decode section headers
          log_debug "@#{cursor} - Beginning of section headers"
          # map<offset,size>
          sections = {}
          line_numbers = {}
          text_section_offset = nil
          nbr_sections.times do |idx_section|
            name = @data[cursor..cursor+7]
            #virtual_size = BinData::Uint32le.read(@data[cursor+8..cursor+11])
            #virtual_address = BinData::Uint32le.read(@data[cursor+12..cursor+15])
            raw_data_size = BinData::Uint32le.read(@data[cursor+16..cursor+19])
            raw_data_offset = BinData::Uint32le.read(@data[cursor+20..cursor+23])
            #relocations_offset = BinData::Uint32le.read(@data[cursor+24..cursor+27])
            line_numbers_offset = BinData::Uint32le.read(@data[cursor+28..cursor+31])
            #nbr_relocations = BinData::Uint16le.read(@data[cursor+32..cursor+33])
            nbr_line_numbers = BinData::Uint16le.read(@data[cursor+34..cursor+35])
            #section_characteristics = BinData::Uint32le.read(@data[cursor+36..cursor+39])
            #invalid_data("@#{cursor+70} - Invalid Section characteristics #{section_characteristics}: bits should be 0") if ((section_characteristics & 18) != 0)
            log_debug "@#{cursor} - Found section #{name}: raw_data_offset=#{raw_data_offset} raw_data_size=#{raw_data_size}"
            # Remember the .text section
            text_section_offset = raw_data_offset if (name == SECTION_TEXT_ID)
            cursor += 40
            progress(cursor)
            sections[raw_data_offset] = raw_data_size if (raw_data_size > 0)
            line_numbers[line_numbers_offset] = nbr_line_numbers if (nbr_line_numbers > 0)
          end
          # Get cursor directly at the end of the headers
          cursor = offset + headers_size if (headers_size != nil)
          progress(cursor)
          # Starting from here, tables and sections might not be contiguous. Therefore we keep track of the maximal cursor encountered.
          max_cursor = cursor
          # Now read all sections defined
          log_debug "@#{cursor} - Beginning of sections"
          sections.keys.sort.each_with_index do |section_offset, idx_section|
            # Align cursor on the next file_alignment
            rest = (file_alignment == nil) ? 0 : ((cursor-offset) % file_alignment)
            cursor += file_alignment - rest if (rest > 0)
            # Check beginning of the section data
            if ((cursor-offset) != section_offset)
              log_debug("@#{cursor} - Section #{idx_section} should have been at offset #{cursor-offset}, but is declared at #{section_offset}")
              cursor = offset + section_offset
            end
            # Check OCX
            if ((text_section_offset == section_offset) and
                (file_type == :dll) and
                (@data.index('DllRegisterServer', cursor) != nil))
              file_type = :ocx
              found_relevant_data(:ocx)
            end
            cursor += sections[section_offset]
            max_cursor = cursor if (cursor > max_cursor)
            progress(cursor)
          end
          # Should have the COFF line numbers sections
          log_debug "@#{cursor} - Beginning of COFF line numbers"
          line_numbers.keys.sort.each do |line_number_offset|
            if ((cursor-offset) != line_number_offset)
              log_debug("@#{cursor} - COFF line number section should have been at offset #{cursor-offset}, but is declared at #{line_number_offset}")
              # Have to realign cursor
              cursor = offset + line_number_offset
            end
            cursor += 6*line_numbers[line_number_offset]
            max_cursor = cursor if (cursor > max_cursor)
            progress(cursor)
          end
          # Should have the symbol table
          log_debug "@#{cursor} - Beginning of symbol tables"
          if (symbol_table_offset > 0)
            if ((cursor-offset) != symbol_table_offset)
              log_debug("@#{cursor} - Symbol table should have been at offset #{cursor-offset}, but is declared at #{symbol_table_offset}")
              cursor = offset + symbol_table_offset
            end
            nbr_symbols.times do |idx_symbol|
              #name = @data[cursor..cursor+7]
              #value = BinData::Uint32le.read(@data[cursor+8..cursor+11])
              #section_number = BinData::Uint16le.read(@data[cursor+12..cursor+13])
              #type = BinData::Uint16le.read(@data[cursor+14..cursor+15])
              #storage_class = @data[cursor+16].ord
              #nbr_auxiliary_symbols = @data[cursor+17].ord
              cursor += 18
              progress(cursor)
              log_debug "@#{cursor} - Finished decoding symbol \##{idx_symbol}"
            end
            # Should have the COFF string table
            log_debug "@#{cursor} - Beginning of COFF string table"
            coff_string_table_size = BinData::Uint32le.read(@data[cursor..cursor+3])
            # Should be greater than 4
            invalid_data("@#{cursor} - COFF string table size should be >= 4 (#{coff_string_table_size})") if (coff_string_table_size < 4)
            cursor += coff_string_table_size
            max_cursor = cursor if (cursor > max_cursor)
            progress(cursor)
          end
          # Should have the certificate table
          log_debug "@#{cursor} - Beginning of certificate table"
          if ((certificate_table_offset != nil) and
              (certificate_table_offset > 0))
            if ((cursor-offset) != certificate_table_offset)
              log_debug("@#{cursor} - Certificate table should have been at offset #{cursor-offset}, but is declared at #{certificate_table_offset}")
              cursor = offset + certificate_table_offset
            end
            while (cursor < offset + certificate_table_offset + certificate_table_size)
              log_debug "@#{cursor} - Read certificate"
              certificate_size = BinData::Uint32le.read(@data[cursor..cursor+3])
              log_debug "@#{cursor} - Found certificate of size #{certificate_size}"
              cursor += certificate_size
              # Round to 8 bytes
              rest = (cursor-offset) % 8
              cursor += 8 - rest if (rest > 0)
              progress(cursor)
            end
            max_cursor = cursor if (cursor > max_cursor)
          end
          # Delay import table is part of the .idata section already
          # # Should have the delay import table
          # log_debug "@#{cursor} - Beginning of delay import table"
          # if ((delay_import_table_offset != nil) and
          #     (delay_import_table_offset > 0))
          #   if ((cursor-offset) != delay_import_table_offset)
          #     invalid_data("@#{cursor} - Delay import table should have been at offset #{cursor-offset}, but is declared at #{delay_import_table_offset}")
          #     cursor = offset + delay_import_table_offset
          #   end
          #   attributes = BinData::Uint32le.read(@data[cursor..cursor+3])
          #   invalid_data("@#{cursor} - Delay import attributes should be 0 (#{attributes})") if (attributes != 0)
          #   name_rva = BinData::Uint32le.read(@data[cursor+4..cursor+7])
          #   module_handle = BinData::Uint32le.read(@data[cursor+8..cursor+11])
          #   delay_import_address_rva = BinData::Uint32le.read(@data[cursor+12..cursor+15])
          #   delay_import_name_rva = BinData::Uint32le.read(@data[cursor+16..cursor+19])
          #   bound_delay_import_rva = BinData::Uint32le.read(@data[cursor+20..cursor+23])
          #   unload_delay_import_rva = BinData::Uint32le.read(@data[cursor+24..cursor+27])
          #   timestamp = BinData::Uint32le.read(@data[cursor+28..cursor+31])
          #   cursor += 32
          #   max_cursor = cursor if (cursor > max_cursor)
          # end
          # Should be the end
          ending_offset = max_cursor
        end

        return ending_offset
      end

    end

  end

end
