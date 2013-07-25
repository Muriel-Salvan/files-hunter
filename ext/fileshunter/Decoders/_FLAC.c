#include "ruby.h"

//#define DEBUG

/** Load the data block containing a given offset and update variables pointing to the underlying data.
 *
 * Parameters::
 * * *rb_self* (_FLAC_): Self
 * * *rb_data* (_IOBlockReader_): Data
 * * *offset* (_int_): Offset indicating the block to be loaded
 * * *ptr_str_cursor* (uint8_t**_): [Result] C-String that points on the offset
 * * *ptr_str_cursor_start* (uint8_t**_): [Result] C-String that points on the offset too
 * * *ptr_str_cursor_end* (uint8_t**_): [Result] C-String that points on the end of the block
 * * *ptr_last_data_block* (_int*_): [Result] Boolean indicating if the data block is the last one. The bool has to be previsouly set to the value of the previous block.
 **/
void load_next_block(
  VALUE rb_self,
  VALUE rb_data,
  int offset,
  uint8_t** ptr_str_cursor,
  uint8_t** ptr_str_cursor_start,
  uint8_t** ptr_str_cursor_end,
  int* ptr_last_data_block) {
  // Check that there is data to read
  if (*ptr_last_data_block) {
    rb_funcall(rb_self, rb_intern("truncated_data"), 2, rb_str_new2("Unable to get next block to read"), rb_ivar_get(rb_self, rb_intern("@end_offset")));
  }
  // Load the block in memory and get it
  VALUE rb_result = rb_funcall(rb_data, rb_intern("get_block_containing_offset"), 1, INT2FIX(offset));
  VALUE rb_str_data_block = rb_ary_entry(rb_result, 0);
  uint32_t size_data_block = RSTRING_LEN(rb_str_data_block);
  uint32_t offset_data_block = FIX2INT(rb_ary_entry(rb_result, 1));
  *ptr_last_data_block = (rb_ary_entry(rb_result, 2) == Qtrue);
  *ptr_str_cursor_start = RSTRING_PTR(rb_str_data_block) + offset - offset_data_block;
  *ptr_str_cursor = (*ptr_str_cursor_start);
  *ptr_str_cursor_end = RSTRING_PTR(rb_str_data_block) + size_data_block;
  //printf("Next block loaded correctly: @%u (size=%u) &start=%u &end=%u\n", offset, size_data_block, *ptr_str_cursor_start, *ptr_str_cursor_end);
}

/** Decode data at a given cursor and cursor_bits position as a given number of samples encoded in a Rice partition
 *
 * Parameters::
 * * *rb_self* (_FLAC_): Self
 * * *rb_cursor* (_Fixnum_): Current cursor
 * * *rb_cursor_bits* (_Fixnum_): Current cursor_bits
 * * *rb_nbr_samples* (_Fixnum_): Number of samples to decode
 * * *rb_rice_parameter* (_Fixnum_): Rice parameter
 * Return::
 * * _Fixnum_: New cursor
 * * _Fixnum_: New cursor_bits
 **/
static VALUE flac_decode_rice(
  VALUE rb_self,
  VALUE rb_cursor,
  VALUE rb_cursor_bits,
  VALUE rb_nbr_samples,
  VALUE rb_rice_parameter) {
  // Translate Ruby objects
  uint32_t cursor = FIX2INT(rb_cursor);
  uint32_t cursor_bits = FIX2INT(rb_cursor_bits);
  uint32_t nbr_samples = FIX2INT(rb_nbr_samples);
  uint32_t rice_parameter = FIX2INT(rb_rice_parameter);
  VALUE rb_data = rb_ivar_get(rb_self, rb_intern("@data"));
  // Initialize the data stream
  int last_data_block = 0;
  uint8_t* str_cursor;
  uint8_t* str_cursor_start;
  uint8_t* str_cursor_end;
  load_next_block(rb_self, rb_data, cursor, &str_cursor, &str_cursor_start, &str_cursor_end, &last_data_block);
  // Temporary variables
  uint8_t current_byte;
  int found;
  uint32_t bits_count;
  uint32_t idx_sample;
#ifdef DEBUG
  uint32_t high_part;
  uint32_t low_part;
  uint32_t remaining_bits_to_decode;
  int32_t value;
  uint32_t temp;
#endif

  // Loop on samples
  for (idx_sample = 0; idx_sample < nbr_samples; ++idx_sample) {

    // cursor is the offset of str_cursor_start in the data stream.
    // str_cursor, cursor_bits point to the data being decoded.
    // str_cursor_start points to the beginning of the current data block
    // str_cursor_end points to the end of the current data block
    // last_data_block indicates if this is the last block

    // 1. Decode next bits as a unary encoded number: this will be the high bits of the value
    //printf("@%u,%u - 0 cursor=%u str_cursor=%u str_cursor_end=%u\n", cursor+str_cursor-str_cursor_start, cursor_bits, cursor, str_cursor-str_cursor_start, str_cursor_end-str_cursor_start);
#ifdef DEBUG
    printf("@%u,%u - Reading %u\n", cursor+str_cursor-str_cursor_start, cursor_bits, *str_cursor);
    high_part = 0;
#endif
    found = 0;
    if (cursor_bits > 0) {
      // Consider ending bits of current byte
      current_byte = *str_cursor;
      while ((cursor_bits < 8) &&
             ((current_byte & (1 << (7-cursor_bits))) == 0)) {
        ++cursor_bits;
#ifdef DEBUG
        ++high_part;
#endif
      }
      if (cursor_bits == 8) {
        // Not found in the current byte
        ++str_cursor;
      } else {
        // Found it
        found = 1;
      }
    }
    //printf("@%u,%u - 0.5 cursor=%u str_cursor=%u str_cursor_end=%u\n", cursor+str_cursor-str_cursor_start, cursor_bits, cursor, str_cursor-str_cursor_start, str_cursor_end-str_cursor_start);
    if (!found) {
      // Here we are byte-aligned
      // str_cursor points on the byte we are starting to search from (can be at the end of our current block)
      // cursor_bits has no significant value
      // First check if we need to read an extra block
      if (str_cursor == str_cursor_end) {
        cursor += str_cursor - str_cursor_start;
        load_next_block(rb_self, rb_data, cursor, &str_cursor, &str_cursor_start, &str_cursor_end, &last_data_block);
      }
      // Now we can continue our inspection
      // Loop until we find a non-null byte
      while (!found) {
        while ((str_cursor != str_cursor_end) &&
               ((*str_cursor) == 0)) {
          ++str_cursor;
#ifdef DEBUG
          high_part += 8;
#endif
        }
        if (str_cursor == str_cursor_end) {
          cursor += str_cursor - str_cursor_start;
          load_next_block(rb_self, rb_data, cursor, &str_cursor, &str_cursor_start, &str_cursor_end, &last_data_block);
        } else {
          found = 1;
        }
      }
      //printf("@%u,%u - 0.8 cursor=%u str_cursor=%u str_cursor_end=%u\n", cursor+str_cursor-str_cursor_start, cursor_bits, cursor, str_cursor-str_cursor_start, str_cursor_end-str_cursor_start);
      // Here, str_cursor points on the first non-null byte
      current_byte = *str_cursor;
      cursor_bits = 0;
      while ((cursor_bits < 8) &&
             ((current_byte & (1 << (7-cursor_bits))) == 0)) {
        ++cursor_bits;
#ifdef DEBUG
        ++high_part;
#endif
      }
    }
    // Here, str_cursor and cursor_bits point on the first bit set to 1
    //printf("@%u,%u - 1 cursor=%u str_cursor=%u str_cursor_end=%u\n", cursor+str_cursor-str_cursor_start, cursor_bits, cursor, str_cursor-str_cursor_start, str_cursor_end-str_cursor_start);

    // 2. Read the next rice_parameter bits: this will be the low bits of the value
#ifdef DEBUG
    printf("@%u,%u - Got high part (%u). Now decode low value (%u bits)\n", cursor+str_cursor-str_cursor_start, cursor_bits, high_part, rice_parameter);
    ++cursor_bits;
    if (cursor_bits == 8) {
      cursor_bits = 0;
      ++str_cursor;
      if (str_cursor == str_cursor_end) {
        cursor += str_cursor - str_cursor_start;
        load_next_block(rb_self, rb_data, cursor, &str_cursor, &str_cursor_start, &str_cursor_end, &last_data_block);
      }
    }
    if (cursor_bits + rice_parameter <= 8) {
      // The value can be decoded using current byte only
      low_part = ((*str_cursor) & ((1 << (8-cursor_bits)) - 1)) >> (8-cursor_bits-rice_parameter);
      cursor_bits += rice_parameter;
    } else {
      // Decode current byte and go on next ones
      low_part = (*str_cursor) & ((1 << (8-cursor_bits)) - 1);
      printf("@%u,%u - A - low_part=%u\n", cursor+str_cursor-str_cursor_start, cursor_bits, low_part);
      ++str_cursor;
      remaining_bits_to_decode = rice_parameter - 8 + cursor_bits;
      cursor_bits = 0;
      while (remaining_bits_to_decode > 0) {
        // Here we are byte aligned
        if (str_cursor == str_cursor_end) {
          cursor += str_cursor - str_cursor_start;
          load_next_block(rb_self, rb_data, cursor, &str_cursor, &str_cursor_start, &str_cursor_end, &last_data_block);
        }
        if (remaining_bits_to_decode >= 8) {
          low_part = (low_part << 8) + (*str_cursor);
          printf("@%u,%u - B (%u) - low_part=%u\n", cursor+str_cursor-str_cursor_start, cursor_bits, remaining_bits_to_decode, low_part);
          ++str_cursor;
          remaining_bits_to_decode -= 8;
        } else {
          // This byte is the last one to decode
          temp = low_part;
          low_part = (low_part << remaining_bits_to_decode) + ((*str_cursor) >> (8-remaining_bits_to_decode));
          printf("@%u,%u - C (%u) - low_part=%u (%u + %u)\n", cursor+str_cursor-str_cursor_start, cursor_bits, remaining_bits_to_decode, low_part, (temp << remaining_bits_to_decode), (current_byte >> (8-remaining_bits_to_decode)));
          cursor_bits = remaining_bits_to_decode;
          remaining_bits_to_decode = 0;
        }
      }
    }
    // Here we have high_part and low_part
    value = (high_part << (rice_parameter-1)) + (low_part >> 1);
    if ((low_part & 1) == 1) {
      value = -value-1;
    }
    printf("@%u,%u - Residual[%u]=%d (%u and %u)\n", cursor+str_cursor-str_cursor_start, cursor_bits, idx_sample, value, high_part, low_part);
#else
    bits_count = cursor_bits + 1 + rice_parameter;
    cursor_bits = (bits_count & 7);
    str_cursor += (bits_count >> 3);
    if (str_cursor >= str_cursor_end) {
      cursor += str_cursor - str_cursor_start;
      load_next_block(rb_self, rb_data, cursor, &str_cursor, &str_cursor_start, &str_cursor_end, &last_data_block);
    }
    //printf("@%u,%u - 2 cursor=%u str_cursor=%u str_cursor_end=%u\n", cursor+str_cursor-str_cursor_start, cursor_bits, cursor, str_cursor-str_cursor_start, str_cursor_end-str_cursor_start);
#endif

  }

  return rb_ary_new3(2, INT2FIX(cursor+str_cursor-str_cursor_start), INT2FIX(cursor_bits));
}

// Initialize the module
void Init__FLAC() {
  VALUE rb_mFilesHunter = rb_define_module("FilesHunter");
  VALUE rb_mDecoders = rb_define_module_under(rb_mFilesHunter, "Decoders");
  VALUE rb_cDecoder = rb_define_class_under(rb_mFilesHunter, "Decoder", rb_cObject);
  VALUE rb_cBeginPatternDecoder = rb_define_class_under(rb_mFilesHunter, "BeginPatternDecoder", rb_cDecoder);
  VALUE rb_cFLAC = rb_define_class_under(rb_mDecoders, "FLAC", rb_cBeginPatternDecoder);
  rb_define_method(rb_cFLAC, "decode_rice", flac_decode_rice, 4);
}
