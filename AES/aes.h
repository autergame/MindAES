#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include "lookup_boxes.h"

void key_expansion_core(unsigned char* in, unsigned char i) {
  unsigned int* q = (unsigned int*) in;
  // Left rotate bytes
  *q = (*q >> 8 | ((*q & 0xff) << 24));

  in[0] = s_box[in[0]]; in[1] = s_box[in[1]];
  in[2] = s_box[in[2]]; in[3] = s_box[in[3]];

  // RCon XOR
  in[0] ^= rcon[i];
}

void key_expansion(unsigned char* input_key, unsigned char* expanded_keys) {
  // Set first 16 bytes to input_key
  for (int i = 0; i < 16; i++)
    expanded_keys[i] = input_key[i];

  unsigned int bytes_generated = 16;
  int rcon_iteration = 1;
  unsigned char temp[4];

  // Generate the next 160 bytes
  while (bytes_generated < 176) {
    // Read 4 bytes for the core
    for (int i = 0; i < 4; i++)
      temp[i] = expanded_keys[i + bytes_generated - 4];

    // Perform the core once for each 16 byte key
    if (bytes_generated % 16 == 0)
      key_expansion_core(temp, rcon_iteration++);

    // XOR temp with [bytes_generated-16], and store in expanded_keys
    for (unsigned char a = 0; a < 4; a++) {
      expanded_keys[bytes_generated] = expanded_keys[bytes_generated - 16] ^ temp[a];
      bytes_generated++;
    }
  }
}

void sub_bytes(unsigned char* state) {
  // Substitute each state value with another byte in the Rijndael S-Box
  for (int i = 0; i < 16; i++)
    state[i] = s_box[state[i]];
}

void inv_sub_bytes(unsigned char* state) {
  // Substitute each state value with another byte in the Rijndael S-Box
  for (int i = 0; i < 16; i++)
    state[i] = inv_s_box[state[i]];
}

void shift_rows(unsigned char* state) {
  unsigned char tmp[16];

  // First row don't shift (idx = idx)
  tmp[0] = state[0];
  tmp[4] = state[4];
  tmp[8] = state[8];
  tmp[12] = state[12];

  // Second row shift right once (idx = (idx + 4) % 16)
  tmp[1] = state[5];
  tmp[5] = state[9];
  tmp[9] = state[13];
  tmp[13] = state[1];

  // Third row shift right twice (idx = (idx +/- 8) % 16)
  tmp[2] = state[10];
  tmp[6] = state[14];
  tmp[10] = state[2];
  tmp[14] = state[6];

  // Fourth row shift right three times (idx = (idx - 4) % 16)
  tmp[3] = state[15];
  tmp[7] = state[3];
  tmp[11] = state[7];
  tmp[15] = state[11];

  for (int i = 0; i < 16; i++)
     state[i] = tmp[i];
}

void inv_shift_rows(unsigned char* state) {
  unsigned char tmp[16];

  // First row don't shift (idx = idx)
  tmp[0] = state[0];
  tmp[4] = state[4];
  tmp[8] = state[8];
  tmp[12] = state[12];

  // Second row shift right once (idx = (idx - 4) % 16)
  tmp[1] = state[13];
  tmp[5] = state[1];
  tmp[9] = state[5];
  tmp[13] = state[9];

  // Third row shift right twice (idx = (idx +/- 8) % 16)
  tmp[2] = state[10];
  tmp[6] = state[14];
  tmp[10] = state[2];
  tmp[14] = state[6];

  // Fourth row shift right three times (idx = (idx + 4) % 16)
  tmp[3] = state[7];
  tmp[7] = state[11];
  tmp[11] = state[15];
  tmp[15] = state[3];

  for (int i = 0; i < 16; i++)
     state[i] = tmp[i];
}

void mix_columns(unsigned char* state) {
  // Dot product and byte mod of state

  unsigned char tmp[16];
  // Column 1 entries
  tmp[0] = (unsigned char) (mul2[state[0]] ^ mul3[state[1]] ^ state[2] ^ state[3]);
  tmp[1] = (unsigned char) (state[0] ^ mul2[state[1]] ^ mul3[state[2]] ^ state[3]);
  tmp[2] = (unsigned char) (state[0] ^ state[1] ^ mul2[state[2]] ^ mul3[state[3]]);
  tmp[3] = (unsigned char) (mul3[state[0]] ^ state[1] ^ state[2] ^ mul2[state[3]]);
 
  // Column 2 entries
  tmp[4] = (unsigned char) (mul2[state[4]] ^ mul3[state[5]] ^ state[6] ^ state[7]);
  tmp[5] = (unsigned char) (state[4] ^ mul2[state[5]] ^ mul3[state[6]] ^ state[7]);
  tmp[6] = (unsigned char) (state[4] ^ state[5] ^ mul2[state[6]] ^ mul3[state[7]]);
  tmp[7] = (unsigned char) (mul3[state[4]] ^ state[5] ^ state[6] ^ mul2[state[7]]);
 
  // Column 3 entries
  tmp[8] = (unsigned char) (mul2[state[8]] ^ mul3[state[9]] ^ state[10] ^ state[11]);
  tmp[9] = (unsigned char) (state[8] ^ mul2[state[9]] ^ mul3[state[10]] ^ state[11]);
  tmp[10] = (unsigned char) (state[8] ^ state[9] ^ mul2[state[10]] ^ mul3[state[11]]);
  tmp[11] = (unsigned char) (mul3[state[8]] ^ state[9] ^ state[10] ^ mul2[state[11]]);
 
  // Column 4 entries
  tmp[12] = (unsigned char) (mul2[state[12]] ^ mul3[state[13]] ^ state[14] ^ state[15]);
  tmp[13] = (unsigned char) (state[12] ^ mul2[state[13]] ^ mul3[state[14]] ^ state[15]);
  tmp[14] = (unsigned char) (state[12] ^ state[13] ^ mul2[state[14]] ^ mul3[state[15]]);
  tmp[15] = (unsigned char) (mul3[state[12]] ^ state[13] ^ state[14] ^ mul2[state[15]]);

  for (int i = 0; i < 16; i++)
     state[i] = tmp[i];
}

void inv_mix_columns(unsigned char* state) {
  unsigned char tmp[16];

  // Column 1
  tmp[0] = (unsigned char) (mul14[state[0]] ^ mul11[state[1]] ^ mul13[state[2]] ^ mul9[state[3]]);
  tmp[1] = (unsigned char) (mul9[state[0]] ^ mul14[state[1]] ^ mul11[state[2]] ^ mul13[state[3]]);
  tmp[2] = (unsigned char) (mul13[state[0]] ^ mul9[state[1]] ^ mul14[state[2]] ^ mul11[state[3]]);
  tmp[3] = (unsigned char) (mul11[state[0]] ^ mul13[state[1]] ^ mul9[state[2]] ^ mul14[state[3]]);
 
  // Column 2
  tmp[4] = (unsigned char) (mul14[state[4]] ^ mul11[state[5]] ^ mul13[state[6]] ^ mul9[state[7]]);
  tmp[5] = (unsigned char) (mul9[state[4]] ^ mul14[state[5]] ^ mul11[state[6]] ^ mul13[state[7]]);
  tmp[6] = (unsigned char) (mul13[state[4]] ^ mul9[state[5]] ^ mul14[state[6]] ^ mul11[state[7]]);
  tmp[7] = (unsigned char) (mul11[state[4]] ^ mul13[state[5]] ^ mul9[state[6]] ^ mul14[state[7]]);
 
  // Column 3
  tmp[8] = (unsigned char) (mul14[state[8]] ^ mul11[state[9]] ^ mul13[state[10]] ^ mul9[state[11]]);
  tmp[9] = (unsigned char) (mul9[state[8]] ^ mul14[state[9]] ^ mul11[state[10]] ^ mul13[state[11]]);
  tmp[10] = (unsigned char) (mul13[state[8]] ^ mul9[state[9]] ^ mul14[state[10]] ^ mul11[state[11]]);
  tmp[11] = (unsigned char) (mul11[state[8]] ^ mul13[state[9]] ^ mul9[state[10]] ^ mul14[state[11]]);
 
  // Column 4
  tmp[12] = (unsigned char) (mul14[state[12]] ^ mul11[state[13]] ^ mul13[state[14]] ^ mul9[state[15]]);
  tmp[13] = (unsigned char) (mul9[state[12]] ^ mul14[state[13]] ^ mul11[state[14]] ^ mul13[state[15]]);
  tmp[14] = (unsigned char) (mul13[state[12]] ^ mul9[state[13]] ^ mul14[state[14]] ^ mul11[state[15]]);
  tmp[15] = (unsigned char) (mul11[state[12]] ^ mul13[state[13]] ^ mul9[state[14]] ^ mul14[state[15]]);

  for (int i = 0; i < 16; i++)
     state[i] = tmp[i];
}

void add_round_key(unsigned char* state, unsigned char* round_key) {
  for (int i = 0; i < 16; i++)
    state[i] ^= round_key[i];
}

char* aes_encrypt(unsigned char* message, unsigned char* expanded_key) {
  unsigned char state[16];

  // Take only the first 16 characters of the message
  for (int i = 0; i < 16; i++)
     state[i] = message[i];

  const unsigned int round_cnt = 9;
  add_round_key(state, expanded_key);

  for (int i = 0; i < round_cnt; i++) {
    sub_bytes(state);
    shift_rows(state);
    mix_columns(state);
    add_round_key(state, expanded_key + (16 * (i + 1)));
  }

  // Final round
  sub_bytes(state);
  shift_rows(state);
  add_round_key(state, expanded_key + 160);

  char* enc_msg  = (char *) malloc(16);
  memcpy(enc_msg, state, 16);
  return enc_msg;
}

char * aes_decrypt(unsigned char* message, unsigned char* expanded_key) {
  unsigned char state[16];

  // Take only the first 16 characters of the message
  for (int i = 0; i < 16; i++)
     state[i] = message[i];

  const int round_cnt = 9;
  add_round_key(state, expanded_key + 160);

  for (int i = round_cnt; i > 0; i--) {
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, expanded_key + (16 * i));
    inv_mix_columns(state);
  }
  inv_shift_rows(state);
  inv_sub_bytes(state);
  add_round_key(state, expanded_key);

  char* dec_msg = (char *) malloc(16);
  memcpy(dec_msg, state, 16);
  return dec_msg;
}