/*
  New Custom Mutator for AFL++
  Written by Khaled Yakdan <yakdan@code-intelligence.de>
             Andrea Fioraldi <andreafioraldi@gmail.com>
             Shengtuo Hu <h1994st@gmail.com>
             Dominik Maier <mail@dmnk.co>
*/

extern "C" {
#include "afl-fuzz.h"
}

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "guide.h"

#define DATA_SIZE (100)

static const char *commands[] = {
    "GET",
    "PUT",
    "DEL",
};

typedef struct my_mutator {

  afl_state_t *afl;

  // any additional data here!
  size_t trim_size_current;
  int    trimmming_steps;
  int    cur_step;

  u8 *mutated_out, *post_process_buf, *trim_buf;

} my_mutator_t;

/**
 * Initialize this custom mutator
 *
 * @param[in] afl a pointer to the internal state object. Can be ignored for
 * now.
 * @param[in] seed A seed for this mutator - the same seed should always mutate
 * in the same way.
 * @return Pointer to the data object this custom mutator instance should use.
 *         There may be multiple instances of this mutator in one afl-fuzz run!
 *         Return NULL on error.
 */
extern "C"
my_mutator_t *afl_custom_init(afl_state_t *afl, unsigned int seed) {

  srand(seed);  // needed also by surgical_havoc_mutate()

  my_mutator_t *data = (my_mutator_t *)calloc(1, sizeof(my_mutator_t));
  if (!data) {

    perror("afl_custom_init alloc");
    return NULL;

  }

  if ((data->mutated_out = (u8 *)malloc(MAX_FILE)) == NULL) {

    perror("afl_custom_init malloc");
    return NULL;

  }

  if ((data->post_process_buf = (u8 *)malloc(MAX_FILE)) == NULL) {

    perror("afl_custom_init malloc");
    return NULL;

  }

  if ((data->trim_buf = (u8 *)malloc(MAX_FILE)) == NULL) {

    perror("afl_custom_init malloc");
    return NULL;

  }

  data->afl = afl;

  return data;

}

/**
 * Perform custom mutations on a given input
 *
 * (Optional for now. Required in the future)
 *
 * @param[in] data pointer returned in afl_custom_init for this fuzz case
 * @param[in] buf Pointer to input data to be mutated
 * @param[in] buf_size Size of input data
 * @param[out] out_buf the buffer we will work on. we can reuse *buf. NULL on
 * error.
 * @param[in] add_buf Buffer containing the additional test case
 * @param[in] add_buf_size Size of the additional test case
 * @param[in] max_size Maximum size of the mutated output. The mutation must not
 *     produce data larger than max_size.
 * @return Size of the mutated output.
 */
extern "C"
size_t afl_custom_fuzz(my_mutator_t *data, uint8_t *buf, size_t buf_size,
                       u8 **out_buf, uint8_t *add_buf,
                       size_t add_buf_size,  // add_buf can be NULL
                       size_t max_size) {

  // Make sure that the packet size does not exceed the maximum size expected by
  // the fuzzer
  size_t mutated_size = DATA_SIZE <= max_size ? DATA_SIZE : max_size;

  memcpy(data->mutated_out, buf, buf_size);

  // Randomly select a command string to add as a header to the packet
  memcpy(data->mutated_out, commands[rand() % 3], 3);

  if (mutated_size > max_size) { mutated_size = max_size; }

  *out_buf = data->mutated_out;
  return mutated_size;

}


/**
 * This method is called at the start of each trimming operation and receives
 * the initial buffer. It should return the amount of iteration steps possible
 * on this input (e.g. if your input has n elements and you want to remove
 * them one by one, return n, if you do a binary search, return log(n),
 * and so on...).
 *
 * If your trimming algorithm doesn't allow you to determine the amount of
 * (remaining) steps easily (esp. while running), then you can alternatively
 * return 1 here and always return 0 in post_trim until you are finished and
 * no steps remain. In that case, returning 1 in post_trim will end the
 * trimming routine. The whole current index/max iterations stuff is only used
 * to show progress.
 *
 * (Optional)
 *
 * @param data pointer returned in afl_custom_init for this fuzz case
 * @param buf Buffer containing the test case
 * @param buf_size Size of the test case
 * @return The amount of possible iteration steps to trim the input.
 *        negative on error.
 */
extern "C"
int32_t afl_custom_init_trim(my_mutator_t *data, uint8_t *buf,
                             size_t buf_size) {
  return 0;
}

/**
 * This method is called for each trimming operation. It doesn't have any
 * arguments because we already have the initial buffer from init_trim and we
 * can memorize the current state in *data. This can also save
 * reparsing steps for each iteration. It should return the trimmed input
 * buffer, where the returned data must not exceed the initial input data in
 * length. Returning anything that is larger than the original data (passed
 * to init_trim) will result in a fatal abort of AFLFuzz.
 *
 * (Optional)
 *
 * @param[in] data pointer returned in afl_custom_init for this fuzz case
 * @param[out] out_buf Pointer to the buffer containing the trimmed test case.
 *     External library should allocate memory for out_buf.
 *     AFL++ will not release the memory after saving the test case.
 *     Keep a ref in *data.
 *     *out_buf = NULL is treated as error.
 * @return Pointer to the size of the trimmed test case
 */
extern "C"
size_t afl_custom_trim(my_mutator_t *data, uint8_t **out_buf) {
  *out_buf = data->trim_buf;
  return data->trim_size_current;
}

/**
 * This method is called after each trim operation to inform you if your
 * trimming step was successful or not (in terms of coverage). If you receive
 * a failure here, you should reset your input to the last known good state.
 *
 * (Optional)
 *
 * @param[in] data pointer returned in afl_custom_init for this fuzz case
 * @param success Indicates if the last trim operation was successful.
 * @return The next trim iteration index (from 0 to the maximum amount of
 *     steps returned in init_trim). negative ret on failure.
 */
extern "C"
int32_t afl_custom_post_trim(my_mutator_t *data, int success) {
  return 0;
}

/**
 * Perform a single custom mutation on a given input.
 * This mutation is stacked with the other muatations in havoc.
 *
 * (Optional)
 *
 * @param[in] data pointer returned in afl_custom_init for this fuzz case
 * @param[in] buf Pointer to the input data to be mutated and the mutated
 *     output
 * @param[in] buf_size Size of input data
 * @param[out] out_buf The output buffer. buf can be reused, if the content
 * fits. *out_buf = NULL is treated as error.
 * @param[in] max_size Maximum size of the mutated output. The mutation must
 *     not produce data larger than max_size.
 * @return Size of the mutated output.
 */
extern "C"
size_t afl_custom_havoc_mutation(my_mutator_t *data, u8 *buf, size_t buf_size,
                                 u8 **out_buf, size_t max_size) {
  *out_buf = buf;
  return buf_size;
}

/**
 * Return the probability (in percentage) that afl_custom_havoc_mutation
 * is called in havoc. By default it is 6 %.
 *
 * (Optional)
 *
 * @param[in] data pointer returned in afl_custom_init for this fuzz case
 * @return The probability (0-100).
 */
extern "C"
uint8_t afl_custom_havoc_mutation_probability(my_mutator_t *data) {
  return 0;
}

/**
 * Deinitialize everything
 *
 * @param data The data ptr from afl_custom_init
 */
extern "C"
void afl_custom_deinit(my_mutator_t *data) {
  free(data->post_process_buf);
  free(data->mutated_out);
  free(data->trim_buf);
  free(data);
}

