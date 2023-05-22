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

#include <sstream>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "guide.h"
#include "gen_regex.h"

struct my_mutator {
  afl_state_t *afl;
  size_t       trim_size_current;
  int          trimmming_steps;
  int          cur_step;
  u8          *mutated_out, *post_process_buf, *trim_buf;
};

extern "C" my_mutator *afl_custom_init(afl_state_t *afl, unsigned int seed) {
  srand(seed);

  my_mutator *data = (my_mutator *)calloc(1, sizeof(my_mutator));
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

static void mutate_choices(std::vector<uint64_t> C) {
  C.at(rand() % C.size()) = rand();
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
extern "C" size_t afl_custom_fuzz(my_mutator *data, uint8_t *buf,
                                  size_t buf_size, u8 **out_buf,
                                  uint8_t *add_buf,
                                  size_t   add_buf_size,  // add_buf can be NULL
                                  size_t   max_size) {
  std::string Str((char *)buf, buf_size);
  std::stringstream SS(Str);
  auto FG = new tree_guide::FileGuide;
  if (!FG->parseChoices(SS)) {
    std::cerr << "couldn't parse choices\n";
    // FIXME do something better 
    return 0;
  }
  auto C1 = FG->getChoices();
  std::cerr << "parsed " << C1.size() << " choices\n";
  mutate_choices(C1);
  std::cerr << "mutated\n";
  FG->replaceChoices(C1);

  tree_guide::SaverGuide SG(FG);
  auto Ch = SG.makeChooser();
  auto Ch2 = static_cast<tree_guide::SaverChooser *>(Ch.get());
  assert(Ch2);
  
  auto S = gen(*Ch2, RegexDepth);

  // the mutated choices may contain extra elements, missing elements,
  // and out-of-range elements; this gets us a cleaned-up version
  auto C2 = Ch2->formatChoices();
  
  // print the choice sequence into mutated_out
  strcpy((char *)data->mutated_out, C2.c_str());
  strcat((char *)data->mutated_out, S.c_str());

  std::cerr << (char *)data->mutated_out;
  
  *out_buf = data->mutated_out;
  // return mutated_size;
  return strlen((char *)data->mutated_out);
}

extern "C" int32_t afl_custom_init_trim(my_mutator *data, uint8_t *buf,
                                        size_t buf_size) {
  return 0;
}

extern "C" size_t afl_custom_trim(my_mutator *data, uint8_t **out_buf) {
  *out_buf = data->trim_buf;
  return data->trim_size_current;
}

extern "C" int32_t afl_custom_post_trim(my_mutator *data, int success) {
  return 0;
}

extern "C" size_t afl_custom_havoc_mutation(my_mutator *data, u8 *buf,
                                            size_t buf_size, u8 **out_buf,
                                            size_t max_size) {
  *out_buf = buf;
  return buf_size;
}

extern "C" uint8_t afl_custom_havoc_mutation_probability(my_mutator *data) {
  return 0;
}

extern "C" void afl_custom_deinit(my_mutator *data) {
  free(data->post_process_buf);
  free(data->mutated_out);
  free(data->trim_buf);
  free(data);
}
