import random
import time


def q_gram_dice_sim(q_gram_set1, q_gram_set2):
    """Calculate the Dice similarity between the two given sets of q-grams.

       Dice similarity is calculated between two sets A and B as

          Dice similarity (A,B) = 2 x number of common elements of A and B
                                  -------------------------------------------
                                  number of elems in A + number of elems in B

       Returns a similarity value between 0 and 1.
    """

    num_common_q_gram = len(q_gram_set1 & q_gram_set2)

    q_gram_dice_sim = (2.0 * num_common_q_gram) / \
                      (len(q_gram_set1) + len(q_gram_set2))

    assert 0 <= q_gram_dice_sim <= 1.0

    return q_gram_dice_sim


class VAH:
    def __init__(self, seed, hardened_q_grams, non_freq_q_grams, l_r):
        self.secret_seed = seed
        self.vuln_q_grams = hardened_q_grams
        self.non_vuln_q_grams = non_freq_q_grams
        self.l_r = l_r
        self.indexed_ref_sets = None


    def generate_reference_sets(self, pub_db_q_gram_sets):
        """Generates reference sets for each vulnerable q-gram by splitting their co-occurring q-gram pools
        extracted from the public database q-gram sets

            Input:
                pub_db_q_gram_sets: Dictionary containing the q-gram sets of the records in the public database

            Output:
                indexed_reference_sets: Dictionary containing the indexed reference sets for each vulnerable q-gram
        """

        random.seed(self.secret_seed)

        start_time = time.time()
        vuln_q_gram_co_occurrences = {key: set() for key in self.vuln_q_grams}
        for rec_id, qs in pub_db_q_gram_sets.items():
            vuln_qs = qs.intersection(self.vuln_q_grams)
            if len(vuln_qs) > 0:
                for q_v in vuln_qs:
                    vuln_q_gram_co_occurrences[q_v].update(qs - {q_v})

        co_occurrence_pool_time = time.time()
        print("Time taken to identify co-occurring q-gram pools: %f seconds" % (
                (co_occurrence_pool_time - start_time) * 1000))

        reference_sets = {}
        total_qs_r_count = 0
        for q_v, co_occurring_q_grams in vuln_q_gram_co_occurrences.items():
            co_occurring_q_grams = list(co_occurring_q_grams)
            reference_sets[q_v] = []
            qv_qs_r_count = 0
            for i in range(0, len(co_occurring_q_grams), self.l_r):
                qs_r = set(co_occurring_q_grams[i:i + self.l_r])

                if len(qs_r) < self.l_r and qv_qs_r_count > 0:
                    while len(qs_r) < self.l_r:
                        qs_r.add(co_occurring_q_grams[random.randint(0, len(co_occurring_q_grams) - 1)])
                elif len(qs_r) < self.l_r and qv_qs_r_count == 0:
                    print("Expected length of qs_r is %d and available co-occurring q-grams is %d" % (
                        self.l_r, len(co_occurring_q_grams)))
                    while len(qs_r) < self.l_r:
                        qs_r.add(self.non_vuln_q_grams[random.randint(0, len(self.non_vuln_q_grams) - 1)])

                assert len(qs_r) == self.l_r, "Length of the reference set does not match the expected length"
                qv_qs_r_count += 1
                reference_sets[q_v].append(qs_r)
            total_qs_r_count += qv_qs_r_count

        print("Generated %d reference sets" % total_qs_r_count)
        init_random_set_gen_time = time.time()
        print("Time taken to generate the initial random reference sets: %f seconds" % (
                    (init_random_set_gen_time - co_occurrence_pool_time) * 1000))

        random_indices = random.sample(range(0, total_qs_r_count * len(self.vuln_q_grams)), total_qs_r_count)
        random.shuffle(random_indices)
        indexed_reference_sets = {}

        for q_v, ref_sets in reference_sets.items():
            indexed_reference_sets[q_v] = {}
            for ref_set in ref_sets:
                indexed_reference_sets[q_v][random_indices.pop()] = ref_set

        print("Time taken for the complete reference set generation process: %f seconds" % (
                    (time.time() - start_time) * 1000))

        assert len(indexed_reference_sets) == len(reference_sets) == len(self.vuln_q_grams), "Mismatch in reference sets generated"

        self.indexed_ref_sets = indexed_reference_sets


    def harden_with_vah_ref_sets(self, data_dict, q_gram_f_dist):
        """Hardens all occurrences of vuln. q-grams in the given records using the reference sets generated

            Input:
                data_dict: Dictionary containing the q-gram sets of the records in the sensitive database
                q_gram_f_dist: Dictionary containing the original frequency distribution of the q-grams in the sensitive
                                database

            Output:
                data_dict: updated dictionary containing the hardened q-gram sets (updated vulnerable record q-gram sets)
        """

        random.seed(self.secret_seed)
        q_gram_to_quali_mapping = {}
        hardened_rec_count = 0

        start_time = time.time()

        for rec_id, qs in data_dict.items():
            vuln_qs = qs.intersection(self.vuln_q_grams)

            if len(vuln_qs) > 0:
                for q_v in vuln_qs:
                    sim_scores = {}
                    for ref_id, ref_set in self.indexed_ref_sets[q_v].items():
                        sim_scores[ref_id] = q_gram_dice_sim(qs, ref_set)

                    sorted_items = sorted(sim_scores.items(), key=lambda item: item[1], reverse=True)
                    max_value = sorted_items[0][1]

                    # to ensure reproducibility
                    max_keys = []
                    for key, value in sorted_items:
                        if value == max_value:
                            max_keys.append(key)
                        else:
                            break

                    qualifier = random.choice(max_keys)

                    replacement = q_v + str(qualifier)
                    qs.remove(q_v)
                    qs.add(replacement)

                    # Update the mapping of q-grams to their replacements
                    if q_v not in q_gram_to_quali_mapping:
                        q_gram_to_quali_mapping[q_v] = [replacement]
                    elif replacement not in q_gram_to_quali_mapping[q_v]:
                        q_gram_to_quali_mapping[q_v].append(replacement)

                    # Update the frequency distribution of the q-grams
                    assert q_v in q_gram_f_dist, f"Q-gram {q_v} not found in the frequency distribution"
                    q_gram_f_dist[q_v] -= 1
                    if q_gram_f_dist[q_v] == 0:
                        del q_gram_f_dist[q_v]

                    if replacement not in q_gram_f_dist:
                        q_gram_f_dist[replacement] = 0
                    q_gram_f_dist[replacement] += 1

                hardened_rec_count += 1
                data_dict[rec_id] = qs

        print("Number of sensitive records hardened: %d" % hardened_rec_count)
        print("VAH q-gram to qualifier mapping: ", q_gram_to_quali_mapping)
        print("VAH q-gram frequency distribution after hardening: ", q_gram_f_dist)

        print("Time taken to harden %d records is %f seconds" % (hardened_rec_count, ((time.time() - start_time) * 1000)))
        return data_dict
