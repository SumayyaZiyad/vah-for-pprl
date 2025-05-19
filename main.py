import copy
import csv
import gzip
import sys
import time

import hardening as hd


def extract_q_gram_sets(file_name, rec_id_col, attribute_list, q, has_header):
    """Extracts the q-gram sets using the provided set of attributes for the given file.

        Input:
            file_name: The name of the file to be loaded
            rec_id_col: The column number of the record identifier
            attribute_list: The list of column numbers of the attributes from which q-grams are to be extracted
            q: The length of a q-gram
            has_header: A boolean indicating whether the file has a header or not

        Output:
            data_dict: A dictionary containing the record identifier as the key and the set of q-grams as the value
            q_gram_dict: A dictionary containing the q-gram frequencies in the provided database
    """

    if file_name.endswith('gz'):
        in_f = gzip.open(file_name, 'rt', encoding="utf8")
    else:
        in_f = open(file_name, encoding="utf8")

    csv_reader = csv.reader(in_f)

    print('Loading data from %s to generate q-gram sets: ' % file_name)

    if has_header:
        header_list = next(csv_reader)
        print('  Record identifier attribute: ' + str(header_list[rec_id_col]))

        headers_used = []
        print('  Attributes to use:')
        for attr_num in attribute_list:
            print('    ' + header_list[attr_num])
            headers_used.append(header_list[attr_num])

    rec_num = 0
    data_dict = {}
    q_gram_dict = {}

    # Iterate through each entry in the file
    for rec_list in csv_reader:
        # Get the record identifier
        rec_id = rec_list[rec_id_col].strip().lower()  # strips the value and transforms to lowercase to get key
        qs = set()

        for attr_id in range(len(rec_list)):
            if attr_id in attribute_list:
                # converts to lowercase, and removes whitespaces
                sensitive_value =  rec_list[attr_id].strip().lower().replace(' ', '')
                attr_q_gram_set = set([sensitive_value[i:i + q] for i in range(len(sensitive_value) - (q - 1))])
                qs = qs.union(attr_q_gram_set)

        data_dict[rec_id] = qs
        for q_gram in qs:
            if q_gram not in q_gram_dict:
                q_gram_dict[q_gram] = 0
            q_gram_dict[q_gram] += 1
        rec_num += 1

    in_f.close()
    print("Analysed %d unique entries" % rec_num)
    print("Identified %d unique q-grams" % len(q_gram_dict))

    return data_dict, q_gram_dict


def get_q_grams_to_be_hardened(q_gram_dict, vuln_q_gram_count):
    """Identifies the q-grams to be hardened based on the frequency distribution of the q-grams.

        Input:
            q_gram_dict: A dictionary containing the q-gram frequencies
            vuln_q_gram_count: The number of vulnerable q-grams to extract

        Output:
            vuln_q_grams: The list of vulnerable q-grams to be hardened
            non_vuln_q_grams: The list of non-vulnerable q-grams
    """

    print("Identifying top %d frequent q-grams to be hardened" % vuln_q_gram_count)
    sorted_q_grams = sorted(q_gram_dict.items(), key=lambda item: item[1])

    vuln_q_grams = [key for key, value in sorted_q_grams[-vuln_q_gram_count:]]
    print("Vulnerable q-grams to harden: ", vuln_q_grams)

    non_vuln_q_grams = [key for key, value in sorted_q_grams[vuln_q_gram_count:]]
    print("Number of non-vulnerable q-grams: ", len(non_vuln_q_grams))

    return vuln_q_grams, non_vuln_q_grams


if __name__ == "__main__":
    """Main function to run the VAH algorithm
    
        Input:
            1. secret_seed: The secret seed
            2. sensitive_db_file: The file containing the sensitive database
            3. sensitive_db_id_col: The column number of the record identifier in the sensitive database
            4. sensitive_attribute_cols: The list of column numbers of the attributes in the sensitive database
            5. sensitive_db_has_header: A boolean indicating whether the sensitive database has a header or not
            6. pub_db_file: The file containing the public database
            7. pub_db_id_col: The column number of the record identifier in the public database
            8. pub_db_attribute_cols: The list of column numbers of the attributes in the public database
            9. pub_db_has_header: A boolean indicating whether the public database has a header or not
            10. n_v: The number of vulnerable q-grams to be hardened
            11. ref_set_length: The length of the reference set to be generated
    """

    q = 2
    secret_seed = int(sys.argv[1])

    sensitive_db_file = sys.argv[2]
    sensitive_db_id_col = int(sys.argv[3])
    sensitive_attribute_cols = [int(i) for i in sys.argv[4].split(",")]
    sensitive_db_has_header = eval(sys.argv[5])

    pub_db_file = sys.argv[6]
    pub_db_id_col = int(sys.argv[7])
    pub_db_attribute_cols = [int(i) for i in sys.argv[8].split(",")]
    pub_db_has_header = eval(sys.argv[9])

    n_v = int(10)
    ref_set_length = int(sys.argv[11])

    print("Generating q-gram sets for the sensitive database")
    data_dict, q_gram_dict = extract_q_gram_sets(sensitive_db_file, sensitive_db_id_col, sensitive_attribute_cols, q, sensitive_db_has_header)
    print("Original q-gram frequency distribution for the sensitive DB: ", q_gram_dict)


    print("Running VAH -----------------------")

    print("Generating q-gram sets for the public database")
    pub_data_dict, pub_q_gram_dict = extract_q_gram_sets(pub_db_file, pub_db_id_col, pub_db_attribute_cols, q,
                                                         pub_db_has_header)
    print("Q-gram frequency distribution for the public database: ", pub_q_gram_dict)

    print("Number of vulnerable q-grams to be hardened: %d" % n_v)
    hardened_q_grams, non_freq_q_grams = get_q_grams_to_be_hardened(pub_q_gram_dict, n_v)

    begin_hardening = time.time()

    # Initiate an instance of the hardening class
    rsh_instance = hd.VAH(secret_seed, set(hardened_q_grams), non_freq_q_grams, ref_set_length)

    print("Generating reference sets")
    rsh_instance.generate_reference_sets(pub_data_dict)

    print("Hardening the sensitive DB %s" % sensitive_db_file)
    hardened_data_dict = rsh_instance.harden_with_vah_ref_sets(copy.deepcopy(data_dict), q_gram_dict)
    print("Time taken to complete ref set generation process and hardening process: %f" % (
            (time.time() - begin_hardening) * 1000))

    print("Writing hardened data to CSV")
    hd_output_file_path = "hardened-data/" + sensitive_db_file.split("/")[-1]
    header = ['rec_id', 'og_q_gram_set', 'hd_q_gram_set']
    with open(hd_output_file_path, 'w', newline='') as out_f:
        csv_writer = csv.writer(out_f)
        csv_writer.writerow(header)

        for rec_id, og_qs in data_dict.items():
            csv_writer.writerow([rec_id, og_qs, hardened_data_dict[rec_id]])

