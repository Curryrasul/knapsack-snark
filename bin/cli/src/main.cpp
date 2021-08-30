// By Magamedrasul Ibragimov

#include <iostream>
#include <gtest/gtest.h>

#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/algorithm/hex.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/bls12.hpp>

#include <nil/crypto3/zk/components/blueprint.hpp>

#include <nil/crypto3/algebra/pairing/bls12.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <nil/crypto3/zk/snark/algorithms/generate.hpp>
#include <nil/crypto3/zk/snark/algorithms/verify.hpp>
#include <nil/crypto3/zk/snark/algorithms/prove.hpp>

#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs.hpp>

#include <nil/crypto3/zk/components/hashes/knapsack/knapsack_component.hpp>
#include <nil/crypto3/zk/components/hashes/hmac_component.hpp>

#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/marshalling.hpp>

#define PREIMAGE_SIZE 256
#define HASHING_LIST_SIZE 4

using namespace nil::crypto3;
using namespace nil::crypto3::zk;
using namespace nil::marshalling;
using namespace components;

typedef algebra::curves::bls12<381> curve_type;
typedef typename curve_type::scalar_field_type field_type;
typedef zk::snark::r1cs_gg_ppzksnark<curve_type> scheme_type;

typedef verifier_input_serializer_tvm<scheme_type> serializer_tvm;
typedef verifier_input_deserializer_tvm<scheme_type> deserializer_tvm;

// Knapsack hash size
constexpr const std::size_t modulus_bits = field_type::modulus_bits;
constexpr const std::size_t modulus_chunks = modulus_bits / 8 + (modulus_bits % 8 ? 1 : 0);

// Convert field_type::value_type to hex string
std::string field_element_to_hex(field_type::value_type element);

// Convert hex string to field_type::value_type
field_type::value_type hex_to_field_element(const std::string& hex);

// Returns hex string = knapsack hash of bit_vector 
std::string knapsack_hash(const std::vector<bool>& bv);

// Converts uint256_t to bit vector
std::vector<bool> number_to_binary(const multiprecision::uint256_t& preimage);

// Deserializing vkey and pkey
std::vector<uint8_t> read_vector_from_disk(boost::filesystem::path file_path);

// Serializing vkey and pkey
void write_vector_to_disk(boost::filesystem::path file_path, const std::vector<uint8_t> &data);

// Generating primary_input file with 4 hashes
void write_primary_input(boost::filesystem::path file_path, const std::vector<std::string>& hashes);

// Reading primary input from file
std::vector<field_type::value_type> read_primary_input(boost::filesystem::path file_path);

scheme_type::proving_key_type get_pkey(boost::filesystem::path pkin);
scheme_type::verification_key_type get_vkey( boost::filesystem::path vkin);

int main(int argc, char *argv[]) {

    boost::program_options::options_description options(
        "Knapsack-hash preimage knowledge proof generator / verifier");
        options.add_options()
        ("hash", "Generate public input (hash) from your secret (preimage)")
        ("keys", "Generate proof key and verifier key")
        ("proof", "Generate proof")
        ("verify", "Verify proof")
        ("test", "Run tests");

    boost::program_options::variables_map vm;
    boost::program_options::store(boost::program_options::command_line_parser(argc, argv).options(options).run(), vm);
    boost::program_options::notify(vm);

    if (argc < 2) {
        std::cout << options << std::endl;
        return 0;
    }

    assert(argc == 2);

    if (vm.count("test")) {
        ::testing::InitGoogleTest();
        return RUN_ALL_TESTS();
    }

    // Primary input file generator (Knapsack hash)
    // Also generates 3 more random hashes, needed for demonstration of PoM
    if (vm.count("hash")) {
        multiprecision::uint256_t preimage;
        uint seed;

        std::cout << "Enter secret number: ";
        std::cin >> preimage;

        boost::random::mt19937 rng(std::time(0));
        boost::random::uniform_int_distribution<> my_rand(10000000, 99999999);

        multiprecision::uint256_t rand1 = my_rand(rng);
        multiprecision::uint256_t rand2 = my_rand(rng);
        multiprecision::uint256_t rand3 = my_rand(rng);

        std::string hash1 = knapsack_hash(number_to_binary(rand1));
        std::string hash2 = knapsack_hash(number_to_binary(rand2));
        std::string hash3 = knapsack_hash(number_to_binary(rand3));
        std::string secret_hash = knapsack_hash(number_to_binary(preimage)); 

        boost::filesystem::path hout = "./primary_input.json";

        write_primary_input(hout, {secret_hash, hash1, hash2, hash3});
        std::cout << "Hash of secret was written to \"./primary_input.json\" file" << std::endl;

        read_primary_input(hout);

        return 0;
    }

    // Create blueprint and constraints
    blueprint<field_type> bp;
    
    // Hash list - primary input
    blueprint_variable_vector<field_type> hash_list;
    hash_list.allocate(bp, HASHING_LIST_SIZE);

    // Bool mask, needed for building constraint that secret hash is in hash_list (private intermediate var)
    blueprint_variable_vector<field_type> bool_mask;
    bool_mask.allocate(bp, HASHING_LIST_SIZE);

    // Secret hash, for building constraint secret_hash = knapsack(preimage) (private intermediate var)
    blueprint_variable<field_type> secret_hash;
    secret_hash.allocate(bp);

    // Preimage (auxilary input)
    block_variable<field_type> secret(bp, PREIMAGE_SIZE);

    bp.set_input_sizes(4);

    // Generating constraints for bool mask
    for (auto field_var: bool_mask) {
        generate_boolean_r1cs_constraint<field_type>(bp, field_var);
    }

    // Constraints for checking that the secret_hash is in hash list
    bp.add_r1cs_constraint(r1cs_constraint<field_type>(1, blueprint_sum<field_type>(bool_mask), 1));

    for (int i = 0; i < HASHING_LIST_SIZE; i++) {
        bp.add_r1cs_constraint(r1cs_constraint<field_type>(bool_mask[i], hash_list[i] - secret_hash, 0));
    }

    // Knapsack component constraint
    knapsack_crh_with_field_out_component<field_type> 
                f(bp, PREIMAGE_SIZE, secret, blueprint_variable_vector<field_type>(1, secret_hash));
    f.generate_r1cs_constraints();

    // Keys generation
    if (vm.count("keys")) {
        boost::filesystem::path pkout = "./pk", vkout = "./vk";
        const snark::r1cs_constraint_system<field_type> constraint_system = bp.get_constraint_system();
        const typename scheme_type::keypair_type keypair = snark::generate<scheme_type>(constraint_system);

        std::cout << "Keys generated (pkey - \"./pkey\", vkey - \"./vkey\")" << std::endl;

        std::vector<std::uint8_t> verification_key_byteblob =
            serializer_tvm::process(keypair.second);
        write_vector_to_disk(vkout, verification_key_byteblob);
        
        std::vector<std::uint8_t> proving_key_byteblob =
            serializer_tvm::process(keypair.first);
        write_vector_to_disk(pkout, proving_key_byteblob);

        return 0;
    }

    // Proof generation
    if (vm.count("proof")) {
        multiprecision::uint256_t preimage;

        std::cout << "Enter secret (preimage of hash): ";
        std::cin >> preimage;
        
        std::vector<bool> preimage_bv = number_to_binary(preimage);
        field_type::value_type secret_hash_w = hex_to_field_element(knapsack_hash(preimage_bv));

        boost::filesystem::path path = "./primary_input.json";
        std::vector<field_type::value_type> hashes = read_primary_input(path);

        // Generating witness

        // Filling primary_input
        for (int i = 0; i < HASHING_LIST_SIZE; i++) {
            bp.val(hash_list[i]) = hashes[i];
        }
        
        // Filling auxilary input and intermediate variables
        secret.generate_r1cs_witness(preimage_bv);
        f.generate_r1cs_witness();
        bp.val(secret_hash) = secret_hash_w;

        for (int i = 0; i < HASHING_LIST_SIZE; i++) {
            if (hashes[i] == secret_hash_w) {
                bp.val(bool_mask[i]) = field_type::value_type::one();
                continue;
            }
            bp.val(bool_mask[i]) = field_type::value_type::zero();
        }

        assert(bp.is_satisfied());

        // Deserializing pkey
        boost::filesystem::path pkin = "./pk";
        scheme_type::proving_key_type pkey = get_pkey(pkin);

        std::cout << "Prooving key was read from \"./pkey\"" << std::endl;

        std::cout << "Start generating the proof" << std::endl;
        const typename scheme_type::proof_type proof = snark::prove<scheme_type>(pkey, bp.primary_input(), bp.auxiliary_input());

        // Serializing proof
        boost::filesystem::path proof_path = "./proof";
        std::vector<std::uint8_t> proof_byteblob =
            serializer_tvm::process(proof);

        boost::filesystem::ofstream poutf(proof_path);
        for (const auto &v : proof_byteblob) {
            poutf << v;
        } 
        poutf.close();

        std::cout << "Proof was written to \"./proof\" file" << std::endl;

        return 0;
    }

    // Verify proof
    if (vm.count("verify")) {
        boost::filesystem::path path = "./primary_input.json";
        std::vector<field_type::value_type> hashes = read_primary_input(path);
        std::cout << "Primary input was read from \"./primary_input.json\" file" << std::endl;

        // Filling primary_input
        for (int i = 0; i < HASHING_LIST_SIZE; i++) {
            bp.val(hash_list[i]) = hashes[i];
        }

        // Deserializing vkey
        boost::filesystem::path vkin = "./vk";
        scheme_type::verification_key_type vkey = get_vkey(vkin);
        std::cout << "Verification key was read from \"./vkey\" file" << std::endl;

        boost::filesystem::path proof_path = "./proof";
        std::vector<uint8_t> proof_v = read_vector_from_disk(proof_path);

        nil::marshalling::status_type proof_deserialize_status;
        scheme_type::proof_type proof = deserializer_tvm::proof_process(
            proof_v.begin(), proof_v.end(), proof_deserialize_status
        );

        if (proof_deserialize_status != nil::marshalling::status_type::success) {
            std::cerr << "Error: Could not deserialize verifying key" << std::endl;
            std::cerr << "Status is:" << static_cast<int>(proof_deserialize_status) << std::endl;
            exit(-1);
        }
        std::cout << "Proof was read from \"./proof\" file" << std::endl;

        bool verified = snark::verify<scheme_type>(vkey, bp.primary_input(), proof);
        std::cout << std::endl << "Verification status: " << verified << std::endl;

        return 0;
    }
    
    return 0;
}

// ----------------------------------------------------------------------------------
// ------------------------------MOVE TO UTILS.CPP-----------------------------------

std::string field_element_to_hex(field_type::value_type element) {
    std::string hex;
    std::vector<std::uint8_t> byteblob(modulus_chunks);
    std::vector<std::uint8_t>::iterator write_iter = byteblob.begin();
    serializer_tvm::field_type_process<field_type>(element, write_iter);
    boost::algorithm::hex(byteblob.begin(), byteblob.end(), std::back_inserter(hex));
    return hex;
}

field_type::value_type hex_to_field_element(const std::string& hex) {
    std::vector<uint8_t> hash_bytes(modulus_chunks);
    boost::algorithm::unhex(hex.begin(), hex.end(), hash_bytes.begin());

    status_type status;
    field_type::value_type result = 
        deserializer_tvm::field_type_process<field_type>(hash_bytes.begin(), hash_bytes.end(), status);

    return result;
}

std::string knapsack_hash(const std::vector<bool>& bv) {
    field_type::value_type h = knapsack_crh_with_field_out_component<field_type>::get_hash(bv)[0];

    return field_element_to_hex(h);
}

std::vector<bool> number_to_binary(const multiprecision::uint256_t& preimage) {
    std::vector<bool> result_i;
    std::vector<bool> result(PREIMAGE_SIZE);

    multiprecision::export_bits(preimage, std::back_inserter(result_i), 1);
    std::swap_ranges(result.begin() + result.size() - result_i.size(), result.end(), result_i.begin());

    return result;
}

std::vector<uint8_t> read_vector_from_disk(boost::filesystem::path file_path) {
    boost::filesystem::ifstream instream(file_path, std::ios::in | std::ios::binary);
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(instream)), std::istreambuf_iterator<char>());
    instream.close();
    return data;
}

void write_vector_to_disk(boost::filesystem::path file_path, const std::vector<uint8_t> &data) {
    boost::filesystem::ofstream ostream(file_path, std::ios::out | std::ios::binary);
    for(auto byte : data) {
        ostream << byte;
    }
    ostream.close();
}

void write_primary_input(boost::filesystem::path file_path, const std::vector<std::string>& hashes) {
    boost::property_tree::ptree root;
    root.put("hash1", hashes[0]);
    root.put("hash2", hashes[1]);
    root.put("hash3", hashes[2]);
    root.put("hash4", hashes[3]);

    boost::filesystem::ofstream ostream(file_path);
    boost::property_tree::write_json(ostream, root);
    ostream.close();
}

std::vector<field_type::value_type> read_primary_input(boost::filesystem::path file_path) {
    boost::filesystem::ifstream instream(file_path);

    boost::property_tree::ptree root;
    boost::property_tree::read_json(instream, root);
    instream.close();

    std::vector<std::string> stringHashes;

    for (auto node: root) {
        stringHashes.push_back(node.second.data());
    }

    std::vector<field_type::value_type> result(stringHashes.size());
    for (int i = 0; i < result.size(); i++) {
        result[i] = hex_to_field_element(stringHashes[i]);
    }
    
    return result;
}

scheme_type::proving_key_type get_pkey(boost::filesystem::path pkin) {
    std::vector<uint8_t> proving_key_byteblob = read_vector_from_disk(pkin);

    nil::marshalling::status_type pk_deserialize_status;
    scheme_type::proving_key_type proving_key =
            deserializer_tvm::proving_key_process(proving_key_byteblob.begin(),
                                                proving_key_byteblob.end(),
                                                pk_deserialize_status);

    if (pk_deserialize_status != nil::marshalling::status_type::success) {
        std::cerr << "Error: Could not deserialize proving key" << std::endl;
        std::cerr << "Status is:" << static_cast<int>(pk_deserialize_status) << std::endl;
        exit(-1);
    }

    return proving_key;
}

scheme_type::verification_key_type get_vkey(boost::filesystem::path vkin) {
    std::vector<uint8_t> verification_key_byteblob = read_vector_from_disk(vkin);

    nil::marshalling::status_type vk_deserialize_status;
    scheme_type::verification_key_type verification_key =
            deserializer_tvm::verification_key_process(verification_key_byteblob.begin(),
                                                verification_key_byteblob.end(),
                                                vk_deserialize_status);

    if (vk_deserialize_status != nil::marshalling::status_type::success) {
        std::cerr << "Error: Could not deserialize verifying key" << std::endl;
        std::cerr << "Status is:" << static_cast<int>(vk_deserialize_status) << std::endl;
        exit(-1);
    }

    return verification_key;
}

// ----------------------------------------------------------------------------------
// -----------------------------UTILS-TESTS------------------------------------------

TEST(serializing_deserializing, number_to_bit_vector) {
    multiprecision::uint256_t number = 1000;
    std::vector<bool> v = 
       {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0};

    EXPECT_TRUE(v.size() == 256);
    EXPECT_TRUE(v == number_to_binary(number));
}

TEST(serializing_deserializing, hash_correctness) {
    EXPECT_TRUE(knapsack_hash(number_to_binary(1000)) == "F4C3926909F99D774211E633EC76CBA1EF65C0B4D7A4D68083EBDCAE5343E918");
}

TEST(serializing_deserializing, string_fieldVariable) {
    std::string hash_hex = knapsack_hash(number_to_binary(1000));
    field_type::value_type hash_field = hex_to_field_element(hash_hex);
    EXPECT_TRUE(field_element_to_hex(hash_field) == hash_hex);
}
