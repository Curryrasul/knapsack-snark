// By Magamedrasul Ibragimov

#include <iostream>

#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

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

#define KNAPSACK_HASH_SIZE 255
#define PREIMAGE_SIZE 256

using namespace nil::crypto3;
using namespace nil::crypto3::zk;
using namespace nil::marshalling;
using namespace components;

typedef algebra::curves::bls12<381> curve_type;
typedef typename curve_type::scalar_field_type field_type;
typedef zk::snark::r1cs_gg_ppzksnark<curve_type> scheme_type;

typedef verifier_input_serializer_tvm<scheme_type> serializer_tvm;
typedef verifier_input_deserializer_tvm<scheme_type> deserializer_tvm;

std::vector<bool> knapsack_hash(const std::vector<bool>& bv);
std::vector<bool> string_to_binary(const std::string& s);
std::vector<bool> number_to_binary(const multiprecision::uint256_t& preimage);
std::vector<uint8_t> read_vector_from_disk(boost::filesystem::path file_path);
void write_vector_to_disk(boost::filesystem::path file_path, const std::vector<uint8_t> &data);
void write_primary_input(boost::filesystem::path file_path, const std::vector<bool> &data);
std::vector<bool> read_primary_input(boost::filesystem::path file_path);
scheme_type::proving_key_type get_pkey(boost::filesystem::path pkin);
scheme_type::verification_key_type get_vkey( boost::filesystem::path vkin);

int main(int argc, char *argv[]) {

    boost::program_options::options_description options(
        "Knapsack-hash preimage knowledge proof generator / verifier");
        options.add_options()
        ("hash", "Generate public input (hash) from your secret (preimage)")
        ("keys", "Generate proof key and verifier key")
        ("proof", "Generate proof")
        ("verify", "Verify proof");

    boost::program_options::variables_map vm;
    boost::program_options::store(boost::program_options::command_line_parser(argc, argv).options(options).run(), vm);
    boost::program_options::notify(vm);

    if (argc < 2) {
        std::cout << options << std::endl;
        return 0;
    }

    assert(argc == 2);

    // Primary input file generator (Knapsack hash)
    if (vm.count("hash")) {
        multiprecision::uint256_t preimage;

        std::cout << "Enter secret number: ";
        std::cin >> preimage;

        std::vector<bool> preimage_bv = number_to_binary(preimage);
        std::vector<bool> h_bv = knapsack_hash(preimage_bv); 

        boost::filesystem::path hout = "./primary_input.json";

        write_primary_input(hout, h_bv);
        std::cout << "Hash of secret was written to \"./primary_input.json\" file" << std::endl;

        return 0;
    }

    // Create blueprint and constraints
    blueprint<field_type> bp;
    
    digest_variable<field_type> out(bp, KNAPSACK_HASH_SIZE);
    block_variable<field_type> x(bp, PREIMAGE_SIZE);

    bp.set_input_sizes(255);

    knapsack_crh_with_bit_out_component<field_type> f(bp, PREIMAGE_SIZE, x, out);

    f.generate_r1cs_constraints();

    // Generate keys
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

    // Proof generator
    if (vm.count("proof")) {
        multiprecision::uint256_t preimage;

        std::cout << "Enter secret (preimage of hash): ";
        std::cin >> preimage;
        
        std::vector<bool> preimage_bv = number_to_binary(preimage);

        boost::filesystem::path hash = "./primary_input.json";
        std::vector<bool> hash_bv = read_primary_input(hash);

        // Generating witness
        x.generate_r1cs_witness(preimage_bv);
        f.generate_r1cs_witness();
        out.generate_r1cs_witness(hash_bv);

        assert(bp.is_satisfied());
        std::cout << "Witness was generated" << std::endl;

        boost::filesystem::path pkin = "./pk";
        scheme_type::proving_key_type pkey = get_pkey(pkin);

        std::cout << "Prooving key was read from \"./pkey\"" << std::endl;

        std::cout << "Start generating the proof" << std::endl;
        const typename scheme_type::proof_type proof = snark::prove<scheme_type>(pkey, bp.primary_input(), bp.auxiliary_input());

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
        boost::filesystem::path hash = "./primary_input.json";
        std::vector<bool> hash_bv = read_primary_input(hash);
        std::cout << "Primary input was read from \"./primary_input.json\" file" << std::endl;

        // Filling primary_input (bp.primary_input())
        out.generate_r1cs_witness(hash_bv);
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

std::vector<bool> knapsack_hash(const std::vector<bool>& bv) {
    return components::knapsack_crh_with_bit_out_component<field_type>::get_hash(bv);
}

std::vector<bool> string_to_binary(const std::string& s) {
    assert(s.size() == KNAPSACK_HASH_SIZE);

    std::vector<bool> result(KNAPSACK_HASH_SIZE);

    for (int i = 0; i < KNAPSACK_HASH_SIZE; i++) {
        assert(s[i] == '0' || s[i] == '1');

        if (s[i] == '0') {
            result[i] = false;
        } else {
            result[i] = true;
        }
    }

    return result;
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

void write_primary_input(boost::filesystem::path file_path, const std::vector<bool> &data) {
    std::stringstream ss;
    for (int bit: data) {
        ss << bit;
    }

    boost::property_tree::ptree root;
    root.put("hash", ss.str());

    boost::filesystem::ofstream ostream(file_path);
    boost::property_tree::write_json(ostream, root);
    ostream.close();
}

std::vector<bool> read_primary_input(boost::filesystem::path file_path) {
    boost::filesystem::ifstream instream(file_path);

    boost::property_tree::ptree root;
    boost::property_tree::read_json(instream, root);
    instream.close();

    std::string bin_hash(root.get<std::string>("hash"));

    std::vector<bool> result = string_to_binary(bin_hash);
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

scheme_type::verification_key_type get_vkey( boost::filesystem::path vkin) {
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
