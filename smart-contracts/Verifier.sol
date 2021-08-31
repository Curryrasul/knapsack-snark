pragma ton-solidity >=0.30.0;

contract PrimaryInputVerificationExample {
    bytes constant vkey = hex"4399cf35940d0604a273e29525f7605687d98bfe662218c6562bb1c3bdc3bd4bf0aca8554005d192a4f65f18d437920fd8323c53c1ba15342ad547424c6087b6120c2d915625502192981ca3e127a81c3955efcfae20ad8d1637f347e1baa90205e84ae286d60e327520ea408282b88eadbf209ea56904f29333d0b2f9e0a61b7f563ef9eac4b7bfade7317c35237506c136283e0a1fdac1e63c8b536852073d31243ac7e1625c7c965a9fbeeaded7284f4557a6a1d55c479c8645837b9a2e08afcde1d3964a419040c02542a496daecf8182dd908aee7ceead0319536c7b0d2afd1f5a241575b2346fe966afa080602c68b35d3d4dbdea93eb369f8a061462f3c01fa87d12f25353a81b81869df446bb571d3d7621a62fa0989ecb18358d112a7ccad67a383c2c4bc6a024038601a96d247cef1eef962046c22c3742cc107fe26be70141959f8db0bfe75fe8c3d710fc08afdeecf67694c881265e005d76e72b6afe141e23f5c91def5210690e029f826aad88ff370f38871adcd005a20190e8834f18f85fc35cbf3057d08d36167ccfff5fbcdd036156d2440e69b289715f44a9e988d35f94793ce4056ec62fabb117940843ea7cd2670f07a8e1e66cfd301118bafdd8651caf57397dcb8b4e9339dc9b867ab7493c4c8ecfea7e2f8a7310c02954c2fc2d55a1d6ebfd84993c21d7279aac877fd1cae59a6ef3aaa88e63cbbdfc923de362ecde0c594f4387210700a0485ce9a0b6c725d104b0441677c75f13772d1f62a47e22db9c1409e3d73572cd1b6dc094265cae740947c454a683f02aefdb6f99e2540e8984a3786f6632267493ed8f02bf636f2358cde2f4ba6c1b4c1f576428499162b04a6ed731bdb21ab15d0536c26594a40e9a4f78d3a5e99d498d7ef571072b14494631470951fd8ec07f6c214ee9b426bb1fbc36ad25d1c128cea8d23b024a7c6914ebd44c30cadcddaa36839cdc57688e0bf203f9b2a972cddbd95e4f162392a843971c6297586b613c6411266b3b3a5131649f1080b552877d027aad083bf81ce2351679c4c5d9c5675c9cf91f22733edc982a807f9024da7d606e52594f0fca4ecaa7664edfd2a18f2b9c07acfe8d35100a6184c582d8bc217f81b3ce1a9a077585b1df1d3e1710400000000000000010000000200000003000000a23b3ef98c479982e36f58a258e4f86ef8ab33e1aaa38ebf20dad5aebf5bcd94160bdfc11a04c0a1b5c8a4a4f597482a84c297dc11090c51708dc05456077616e5cd44a5c5f8d2cfeefcd56ea6ae0ae810f0418dd8797d80416774459aad951f90864733b2cb25286eebe1c6a44b4134ffac0632be4764b5fe94278973df898b5526eb844aa48b569b9332ff2a4e5efcb12111c4165b4b87b11f0c289a0222f533313f4875670d7f1e8ce47223603e0b6443d7efc49c168125c794c1237639810400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"; //change that
    uint8 constant PROOF_SIZE = 192;
    uint32 constant HASHING_LIST_SIZE = 4; //change that
    uint8 constant field_element_bytes = 32;

    uint[] hash_list = new uint[](HASHING_LIST_SIZE);

    constructor(uint256[] l) public {
        for (uint i = 0; i < HASHING_LIST_SIZE; i++) {
            hash_list[i] = l[i];
        }
    }

    // You should change/add/remove arguments according to your circuit.
    function verify(bytes proof) public returns (bool) {
        require(proof.length == PROOF_SIZE);
        tvm.accept();

        string blob_str = proof;
        blob_str.append(encode_little_endian(HASHING_LIST_SIZE,4));

        for (uint i = 0; i < HASHING_LIST_SIZE; i++) {
            blob_str.append(uint256_to_bytes(hash_list[i]));
        }

        blob_str.append(vkey);

        return tvm.vergrth16(blob_str);
    }

    function encode_little_endian(uint256 number, uint32 bytes_size) internal pure returns (bytes) {
        TvmBuilder ref_builder;
        for(uint32 i=0; i<bytes_size; ++i) {
            ref_builder.store(byte(uint8(number & 0xFF)));
            number>>=8;
        }
        TvmBuilder builder;
        builder.storeRef(ref_builder.toCell());
        return builder.toSlice().decode(bytes);
    }

    function uint256_to_bytes(uint256 number) internal pure returns (bytes) {
        TvmBuilder ref_builder;
        ref_builder.store(bytes32(number));
        TvmBuilder builder;
        builder.storeRef(ref_builder.toCell());
        return builder.toSlice().decode(bytes);
    }
}
