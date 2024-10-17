use alloy_sol_types::sol;

sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct PublicValuesStruct {
        bytes32 from_domain_hash;
        bytes32 public_key_hash;
        bool result;
        string receiver;
        string amount;
        string sender;
    }
}