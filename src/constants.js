class Constants {

    // length of truncated hashes
    static TRUNCATED_HASHLENGTH_IN_BITS = 128;
    static TRUNCATED_HASHLENGTH_IN_BYTES = this.TRUNCATED_HASHLENGTH_IN_BITS / 8;

    // length of identity name hashes
    static IDENTITY_NAME_HASH_LENGTH_IN_BITS = 80;
    static IDENTITY_NAME_HASH_LENGTH_IN_BYTES = this.IDENTITY_NAME_HASH_LENGTH_IN_BITS / 8;

}

module.exports = Constants;
