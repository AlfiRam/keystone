#include <seal/seal.h>
#include <iostream>
using namespace std;
using namespace seal;

int main() {
    // Set encryption parameters
    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(4096);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(4096));
    parms.set_plain_modulus(1024);

    // Create SEALContext
    SEALContext context(parms);

    // Generate keys
    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    SecretKey secret_key = keygen.secret_key();

    // Create encryptor, evaluator, and decryptor
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    // Values to be encrypted
    int value1 = 7;
    int value2 = 10;

    // Create plaintexts
    Plaintext plaintext1(to_string(value1));
    Plaintext plaintext2(to_string(value2));

    // Encrypt plaintexts
    Ciphertext ciphertext1, ciphertext2;
    encryptor.encrypt(plaintext1, ciphertext1);
    encryptor.encrypt(plaintext2, ciphertext2);

    // Perform addition on ciphertexts
    Ciphertext addition_result;
    evaluator.add(ciphertext1, ciphertext2, addition_result);

    // Decrypt the addition result
    Plaintext decrypted_addition_result;
    decryptor.decrypt(addition_result, decrypted_addition_result);
    cout << "Addition result: " << decrypted_addition_result.to_string() << endl;

    // Perform multiplication on ciphertexts
    Ciphertext multiplication_result;
    evaluator.multiply(ciphertext1, ciphertext2, multiplication_result);

    // Decrypt the multiplication result
    Plaintext decrypted_multiplication_result;
    decryptor.decrypt(multiplication_result, decrypted_multiplication_result);
    cout << "Multiplication result: " << decrypted_multiplication_result.to_string() << endl;

    return 0;
}