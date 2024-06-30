#include <iostream>
#include <vector>
#include "seal/seal.h"

using namespace std;
using namespace seal;

void print_matrix(const vector<vector<int>>& matrix) {
    for (const auto& row : matrix) {
        for (int val : row) {
            cout << val << " ";
        }
        cout << endl;
    }
}

int main() {
    //Set up encryption parameters
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 4096;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

    //create SEALContext
    SEALContext context(parms);

    //Generate keys
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    //Set up encryptor, evaluator, and decryptor
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    //Define matrices
    vector<vector<int>> matrix1 = {{1, 2, 3, 4}, 
                                    {5, 6, 7, 8},
                                    {9, 10, 11, 12}};
    vector<vector<int>> matrix2 = {{1, 2},
                                    {3, 4},
                                    {5, 6},
                                    {7, 8}};

    //Encrypt matrices
    vector<vector<Ciphertext>> encrypted_matrix1, encrypted_matrix2;
    for (const auto& row : matrix1) {
        vector<Ciphertext> encrypted_row;
        for (int val : row) {
            Plaintext plain(to_string(val));
            Ciphertext encrypted;
            encryptor.encrypt(plain, encrypted);
            encrypted_row.push_back(encrypted);
        }
        encrypted_matrix1.push_back(encrypted_row);
    }
    for (const auto& row : matrix2) {
        vector<Ciphertext> encrypted_row;
        for (int val : row) {
            Plaintext plain(to_string(val));
            Ciphertext encrypted;
            encryptor.encrypt(plain, encrypted);
            encrypted_row.push_back(encrypted);
        }
        encrypted_matrix2.push_back(encrypted_row);
    }

    //matrix multiplication
    vector<vector<Ciphertext>> result_matrix;
    for (size_t i = 0; i < encrypted_matrix1.size(); i++) {
        vector<Ciphertext> result_row;
        for (size_t j = 0; j < encrypted_matrix2[0].size(); j++) {
            Ciphertext sum;
            encryptor.encrypt(Plaintext("0"), sum);
            for (size_t k = 0; k < encrypted_matrix2.size(); k++) {
                Ciphertext product;
                evaluator.multiply(encrypted_matrix1[i][k], encrypted_matrix2[k][j], product);
                evaluator.relinearize_inplace(product, relin_keys);
                evaluator.add_inplace(sum, product);
            }
            result_row.push_back(sum);
        }
        result_matrix.push_back(result_row);
    }

    // Decrypt and print result
    cout << "Result of matrix multiplication:" << endl;
    for (const auto& row : result_matrix) {
        for (const auto& encrypted : row) {
            Plaintext decrypted;
            decryptor.decrypt(encrypted, decrypted);
            string hex_str = decrypted.to_string();
            int decimal_value;
            stringstream ss;
            ss << hex << hex_str;
            ss >> decimal_value;
            cout << decimal_value << " ";
        }
        cout << endl;
    }

    return 0;
}