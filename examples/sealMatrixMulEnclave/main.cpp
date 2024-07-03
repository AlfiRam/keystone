#include <iostream>
#include <vector>
#include <seal/seal.h>

using namespace std;
using namespace seal;

// Function to encrypt a matrix
vector<vector<Ciphertext>> encryptMatrix(const vector<vector<int>>& matrix, Encryptor& encryptor, BatchEncoder& batch_encoder) {
    vector<vector<Ciphertext>> encrypted_matrix;
    for (const auto& row : matrix) {
        vector<Ciphertext> encrypted_row;
        for (int val : row) {
            vector<uint64_t> pod_matrix(batch_encoder.slot_count(), val);
            Plaintext plain_matrix;
            batch_encoder.encode(pod_matrix, plain_matrix);
            Ciphertext encrypted;
            encryptor.encrypt(plain_matrix, encrypted);
            encrypted_row.push_back(encrypted);
        }
        encrypted_matrix.push_back(encrypted_row);
    }
    return encrypted_matrix;
}

// Function to decrypt a matrix
vector<vector<int>> decryptMatrix(const vector<vector<Ciphertext>>& encrypted_matrix, Decryptor& decryptor, BatchEncoder& batch_encoder) {
    vector<vector<int>> decrypted_matrix;
    for (const auto& row : encrypted_matrix) {
        vector<int> decrypted_row;
        for (const auto& encrypted : row) {
            Plaintext plain_result;
            decryptor.decrypt(encrypted, plain_result);
            vector<uint64_t> pod_result;
            batch_encoder.decode(plain_result, pod_result);
            decrypted_row.push_back(static_cast<int>(pod_result[0]));
        }
        decrypted_matrix.push_back(decrypted_row);
    }
    return decrypted_matrix;
}

// Function to multiply encrypted matrices
vector<vector<Ciphertext>> multiplyEncryptedMatrices(const vector<vector<Ciphertext>>& matrix1, 
                                                     const vector<vector<Ciphertext>>& matrix2, 
                                                     Evaluator& evaluator) {
    size_t rows1 = matrix1.size();
    size_t cols1 = matrix1[0].size();
    size_t cols2 = matrix2[0].size();

    vector<vector<Ciphertext>> result(rows1, vector<Ciphertext>(cols2));

    for (size_t i = 0; i < rows1; ++i) {
        for (size_t j = 0; j < cols2; ++j) {
            Ciphertext sum;
            evaluator.multiply(matrix1[i][0], matrix2[0][j], sum);
            for (size_t k = 1; k < cols1; ++k) {
                Ciphertext product;
                evaluator.multiply(matrix1[i][k], matrix2[k][j], product);
                evaluator.add_inplace(sum, product);
            }
            result[i][j] = sum;
        }
    }

    return result;
}

// Function to print a matrix
void printMatrix(const vector<vector<int>>& matrix) {
    for (const auto& row : matrix) {
        for (int val : row) {
            cout << val << " ";
        }
        cout << endl;
    }
}

int main() {
    // Set up encryption parameters
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 4096;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

    SEALContext context(parms);

    // Generate keys
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);

    // Set up encryption tools
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    BatchEncoder batch_encoder(context);

    // Define input matrices
    vector<vector<int>> matrix1 = {{1, 2, 3, 4}, 
                                   {5, 6, 7, 8},
                                   {9, 10, 11, 12}};

    vector<vector<int>> matrix2 = {{1, 2},
                                   {3, 4},
                                   {5, 6},
                                   {7, 8}};

    cout << "Matrix 1:" << endl;
    printMatrix(matrix1);

    cout << "\nMatrix 2:" << endl;
    printMatrix(matrix2);

    // Encrypt matrices
    auto encrypted_matrix1 = encryptMatrix(matrix1, encryptor, batch_encoder);
    auto encrypted_matrix2 = encryptMatrix(matrix2, encryptor, batch_encoder);

    // Perform encrypted matrix multiplication
    auto encrypted_result = multiplyEncryptedMatrices(encrypted_matrix1, encrypted_matrix2, evaluator);

    // Decrypt result
    auto decrypted_result = decryptMatrix(encrypted_result, decryptor, batch_encoder);

    cout << "\nDecrypted Result of matrix multiplication with FHE:" << endl;
    printMatrix(decrypted_result);

    return 0;
}