#include <iostream>
#include <vector>
#include <seal/seal.h>
#include <iomanip>

using namespace std;
using namespace seal;

void print_matrix(const vector<vector<uint64_t>>& matrix, const string& label) {
    cout << label << ":" << endl;
    for (const auto& row : matrix) {
        cout << "[";
        for (size_t i = 0; i < row.size(); ++i) {
            cout << row[i] << (i < row.size() - 1 ? ", " : "");
        }
        cout << "]" << endl;
    }
}

// Pad and encrypt a vector (now a row of the input matrix)
Ciphertext prepare_vector(const vector<uint64_t>& v, const BatchEncoder& batch_encoder, const Encryptor& encryptor) {
    size_t slot_count = batch_encoder.slot_count();
    vector<uint64_t> padded_v(slot_count, 0ULL);
    for (size_t i = 0; i < slot_count; ++i) {
        padded_v[i] = v[i % v.size()];
    }
    Plaintext plain_v;
    batch_encoder.encode(padded_v, plain_v);
    Ciphertext encrypted_v;
    encryptor.encrypt(plain_v, encrypted_v);
    return encrypted_v;
}

// Function to perform FHE matrix pointwise multiplication
vector<Ciphertext> fhe_matrix_pointwise_multiplication(
    const vector<vector<uint64_t>>& A,
    const vector<vector<uint64_t>>& B,
    const BatchEncoder& batch_encoder,
    const Encryptor& encryptor,
    const Evaluator& evaluator) {
    
    size_t rows = A.size();
    size_t cols = A[0].size();
    vector<Ciphertext> result;

    for (size_t i = 0; i < rows; i++) {
        Ciphertext encrypted_row_A = prepare_vector(A[i], batch_encoder, encryptor);
        Ciphertext encrypted_row_B = prepare_vector(B[i], batch_encoder, encryptor);
        
        Ciphertext product;
        evaluator.multiply(encrypted_row_A, encrypted_row_B, product);
        result.push_back(product);
    }

    return result;
}

int main() {
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));
    SEALContext context(parms);

    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    BatchEncoder batch_encoder(context);

    // Example matrices
    vector<vector<uint64_t>> A = {
        {1, 2, 3, 4},
        {5, 6, 7, 8},
        {9, 10, 11, 12},
        {13, 14, 15, 16}
    };

    vector<vector<uint64_t>> B = {
        {1, 2, 3, 4},
        {5, 6, 7, 8},
        {9, 10, 11, 12},
        {13, 14, 15, 16}
    };

    cout << "Input matrix A:" << endl;
    print_matrix(A, "A");
    cout << "Input matrix B:" << endl;
    print_matrix(B, "B");

    // In the main function, replace the multiplication part with:
    cout << "\nPerforming encrypted matrix-matrix pointwise multiplication..." << endl;

    vector<Ciphertext> encrypted_result = fhe_matrix_pointwise_multiplication(A, B, batch_encoder, encryptor, evaluator);

    cout << "\nEncrypted computation complete." << endl;

    // Decrypt and print the result
    vector<vector<uint64_t>> final_result;
    for (const auto& enc_row : encrypted_result) {
        Plaintext plain_row;
        decryptor.decrypt(enc_row, plain_row);
        vector<uint64_t> dec_row;
        batch_encoder.decode(plain_row, dec_row);
        final_result.push_back(vector<uint64_t>(dec_row.begin(), dec_row.begin() + B[0].size()));
    }

    cout << "\nFinal result of A .* B (pointwise multiplication):" << endl;
    print_matrix(final_result, "Result");
}