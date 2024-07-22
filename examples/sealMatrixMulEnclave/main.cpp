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

// Set the diagonals of the matrix 
vector<vector<uint64_t>> prepare_matrix_diagonals(const vector<vector<uint64_t>>& M, size_t slot_count) {
    size_t rows = M.size();
    size_t cols = M[0].size();
    vector<vector<uint64_t>> diagonals(rows, vector<uint64_t>(slot_count, 0ULL));
    for (size_t i = 0; i < rows; ++i) {
        for (size_t j = 0; j < slot_count; ++j) {
            diagonals[i][j] = M[(j + i) % rows][j % cols];
        }
    }
    return diagonals;
}

// Pad and encrypt a vector row-wise
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

vector<Ciphertext> fhe_matrix_matrix_multiplication(
    const vector<vector<uint64_t>>& A,
    const vector<vector<uint64_t>>& B,
    const BatchEncoder& batch_encoder,
    const Encryptor& encryptor,
    const Evaluator& evaluator,
    const GaloisKeys& galois_keys) {
    
    vector<Ciphertext> result;
    vector<vector<uint64_t>> B_diagonals = prepare_matrix_diagonals(B, batch_encoder.slot_count());

    size_t A_rows = A.size();
    size_t B_rows = B.size();
    size_t B_cols = B[0].size();

    for (size_t row_index = 0; row_index < A_rows; row_index++) {
        Ciphertext encrypted_row = prepare_vector(A[row_index], batch_encoder, encryptor);
        Ciphertext row_result;

        // Vector-matrix multiplication logic
        for (size_t i = 0; i < B_rows; ++i) {
            //encrypt the diagonal
            Plaintext plain_diag;
            batch_encoder.encode(B_diagonals[i], plain_diag);
            Ciphertext encrypted_diag;
            encryptor.encrypt(plain_diag, encrypted_diag);

            // Multiply the encrypted vector with the encrypted diagonal
            Ciphertext temp;
            evaluator.multiply(encrypted_row, encrypted_diag, temp);

            // Add the result of the multiplication to the accumulator
            if (i == 0) {
                row_result = temp;
            } else {
                evaluator.add_inplace(row_result, temp);
            }

            // Rotate the encrypted vector
            if (i < B_rows - 1) {
                evaluator.rotate_rows_inplace(encrypted_row, 1, galois_keys);
            }
        }

        result.push_back(row_result);
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
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);

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

    cout << "\nPerforming encrypted matrix-matrix multiplication..." << endl;

    vector<Ciphertext> encrypted_result = fhe_matrix_matrix_multiplication(A, B, batch_encoder, encryptor, evaluator, galois_keys);
    
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

    cout << "\nFinal result of A * B:" << endl;
    print_matrix(final_result, "Result");

    return 0;
}



