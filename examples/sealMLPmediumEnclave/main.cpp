#include <iostream>
#include <vector>
#include <iomanip>
#include <seal/seal.h>

using namespace std;
using namespace seal;

void print_matrix(const vector<vector<double>>& matrix, const string& label) {
    cout << label << ":" << endl;
    for (const auto& row : matrix) {
        cout << "[";
        for (size_t i = 0; i < row.size(); i++) {
            cout << fixed << setprecision(6) << row[i] << (i < row.size() - 1 ? ", " : "");
        }
        cout << "]" << endl;
    }
}

bool are_compatible(const vector<vector<double>>& A, const vector<vector<double>>& B) {
    return !A.empty() && !B.empty() && A[0].size() == B.size();
}

vector<vector<double>> prepare_matrix_diagonals(const vector<vector<double>>& M, size_t slot_count) {
    size_t rows = M.size();
    size_t cols = M[0].size();
    vector<vector<double>> diagonals(rows, vector<double>(slot_count, 0.0));
    for (size_t i = 0; i < rows; i++) {
        for (size_t j = 0; j < slot_count; j++) {
            diagonals[i][j] = M[(j + i) % rows][j % cols];
        }
    }
    return diagonals;
}

Ciphertext prepare_vector(const vector<double>& v, const CKKSEncoder& encoder, const Encryptor& encryptor, double scale) {
    size_t slot_count = encoder.slot_count();
    vector<double> padded_v(slot_count, 0.0);
    for (size_t i = 0; i < slot_count; i++) {
        padded_v[i] = v[i % v.size()];
    }
    Plaintext plain_v;
    encoder.encode(padded_v, scale, plain_v);
    Ciphertext encrypted_v;
    encryptor.encrypt(plain_v, encrypted_v);
    return encrypted_v;
}

vector<Ciphertext> fhe_matrix_matrix_multiplication(
    const vector<vector<double>>& A,
    const vector<vector<double>>& B,
    const CKKSEncoder& encoder,
    const Encryptor& encryptor,
    const Evaluator& evaluator,
    const GaloisKeys& galois_keys,
    const RelinKeys& relin_keys,
    double scale) {
    
    vector<Ciphertext> result;
    vector<vector<double>> B_diagonals = prepare_matrix_diagonals(B, encoder.slot_count());

    size_t A_rows = A.size();
    size_t B_rows = B.size();
    size_t B_cols = B[0].size();

    for (size_t row_index = 0; row_index < A_rows; row_index++) {
        Ciphertext encrypted_row = prepare_vector(A[row_index], encoder, encryptor, scale);
        Ciphertext row_result;

        for (size_t i = 0; i < B_rows; i++) {
            Plaintext plain_diag;
            encoder.encode(B_diagonals[i], scale, plain_diag);
            Ciphertext encrypted_diag;
            encryptor.encrypt(plain_diag, encrypted_diag);

            Ciphertext temp;
            evaluator.multiply(encrypted_row, encrypted_diag, temp);
            evaluator.relinearize_inplace(temp, relin_keys);
            evaluator.rescale_to_next_inplace(temp);

            if (i == 0) {
                row_result = temp;
            } else {
                evaluator.add_inplace(row_result, temp);
            }

            if (i < B_rows - 1) {
                evaluator.rotate_vector_inplace(encrypted_row, 1, galois_keys);
            }
        }

        result.push_back(row_result);
    }

    return result;
}

Ciphertext add_bias(
    const Ciphertext& matrix_result,
    const vector<double>& bias,
    const SEALContext& context,
    const CKKSEncoder& encoder,
    const Encryptor& encryptor,
    const Evaluator& evaluator,
    const RelinKeys& relin_keys,
    double scale) {
    
    Ciphertext encrypted_bias = prepare_vector(bias, encoder, encryptor, scale);

    Ciphertext mod_bias = encrypted_bias;
    evaluator.mod_switch_to_inplace(mod_bias, matrix_result.parms_id());
    mod_bias.scale() = matrix_result.scale();

    Ciphertext result;
    evaluator.add(matrix_result, mod_bias, result);

    return result;
}

int main() {
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
    double scale = pow(2.0, 40);
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
    CKKSEncoder encoder(context);

    vector<vector<double>> input = {{1.0, 2.0, 3.0, 4.0, 5.0}}; // 1x5 input vector
    vector<vector<double>> weights = {
        {0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8},
        {0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0, 1.1},
        {0.7, 0.8, 0.9, 1.0, 1.1, 1.2, 1.3, 1.4},
	    {1.0, 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7},
	    {1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 2.0},
    }; // 5x8 weight matrix
    vector<double> bias = {0.01, 0.02, 0.03, 0.04, 0.05, 0.06, 0.07, 0.08}; // 1x8 bias vector

    // Perform matrix multiplication (input * weights)
    vector<Ciphertext> matrix_result = fhe_matrix_matrix_multiplication(input, weights, encoder, encryptor, evaluator, galois_keys, relin_keys, scale);

    // Add bias to the result (now we're sure matrix_result has only one element)
    Ciphertext feedforward_result = add_bias(matrix_result[0], bias, context, encoder, encryptor, evaluator, relin_keys, scale);

    // Decrypt and print the final result
    Plaintext plain_result;
    decryptor.decrypt(feedforward_result, plain_result);
    vector<double> dec_result;
    encoder.decode(plain_result, dec_result);

    // Trim the result to the correct size
    vector<double> final_result(dec_result.begin(), dec_result.begin() + weights[0].size());

    for (size_t i = 0; i < final_result.size(); i++) {
        cout << fixed << setprecision(6) << final_result[i] << (i < final_result.size() - 1 ? ", " : "");
    }
    cout << "]" << endl;

    return 0;
}