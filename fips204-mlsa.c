#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// FIPS 204 parameters for security level 2
// Other levels (3,5) would use different parameters
#define K 4  // Number of polynomial vectors
#define L 3  // Number of polynomial vectors
#define D 13  // Number of dropped bits
#define N 256  // Ring dimension, must be a power of 2
#define Q 8380417  // Modulus q
#define ROOT 1753  // Primitive 2N-th root of unity modulo Q
#define TAU 39  // Number of +/- 1's in challenge
#define GAMMA1 ((1 << 17) - 1)  // γ₁
#define GAMMA2 ((Q - 1) / 88)  // γ₂
#define BETA 78  // β
#define OMEGA 80  // ω

// Key sizes according to FIPS 204
#define PUBLICKEYBYTES (32 + 4 * K * N / 2)  // rho + t1 packed
#define SECRETKEYBYTES (2 * 32 + 4 * L * N + 4 * K * N + 4 * K * N / 2)  // rho + key + s1 + s2 + t0

// NTT-related constants
#define MONT -4186625 // 2^32 % Q
#define QINV 58728449 // q^(-1) mod 2^32
#define R2 -4186625   // 2^32 % Q

// Polynomial ring element
typedef struct {
    int32_t coeffs[N];
} poly;

// Matrix of polynomials
typedef struct {
    poly *rows;
    int nrows;
    int ncols;
} matrix;

// Power of 2 round
static int32_t power2round(int32_t a, int D) {
    int32_t a1 = (a + (1 << (D-1)) - 1) >> D;
    return a1;
}

// Decompose into high and low bits
static void decompose(int32_t *a0, int32_t *a1, int32_t a) {
    *a1 = power2round(a, D);
    *a0 = a - (*a1 << D);
}

// High-order bits
static int32_t highbits(int32_t a) {
    int32_t a0, a1;
    decompose(&a0, &a1, a);
    return a1;
}

// Low-order bits
static int32_t lowbits(int32_t a) {
    int32_t a0, a1;
    decompose(&a0, &a1, a);
    return a0;
}

// Hint bit computation
static int makeHint(int32_t z, int32_t r) {
    int32_t r1 = highbits(r);
    int32_t v1 = highbits(r + z);
    return r1 != v1;
}

// Use hint bit
static int32_t useHint(int32_t h, int32_t r) {
    int32_t r1 = highbits(r);
    int32_t v1 = highbits(r + h * (Q / 2));
    return v1;
}

// Polynomial sampling from challenge space
static void sampleInBall(poly *c) {
    int32_t signs[N] = {0};
    int32_t pos[TAU] = {0};
    
    // Sample TAU unique positions
    for(int i = 0; i < TAU; i++) {
        int j;
        do {
            j = rand() % N;
            // Check if position already used
            int used = 0;
            for(int k = 0; k < i; k++)
                if(pos[k] == j)
                    used = 1;
            if(!used) {
                pos[i] = j;
                break;
            }
        } while(1);
        signs[j] = (rand() % 2) ? 1 : -1;
    }

    // Set coefficients
    for(int i = 0; i < N; i++)
        c->coeffs[i] = signs[i];
}

// Uniform sampling in [0,Q-1]
static void sample_uniform_poly(poly *a, const uint8_t *seed, uint16_t nonce) {
    uint32_t buf[N];
    // In practice, use SHAKE-256 with seed and nonce
    for(int i = 0; i < N; i++) {
        buf[i] = rand() % Q;  // Replace with proper SHAKE-256 expansion
        a->coeffs[i] = buf[i];
    }
}

// Sample from centered binomial distribution
static void sample_eta(poly *a) {
    for(int i = 0; i < N; i++) {
        int32_t t = 0;
        for(int j = 0; j < 2; j++) {  // η = 2 for FIPS 204 security level 2
            t += (rand() % 2) - (rand() % 2);  // Replace with proper random generation
        }
        a->coeffs[i] = t;
    }
}

// Montgomery reduction (assuming MONT and QINV are defined as before)
static int32_t montgomery_reduce(int64_t a) {
    int32_t t = (int32_t)a * QINV;
    t = (a - (int64_t)t * Q) >> 32;
    return t;
}

// Barrett reduction
static int32_t barrett_reduce(int32_t a) {
    int32_t v = ((int64_t)a * R2) >> 32;
    int32_t t = (v * Q + 0x7FFFFFFF) >> 31;
    return a - t * Q;
}

// Modular multiplication
static int32_t mul_mod(int32_t a, int32_t b) {
    return montgomery_reduce((int64_t)a * b);
}

// Bit-reversal function
static int32_t bitrev(int32_t x, int32_t bits) {
    int32_t y = 0;
    for (int32_t i = 0; i < bits; i++) {
        y = (y << 1) | (x & 1);
        x >>= 1;
    }
    return y;
}

// NTT forward transform
void ntt(int32_t *a) {
    int32_t len, start, j, k;
    int32_t t, u;

    for (len = 2; len <= N; len <<= 1) {
        for (start = 0; start < N; start += len) {
            int32_t zeta = ROOT;
            for (j = start; j < start + len / 2; j++) {
                t = a[j];
                u = mul_mod(a[j + len / 2], zeta);
                a[j] = (t + u) % Q;
                a[j + len / 2] = (t - u + Q) % Q;
                zeta = mul_mod(zeta, ROOT);
            }
        }
    }

    // Bit-reversal permutation
    for (int32_t i = 0; i < N; i++) {
        int32_t rev = bitrev(i, 8);  // log2(N) = 8
        if (i < rev) {
            int32_t tmp = a[i];
            a[i] = a[rev];
            a[rev] = tmp;
        }
    }
}

// Inverse NTT forward transform
void invntt(int32_t *a) {
    int32_t len, start, j, k;
    int32_t t, u;
    int32_t inv_root = 4404568;  // Modular inverse of ROOT

    // Bit-reversal permutation
    for (int32_t i = 0; i < N; i++) {
        int32_t rev = bitrev(i, 8);  // log2(N) = 8
        if (i < rev) {
            int32_t tmp = a[i];
            a[i] = a[rev];
            a[rev] = tmp;
        }
    }

    for (len = N; len >= 2; len >>= 1) {
        for (start = 0; start < N; start += len) {
            int32_t zeta = inv_root;
            for (j = start; j < start + len / 2; j++) {
                t = a[j];
                u = a[j + len / 2];
                a[j] = (t + u) % Q;
                u = mul_mod((t - u + Q) % Q, zeta);
                a[j + len / 2] = u;
                zeta = mul_mod(zeta, inv_root);
            }
        }
    }

    int32_t n_inv = 8347681;  // Modular inverse of N
    for (int32_t i = 0; i < N; i++) {
        a[i] = mul_mod(a[i], n_inv);
    }
}

// Matrix-vector multiplication in NTT domain
static void matrix_multiply(poly *t, const matrix *A, const poly *s, int rows, int cols) {
    for(int i = 0; i < rows; i++) {
        poly_zero(&t[i]);
        for(int j = 0; j < cols; j++) {
            poly tmp;
            poly_mul(&tmp, &A[i * cols + j], &s[j]);
            poly_add(&t[i], &t[i], &tmp);
        }
    }
}

// Helper functions for packing/unpacking
static void pack_t1(uint8_t *buf, const poly *t1, int count) {
    size_t off = 0;
    for(int i = 0; i < count; i++) {
        for(int j = 0; j < N/2; j++) {
            uint32_t t1_0 = t1[i].coeffs[2*j];
            uint32_t t1_1 = t1[i].coeffs[2*j+1];
            buf[off++] = t1_0;
            buf[off++] = t1_0 >> 8;
            buf[off++] = t1_1;
            buf[off++] = t1_1 >> 8;
        }
    }
}

static void pack_s(uint8_t *buf, const poly *s, int count) {
    size_t off = 0;
    for(int i = 0; i < count; i++) {
        for(int j = 0; j < N; j++) {
            int32_t coeff = s[i].coeffs[j];
            buf[off++] = coeff;
            buf[off++] = coeff >> 8;
            buf[off++] = coeff >> 16;
            buf[off++] = coeff >> 24;
        }
    }
}

static void pack_t0(uint8_t *buf, const int32_t *t0, int count) {
    size_t off = 0;
    for(int i = 0; i < count * N; i++) {
        int32_t coeff = t0[i];
        buf[off++] = coeff;
        buf[off++] = coeff >> 8;
        buf[off++] = coeff >> 16;
        buf[off++] = coeff >> 24;
    }
}

// Helper functions for keygen
void poly_add(poly *c, const poly *a, const poly *b) {
    for (int i = 0; i < N; i++) {
        c->coeffs[i] = barrett_reduce(a->coeffs[i] + b->coeffs[i]);
    }
}

void poly_sub(poly *c, const poly *a, const poly *b) {
    for (int i = 0; i < N; i++) {
        c->coeffs[i] = barrett_reduce(a->coeffs[i] - b->coeffs[i]);
    }
}

void poly_mul(poly *c, const poly *a, const poly *b) {
    ntt(a->coeffs);
    ntt(b->coeffs);
    for (int i = 0; i < N; i++) {
        c->coeffs[i] = montgomery_reduce((int64_t)a->coeffs[i] * b->coeffs[i]);
    }
    invntt(c->coeffs);
}

// Generate keypair
void keygen(uint8_t *pk, uint8_t *sk) {
    matrix A;
    poly s1[L], s2[K], t[K];
    int32_t t0[K * N];
    uint8_t rho[32], seed_s[32], key[32];
    
    // 1. Generate random values using SHAKE-256
    uint8_t seed[32];
    randombytes(seed, 32);  // Secure random generation
    shake256(rho, 32, seed, 32);
    shake256(seed_s, 32, seed, 32);
    shake256(key, 32, seed, 32);
    
    // 2. Generate matrix A using expandA
    for(int i = 0; i < K; i++) {
        for(int j = 0; j < L; j++) {
            sample_uniform_poly(&A.rows[i * L + j], rho, (i << 8) + j);
            ntt(&A.rows[i * L + j]);
        }
    }
    
    // 3. Sample secret vectors s1 and s2
    for(int i = 0; i < L; i++) {
        sample_eta(&s1[i]);
        ntt(&s1[i]);
    }
    for(int i = 0; i < K; i++) {
        sample_eta(&s2[i]);
        ntt(&s2[i]);
    }
    
    // 4. Compute t = As1 + s2
    matrix_multiply(t, &A, s1, K, L);
    for(int i = 0; i < K; i++) {
        poly_add(&t[i], &t[i], &s2[i]);
    }
    
    // 5. Decompose t and pack public key
    poly t1[K];
    size_t off_pk = 0;
    size_t off_sk = 0;
    
    // Pack rho into public key
    memcpy(pk + off_pk, rho, 32);
    off_pk += 32;
    
    // Decompose t and pack t1
    for(int i = 0; i < K; i++) {
        for(int j = 0; j < N; j++) {
            int32_t t0_val, t1_val;
            decompose(&t0_val, &t1_val, t[i].coeffs[j]);
            t1[i].coeffs[j] = t1_val;
            t0[i * N + j] = t0_val;
        }
    }
    pack_t1(pk + off_pk, t1, K);
    
    // 6. Pack secret key
    // Pack rho
    memcpy(sk + off_sk, rho, 32);
    off_sk += 32;
    
    // Pack key
    memcpy(sk + off_sk, key, 32);
    off_sk += 32;
    
    // Pack s1
    pack_s(sk + off_sk, s1, L);
    off_sk += 4 * L * N;
    
    // Pack s2
    pack_s(sk + off_sk, s2, K);
    off_sk += 4 * K * N;
    
    // Pack t0
    pack_t0(sk + off_sk, t0, K);
    off_sk += 4 * K * N;
    
    // Pack t1 (same format as public key)
    pack_t1(sk + off_sk, t1, K);
}

int main() {
    // Example usage
    matrix A;  // Public matrix
    poly s1, s2;  // Secret key
    poly t;   // Public key
    int tr[OMEGA];  // Key generation trace
    
    // Generate keypair
    keygen(&A, &s1, &s2, &t, tr);
    
    // Message to sign
    const char *msg = "Hello, FIPS 204!";
    size_t mlen = strlen(msg);
    
    // Signature components
    poly z, h, c;
    
    // Sign
    sign((const uint8_t*)msg, mlen, &A, &s1, &s2, &t, tr, &z, &h, &c);
    
    // Verify
    int valid = verify((const uint8_t*)msg, mlen, &A, &t, &z, &h, &c);
    
    printf("FIPS 204 signature verification %s\n", valid ? "succeeded" : "failed");
    
    return 0;
}
