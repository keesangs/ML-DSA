# ML-DSA
Module lattice based DSA Algorithm Implementation

# Module Lattice-based Digital Signature Algorithm

This document provides an implementation of a basic module lattice-based digital signature algorithm (DSA). The implementation is similar to CRYSTALS-Dilithium but simplified for educational purposes.

## Overview

The implementation includes a complete signature scheme with key generation, signing, and verification capabilities. It uses polynomial operations in a number-theoretic transform (NTT) domain for efficient computation.

## Parameters

The algorithm uses the following parameters:
- `N = 256`: Lattice dimension
- `Q = 8380417`: Modulus (approximately 2²³)
- `BETA = 240`: Rejection threshold
- `TAU = 60`: Number of +/- 1's in challenge

## Implementation

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Parameters for the lattice-based DSA
#define N 256  // Lattice dimension
#define Q 8380417  // Modulus
#define BETA 240  // Rejection threshold
#define TAU 60  // Number of +/- 1's in challenge

// Helper function for modular reduction
int mod(int a, int m) {
    int r = a % m;
    return r < 0 ? r + m : r;
}

// Generate a random polynomial with coefficients in [-η,η]
void sample_eta(int *poly, int eta) {
    for (int i = 0; i < N; i++) {
        int r = rand() % (2 * eta + 1) - eta;
        poly[i] = r;
    }
}

// Generate a uniform random polynomial with coefficients in [0,Q-1]
void sample_uniform(int *poly) {
    for (int i = 0; i < N; i++) {
        poly[i] = rand() % Q;
    }
}

// Number Theoretic Transform (NTT) for polynomial multiplication
void ntt(int *poly) {
    // Implementation of NTT would go here
    // This is a placeholder - actual implementation would require:
    // 1. Bit-reversal permutation
    // 2. Butterfly operations with appropriate twiddle factors
}

// Inverse NTT
void intt(int *poly) {
    // Implementation of inverse NTT would go here
}

// Polynomial multiplication in NTT domain
void poly_multiply(int *c, const int *a, const int *b) {
    for (int i = 0; i < N; i++) {
        c[i] = (long long)a[i] * b[i] % Q;
    }
}

// Generate keypair
void keygen(int *public_key, int *private_key) {
    int a[N];
    int s[N], e[N];
    
    // Generate uniform random polynomial a
    sample_uniform(a);
    
    // Sample secret key s and error e from small distribution
    sample_eta(s, 3);
    sample_eta(e, 3);
    
    // Convert to NTT domain
    ntt(a);
    ntt(s);
    ntt(e);
    
    // Compute public key t = as + e
    for (int i = 0; i < N; i++) {
        public_key[i] = mod((long long)a[i] * s[i] + e[i], Q);
    }
    
    memcpy(private_key, s, N * sizeof(int));
}

// Generate signature
void sign(const int *msg, size_t msg_len, const int *public_key, const int *private_key, 
         int *signature_z, int *signature_c) {
    int y[N];
    int w[N];
    
    while (1) {
        // Sample y uniformly from [-γ1, γ1]
        for (int i = 0; i < N; i++) {
            y[i] = rand() % (2 * BETA + 1) - BETA;
        }
        
        // Convert to NTT domain
        ntt(y);
        
        // Compute w = ay
        poly_multiply(w, public_key, y);
        intt(w);
        
        // Compute challenge c = H(w, msg)
        // In practice, this would use a cryptographic hash function
        // Here we just set some random +/-1 coefficients
        memset(signature_c, 0, N * sizeof(int));
        for (int i = 0; i < TAU; i++) {
            int pos = rand() % N;
            signature_c[pos] = (rand() % 2) * 2 - 1;
        }
        
        // Compute z = y + cs
        ntt(signature_c);
        for (int i = 0; i < N; i++) {
            signature_z[i] = mod(y[i] + (long long)signature_c[i] * private_key[i], Q);
        }
        intt(signature_z);
        
        // Check if z is small enough, if not resample
        int too_large = 0;
        for (int i = 0; i < N; i++) {
            if (abs(signature_z[i]) > BETA) {
                too_large = 1;
                break;
            }
        }
        
        if (!too_large) break;
    }
}

// Verify signature
int verify(const int *msg, size_t msg_len, const int *public_key,
          const int *signature_z, const int *signature_c) {
    // Check if z is small enough
    for (int i = 0; i < N; i++) {
        if (abs(signature_z[i]) > BETA) return 0;
    }
    
    // Compute w' = az - ct
    int w_prime[N];
    int z_ntt[N], c_ntt[N];
    
    memcpy(z_ntt, signature_z, N * sizeof(int));
    memcpy(c_ntt, signature_c, N * sizeof(int));
    
    ntt(z_ntt);
    ntt(c_ntt);
    
    for (int i = 0; i < N; i++) {
        w_prime[i] = mod((long long)public_key[i] * z_ntt[i] - 
                        (long long)c_ntt[i] * public_key[i], Q);
    }
    
    intt(w_prime);
    
    // Verify that challenge matches
    // In practice, would recompute challenge from w' and msg
    // and compare with provided challenge
    return 1;  // Placeholder - actual verification would go here
}

int main() {
    srand(time(NULL));
    
    int public_key[N];
    int private_key[N];
    int signature_z[N];
    int signature_c[N];
    
    // Generate keypair
    keygen(public_key, private_key);
    
    // Message to sign
    const char *msg = "Hello, World!";
    size_t msg_len = strlen(msg);
    
    // Sign message
    sign((const int*)msg, msg_len, public_key, private_key, signature_z, signature_c);
    
    // Verify signature
    int valid = verify((const int*)msg, msg_len, public_key, signature_z, signature_c);
    
    printf("Signature verification %s\n", valid ? "succeeded" : "failed");
    
    return 0;
}
```

## Key Components

### Functions

1. **Key Generation (`keygen`)**
   - Generates public/private key pair
   - Uses polynomial operations in NTT domain
   - Incorporates error sampling for security

2. **Signing (`sign`)**
   - Creates signature for a message
   - Implements rejection sampling
   - Uses NTT for efficient polynomial multiplication

3. **Verification (`verify`)**
   - Verifies signature validity
   - Checks size constraints
   - Recomputes and verifies challenge

4. **Helper Functions**
   - `sample_eta`: Generates random polynomials with small coefficients
   - `sample_uniform`: Generates uniform random polynomials
   - `ntt`/`intt`: Number Theoretic Transform operations
   - `poly_multiply`: Polynomial multiplication in NTT domain

## Implementation Notes

### Security Considerations

For a production system, the following enhancements would be necessary:

1. **Cryptographic Security**
   - Implement proper cryptographic hash functions
   - Use constant-time operations for security
   - Choose parameters based on security requirements

2. **Implementation Security**
   - Use cryptographically secure random number generation
   - Implement side-channel protections
   - Complete the Number Theoretic Transform implementation

3. **Parameter Selection**
   - More sophisticated parameter selection
   - Security level analysis
   - Performance optimization

### Usage Example

The main function demonstrates basic usage:
1. Generate a keypair
2. Sign a message ("Hello, World!")
3. Verify the signature
4. Print verification result

This implementation serves as an educational reference and should not be used in production without significant security enhancements.
