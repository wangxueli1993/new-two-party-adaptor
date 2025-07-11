use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::proofs::sigma_ec_ddh::{ECDDHProof, ECDDHWitness, ECDDHStatement};
use curv::elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar};
use curv::{BigInt, HashChoice};
use sha2::Sha256;

pub fn instance_generate(y: Scalar<Secp256k1>, pk: Point<Secp256k1>) -> (Point<Secp256k1>, Point<Secp256k1>, ECDDHProof<Secp256k1, Sha256>) {
    let base = Point::generator();
    let Y = base * &y;
    let Z = pk.clone() * &y;
    let witness = ECDDHWitness { x: y };
    let statement = ECDDHStatement {
        g1: base.to_point(),
        h1: Y.clone(),
        g2: pk,
        h2: Z.clone(),
    };
    let proof = ECDDHProof::prove(&witness, &statement);
    (Y, Z, proof)
}

pub fn prove_with_assigned_point(
    sk: &Scalar<Secp256k1>,
    base_point: &Point<Secp256k1>,
) -> DLogProof<Secp256k1, Sha256> {
    let sk_t_rand_commitment = Scalar::random();
    let pk_t_rand_commitment = base_point * &sk_t_rand_commitment;
    let pk = base_point * sk;

    let challenge = Sha256::new()
        .chain_points([&pk_t_rand_commitment])
        .chain_point(base_point)
        .chain_point(&pk)
        .result_scalar();

    let challenge_mul_sk = challenge * sk;
    let challenge_response = &sk_t_rand_commitment - &challenge_mul_sk;
    DLogProof {
        pk,
        pk_t_rand_commitment,
        challenge_response,
        hash_choice: HashChoice::new(),
    }
}

pub fn com_nonce(
    k: &Scalar<Secp256k1>,
    base: &Point<Secp256k1>,
) -> (Point<Secp256k1>, DLogProof<Secp256k1, Sha256>) {
    let R1 = base * k;
    let proof = prove_with_assigned_point(k, base);
    (R1, proof)
}

pub fn com_party_two_nonce(
    base: &Point<Secp256k1>,
) -> (Point<Secp256k1>, DLogProof<Secp256k1, Sha256>) {
    let k1 = Scalar::<Secp256k1>::random();
    let R1 = base * &k1;
    let proof = prove_with_assigned_point(&k1, base);
    (R1, proof)
}