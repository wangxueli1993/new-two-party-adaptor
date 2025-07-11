use curv::arithmetic::traits::Samplable;
use curv::elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar};
use curv::cryptographic_primitives::proofs::sigma_ec_ddh::{ECDDHProof, ECDDHWitness, ECDDHStatement};
use curv::cryptographic_primitives::proofs::sigma_dlog::{DLogProof};

use curv::{BigInt, HashChoice};

use two_party_adaptor::{party_one, party_two};
use std::time::{Duration, Instant};
use sha2::{Sha256};
use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
use paillier::{Decrypt, Paillier};
use paillier::{Add, Encrypt, Mul};
use std::cmp;
use paillier::{RawCiphertext, RawPlaintext};
use two_party_adaptor::Signature;

const ITERS: u128 = 10;

pub fn instance_generate(y: Scalar<Secp256k1>, pk: Point<Secp256k1>)->(Point<Secp256k1>, Point<Secp256k1>, ECDDHProof<Secp256k1, Sha256>)
{
    let base = Point::generator();
    let Y = base*&y;
    let Z = pk.clone()*&y;
    let witness = ECDDHWitness{x:y};
    let statement = ECDDHStatement{g1:base.to_point(),h1:Y.clone(),g2:pk,h2:Z.clone()};
    let proof = ECDDHProof::prove(&witness, &statement);
    (Y, Z, proof)
}

pub fn prove_with_assigned_point(sk: &Scalar<Secp256k1>, base_point: &Point<Secp256k1>) -> DLogProof<Secp256k1, Sha256>
{
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

pub fn com_nonce(k: &Scalar<Secp256k1>, base: &Point<Secp256k1>)->(Point<Secp256k1>, DLogProof<Secp256k1, Sha256>)
{
    let R1 = base * k;
    let proof = prove_with_assigned_point(k, base);
    (R1, proof)
}

pub fn com_party_two_nonce(base: &Point<Secp256k1>)->(Point<Secp256k1>, DLogProof<Secp256k1, Sha256>)
{
    let k1 = Scalar::<Secp256k1>::random();
    let R1 = base * &k1;
    let proof = prove_with_assigned_point(&k1, base);
    (R1, proof)
}

fn ndss() {
    let mut keygen_time: u128 = 0;
    let mut presign_time: u128 = 0;
    let mut adapt_time: u128 = 0;
    let mut vrfy_time: u128 = 0;
    let mut recover_time: u128 = 0;
    for _ in 0..ITERS {
        let start1 = Instant::now();
        // assume party1 and party2 engaged with KeyGen in the past resulting in
        // party1 owning private share and paillier key-pair
        // party2 owning private share and paillier encryption of party1 share
        let (party_one_first_message, comm_witness, keypair_party1) = party_one::keygen::first_message();
        let (party_two_private_share_gen, keypair_party2) = party_two::keygen::first_message();
        let (party_one_second_message, keypair, party1_private) = party_one::keygen::second_message(comm_witness.clone(), &keypair_party1, &comm_witness.d_log_proof).unwrap();
        let salt:&[u8] = &[75, 90, 101, 110];
        let (_party_two_paillier) = party_two::keygen::second_message(&party_one_first_message, &party_one_second_message, salt);
        let duration1 = start1.elapsed().as_nanos();
        keygen_time = keygen_time + duration1;
        
        let start2 = Instant::now();
        // generating adaptor witness (y)
        let y = Scalar::<Secp256k1>::random();
    
        // creating the ephemeral private shares:
        let (p2_presign_msg1, p2_presign_local1) =
            party_two::sign::first_message(&y);
        let (eph_party_one_first_message, r1) = party_one::sign::first_message();
    
    
        let message = BigInt::from(1234);
        let partial_sig = party_two::sign::second_message(
            p2_presign_local1.k2_commit,
            &eph_party_one_first_message,
            &keypair.ek,
            &keypair.encrypted_share,
            &keypair_party2,
            &p2_presign_local1.k2_pair,
            &eph_party_one_first_message.public_share,
            &p2_presign_local1.k3_pair,
            &message,
        ).unwrap();
    
        let _ = party_one::sign::verify_commitments_and_dlog_proof(
            &p2_presign_msg1,
            &partial_sig.comm_witness,
        )
            .expect("failed to verify commitments and DLog proof");
    
        let party1_private = party_one::Party1Private::set_private_key(&keypair_party1, &keypair);
    
        let (encrypted_sig, duration4) = party_one::sign::second_message(
            &party1_private,
            &keypair_party1.public_share,
            &partial_sig.c3,
            &r1,
            &partial_sig.comm_witness.public_share,
            &p2_presign_local1.k3_pair.public_share,
            &message,
        );
        vrfy_time = vrfy_time + duration4;
        let duration2 = start2.elapsed().as_nanos();
        presign_time = presign_time + duration2;
        let start3 = Instant::now();
        let signature = party_two::sign::decrypt_signature(&encrypted_sig, &y, &r1.public_share, &p2_presign_local1.k3_pair.secret_share);
        let duration3 = start3.elapsed().as_nanos();
        adapt_time = adapt_time + duration3;
        //let start4 = Instant::now();
        let pubkey =
            party_one::keygen::compute_pubkey(&keypair_party1, &party_two_private_share_gen.public_share);
        party_one::verify_signature(&signature, &pubkey, &message).expect("Invalid signature");
        //let duration4 = start4.elapsed().as_nanos();
        
        let start5 = Instant::now();
        let _y_check = party_one::sign::recover_witness(encrypted_sig, &signature);
        let duration5 = start5.elapsed().as_nanos();
        recover_time = recover_time + duration5;
        //assert_eq!(y_check, y);
    }
    println!("[ITER {:?} times] NDSS keygen time: {:?} ns", ITERS, keygen_time);
    println!("[ITER {:?} times] NDSS pre sign time: {:?} ns", ITERS, presign_time);
    println!("[ITER {:?} times] NDSS adapt time: {:?} ns", ITERS, adapt_time);
    println!("[ITER {:?} times] NDSS vrfy time: {:?} ns", ITERS, vrfy_time);
    println!("[ITER {:?} times] NDSS recover witness time: {:?} ns", ITERS, recover_time);
    
}

fn our_two_party_adaptor() {
    let mut keygen_time: u128 = 0;
    let mut presign_time: u128 = 0;
    let mut offline: u128 = 0;
    let mut online: u128 = 0;
    let mut adapt_time: u128 = 0;
    let mut vrfy_time: u128 = 0;
    let mut recover_time: u128 = 0;
    for _ in 0..ITERS {
        let start1 = Instant::now();
        // assume party1 and party2 engaged with KeyGen in the past resulting in
        // party1 owning private share and paillier key-pair
        // party2 owning private share and paillier encryption of party1 share
        let (party_one_first_message, comm_witness, keypair_party1) = party_one::keygen::first_message();
        let (party_two_private_share_gen, keypair_party2) = party_two::keygen::first_message();
        let (party_one_second_message, keypair, party1_private) = party_one::keygen::second_message(comm_witness.clone(), &keypair_party1, &comm_witness.d_log_proof).unwrap();
        let salt:&[u8] = &[75, 90, 101, 110];
        let (_party_two_paillier) = party_two::keygen::second_message(&party_one_first_message, &party_one_second_message, salt);
        let duration1 = start1.elapsed().as_nanos();
        keygen_time = keygen_time + duration1;
        let pk = party_one::keygen::compute_pubkey(&keypair_party1, &party_two_private_share_gen.public_share);
        
    
        // generating adaptor witness (y)
        let y = Scalar::<Secp256k1>::random();
        let (Y, Z, proof) = instance_generate(y.clone(), pk);
    
        let start2 = Instant::now();
        // commitment of party one nonce:
        let k1 = Scalar::<Secp256k1>::random();
        let (R1, proof_1) = com_nonce(&k1, &Y);

        // commitment of party two nonce and compute rx
        let k2 = Scalar::<Secp256k1>::random();
        let (_R2, proof_2) = com_nonce(&k2, &Y);
        let _vrfy_result_2 = DLogProof::verify(&proof_2);
        let _vrfy_result_1 = DLogProof::verify(&proof_1);
        let R = k2.clone()*R1;
        let q = Scalar::<Secp256k1>::group_order();
        let r = R.x_coord().unwrap().mod_floor(q);

        //encrypt part of pre-signature
        let rho = BigInt::sample_below(&q.pow(2));
        let k2_inv = BigInt::mod_inv(&k2.to_bigint(), q).unwrap();
        let message = BigInt::from(1234);
        let partial_sig = rho * q + BigInt::mod_mul(&k2_inv, &message, q);
        let c1 = Paillier::encrypt(&keypair.ek, RawPlaintext::from(partial_sig));
        let v = BigInt::mod_mul(
            &k2_inv,
            &BigInt::mod_mul(&r, &keypair_party2.secret_share.to_bigint(), q),
            q,
        );
        let c2 = Paillier::mul(
            &keypair.ek,
            RawPlaintext::from(v),
            RawCiphertext::from(keypair.encrypted_share),
        );
        let c3 = Paillier::add(&keypair.ek, c2, c1).0.into_owned();
        let duration2 = start2.elapsed().as_nanos();
        offline = offline + duration2;
        //online sign
        let start3 = Instant::now();
        let s1 = Paillier::decrypt(&keypair.dk, &RawCiphertext::from(c3));
        let k1_inv = BigInt::mod_inv(&k1.to_bigint(), q).unwrap();
        let s_tag = BigInt::mod_mul(&k1_inv, &s1.0, q);
        let s_hat = cmp::min(
            s_tag.clone(),
            q - s_tag,
        );

        let signature = crate::Signature {
            s:s_hat.clone(),
            r:r.clone()
        };

        //verify pre-signature
        let start4 = Instant::now();
        let s_hat_inv = BigInt::mod_inv(&s_hat, q).unwrap();
        let r_prime = Scalar::from_bigint(&s_hat_inv)*(Scalar::from_bigint(&message)*Y + Scalar::from_bigint(&r)*Z);
        assert_eq!(r_prime.x_coord().unwrap().mod_floor(q), r);
        let duration3 = start4.elapsed().as_nanos();
        vrfy_time = vrfy_time + duration3;
        let duration4 = start3.elapsed().as_nanos();
        online = online + duration4;
        let duration5 = start2.elapsed().as_nanos();
        presign_time = presign_time + duration5;

        //adapt
        let start5 = Instant::now();
        let y_inv = y.invert().unwrap();
        let s = Scalar::from_bigint(&signature.s) * y_inv;
        let duration5 = start5.elapsed().as_nanos();
        adapt_time = adapt_time + duration5;
    }
    println!("[ITER {:?} times] Ours lindell keygen time: {:?} ns", ITERS, keygen_time);
    println!("[ITER {:?} times] Ours lindell sign time: {:?} ns", ITERS, presign_time);
    println!("[ITER {:?} times] Ours lindell offline time: {:?} ns", ITERS, offline);
    println!("[ITER {:?} times] Ours lindell online time: {:?} ns", ITERS, online);
    println!("[ITER {:?} times] Ours lindell vrfy time: {:?} ns", ITERS, vrfy_time);
    println!("[ITER {:?} times] Ours lindell adapt time: {:?} ns", ITERS, adapt_time);
   //println!("[ITER {:?} times] NDSS recover witness time: {:?} ns", ITERS, recover_time);
}
fn main() {
    ndss();
    our_two_party_adaptor()
}
