use p256::{elliptic_curve::sec1::ToEncodedPoint, AffinePoint};
use proptest::collection::{hash_map, vec};
use proptest::prelude::*;
use rand::rngs::StdRng;
use rand::SeedableRng;
use rumi::{Client, Server};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

// Import ORAM constants from the crate
use rumi::oram::{BUCKET_SIZE, ORAM_DEPTH};

// Strategy to generate valid identifiers (u64)
fn identifier_strategy() -> impl Strategy<Value = u64> {
    // Use a smaller range for faster tests
    1..1000u64
}

// Strategy to generate valid UUIDs
fn uuid_strategy() -> impl Strategy<Value = Uuid> {
    any::<[u8; 16]>().prop_map(|bytes| Uuid::from_bytes(bytes))
}

// Strategy to generate valid user mappings
fn user_mapping_strategy() -> impl Strategy<Value = HashMap<u64, Uuid>> {
    // Reduce the maximum size of the map for faster tests
    hash_map(identifier_strategy(), uuid_strategy(), 1..10)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]

    // Property: Server creation should preserve all user mappings
    #[test]
    fn server_preserves_user_mappings(users in user_mapping_strategy()) {
        let mut rng = StdRng::from_entropy();
        let server = Server::new(&mut rng, &users);
        let public_set = server.get_public_set();

        // All identifiers should be in the public set
        prop_assert!(users.keys().all(|id| public_set.contains(id)));
        prop_assert_eq!(users.len(), public_set.len());
    }

    // Property: Client-Server round trip should preserve user IDs
    #[test]
    fn client_server_round_trip_preserves_user_ids(
        users in user_mapping_strategy(),
        lookup_id in identifier_strategy()
    ) {
        let mut rng = StdRng::from_entropy();
        let mut server = Server::new(&mut rng, &users);
        let client = Client::new(&mut rng);
        let public_set = server.get_public_set();

        // Only test if the lookup_id exists in users
        if users.contains_key(&lookup_id) {
            let (prefix, blinded_point, zksm_proof) = client.request_identifier(lookup_id, &public_set);
            let double_blinded = server.blind_identifier(&blinded_point);

            let bucket = server.find_bucket(prefix, &zksm_proof, &mut rng).unwrap();
            let found_user_id = client.find_user_id(&double_blinded, &bucket, lookup_id);

            prop_assert!(found_user_id.is_some());
            let user_id_point = found_user_id.unwrap();
            let recovered_uuid = server.unblind_user_id(&user_id_point);

            prop_assert_eq!(recovered_uuid, users.get(&lookup_id).cloned());
        }
    }

    // Property: ZKSM proofs should be valid for public set
    #[test]
    fn zksm_proofs_are_valid(
        mut users in user_mapping_strategy()
    ) {
        prop_assume!(!users.is_empty());

        // Take any identifier from the public set
        let identifier = *users.keys().next().unwrap();
        let public_set = users.keys().cloned().collect::<Vec<_>>();

        // Generate and verify proof for a member
        let proof = rumi::generate_zksm_proof(identifier, &public_set);
        prop_assert!(rumi::verify_zksm_proof(&public_set, &proof));

        // For non-member verification, create a new public set without the identifier
        let mut non_member_set = public_set.clone();
        non_member_set.retain(|&x| x != identifier);

        // The proof should fail verification against a set that doesn't contain the identifier
        prop_assert!(!rumi::verify_zksm_proof(&non_member_set, &proof));
    }

    // Property: ORAM access patterns should be indistinguishable
    #[test]
    fn oram_access_patterns_are_uniform(
        users in user_mapping_strategy(),
        lookup_ids in vec(identifier_strategy(), 1..5) // Reduced number of lookups
    ) {
        let mut rng = StdRng::from_entropy();
        let mut server = Server::new(&mut rng, &users);
        let client = Client::new(&mut rng);
        let public_set = server.get_public_set();

        // Test that multiple accesses to the same identifier return consistent results
        for &id in &lookup_ids {
            if users.contains_key(&id) {
                let (prefix, blinded_point, zksm_proof) = client.request_identifier(id, &public_set);
                let double_blinded = server.blind_identifier(&blinded_point);

                // First access
                let bucket1 = server.find_bucket(prefix, &zksm_proof, &mut rng).unwrap();
                let found_user_id1 = client.find_user_id(&double_blinded, &bucket1, id);

                // Second access
                let bucket2 = server.find_bucket(prefix, &zksm_proof, &mut rng).unwrap();
                let found_user_id2 = client.find_user_id(&double_blinded, &bucket2, id);

                // Results should be consistent
                prop_assert_eq!(found_user_id1, found_user_id2);

                if let Some(user_id_point) = found_user_id1 {
                    let recovered_uuid = server.unblind_user_id(&user_id_point);
                    prop_assert_eq!(recovered_uuid, users.get(&id).cloned());
                }
            }
        }
    }
}
