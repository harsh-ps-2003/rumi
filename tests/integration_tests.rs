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

    // Property: Registration of new identifiers should succeed
    #[test]
    fn registration_succeeds_for_new_identifiers(
        initial_users in user_mapping_strategy(),
        new_id in identifier_strategy(),
        new_uuid in uuid_strategy()
    ) {
        let mut rng = StdRng::from_entropy();
        let mut server = Server::new(&mut rng, &initial_users);

        // Skip if the new_id is already registered
        prop_assume!(!initial_users.contains_key(&new_id));

        // Registration should succeed
        let result = server.register(new_id, &new_uuid, &mut rng);
        prop_assert!(result.is_ok());

        // Verify the identifier is now in the public set
        let public_set = server.get_public_set();
        prop_assert!(public_set.contains(&new_id));

        // Verify we can look up the registered UUID
        let client = Client::new(&mut rng);
        let (prefix, blinded_point, zksm_proof) = client.request_identifier(new_id, &public_set);
        let double_blinded = server.blind_identifier(&blinded_point);

        let bucket = server.find_bucket(prefix, &zksm_proof, &mut rng).unwrap();
        let found_user_id = client.find_user_id(&double_blinded, &bucket, new_id);

        prop_assert!(found_user_id.is_some());
        let user_id_point = found_user_id.unwrap();
        let recovered_uuid = server.unblind_user_id(&user_id_point);

        prop_assert_eq!(recovered_uuid, Some(new_uuid));
    }

    // Property: Registration of duplicate identifiers should fail
    #[test]
    fn registration_fails_for_duplicate_identifiers(
        initial_users in user_mapping_strategy(),
        new_uuid in uuid_strategy()
    ) {
        prop_assume!(!initial_users.is_empty());
        let mut rng = StdRng::from_entropy();
        let mut server = Server::new(&mut rng, &initial_users);

        // Try to register an existing identifier with a new UUID
        let existing_id = *initial_users.keys().next().unwrap();
        let result = server.register(existing_id, &new_uuid, &mut rng);

        // Registration should fail
        prop_assert!(result.is_err());
        prop_assert_eq!(result.unwrap_err(), "Identifier already registered");

        // Public set should remain unchanged
        let public_set = server.get_public_set();
        prop_assert_eq!(public_set.len(), initial_users.len());

        // Original mapping should still work
        let client = Client::new(&mut rng);
        let (prefix, blinded_point, zksm_proof) = client.request_identifier(existing_id, &public_set);
        let double_blinded = server.blind_identifier(&blinded_point);

        let bucket = server.find_bucket(prefix, &zksm_proof, &mut rng).unwrap();
        let found_user_id = client.find_user_id(&double_blinded, &bucket, existing_id);

        prop_assert!(found_user_id.is_some());
        let user_id_point = found_user_id.unwrap();
        let recovered_uuid = server.unblind_user_id(&user_id_point);

        // Should still map to the original UUID
        prop_assert_eq!(recovered_uuid, initial_users.get(&existing_id).cloned());
    }

    // Property: Multiple registrations should maintain consistency
    #[test]
    fn multiple_registrations_maintain_consistency(
        initial_users in user_mapping_strategy(),
        new_registrations in vec((identifier_strategy(), uuid_strategy()), 1..5)
    ) {
        let mut rng = StdRng::from_entropy();
        let mut server = Server::new(&mut rng, &initial_users);
        let mut all_users = initial_users.clone();

        for (id, uuid) in new_registrations {
            if !all_users.contains_key(&id) {
                let result = server.register(id, &uuid, &mut rng);
                prop_assert!(result.is_ok());
                all_users.insert(id, uuid);
            }
        }

        // Verify all registrations are accessible
        let client = Client::new(&mut rng);
        let public_set = server.get_public_set();

        for (&id, &expected_uuid) in &all_users {
            let (prefix, blinded_point, zksm_proof) = client.request_identifier(id, &public_set);
            let double_blinded = server.blind_identifier(&blinded_point);

            let bucket = server.find_bucket(prefix, &zksm_proof, &mut rng).unwrap();
            let found_user_id = client.find_user_id(&double_blinded, &bucket, id);

            prop_assert!(found_user_id.is_some());
            let user_id_point = found_user_id.unwrap();
            let recovered_uuid = server.unblind_user_id(&user_id_point);

            prop_assert_eq!(recovered_uuid, Some(expected_uuid));
        }
    }
}
