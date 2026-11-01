#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::runtime::Runtime;
    use tokio::sync::RwLock;

    #[test]
    fn test_user_registration() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let governance = SelfAmendingGovernance::new(
                Arc::new(QuantumSecure::new().unwrap()),
                Arc::new(BLEEPZKPModule::unconfigured()),
                Arc::new(BLEEPInteroperabilityModule::new()),
                "models/proposal_categorization.onnx",
            )
            .unwrap();

            let user_id = governance
                .register_user("Alice", "Admin", vec![1, 2, 3, 4])
                .await;

            assert!(user_id.is_ok(), "User registration should succeed");
            assert!(governance.users.contains_key(&user_id.unwrap()), "User should be stored in governance module");
        });
    }

    #[test]
    fn test_proposal_submission() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let governance = SelfAmendingGovernance::new(
                Arc::new(QuantumSecure::new().unwrap()),
                Arc::new(BLEEPZKPModule::unconfigured()),
                Arc::new(BLEEPInteroperabilityModule::new()),
                "models/proposal_categorization.onnx",
            )
            .unwrap();

            let user = User {
                id: 1,
                username: "Alice".to_string(),
                role: "Admin".to_string(),
                public_key: vec![1, 2, 3, 4],
            };

            let proposal_id = governance
                .submit_proposal(user.clone(), "New Policy", "Implement decentralized voting")
                .await;

            assert!(proposal_id.is_ok(), "Proposal submission should succeed");
            assert!(governance.proposals.contains_key(&proposal_id.unwrap()), "Proposal should be stored");
        });
    }

    #[test]
    fn test_proposal_categorization() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let governance = SelfAmendingGovernance::new(
                Arc::new(QuantumSecure::new().unwrap()),
                Arc::new(BLEEPZKPModule::unconfigured()),
                Arc::new(BLEEPInteroperabilityModule::new()),
                "models/proposal_categorization.onnx",
            )
            .unwrap();

            let category = governance
                .categorize_proposal("Implement smart contract automation")
                .await;

            assert!(category.is_ok(), "AI-based categorization should succeed");
            assert!(
                ["Governance", "Development", "Update", "Miscellaneous"].contains(&category.unwrap().as_str()),
                "Category should be correctly assigned"
            );
        });
    }

    #[test]
    fn test_voting_with_zkp() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let governance = SelfAmendingGovernance::new(
                Arc::new(QuantumSecure::new().unwrap()),
                Arc::new(BLEEPZKPModule::unconfigured()),
                Arc::new(BLEEPInteroperabilityModule::new()),
                "models/proposal_categorization.onnx",
            )
            .unwrap();

            let user = User {
                id: 1,
                username: "Bob".to_string(),
                role: "Voter".to_string(),
                public_key: vec![1, 2, 3, 4],
            };

            let proposal_id = governance
                .submit_proposal(user.clone(), "Upgrade Security", "Integrate quantum-safe encryption")
                .await
                .unwrap();

            let vote_result = governance.vote(proposal_id, user, 25, true).await;

            assert!(vote_result.is_ok(), "Voting should succeed");
            let proposal = governance.proposals.get(&proposal_id).unwrap();
            assert!(proposal.votes_for > 0, "Votes should be recorded correctly");
        });
    }

    #[test]
    fn test_proposal_execution() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let governance = SelfAmendingGovernance::new(
                Arc::new(QuantumSecure::new().unwrap()),
                Arc::new(BLEEPZKPModule::unconfigured()),
                Arc::new(BLEEPInteroperabilityModule::new()),
                "models/proposal_categorization.onnx",
            )
            .unwrap();

            let user = User {
                id: 1,
                username: "Charlie".to_string(),
                role: "Admin".to_string(),
                public_key: vec![1, 2, 3, 4],
            };

            let proposal_id = governance
                .submit_proposal(user.clone(), "Integrate AI Governance", "Use AI for automated voting analysis")
                .await
                .unwrap();

            governance.vote(proposal_id, user.clone(), 100, true).await.unwrap();

            let execute_result = governance.execute_proposal(proposal_id).await;
            assert!(execute_result.is_ok(), "Proposal execution should succeed");

            let proposal = governance.proposals.get(&proposal_id).unwrap();
            assert!(proposal.executed, "Proposal should be marked as executed");
        });
    }

    #[test]
    fn test_logging_to_blockchain() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let governance = SelfAmendingGovernance::new(
                Arc::new(QuantumSecure::new().unwrap()),
                Arc::new(BLEEPZKPModule::unconfigured()),
                Arc::new(BLEEPInteroperabilityModule::new()),
                "models/proposal_categorization.onnx",
            )
            .unwrap();

            let log_result = governance.log_to_blockchain("Proposal successfully executed").await;
            assert!(log_result.is_ok(), "Blockchain logging should succeed");
        });
    }
              } 
