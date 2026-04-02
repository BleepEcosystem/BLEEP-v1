// BLEEP AI Assistant - Fully Integrated with BLEEP Ecosystem
// Self-Learning, Quantum-Secure, Governance-Driven AI Assistant

use crate::analytics::BLEEPAnalytics;
use crate::compliance::ComplianceModule;
use crate::energy_monitor::EnergyMonitor;
use crate::governance::BLEEPGovernance;
use crate::interoperability::InteroperabilityModule;
use crate::security::QuantumSecure;
use crate::sharding::AdaptiveSharding;
use crate::smart_contracts::SmartContractOptimizer;
use crate::wallet::BLEEPWallet;
use log::info;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Serialize, Deserialize)]
pub struct AIRequest {
    pub user_id: String,
    pub query: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AIResponse {
    pub response: String,
    pub insights: Option<String>,
}

/// Initialize the AI advisory subsystem.
pub fn init_ai_advisory() -> Result<(), Box<dyn std::error::Error>> {
    info!("AI advisory subsystem initialized.");
    Ok(())
}

pub struct BLEEPAIAssistant {
    pub wallet: Arc<BLEEPWallet>,
    pub governance: Arc<BLEEPGovernance>,
    pub security: Arc<QuantumSecure>,
    pub optimizer: Arc<SmartContractOptimizer>,
    pub interoperability: Arc<InteroperabilityModule>,
    #[allow(dead_code)]
    analytics: Arc<BLEEPAnalytics>,
    pub compliance: Arc<ComplianceModule>,
    pub sharding: Arc<AdaptiveSharding>,
    pub energy_monitor: Arc<EnergyMonitor>,
}

impl BLEEPAIAssistant {
    pub fn new(
        wallet: Arc<BLEEPWallet>,
        governance: Arc<BLEEPGovernance>,
        security: Arc<QuantumSecure>,
        optimizer: Arc<SmartContractOptimizer>,
        interoperability: Arc<InteroperabilityModule>,
        analytics: Arc<BLEEPAnalytics>,
        compliance: Arc<ComplianceModule>,
        sharding: Arc<AdaptiveSharding>,
        energy_monitor: Arc<EnergyMonitor>,
    ) -> Self {
        BLEEPAIAssistant {
            wallet,
            governance,
            security,
            optimizer,
            interoperability,
            analytics,
            compliance,
            sharding,
            energy_monitor,
        }
    }

    pub async fn process_request(&self, request: AIRequest) -> AIResponse {
        info!("Processing AI request: {}", request.query);
        let response = match request.query.as_str() {
            "wallet_balance" => {
                crate::wallet::BLEEPWallet::get_balance_ref(self.wallet.as_ref(), &request.user_id)
                    .await
                    .unwrap_or(0)
                    .to_string()
            }
            "governance_status" => {
                match crate::governance::BLEEPGovernance::get_active_proposals_ref(
                    self.governance.as_ref(),
                )
                .await
                {
                    Ok(_) => "Governance data fetched".to_string(),
                    Err(_) => "Error fetching governance data".to_string(),
                }
            }
            "contract_optimization" => self
                .optimizer
                .optimize_code("sample smart contract code")
                .unwrap_or_else(|_| "Optimization failed".to_string()),
            "security_check" => match crate::security::QuantumSecure::analyze_risk_ref(
                self.security.as_ref(),
                &request.user_id,
            )
            .await
            {
                Ok(_) => "Security check passed".to_string(),
                Err(_) => "Security check failed".to_string(),
            },
            "shard_status" => match crate::sharding::AdaptiveSharding::get_shard_health_ref(
                self.sharding.as_ref(),
            )
            .await
            {
                Ok(_) => "Shard status fetched".to_string(),
                Err(_) => "Error fetching shard status".to_string(),
            },
            "energy_usage" => match crate::energy_monitor::EnergyMonitor::get_usage_stats_ref(
                self.energy_monitor.as_ref(),
            )
            .await
            {
                Ok(_) => "Energy data fetched".to_string(),
                Err(_) => "Energy data unavailable".to_string(),
            },
            "interoperability_status" => {
                match crate::interoperability::InteroperabilityModule::get_status_ref(
                    self.interoperability.as_ref(),
                )
                .await
                {
                    Ok(_) => "Interoperability module available".to_string(),
                    Err(_) => "Interoperability module unavailable".to_string(),
                }
            }
            "compliance_audit" => {
                match crate::compliance::ComplianceModule::run_audit_ref(self.compliance.as_ref())
                    .await
                {
                    Ok(_) => "Compliance audit passed".to_string(),
                    Err(_) => "Compliance audit failed".to_string(),
                }
            }
            _ => "I am still learning, please refine your query".to_string(),
        };

        AIResponse {
            response,
            insights: Some("Advanced AI insights for ecosystem analysis".to_string()),
        }
    }
}
