pub struct BLEEPWallet;

impl BLEEPWallet {
    pub async fn get_balance(&self, _user_id: &str) -> Result<u64, ()> {
        Ok(0)
    }
    pub async fn get_balance_ref(this: &Self, user_id: &str) -> Result<u64, ()> {
        this.get_balance(user_id).await
    }
}
