use crate::persistence::PersistenceChain;

pub mod cron;
pub mod systemd;
pub mod bash_profile;

pub fn get_chain() -> PersistenceChain {
    PersistenceChain::new(vec![])  // temporary stub — backends added in Tasks 2-4
}
