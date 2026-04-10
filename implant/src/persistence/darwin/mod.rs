use crate::persistence::{PersistenceChain, PersistenceTrait};
pub mod launch_agent;
pub mod login_item;

pub fn get_chain() -> PersistenceChain {
    PersistenceChain::new(vec![
        Box::new(launch_agent::LaunchAgentPersistence),
        Box::new(login_item::LoginItemPersistence),
    ])
}
