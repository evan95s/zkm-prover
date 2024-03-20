use crate::contexts::{agg_context, agg_all_context, AggContext, AggAllContext, ProveContext, SplitContext};
use crate::provers::{SplitProver, ProveProver, AggProver, AggAllProver, Prover};

use anyhow::{anyhow, bail, Result};
use std::path::Path;
use std::sync::Mutex;

#[derive(Debug, Default)]
pub struct Pipeline {
    mutex: Mutex<usize>,
}

static PIPELINE_MUTEX: Mutex<usize> = Mutex::new(0);

impl Pipeline {
    pub fn new() -> Self {
        Pipeline {
            mutex: Mutex::new(0),
        }
    }

    pub fn split_prove(&mut self, split_context: &SplitContext) -> bool {
        let result = PIPELINE_MUTEX.try_lock();
        match result {
            Ok(_) => {
                match SplitProver::new().prove(split_context) {
                    Ok(()) => {
                        true
                    }
                    Err(e) => {
                        log::error!("split_prove error {:#?}", e);
                        false
                    }   
                }
            }
            Err(_) => {
                log::error!("split_prove busy");
                false
            }
        }
    }

    pub fn root_prove(&mut self, prove_context: &ProveContext) -> bool {
        let result = PIPELINE_MUTEX.try_lock();
        match result {
            Ok(_) => {
                match ProveProver::new().prove(prove_context) {
                    Ok(()) => {
                        true
                    }
                    Err(e) => {
                        log::error!("root_prove error {:#?}", e);
                        false
                    }   
                }
            }
            Err(e) => {
                log::error!("root_prove busy");
                false
            }
        }
    }

    pub fn aggregate_prove(&mut self, agg_context: &AggContext) -> bool {
        let result = PIPELINE_MUTEX.try_lock();
        match result {
            Ok(_) => {
                match AggProver::new().prove(agg_context) {
                    Ok(()) => {
                        true
                    }
                    Err(e) => {
                        log::error!("aggregate_prove error {:#?}", e);
                        false
                    }   
                }
            }
            Err(_) => {
                log::error!("aggregate_prove busy");
                false
            }
        }
    }

    pub fn aggregate_all_prove(&mut self, final_context: &AggAllContext) -> bool {
        let result = PIPELINE_MUTEX.try_lock();
        match result {
            Ok(_) => {
                match AggAllProver::new().prove(final_context) {
                    Ok(()) => {
                        true
                    }
                    Err(e) => {
                        log::error!("aggregate_all_prove error {:#?}", e);
                        false
                    }   
                }
            }
            Err(_) => {
                log::error!("aggregate_all_prove busy");
                false
            }
        }
    }

    /// Return prover status
    pub fn get_status(&mut self) -> bool {
        let result = PIPELINE_MUTEX.try_lock();
        match result {
            Ok(_) => {
                true
            }
            Err(_) => {
                false
            }
        }
    }
}