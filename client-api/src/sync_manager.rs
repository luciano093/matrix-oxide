use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};

use serde_json::json;
use tokio::sync::broadcast::{self, Receiver, Sender};

use crate::sync::Sync;

// TODO: change this to a db
#[derive(Clone)]
pub struct SyncManager {
    // Maps users to a map of states to Sync
    // TODO: fix infinite BTreeMap by limiting its size
    states: Arc<RwLock<HashMap<String, BTreeMap<u128, Arc<Sync>>>>>,
    sender: Arc<RwLock<Sender<String>>>,
    reciever: Arc<RwLock<Receiver<String>>>,
}

impl SyncManager {
    pub fn new() -> Self {
        let (sender, reciever) = broadcast::channel::<String>(16);

        Self {
            states: Arc::new(RwLock::new(HashMap::new())),
            sender: Arc::new(RwLock::new(sender)),
            reciever: Arc::new(RwLock::new(reciever)),
        }
    }

    // TODO: send difference between previous state and current instead of whole current state
    pub fn sync(&self, username: &str, old_state: Option<u128>) -> (u128, Arc<Sync>) {
        let read_lock = self.states.read().unwrap();
        // check if current state differs from old state
        let prev_state = read_lock.get(username).unwrap().get(&old_state.unwrap_or(0)).unwrap();
        let (curr_key, curr_state) = read_lock.get(username).unwrap().last_key_value().unwrap();

        // TODO: if previous and current state differ, return the difference
        // otherwise, wait for the receiver channel to detect data and return that

        let (curr_batch, curr_state) = (curr_key.clone(), curr_state.clone());

        let next_batch = curr_batch + 1;
  
        let next_state = Sync::new(
            curr_state.account_data().cloned(), 
            curr_state.device_lists().cloned(), 
            curr_state.device_one_time_keys_count(), 
            next_batch.to_string(),
            curr_state.presence().cloned(), 
            curr_state.rooms().cloned()
        );

        println!("next_state: {}", json!(next_state));

        drop(read_lock);

        // create new state
        self.states.write().unwrap().get_mut(username).unwrap().insert(next_batch, Arc::new(next_state));

        (curr_batch, curr_state)
    }

    pub fn get_state(&self, username: &str, state: u128) -> Arc<Sync> {
        let map = self.states.read().unwrap();
        let map2 = map.get(username).unwrap();
        map2.get(&state).unwrap().clone()
    }

    pub fn add_user(&self, username: &str) {
        let first_state = 0;

        let mut user_states = BTreeMap::new();
        user_states.insert(first_state.clone(), Arc::new(Sync::new(None, None, None, first_state.to_string(), None, None)));

        self.states.write().unwrap().insert(username.to_string(), user_states);
    }
}