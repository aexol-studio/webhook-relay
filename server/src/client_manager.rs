use std::collections::HashMap;
use std::sync::Arc;

use api::{ClientConfig, HttpRequest, HttpResponse};
use tokio::sync::{mpsc, oneshot, RwLock};

use crate::config::Config;

pub struct PendingRequest {
    pub response_tx: oneshot::Sender<HttpResponse>,
}

pub struct ConnectedClient {
    pub client_id: String,
    pub route: String,
    pub request_tx: mpsc::Sender<HttpRequest>,
    pub pending_requests: Arc<RwLock<HashMap<String, PendingRequest>>>,
}

pub struct ClientManager {
    /// Map from route -> client
    clients_by_route: RwLock<HashMap<String, Arc<ConnectedClient>>>,
    /// Map from client_id -> route (for idempotent registration)
    routes_by_client: RwLock<HashMap<String, String>>,
    external_url: String,
}

impl ClientManager {
    pub fn new(config: &Config) -> Self {
        Self {
            clients_by_route: RwLock::new(HashMap::new()),
            routes_by_client: RwLock::new(HashMap::new()),
            external_url: config.external_url.clone().trim_end_matches('/').to_string(),
        }
    }
    
    pub async fn register_client(
        &self,
        client_id: String,
        request_tx: mpsc::Sender<HttpRequest>,
    ) -> ClientConfig {
        // Check if client already has a route
        let existing_route = {
            let routes = self.routes_by_client.read().await;
            routes.get(&client_id).cloned()
        };
        
        let route = existing_route.unwrap_or_else(generate_route);
        let endpoint = format!("{}/{}", self.external_url, route);
        
        let client = Arc::new(ConnectedClient {
            client_id: client_id.clone(),
            route: route.clone(),
            request_tx,
            pending_requests: Arc::new(RwLock::new(HashMap::new())),
        });
        
        {
            let mut clients = self.clients_by_route.write().await;
            clients.insert(route.clone(), client);
        }
        
        {
            let mut routes = self.routes_by_client.write().await;
            routes.insert(client_id.clone(), route.clone());
        }
        
        tracing::info!(
            client_id = %client_id,
            route = %route,
            "Client registered"
        );
        
        ClientConfig {
            client_id,
            endpoint,
        }
    }
    
    pub async fn unregister_client(&self, route: &str) {
        let mut clients = self.clients_by_route.write().await;
        if let Some(client) = clients.remove(route) {
            // Also remove the route mapping
            let mut routes = self.routes_by_client.write().await;
            routes.remove(&client.client_id);
            
            tracing::info!(
                client_id = %client.client_id,
                route = %route,
                "Client unregistered"
            );
        }
    }
    
    pub async fn get_client(&self, route: &str) -> Option<Arc<ConnectedClient>> {
        let clients = self.clients_by_route.read().await;
        clients.get(route).cloned()
    }
}

fn generate_route() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 12] = rng.r#gen();
    hex::encode(bytes)
}
