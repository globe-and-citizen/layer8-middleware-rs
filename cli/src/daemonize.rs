use std::path::{Path, PathBuf};

use log::debug;
use serde::{Deserialize, Serialize};

// This version is tied to the middleware version; make sure to update it when the middleware version changes.
const VERSION: &str = "0.1.24";

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct L8ProxyConfig {
    pub version: String,
    pub proxies: Vec<Proxy>,
}

impl Default for L8ProxyConfig {
    fn default() -> Self {
        Self {
            version: VERSION.to_string(),
            proxies: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Proxy {
    pub port: u16,
    pub service_port: u16,
}

pub fn prepare_bookkeeping() {
    _ = create_file_if_not_exists();
}

// Todo: this is not async safe; will cause data races and data corruption if used in async context
pub fn add_proxy(port: u16, service_port: u16) -> Result<(), String> {
    let mut val = get_all_proxies()?;
    val.push(Proxy { port, service_port });

    let path = create_file_if_not_exists()?;
    std::fs::write(
        path.clone(),
        serde_json::to_string(&L8ProxyConfig {
            version: VERSION.to_string(),
            proxies: val,
        })
        .map_err(|e| format!("Failed to serialize the data. Error: {}", e))?,
    )
    .map_err(|e| format!("Failed to write to the file: {}. Error: {}", path.to_string_lossy(), e))?;

    Ok(())
}

pub fn remove_proxy(port: u16) -> Result<(), String> {
    let mut val = get_all_proxies()?;
    val.retain(|proxy| proxy.port != port);

    let path = create_file_if_not_exists()?;
    std::fs::write(
        path.clone(),
        serde_json::to_string(&L8ProxyConfig {
            version: VERSION.to_string(),
            proxies: val,
        })
        .map_err(|e| format!("Failed to serialize the data. Error: {}", e))?,
    )
    .map_err(|e| format!("Failed to write to the file: {}. Error: {}", path.to_string_lossy(), e))?;

    Ok(())
}

pub fn get_proxy(port: u16) -> Result<Option<Proxy>, String> {
    let proxies = get_all_proxies()?;
    Ok(proxies.into_iter().find(|proxy| proxy.port == port))
}

pub fn get_all_proxies() -> Result<Vec<Proxy>, String> {
    let path = create_file_if_not_exists()?;
    let file = std::fs::File::open(path.clone()).map_err(|e| format!("Failed to open the file: {}. Error: {}", path.to_string_lossy(), e))?;
    let conf = serde_json::from_reader::<_, L8ProxyConfig>(file)
        .map_err(|e| format!("Failed to read the file: {}. Error: {}", path.to_string_lossy(), e))?;

    Ok(conf.proxies)
}

// TODO: we need to have a lock on the file to prevent race conditions and data corruption
fn create_file_if_not_exists() -> Result<PathBuf, String> {
    let path = if cfg!(unix) {
        // `~/.config/MyApp` for unix systems
        format!("{}/.config/l8proxy", std::env::var("HOME").unwrap())
    } else if cfg!(windows) {
        // `%USERPROFILE%\AppData\Local\.l8proxy\` for windows
        format!("{}\\AppData\\Local\\l8proxy", std::env::var("USERPROFILE").unwrap())
    } else {
        panic!("Unsupported OS. Please open an issue on the repo to add support for this OS")
    };

    let conf_file = Path::new(&path).join("proc.json");
    if !conf_file.exists() {
        // make sure path is created
        if !Path::new(&path).exists() {
            debug!("Creating the directory: `{}`", path);
            std::fs::create_dir_all(&path).map_err(|e| format!("Failed to create the directory: {}. Error: {}", path, e))?;
        }

        let write_out = std::fs::File::create_new(&conf_file).map_err(|e| {
            format!(
                "Failed to create the file: {}. Error: {}",
                conf_file.join("proc.json").to_string_lossy(),
                e
            )
        })?;

        debug!("Created the file: `{}`", conf_file.to_string_lossy());

        // we need to seed the file with an empty array
        serde_json::to_writer(write_out, &L8ProxyConfig::default()).map_err(|e| {
            format!(
                "Failed to write to the file: {}. Error: {}",
                conf_file.join("proc.json").to_string_lossy(),
                e
            )
        })?;
    }

    // let's make some assertions before we proceed
    if cfg!(debug_assertions) {
        debug!("Validating the file: {}", conf_file.to_string_lossy());

        // file now exists
        if !conf_file.exists() {
            Err(format!("Failed to create the file: `{}`", conf_file.to_string_lossy()))?;
        }

        // the file has content that is parsable
        let file = std::fs::File::open(&conf_file).map_err(|e| format!("Failed to open the file: {}. Error: {}", conf_file.to_string_lossy(), e))?;
        let _ = serde_json::from_reader::<_, L8ProxyConfig>(file)
            .map_err(|e| format!("Failed to read the file: {}. Error: {}", conf_file.to_string_lossy(), e))?;
    }

    Ok(conf_file)
}
