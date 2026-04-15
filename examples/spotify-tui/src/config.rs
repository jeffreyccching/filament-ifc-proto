use super::banner::BANNER;
use anyhow::{anyhow, Error, Result};
use macros::*;
use serde::{Deserialize, Serialize};
use std::{
  fs,
  io::{stdin, Write},
  path::{Path, PathBuf},
};
use typing_rules::*;

use typing_rules::secure_io::SecureFile;

const DEFAULT_PORT: u16 = 8888;
const FILE_NAME: &str = "client.yml";
const CONFIG_DIR: &str = ".config";
const APP_CONFIG_DIR: &str = "spotify-tui";
const TOKEN_CACHE_FILE: &str = ".spotify_token_cache.json";

#[derive(Clone, Serialize, Deserialize)]
pub struct ClientConfigSerde {
  client_id: String,
  client_secret: String,
  device_id: Option<String>,
  port: Option<u16>,
}

impl ClientConfigSerde {
  fn with_device_id(&self, id: String) -> Self {
    let mut cloned = self.clone();
    cloned.device_id = Some(id);
    cloned
  }

  fn client_secret_cloned(&self) -> String {
    self.client_secret.clone()
  }
}

#[derive(Default, Clone, PartialEq)]
pub struct ClientConfig {
  pub client_id: String,
  pub client_secret: Labeled<String, A>,
  pub device_id: Option<String>,
  pub port: Option<u16>,
}

pub struct ConfigPaths {
  pub config_file_path: PathBuf,
  pub token_cache_path: PathBuf,
}

impl ClientConfig {
  pub fn new() -> ClientConfig {
    ClientConfig {
      client_id: "".to_string(),
      client_secret: lattice::Labeled::new("".to_string()),
      device_id: None,
      port: None,
    }
  }

  pub fn get_redirect_uri(&self) -> String {
    format!("http://localhost:{}/callback", self.get_port())
  }

  pub fn get_port(&self) -> u16 {
    self.port.unwrap_or(DEFAULT_PORT)
  }

  pub fn get_or_build_paths(&self) -> Result<ConfigPaths> {
    match dirs::home_dir() {
      Some(home) => {
        let path = Path::new(&home);
        let home_config_dir = path.join(CONFIG_DIR);
        let app_config_dir = home_config_dir.join(APP_CONFIG_DIR);

        if !home_config_dir.exists() {
          fs::create_dir(&home_config_dir)?;
        }

        if !app_config_dir.exists() {
          fs::create_dir(&app_config_dir)?;
        }

        let config_file_path = &app_config_dir.join(FILE_NAME);
        let token_cache_path = &app_config_dir.join(TOKEN_CACHE_FILE);

        let paths = ConfigPaths {
          config_file_path: config_file_path.to_path_buf(),
          token_cache_path: token_cache_path.to_path_buf(),
        };

        Ok(paths)
      }
      None => Err(anyhow!("No $HOME directory found for client config")),
    }
  }

  pub fn set_device_id(&mut self, device_id: String) -> Result<()> {
    let paths = self.get_or_build_paths()?;
    let config_file = SecureFile::<A>::open(paths.config_file_path);
    let config_string = mcall!(config_file.read_to_string()?);
    let mut config_plain = fcall!(serde_yaml::from_str::<ClientConfigSerde>(&config_string)?);

    self.device_id = Some(device_id.clone());
    config_plain = mcall!(config_plain.with_device_id(device_id));

    let new_config = fcall!(serde_yaml::to_string(&config_plain)?);
    mcall!(config_file.write(&new_config)?);

    Ok(())
  }

  pub fn load_config(&mut self) -> Result<std::time::Instant> {
    let paths = self.get_or_build_paths()?;

    if paths.config_file_path.exists() {
      let config_file = SecureFile::<A>::open(paths.config_file_path);
      let config_string = mcall!(config_file.read_to_string()?);
      let start = std::time::Instant::now();
      let config_plain = fcall!(serde_yaml::from_str::<ClientConfigSerde>(&config_string)?);

      self.client_secret = mcall!(config_plain.client_secret_cloned());
      let cfg: ClientConfigSerde = declassify(config_plain);
      self.client_id = cfg.client_id;
      self.device_id = cfg.device_id;
      self.port = cfg.port;

      Ok(start)
    } else {
      if cfg!(debug_assertions) {
        println!("{}", BANNER);
        println!(
          "Config will be saved to {}",
          paths.config_file_path.display()
        );
        println!("\nHow to get setup:\n");

        let instructions = [
          "Go to the Spotify dashboard - https://developer.spotify.com/dashboard/applications",
          "Click `Create a Client ID` and create an app",
          "Now click `Edit Settings`",
          &format!(
            "Add `http://localhost:{}/callback` to the Redirect URIs",
            DEFAULT_PORT
          ),
          "You are now ready to authenticate with Spotify!",
        ];
        let mut number = 1;
        for item in instructions.iter() {
          println!("  {}. {}", number, item);
          number += 1;
        }
      }
      let client_id = declassify(ClientConfig::get_client_key_from_input("Client ID")?);
      let client_secret = ClientConfig::get_client_key_from_input("Client Secret")?;

      let mut port = String::new();
      #[cfg(debug_assertions)]
      println!("\nEnter port of redirect uri (default {}): ", DEFAULT_PORT);
      stdin().read_line(&mut port)?;
      let port = port.trim().parse::<u16>().unwrap_or(DEFAULT_PORT);

      let config_plain = relabel!(
        ClientConfigSerde {
          client_id,
          client_secret: declassify(client_secret),
          device_id: None,
          port: Some(port),
        },
        A
      );
      let content_yml = fcall!(serde_yaml::to_string(&config_plain)?);
      let config_file = SecureFile::<A>::open(paths.config_file_path);
      mcall!(config_file.write(&content_yml)?);

      self.client_secret = mcall!(config_plain.client_secret_cloned());
      let cfg: ClientConfigSerde = declassify(config_plain);
      self.client_id = cfg.client_id;
      self.device_id = cfg.device_id;
      self.port = cfg.port;

      Ok(std::time::Instant::now())
    }
  }

  fn get_client_key_from_input(type_label: &'static str) -> Result<Labeled<String, A>> {
    let mut raw_key = String::new();
    const MAX_RETRIES: u8 = 5;
    let mut num_retries = 0;
    loop {
      #[cfg(debug_assertions)]
      println!("\nEnter your {}: ", type_label);
      stdin().read_line(&mut raw_key)?;
      raw_key = raw_key.trim().to_string();
      let client_key = Labeled::<String, A>::new(raw_key.clone());
      match ClientConfig::validate_client_key(&client_key).declassify_ref() {
        Ok(_) => return Ok(client_key),
        Err(error_string) => {
          println!("{}", error_string);
          raw_key.clear();
          num_retries += 1;
          if num_retries == MAX_RETRIES {
            return Err(Error::from(std::io::Error::new(
              std::io::ErrorKind::Other,
              format!("Maximum retries ({}) exceeded.", MAX_RETRIES),
            )));
          }
        }
      };
    }
  }

  pub fn validate_client_key(key: &Labeled<String, A>) -> Labeled<Result<()>, A> {
    const EXPECTED_LEN: usize = 32;
    let len = mcall!(key.len());
    let is_all_hex = mcall!(key.chars().all(|c| c.is_ascii_hexdigit()));
    let len_err: Labeled<Result<()>, A> = Labeled::new(Err(Error::from(std::io::Error::new(
      std::io::ErrorKind::InvalidInput,
      "invalid length (must be 32 hex digits)",
    ))));
    let hex_err: Labeled<Result<()>, A> = Labeled::new(Err(Error::from(std::io::Error::new(
      std::io::ErrorKind::InvalidInput,
      "invalid character found (must be hex digits)",
    ))));
    let mut result: Labeled<Result<()>, A> = Labeled::new(Ok(()));
    pc_block! { (A) {
      
      if len != EXPECTED_LEN {
        result = len_err;
      }
      if !is_all_hex {
        result = hex_err;
      }
    } };
    result
  }
}
