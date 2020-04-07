use anyhow::{anyhow, Result};
use std::env::var;
use std::fs::read_to_string;
use std::path::PathBuf;

const CRED_KEY: &str = "aws_access_key_id";
const CRED_SECRET: &str = "aws_secret_access_key";
const CONF_REGION: &str = "region";

#[derive(Debug)]
pub struct Configuration {
  pub region: String,
  pub key: String,
  pub secret: String,
}

impl Configuration {
  pub fn from_static(region: String, key: String, secret: String) -> Self {
    Self {
      region,
      key,
      secret,
    }
  }

  /// Precedence:
  ///   env vars (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY) (AWS_DEFAULT_REGION)
  ///   profile (AWS_PROFILE)
  ///   default profile
  pub fn auto() -> Result<Self> {
    if let Ok(c) = Self::from_env() {
      Ok(c)
    } else if let Ok(c) = Self::from_profile_env() {
      Ok(c)
    } else if let Ok(c) = Self::from_profile_static("default") {
      Ok(c)
    } else {
      Err(anyhow!("failed to find configuration automatically"))
    }
  }

  pub fn from_env() -> Result<Self> {
    let c = Self {
      region: var("AWS_DEFAULT_REGION")?,
      key: var("AWS_ACCESS_KEY_ID")?,
      secret: var("AWS_SECRET_ACCESS_KEY")?,
    };

    Ok(c)
  }

  pub fn from_profile_static(profile: &str) -> Result<Self> {
    let (cred_path, conf_path) = paths()?;

    let (key, secret) = {
      let cred_raw = read_to_string(cred_path)?;
      let profile_line = format!("[{}]", profile);
      let mut profile_found = false;
      let mut key = None;
      let mut secret = None;

      for line in cred_raw.lines() {
        if line.starts_with("[") {
          if profile_found {
            // profile header should only appear once
            break;
          }

          if line == profile_line {
            profile_found = true;
            continue;
          }
        }

        if profile_found {
          let lp: Vec<&str> = line.split("=").map(|x| x.trim()).collect();
          match lp[..] {
            [CRED_KEY, val] => key = Some(val.to_owned()),
            [CRED_SECRET, val] => secret = Some(val.to_owned()),
            _ => {}
          }
        }
      }

      if !profile_found {
        return Err(anyhow!("profile not found in credentials"));
      }

      (key, secret)
    };

    let region = {
      let config_raw = read_to_string(conf_path)?;
      let profile_line = if profile == "default" {
        "[default]".to_owned()
      } else {
        format!("[profile {}]", profile)
      };
      let mut profile_found = false;
      let mut region = None;

      for line in config_raw.lines() {
        if line.starts_with("[") {
          if profile_found {
            // profile header should only appear once
            break;
          }

          if line == profile_line {
            profile_found = true;
            continue;
          }
        }

        if profile_found {
          let lp: Vec<&str> = line.split("=").map(|x| x.trim()).collect();
          match lp[..] {
            [CONF_REGION, val] => region = Some(val.to_owned()),
            _ => {}
          }
        }
      }

      if !profile_found {
        return Err(anyhow!("profile not found in config"));
      }

      region
    };

    Ok(Self {
      region: region.ok_or(anyhow!("region not found for profile"))?,
      key: key.ok_or(anyhow!("aws_access_key_id not found for profile"))?,
      secret: secret
        .ok_or(anyhow!("aws_secret_access_key not found for profile"))?,
    })
  }

  pub fn from_profile_env() -> Result<Self> {
    let p = var("AWS_PROFILE")?;
    Self::from_profile_static(&p)
  }
}

#[cfg(target_os = "windows")]
fn paths() -> Result<(PathBuf, PathBuf)> {
  let mut config = PathBuf::from(var("HOMEPATH")?);
  config.push(".aws");

  let mut cred = config.clone();
  cred.push("credentials");

  config.push("config");

  Ok((cred, config))
}

#[cfg(not(target_os = "windows"))]
fn paths() -> Result<(PathBuf, PathBuf)> {
  let mut config = PathBuf::from(var("HOME")?);
  config.push(".aws");

  let mut cred = config.clone();
  cred.push("credentials");

  config.push("config");

  Ok((cred, config))
}
