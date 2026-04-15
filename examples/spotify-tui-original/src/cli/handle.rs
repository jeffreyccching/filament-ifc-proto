use crate::network::{IoEvent, Network};
use crate::user_config::UserConfig;

use super::{
  util::{Flag, JumpDirection, Type},
  CliApp,
};

use anyhow::{anyhow, Result};
use clap::ArgMatches;

pub async fn handle_matches(
  matches: &ArgMatches<'_>,
  cmd: String,
  net: Network<'_>,
  config: UserConfig,
) -> Result<String> {
  let mut cli = CliApp::new(net, config);

  cli.net.handle_network_event(IoEvent::GetDevices).await;
  cli
    .net
    .handle_network_event(IoEvent::GetCurrentPlayback)
    .await;

  let devices_list = match &cli.net.app.lock().await.devices {
    Some(p) => p
      .devices
      .iter()
      .map(|d| d.id.clone())
      .collect::<Vec<String>>(),
    None => Vec::new(),
  };

  let device_id = cli.net.client_config.device_id.clone();
  if device_id.is_none() || !devices_list.contains(&device_id.unwrap()) {
    
    if let Some(d) = devices_list.get(0) {
      cli.net.client_config.set_device_id(d.clone())?;
    }
  }

  if let Some(d) = matches.value_of("device") {
    cli.set_device(d.to_string()).await?;
  }

  let output = match cmd.as_str() {
    "playback" => {
      let format = matches.value_of("format").unwrap();

      if matches.is_present("share-track") {
        return cli.share_track_or_episode().await;
      } else if matches.is_present("share-album") {
        return cli.share_album_or_show().await;
      }

      if matches.is_present("toggle") {
        cli.toggle_playback().await;
      }
      if let Some(d) = matches.value_of("transfer") {
        cli.transfer_playback(d).await?;
      }
      
      if matches.is_present("flags") {
        let flags = Flag::from_matches(matches);
        for f in flags {
          cli.mark(f).await?;
        }
      }
      if matches.is_present("jumps") {
        let (direction, amount) = JumpDirection::from_matches(matches);
        for _ in 0..amount {
          cli.jump(&direction).await;
        }
      }
      if let Some(vol) = matches.value_of("volume") {
        cli.volume(vol.to_string()).await?;
      }
      if let Some(secs) = matches.value_of("seek") {
        cli.seek(secs.to_string()).await?;
      }

      cli.get_status(format.to_string()).await
    }
    "play" => {
      let queue = matches.is_present("queue");
      let random = matches.is_present("random");
      let format = matches.value_of("format").unwrap();

      if let Some(uri) = matches.value_of("uri") {
        cli.play_uri(uri.to_string(), queue, random).await;
      } else if let Some(name) = matches.value_of("name") {
        let category = Type::play_from_matches(matches);
        cli.play(name.to_string(), category, queue, random).await?;
      }

      cli.get_status(format.to_string()).await
    }
    "list" => {
      let format = matches.value_of("format").unwrap().to_string();

      if let Some(max) = matches.value_of("limit") {
        cli.update_query_limits(max.to_string()).await?;
      }

      let category = Type::list_from_matches(matches);
      Ok(cli.list(category, &format).await)
    }
    "search" => {
      let format = matches.value_of("format").unwrap().to_string();

      if let Some(max) = matches.value_of("limit") {
        cli.update_query_limits(max.to_string()).await?;
      }

      let category = Type::search_from_matches(matches);
      Ok(
        cli
          .query(
            matches.value_of("search").unwrap().to_string(),
            format,
            category,
          )
          .await,
      )
    }
    
    _ => unreachable!(),
  };

  let api_error = cli.net.app.lock().await.api_error.clone();
  if api_error.is_empty() {
    output
  } else {
    Err(anyhow!("{}", api_error))
  }
}
