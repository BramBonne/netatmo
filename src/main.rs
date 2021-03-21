use anyhow::{anyhow, Context, Result};
use chrono::{Local, TimeZone};
use clap::{Arg, App};
use config::Config;
use reqwest;
use serde::Deserialize;
use std::io::prelude::*;
use std::path::Path;
use std::thread;
use std::time::Duration;

const DEFAULT_CONFIG_FILE_PATH: &str = ".config/healthyhome/config.toml";
const DEFAULT_UPDATE_INTERVAL: &str = "0";
const API_TOKEN_URL: &str = "https://api.netatmo.com/oauth2/token";
const API_HOMECOACH_DATA_URL: &str = "https://api.netatmo.com/api/gethomecoachsdata";

#[derive(Debug, Deserialize, Clone)]
struct Settings {
    username: String,
    password: String,
    client_id: String,
    client_secret: String,
    mac_address: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

#[derive(Debug, Deserialize, Copy, Clone)]
struct DashboardData {
    time_utc: i64,
    #[serde(rename = "Temperature")]
    temperature: f32,
    #[serde(rename = "CO2")]
    co2: u32,
    #[serde(rename = "Humidity")]
    humidity: f32,
    #[serde(rename = "Noise")]
    noise: f32,
}
#[derive(Deserialize, Debug)]
struct Device {
    dashboard_data: DashboardData,
}
#[derive(Deserialize, Debug)]
struct HealthyHomeBody {
    devices: Vec<Device>,
}
#[derive(Deserialize, Debug)]
struct HealthyHomeResponse {
    body: HealthyHomeBody,
}

fn retrieve_device_data(config: &Settings) -> Result<DashboardData> {
    let client = reqwest::blocking::Client::new();

    let token_params = reqwest::blocking::multipart::Form::new()
        .text("grant_type", "password")
        .text("username", config.username.clone())
        .text("password", config.password.clone())
        .text("client_id", config.client_id.clone())
        .text("client_secret", config.client_secret.clone())
        .text("scope", "read_homecoach");
    let token_response: TokenResponse = client
        .post(API_TOKEN_URL)
        .multipart(token_params)
        .send()
        .context("Could not get auth token response")?
        .json()
        .context("Could not parse auth token json")?;
    let access_token = token_response.access_token;

    let request_params = reqwest::blocking::multipart::Form::new()
        .text("access_token", access_token)
        .text("device_id", config.mac_address.clone());
    let homecoach_response: HealthyHomeResponse = client
        .post(API_HOMECOACH_DATA_URL)
        .multipart(request_params)
        .send()
        .context("Could not get homecoach response")?
        .json()
        .context("Could not parse homecoach response")?;

    match homecoach_response.body.devices.get(0) {
        Some(device) => Ok(device.dashboard_data),
        None => Err(anyhow!("No device returned by server")),
    }
}

fn maybe_colorize<T: PartialOrd>(format_string: String, value: T, high_bound: T) -> String {
    if value < high_bound {
        format_string
    } else {
        format!("<span color='#FF0000'>{}</span>", format_string)
    }
}

fn update_values(settings: &Settings, output_filename: Option<&str>) -> Result<()> {
    let device_data = retrieve_device_data(&settings)?;

    let formatted = format!(
        " {} {} 💧 {}%",
        maybe_colorize(format!("☁️ {} ppm", device_data.co2), device_data.co2, 1000),
        maybe_colorize(
            format!("🌡️ {} °C", device_data.temperature),
            device_data.temperature,
            27.0
        ),
        device_data.humidity,
        /*maybe_colorize(
            format!("🗣️ {} dB", device_data.noise),
            device_data.noise,
            70.0
        ),*/
        //Local.timestamp(device_data.time_utc, 0).format("%H:%M")
    );
    println!("{}", formatted);

    if let Some(path) = output_filename {
        let mut out_file = std::fs::File::create(Path::new(path))?;
        out_file.write_all(formatted.as_bytes())?;
    }

    Ok(())
}

fn main() {
    let args = App::new("HealthyHome poller")
        .version("0.1.0")
        .author("Bram Bonné")
        .about("Regularly polls for new HealthyHome values, and stores them in a file")
        .arg(Arg::with_name("config_file")
                 .short("c")
                 .long("config_file")
                 .takes_value(true)
                 .default_value(DEFAULT_CONFIG_FILE_PATH)
                 .help("File containing the configuration values"))
        .arg(Arg::with_name("update_interval")
                 .short("i")
                 .long("update_interval")
                 .takes_value(true)
                 .default_value(DEFAULT_UPDATE_INTERVAL)
                 .help("Polling interval, in seconds. Set to 0 for single-shot."))
        .arg(Arg::with_name("output_file")
                 .short("o")
                 .long("output_file")
                 .takes_value(true)
                 .help("Optional file to write retrieved values to"))
        .get_matches();

    let update_interval = args.value_of("update_interval").unwrap().parse::<u64>().unwrap();
    let config_filename = args.value_of("config_file").unwrap();
    let mut config = Config::new();
    config.merge(config::File::with_name(config_filename)).unwrap();
    let settings = config.try_into::<Settings>().expect(&format!("Could not parse {}", config_filename));

    if update_interval > 0 {
        loop {
            match update_values(&settings, args.value_of("output_file")) {
                Ok(_) => println!("Successfully updated"),
                Err(error) => eprintln!("Error when updating: {:?}", error),
            }
            thread::sleep(Duration::from_secs(update_interval));
        }
    } else {
        update_values(&settings, args.value_of("output_file")).unwrap()
    }
}
