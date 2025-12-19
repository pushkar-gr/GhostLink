mod config;

use crate::config::Config;

fn main() {
    let config = Config::load();
    println!("{:?}", config);
}
