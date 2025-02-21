use url::Url;

pub mod config;

fn is_valid_address(str: &str) -> bool {
    let input_with_scheme = if str.contains("://") {
        str.to_string()
    } else {
        format!("http://{}", str)
    };

    Url::parse(&input_with_scheme).is_ok()
}

fn is_valid_port(str: &str) -> bool {
    str.parse::<u16>().map_or(false, |port| port != 0)
}