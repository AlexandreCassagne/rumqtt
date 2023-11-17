use crate::keygen;
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use rumqttd::{Broker, ServerSettings};
use std::collections::HashMap;
use tempdir::TempDir;

pub fn start_rsa_broker(temp_dir: &TempDir) -> (PKey<Private>, X509, Vec<u8>, Broker) {
    /* I: Certificate Authority */
    let (
        ca_private_key,
        ca_x509_cert,
        client_private_key,
        client_signed_cert,
        server_private_key,
        server_signed_cert,
    ) = keygen::provide_broker_crypto_rsa();

    let ca_x509_cert_pem = ca_x509_cert
        .to_pem()
        .expect("Failed to convert CA cert to PEM");

    /* TODO: Allow rumqttd config to be initialized without a file, for instance with PEM/other formats directly */
    /* Save the CA cert to a file, required per rumqttd config */
    let ca_key_and_cert = keygen::save_key_pair(&temp_dir, (&ca_private_key, &ca_x509_cert));
    let ca_cert_path = ca_key_and_cert.certificate_path;

    /* II. Server Setup */
    let server_key_and_cert =
        keygen::save_key_pair(&temp_dir, (&server_private_key, &server_signed_cert));

    let server_signed_cert_path = server_key_and_cert.certificate_path;
    let server_private_key_path = server_key_and_cert.private_key_path;

    /* Build the rumqttd server settings */
    let v4 = sample_server_config_with_tls(
        &ca_cert_path,
        &server_signed_cert_path,
        &server_private_key_path,
    );

    /* Initialize the broker */
    let mut config = rumqttd::Config::default();
    config.id = 0;
    config.router.max_connections = 1000;
    config.router.max_outgoing_packet_count = 1000;
    config.router.max_segment_size = 1024;
    config.router.max_segment_count = 1000;

    config.v4 = Some(v4);

    let broker = Broker::new(config);
    (
        client_private_key,
        client_signed_cert,
        ca_x509_cert_pem,
        broker,
    )
}

/// Utility method to create a sample server config with TLS.
fn sample_server_config_with_tls(
    ca_cert_path: &str,
    cert_path: &str,
    private_key_path: &str,
) -> HashMap<String, ServerSettings> {
    let toml = format!(
        r#"
    name = "v4-1"
    listen = "0.0.0.0:8883"
    next_connection_delay_ms = 1000
    max_connections = 1000
    
    [connections]
    connection_timeout_ms = 60000
    max_payload_size = 20480
    max_inflight_count = 100
    dynamic_filters = true

    # tls config for rustls
    [tls]
    capath = "{0}"
    certpath = "{1}"
    keypath = "{2}"
    "#,
        ca_cert_path, cert_path, private_key_path
    );

    let settings = toml::from_str::<ServerSettings>(&toml).expect("Failed to parse server config");

    let mut v4 = HashMap::new();
    v4.insert("1".to_owned(), settings);
    v4
}

#[cfg(test)]
mod test {
    use crate::test_broker;
    use rumqttd::TlsConfig;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    /// Verify that the server config is parsed correctly by the utility method
    #[test]
    fn test_server_config_parsed_correctly() {
        let x = test_broker::sample_server_config_with_tls(
            "ca_path.key",
            "cert_path.key",
            "private_key_path.key",
        );
        assert_eq!(x.len(), 1);
        let server_1 = x.get("1").unwrap();
        assert_eq!(server_1.name, "v4-1");
        assert_eq!(
            server_1.listen,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 8883)
        );

        let tls = server_1.tls.clone();
        assert!(tls.is_some());
        let tls_config = tls.unwrap();

        match tls_config {
            TlsConfig::Rustls {
                capath,
                certpath,
                keypath,
            } => {
                assert_eq!(capath, "ca_path.key");
                assert_eq!(certpath, "cert_path.key");
                assert_eq!(keypath, "private_key_path.key");
            }
            TlsConfig::NativeTls { .. } => {
                panic!("Expected Rustls")
            }
        }
    }
}
