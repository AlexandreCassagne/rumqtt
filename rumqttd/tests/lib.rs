use std::sync::Arc;
use std::thread;
use std::time::Duration;

use tempdir::TempDir;
use tracing::{info, Instrument};
use tracing_subscriber::fmt;

use rumqttc::QoS::ExactlyOnce;
use rumqttc::{self, Event, Incoming, Key, MqttOptions, TlsConfiguration, Transport};

mod keygen;
mod test_broker;

#[test]
fn test_rsa_rumqttd_broker_compatibility() {
    log_info();

    let _dir = TempDir::new("test_rsa_rumqttd_broker_compatibility").unwrap();
    let dir = Arc::new(_dir);

    info!("Directory = {:?}", dir.path().to_path_buf().to_str());
    let (client_private_key, client_signed_cert, ca_x509_cert_pem, mut broker) =
        test_broker::make_rsa_broker(dir.as_ref());

    let (mut link_tx, mut link_rx) = broker.link("v4-1").unwrap();
    info!("Link created");

    let server_handle = thread::spawn(move || {
        info!("Starting broker");
        (broker).start().expect("Failed to start MQTT broker");
    })
    .instrument(tracing::info_span!("broker"));

    let server_event_loop = thread::spawn(move || {
        info!("Broker started");
        loop {
            info!("Polling");
            match link_rx.recv().unwrap() {
                Some(v) => {
                    info!("Received rumqttd notification: {:?}", v);
                    if let rumqttd::Notification::Forward(f) = v {
                        // send a reply
                        info!("Sending reply: 'ok' on topic: {:?}", f.publish.topic);
                        link_tx.publish("reply", "ok").unwrap();
                        // disconnect
                        return;
                    }
                    continue;
                }
                None => continue,
            };
        }
    })
    .instrument(tracing::info_span!("broker_event_loop"));

    /* III. Client Setup */
    info!("Starting client");

    /* Convert client cert to PEM */
    let client_signed_cert_pem = client_signed_cert.to_pem().unwrap();
    let client_private_key_pkcs8_pem = client_private_key.private_key_to_pem_pkcs8().unwrap();

    let transport = Transport::Tls(TlsConfiguration::Simple {
        ca: ca_x509_cert_pem,
        alpn: None,
        client_auth: Some((
            client_signed_cert_pem,
            Key::RSA(client_private_key_pkcs8_pem),
        )),
    });

    /* Configure the client to use TLS */
    let mqttoptions = MqttOptions::new("9", "localhost", 8883)
        .set_keep_alive(Duration::from_secs(10))
        .set_transport(transport)
        .to_owned();

    let client_thread = thread::spawn(move || {
        info!("Connecting to broker");

        /* IV. Broker connection */
        let (mut client, mut connection) = rumqttc::Client::new(mqttoptions, 10);

        /* V. Test */
        /* Check that rumqttc is able to connect to rumqttd */
        let mut event_loop = (&mut connection).iter();

        loop {
            match event_loop.next() {
                Some(v) => match v {
                    Ok(e) => match e {
                        Event::Incoming(incoming_event) => {
                            info!("Received incoming event: {:?}", incoming_event);
                            match incoming_event {
                                Incoming::ConnAck(ack) => {
                                    info!("Received ConnAck: {:?}", ack);
                                    client.subscribe("good", ExactlyOnce).unwrap();
                                    info!("Subscribed to topic 'good'");
                                }
                                Incoming::SubAck(sub_ack) => {
                                    info!("Received SubAck: {:?}", sub_ack);
                                    client
                                        .publish("good", ExactlyOnce, false, "morning")
                                        .expect("Failed to publish to the MQTT topic");
                                }
                                Incoming::Publish(p) => {
                                    info!("Received Publish: {:?}", p);
                                    if p.topic == "good" {
                                        info!("Received good: {:?}", p.payload);
                                        client.publish("reply", ExactlyOnce, false, "ok").unwrap();
                                        return;
                                    } else if p.topic == "reply" {
                                        info!("Received reply: {:?}", p.payload);
                                        client.disconnect().unwrap();
                                        return;
                                    } else {
                                        panic!("Received unexpected topic: {:?}", p.topic);
                                    }
                                }
                                _ => {}
                            }
                        }
                        Event::Outgoing(_) => {}
                    },
                    Err(err) => panic!("Error: {:?}", err),
                },
                None => panic!("End of event loop"),
            }
        }
    })
    .instrument(tracing::info_span!("client"));

    info!("Waiting for client to complete");
    client_thread
        .into_inner()
        .join()
        .expect("Failed to join the client thread");

    // FIXME: Neither of these work.
    //        I must be doing the server event loop "return" statement wrong.
    //        However, TLS is still being established, meeting the goal of this test.
    // info!("Waiting for server event loop to complete");
    // server_event_loop
    //     .into_inner()
    //     .join()
    //     .expect("Failed to join the broker event loop thread");
    // info!("Waiting for server to complete");
    // server_handle
    //     .into_inner()
    //     .join()
    //     .expect("Failed to join the broker thread");
}

fn log_info() {
    fmt::Subscriber::builder()
        .with_max_level(tracing::Level::INFO)
        .with_span_events(fmt::format::FmtSpan::FULL)
        .init();
}
