use std::error::Error;
use std::fs;

use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::stack::Stack;
use openssl::x509::extension::{BasicConstraints, KeyUsage, SubjectKeyIdentifier};
use openssl::x509::{X509Name, X509NameBuilder, X509Req, X509ReqBuilder, X509};
use rand::random;
use tempdir::TempDir;

/* TODO: 17-Nov-2023 Provide a "provision" command sample code as a standalone module,
 *       in this crate or another, to allow for Rust programmatic provision of
 *       TLS configurations of this MQTT broker and client
 */

/// Generate a key pair (i.e., private key and CSR) for the client or server
pub fn openssl_rsa_key_pair(is_server: bool) -> Result<(PKey<Private>, X509Req), Box<dyn Error>> {
    let private_key = generate_rsa_private_pkey()?;

    let name = rumqtt_x509_name();

    let mut req_builder = X509ReqBuilder::new()?;
    req_builder.set_pubkey(&private_key)?;
    req_builder.set_subject_name(&name)?;
    req_builder.sign(&private_key, MessageDigest::sha256())?;

    if is_server {
        let ip_address_san = openssl::x509::extension::SubjectAlternativeName::new()
            .dns("localhost")
            .build(&req_builder.x509v3_context(None))?;

        let key_usage = KeyUsage::new()
            .key_encipherment()
            .digital_signature()
            .build()?;

        // ext key usage for server auth
        let ext_key_usage = openssl::x509::extension::ExtendedKeyUsage::new()
            .server_auth()
            .build()?;

        let mut extensions = Stack::new().unwrap();
        extensions.push(key_usage).unwrap();
        extensions.push(ext_key_usage).unwrap();
        extensions.push(ip_address_san).unwrap();

        req_builder.add_extensions(&extensions).unwrap();
    } else {
        /* from provision.go
            ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
            KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
        */

        let device_id = "9";

        let key_usage = KeyUsage::new()
            .key_encipherment()
            .digital_signature()
            .build()?;

        let ext_key_usage = openssl::x509::extension::ExtendedKeyUsage::new()
            .client_auth()
            .build()?;

        let device_id_san = openssl::x509::extension::SubjectAlternativeName::new()
            .dns(device_id)
            .build(&req_builder.x509v3_context(None))?;

        let mut extensions = Stack::new().unwrap();
        extensions.push(key_usage).unwrap();
        extensions.push(ext_key_usage).unwrap();
        extensions.push(device_id_san).unwrap();

        // CN: device_id
        req_builder.set_subject_name(&name)?;

        req_builder.add_extensions(&extensions).unwrap();
    }

    let req = req_builder.build();

    Ok((private_key, req))
}

fn generate_rsa_private_pkey() -> Result<PKey<Private>, Box<dyn Error>> {
    let rsa = Rsa::generate(2048)?;
    let private_key = PKey::from_rsa(rsa)?;
    Ok(private_key)
}

///
pub fn openssl_ecc_ca() -> Result<(X509, PKey<Private>), Box<dyn Error>> {
    let key_pair = generate_ec_private_pkey()?;

    let mut x509_name = X509NameBuilder::new()?;
    // XZ = international waters
    x509_name.append_entry_by_text("C", "XZ")?;
    // x509_name.append_entry_by_text("O", "Rumqtt Team")?;
    x509_name.append_entry_by_text("CN", "localhost")?;
    let x509_name = x509_name.build();

    let mut cert_builder = X509::builder()?;
    cert_builder.set_version(2)?;
    let serial_number = {
        let serial = BigNum::from_u32(2023)?;
        // let mut serial = BigNum::new()?;
        //     serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
        serial.to_asn1_integer()?
    };
    cert_builder.set_serial_number(&serial_number)?;
    cert_builder.set_subject_name(&x509_name)?;
    cert_builder.set_issuer_name(&x509_name)?;
    cert_builder.set_pubkey(&key_pair)?;
    let not_before = Asn1Time::days_from_now(0)?;
    cert_builder.set_not_before(&not_before)?;
    let not_after = Asn1Time::days_from_now(365)?;
    cert_builder.set_not_after(&not_after)?;

    cert_builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
    /* x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign */
    cert_builder.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .digital_signature()
            .build()?,
    )?;

    let subject_key_identifier =
        SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(None, None))?;
    cert_builder.append_extension(subject_key_identifier)?;

    cert_builder.sign(&key_pair, MessageDigest::sha256())?;
    let cert = cert_builder.build();

    Ok((cert, key_pair))
}

fn generate_ec_private_pkey() -> Result<PKey<Private>, Box<dyn Error>> {
    let group_ref = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1)?;
    let ecc = openssl::ec::EcKey::generate(group_ref.as_ref())?;

    let key_pair = PKey::from_ec_key(ecc)?;
    Ok(key_pair)
}

pub fn openssl_rsa_ca() -> Result<(X509, PKey<Private>), Box<dyn Error>> {
    let rsa = Rsa::generate(2048)?;
    let key_pair = PKey::from_rsa(rsa)?;

    let mut x509_name = X509NameBuilder::new()?;
    // XZ = international waters
    x509_name.append_entry_by_text("C", "XZ")?;
    // x509_name.append_entry_by_text("O", "Rumqtt Team")?;
    x509_name.append_entry_by_text("CN", "localhost")?;
    let x509_name = x509_name.build();

    let mut cert_builder = X509::builder()?;
    cert_builder.set_version(2)?;
    let serial_number = {
        let serial = BigNum::from_u32(2023)?;
        // let mut serial = BigNum::new()?;
        //     serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
        serial.to_asn1_integer()?
    };
    cert_builder.set_serial_number(&serial_number)?;
    cert_builder.set_subject_name(&x509_name)?;
    cert_builder.set_issuer_name(&x509_name)?;
    cert_builder.set_pubkey(&key_pair)?;
    let not_before = Asn1Time::days_from_now(0)?;
    cert_builder.set_not_before(&not_before)?;
    let not_after = Asn1Time::days_from_now(365)?;
    cert_builder.set_not_after(&not_after)?;

    cert_builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
    /* x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign */
    cert_builder.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .digital_signature()
            .build()?,
    )?;

    let subject_key_identifier =
        SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(None, None))?;
    cert_builder.append_extension(subject_key_identifier)?;

    cert_builder.sign(&key_pair, MessageDigest::sha256())?;
    let cert = cert_builder.build();

    Ok((cert, key_pair))
}

fn rumqtt_x509_name() -> X509Name {
    let mut x509_name = X509NameBuilder::new().unwrap();
    x509_name.append_entry_by_text("C", "XZ").unwrap();
    // x509_name.append_entry_by_text("CN", "localhost").unwrap();
    x509_name.build()
}

// Sign the CSR with the CA
pub fn sign_csr_with_ca(
    ca_cert: &X509,
    ca_private_key: &PKey<Private>,
    csr: &X509Req,
) -> Result<X509, Box<dyn Error>> {
    let mut builder = X509::builder()?;

    builder.set_version(2)?;
    builder.set_subject_name(csr.subject_name())?;
    builder.set_issuer_name(ca_cert.subject_name())?;
    let csr_public_key = csr.public_key()?;

    builder.set_pubkey(&csr_public_key.as_ref())?;

    // dns from csr
    builder.append_extension(
        openssl::x509::extension::SubjectAlternativeName::new()
            .dns("localhost")
            .build(&builder.x509v3_context(Some(ca_cert), None))?,
    )?;

    // Set the certificate validity period here
    let start_time = Asn1Time::days_from_now(0)?;
    let end_time = Asn1Time::days_from_now(7)?;
    builder.set_not_before(start_time.as_ref())?;
    builder.set_not_after(end_time.as_ref())?;

    builder.sign(&ca_private_key, MessageDigest::sha256())?;

    let certificate = builder.build();
    Ok(certificate)
}

pub struct KeyAndCertificatePaths {
    pub(crate) private_key_path: String,
    pub(crate) certificate_path: String,
}

// pub fn save_private_key(temp_dir: TempDir, private_key: &PKey<Private>) -> String {
//     let private_key_pkcs8 = private_key
//         .private_key_to_pkcs8()
//         .expect("Failed to convert private key to pkcs8");
//
//     let private_key_path = temp_dir.path().join("private_key.pem");
//
//     fs::write(&private_key_path, private_key_pkcs8).expect("Failed to write private key to file");
//     private_key_path.to_str().unwrap().to_owned()
// }

/// private, public
pub fn save_key_pair(temp_dir: &TempDir, pair: (&PKey<Private>, &X509)) -> KeyAndCertificatePaths {
    let random_id = random::<u16>();
    let private_key = pair.0;
    let public_key = pair.1;

    let private_key_pem = private_key
        .private_key_to_pem_pkcs8()
        .expect("Failed to generate private key pem");
    let public_key_pem = public_key
        .to_pem()
        .expect("Failed to convert public key to pem");

    let private_key_path = temp_dir
        .path()
        .join(format!("private_key_{}.pem", random_id));
    fs::write(&private_key_path, private_key_pem).expect("Failed to write private key to file");

    let public_key_path = temp_dir
        .path()
        .join(format!("public_key_{}.pem", random_id));
    fs::write(&public_key_path, public_key_pem).expect("Failed to write public key to file");

    KeyAndCertificatePaths {
        private_key_path: private_key_path.to_str().unwrap().to_owned(),
        certificate_path: public_key_path.to_str().unwrap().to_owned(),
    }
}

#[cfg(test)]
mod test {
    use crate::keygen::openssl_rsa_ca;

    #[test]
    fn rsa_ca_should_correctly_generate_pem() {
        let (certificate, private) = openssl_rsa_ca().expect("Failed to generate CA");
        let private_pem = private
            .private_key_to_pem_pkcs8()
            .expect("Failed to generate private key pem");

        let key_string = String::from_utf8(private_pem).expect("Failed to convert to string");

        let mut lines = key_string.lines();
        let first_line = lines.next().unwrap();
        let last_line = lines.last().unwrap();

        assert_eq!(first_line, "-----BEGIN PRIVATE KEY-----");
        assert_eq!(last_line, "-----END PRIVATE KEY-----");
    }
}

pub(crate) fn save_x509_cert(
    temp_dir: &TempDir,
    certificate: &X509,
) -> Result<String, Box<dyn Error>> {
    let random_id = random::<u16>();
    let cert_pem = certificate.to_pem()?;
    let cert_path = temp_dir.path().join(format!("cert_{}.pem", random_id));
    fs::write(&cert_path, cert_pem).expect("Failed to write cert to file");
    Ok(cert_path.to_str().unwrap().to_owned())
}

/// Provide the necessary keys (CA, client, server) and certs (CA, client, server) for the broker
pub fn provide_broker_crypto_rsa() -> (
    /* certificate authority*/
    PKey<Private>,
    X509,
    /* client */
    PKey<Private>,
    X509,
    /* server */
    PKey<Private>,
    X509,
) {
    let (ca_x509_cert, ca_private_key) = openssl_rsa_ca().expect("Failed to generate CA");

    // Generate signed key pairs for client and server
    let (client_private_key, client_signed_cert) =
        generate_signed_key_pair(&ca_private_key, &ca_x509_cert, false);
    let (server_private_key, server_signed_cert) =
        generate_signed_key_pair(&ca_private_key, &ca_x509_cert, true);

    (
        ca_private_key,
        ca_x509_cert,
        client_private_key,
        client_signed_cert,
        server_private_key,
        server_signed_cert,
    )
}

fn generate_signed_key_pair(
    ca_private_key: &PKey<Private>,
    ca_x509_cert: &X509,
    is_server: bool,
) -> (PKey<Private>, X509) {
    // 1. Generate the client or server key and CSR
    let (client_private_key, csr) =
        openssl_rsa_key_pair(is_server).expect("Failed to generate key pair");

    // 2. sign the CSR with the CA
    let client_signed_cert =
        sign_csr_with_ca(&ca_x509_cert, &ca_private_key, &csr).expect("Failed to sign CSR");
    (client_private_key, client_signed_cert)
}
