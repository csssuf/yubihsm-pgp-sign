extern crate asn1;
extern crate clap;
extern crate digest;
extern crate failure;
extern crate gcrypt;
extern crate pretty_good;
extern crate sha2;
extern crate yubihsm;

use asn1::ObjectIdentifier;
use clap::{App, Arg, ArgMatches};
use failure::Error;
use gcrypt::mpi::integer::{Format, Integer};
use pretty_good::*;
use yubihsm::Yubihsm;

use std::fs::File;
use std::io::{Read, Write};

fn main() {
    let matches = App::new("HSM Payload Builder")
        .version("0.1.0")
        .author("James Forcier <james.forcier@coreos.com>")
        .arg(
            Arg::with_name("INPUT")
                .takes_value(true)
                .required(true)
                .value_name("INFILE")
                .help("File to generate payload for"),
        )
        .arg(
            Arg::with_name("OUTPUT")
                .takes_value(true)
                .required(true)
                .value_name("OUTFILE")
                .help("File to output payload to"),
        )
        .arg(
            Arg::with_name("AUTHKEY")
                .takes_value(true)
                .required(true)
                .value_name("AUTHKEY")
                .help("Authentication key ID for YubiHSM"),
        )
        .arg(
            Arg::with_name("PASSWORD")
                .takes_value(true)
                .required(true)
                .value_name("PASSWORD")
                .help("Password for HSM Authkey"),
        )
        .arg(
            Arg::with_name("SIGNINGKEY")
                .takes_value(true)
                .required(true)
                .value_name("SIGNINGKEY")
                .help("Signing key ID for YubiHSM"),
        )
        .arg(
            Arg::with_name("SIGNER")
                .takes_value(true)
                .required(true)
                .value_name("SIGNER")
                .help("GPG key ID of signer (e.g. 0x9542AC516CCAA1DF)"),
        )
        .get_matches();

    if let Err(ref e) = run(&matches) {
        use std::io::Write;
        let stderr = &mut ::std::io::stderr();
        let errmsg = "Error writing to stderr";

        writeln!(stderr, "{}", e).expect(errmsg);
        ::std::process::exit(1);
    }
}

fn run(matches: &ArgMatches) -> Result<(), Error> {
    let infile = matches.value_of("INPUT").unwrap();
    let outfile = matches.value_of("OUTPUT").unwrap();
    let auth_key = matches.value_of("AUTHKEY").unwrap().parse()?;
    let password = matches.value_of("PASSWORD").unwrap();
    let signing_key = matches.value_of("SIGNINGKEY").unwrap().parse()?;
    let signer = u64::from_str_radix(&matches.value_of("SIGNER").unwrap()[2..], 16)?;

    let mut signature = SignaturePacket::new(
        SignatureType::BinaryDocument,
        PublicKeyAlgorithm::Rsa,
        HashAlgorithm::Sha256
    )?;
    signature.set_signer(signer);

    let mut file = File::open(infile)?;
    let mut file_contents: Vec<u8> = Vec::new();
    file.read_to_end(&mut file_contents)?;

    let hash = signature.signable_payload(file_contents)?;

    let digestinfo = add_digestinfo(&hash)?;
 
    let hsm_signature = hsm_sign(&digestinfo, auth_key, password, signing_key)?;
    let hsm_signature_mpi = Integer::from_bytes(Format::Unsigned, hsm_signature)?;
    signature.set_contents(Signature::Rsa(hsm_signature_mpi))?;

    let pgp_signature = Packet::Signature(signature).to_bytes()?;
    let mut output = File::create(outfile)?;
    output.write_all(&pgp_signature)?;

    Ok(())
}

fn add_digestinfo(hash: &[u8]) -> Result<Vec<u8>, Error> {
    let sha256_oid = ObjectIdentifier::new(vec![2, 16, 840, 1, 101, 3, 4, 2, 1]).unwrap();

    let digestinfo = asn1::to_vec(|s| {
        s.write_sequence(|seq| {
            seq.write_sequence(|internal_seq| {
                internal_seq.write_object_identifier(sha256_oid.clone());
                internal_seq.write_null();
            });
            seq.write_octet_string(hash);
        });
    });

    Ok(digestinfo)
}

fn hsm_sign(
    digestinfo: &[u8],
    auth_key: u16,
    password: &str,
    signing_key: u16,
) -> Result<Vec<u8>, Error> {
    let yubihsm_lib = Yubihsm::new()?;
    let connector = yubihsm_lib.create_connector("http://127.0.0.1:12345")?;
    connector.connect()?;
    let session = connector.create_session_from_password(auth_key, password, false)?;

    let signature = session.sign_pkcs1v1_5(signing_key, false, digestinfo)?;
    Ok(signature)
}
