
use serde::{ Serialize, Deserialize };
use biscuit::*;
use biscuit::jws::*;
use biscuit::jwa::SignatureAlgorithm;
use chrono::{ Utc, Duration } ;

use std::io::BufReader;
use std::fs::File;
use std::path::Path;
use std::convert::AsRef;
use std::str::FromStr;

#[derive(Clone, Deserialize)]
pub struct FirebaseConfig {
    pub project_id: String,
    pub privileged_firebase_uids: Vec<String>,
    pub public_key_ids: Vec<String>,
    pub public_keys: Vec<String>,
}

pub fn load_firebase_config<P: AsRef<Path>>(path: Option<P>) -> Option<FirebaseConfig>{
    match path {
        Some(p) => { 
            let file = BufReader::new(File::open(p.as_ref()).ok()?);
            Some(serde_json::from_reader(file).ok()?)
        },
        _ => None,
    }
}

pub enum AuthenticateFirebaseStatus {
    InvalidHeader(String),
    InvalidPayload(String),
    InvalidSignature(String),
    Uid(String),
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadExtras {
    pub auth_time: Timestamp,
    //pub sub: String,
}

pub fn authenticate(token: &str, firebase_config: &FirebaseConfig) -> Result<AuthenticateFirebaseStatus, biscuit::errors::Error> {
    let token = JWT::<PayloadExtras, Empty>::new_encoded(&token);

    // get header before verifying signature 
    // (because we need "kid" from header to get public key)
    let Header { 
        registered: RegisteredHeader {
            algorithm,
            key_id,
            ..
        }, 
        .. 
    } = token.unverified_header()?;

    // verify header
    let key_id_idx = key_id.and_then(|k| 
        firebase_config.public_key_ids.iter().position(|id| id == k.as_str()));

    if key_id_idx.is_none() || algorithm != SignatureAlgorithm::RS256 {
        let bad_status = AuthenticateFirebaseStatus::InvalidHeader(
            format!("Invalid header constraints - received key_id_idx = {:?}, algorithm = {:?}", 
            key_id_idx, algorithm));
        return Ok(bad_status);
    }

    //verify signature and get fields from payload
    let public_key_str = firebase_config.public_keys[key_id_idx.unwrap()].as_str();
    let public_key = Secret::PublicKey(public_key_str.into());
    let (_, payload) = match token.decode(&public_key, algorithm) {
        Ok(parsed_data) => parsed_data.unwrap_decoded(),
        Err(jwt_e) => return Ok(AuthenticateFirebaseStatus::InvalidSignature(
            format!("Signature error: {}; pub_key: {}", jwt_e.to_string(), public_key_str))),
    };

    let ClaimsSet {
        registered: RegisteredClaims {
            expiry,
            issued_at,
            issuer,
            audience,
            subject,
            ..
        },
        private: PayloadExtras { auth_time },
    } = payload; //= token.unverified_payload()?;

    // verify payload
    let expected_issuer: StringOrUri = FromStr::from_str(
        format!("https://securetoken.google.com/{}", firebase_config.project_id).as_str()
    ).unwrap();
    let expected_audience: StringOrUri = FromStr::from_str(firebase_config.project_id.as_str()).unwrap();
    
    let check_expiry = expiry.map_or(false, 
        |exp| exp.timestamp() > Utc::now().checked_sub_signed(Duration::days(10)).unwrap().timestamp()); // TODO(laralex): sub only for debug
    let check_issued_at = issued_at.map_or(false, |at| at.timestamp() < Utc::now().timestamp());
    let check_issuer = issuer.as_ref().map_or(false, |iss| iss == &expected_issuer);
    let check_audience =  audience.as_ref().map_or(false, 
        |aud| if let SingleOrMultiple::Single(aud) = aud { aud == &expected_audience } else { false} );
    let check_auth_time = auth_time.timestamp() < Utc::now().timestamp();
    let check_subject = subject.is_some() && firebase_config.privileged_firebase_uids.iter()
        .any(|uid| uid == subject.as_ref().unwrap().as_ref());
    
    let payload_verification = check_expiry && check_issued_at && check_issuer && check_audience && check_auth_time && check_subject;
    if !payload_verification {
        let bad_status = AuthenticateFirebaseStatus::InvalidPayload(format!("Invalid payload constraints"));
        return Ok(bad_status);
    }

    Ok(AuthenticateFirebaseStatus::Uid(subject.unwrap().to_string()))
}

