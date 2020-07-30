
use serde::{ Serialize, Deserialize };
use biscuit::*;
use biscuit::jws::*;
use biscuit::jwa::SignatureAlgorithm;
use chrono::{ Utc, Duration } ;

use std::io::BufReader;
use std::fs::File;
use std::path::Path;
use std::convert::AsRef;

#[derive(Clone, Deserialize)]
pub struct FirebaseConfig {
    pub project_id: String,
    pub privileged_firebase_uids: Vec<String>,
    pub public_keys_ids: Vec<String>,
    pub public_keys_files: Vec<String>,
    #[serde(skip_deserializing)]
    pub public_keys: Vec<Secret>,
}

pub fn load_firebase_config<P: AsRef<Path>>(path: Option<P>) -> Option<FirebaseConfig>{
    match path {
        Some(p) => { 
            let file = BufReader::new(File::open(p.as_ref()).ok()?);
            let mut config: FirebaseConfig = serde_json::from_reader(file).ok()?;
            let keys_opt: Option<Vec<Secret>> = config.public_keys_files.iter()
                .map(|kf| Secret::public_key_from_file(kf).ok())
                .collect();
            match keys_opt {
                Some(keys) => config.public_keys = keys,
                _ => return None,
            }
            Some(config)
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

    let key_id_idx = key_id.and_then(|k| firebase_config.public_keys_ids.iter()
        .position(|id| id.as_str() == k.as_str()));
        // public_key.is_none() 
    if key_id_idx.is_none() || algorithm != SignatureAlgorithm::RS256 {
        let bad_status = AuthenticateFirebaseStatus::InvalidHeader(
            format!("Invalid header constraints - received algorithm = {:?}", 
            algorithm));
            return Ok(bad_status);
        }
    
    let public_key = &firebase_config.public_keys[key_id_idx.unwrap()];

    //verify signature and get fields from payload
    let (_, payload) = match token.decode(public_key, algorithm) {
        Ok(parsed_data) => parsed_data.unwrap_decoded(),
        Err(jwt_e) => return Ok(AuthenticateFirebaseStatus::InvalidSignature(
            format!("Signature error: {}", jwt_e.to_string()))),
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
    let expected_issuer = format!("https://securetoken.google.com/{}", firebase_config.project_id);
    let expected_audience = firebase_config.project_id.clone();
    
    let check_expiry = expiry.map_or(false, 
        |exp| exp.timestamp() > Utc::now().checked_sub_signed(Duration::days(10)).unwrap().timestamp()); // TODO(laralex): sub only for debug
    let check_issued_at = issued_at.map_or(false, |at| at.timestamp() < Utc::now().timestamp());
    let check_issuer = issuer.is_some() && issuer.unwrap() == expected_issuer;
    let check_audience =  audience.is_some() && if let SingleOrMultiple::Single(aud) = audience.unwrap() { 
        aud == expected_audience 
    } else { 
        false 
    };
    let check_auth_time = auth_time.timestamp() < Utc::now().timestamp();
    let check_subject = subject.is_some() && firebase_config.privileged_firebase_uids.iter()
        .any(|uid| uid == subject.as_ref().unwrap());
    
    let payload_verification = check_expiry && check_issued_at && check_issuer && check_audience && check_auth_time && check_subject;
    if !payload_verification {
        let bad_status = AuthenticateFirebaseStatus::InvalidPayload(format!("Invalid payload constraints"));
        return Ok(bad_status);
    }

    Ok(AuthenticateFirebaseStatus::Uid(subject.unwrap().to_string()))
}

