
use serde::{Serialize, Deserialize, de, Deserializer};
use biscuit::*;
use biscuit::jws::*;
use biscuit::jwa::*;
use chrono::Utc;

use std::io::{ BufRead, BufReader };
use std::fs::File;
use std::path::Path;
use std::convert::AsRef;
use std::str::FromStr;
use std::fmt::Display;

// TODO(laralex): check if keys are updated:
// https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com

static PUBLIC_FIREBASE_KEY_IDS: [&str; 2] = [
    "6cfc235bd610facaec5eb0ade9589da95282decd",
    "554a754778587c94c1673e8ea244616c0c043cbc",
];
static PUBLIC_FIREBASE_KEYS: [&str; 2] = [
        "-----BEGIN CERTIFICATE-----\n
        MIIDHDCCAgSgAwIBAgIIOvZ+ZDrIgmQwDQYJKoZIhvcNAQEFBQAwMTEvMC0GA1UE\n
        AxMmc2VjdXJldG9rZW4uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20wHhcNMjAw\n
        NzI0MDkyMDAxWhcNMjAwODA5MjEzNTAxWjAxMS8wLQYDVQQDEyZzZWN1cmV0b2tl\n
        bi5zeXN0ZW0uZ3NlcnZpY2VhY2NvdW50LmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD\n
        ggEPADCCAQoCggEBANSBPQydBvIITxwMsm0adXL5ToKR6Aihi3fCepGZj1Oq2pdq\n
        r9ObfFcDX4GKHF7w6pm8WXxoZnjO37waSJc1ECmZt11tR0Ei/f0huLqDqNItGWRc\n
        ApogR3Af8C12IwFbxvp5tPj4s8H7Ldnrr97zzXogrTKvQCVJQJE43SfqcOO0T1br\n
        gfskj+G863Uy5JN7S8OijDLFK3YGIIvQDv6jp0tVrRwUUedJ4qET3IVWLkW5jAcd\n
        WAy7/RmIVVZFXuqjyunU6xNd6gLw5uZPZdLjSW9CccFmZQfinuNKyFGLhdF00TMq\n
        Torq8EOjFanRbxRi3mb9g01hVKY8WcsK1CE4RCMCAwEAAaM4MDYwDAYDVR0TAQH/\n
        BAIwADAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwIwDQYJ\n
        KoZIhvcNAQEFBQADggEBAGMRck+Afw3zQF3SqgJ80bCgFJy4CidQuoNuElA673Y+\n
        H4ulR5n/UV3feelR2+q0PvbZIVNf3Y5Yt+AWK9uK3LPprouFnx4U2X+mxsLHlHUC\n
        Kl+wKoLuDvAmiDHu5JIjoYO0el6JJYNVnG3wCrSLLc6ehA32hfngdtJmkDN0/OoM\n
        xmbj7X3JWctiJw0NxmH8wrKbeZLVIsaCwfc8iKjwcqRyA6hUxTobcsNs3IZsYv2W\n
        g/5ZupoI8k2foTq4OdXJH/hkq4N5AyLp9S/RSodW6X+gexxohtgJxGx0gojotMzX\n
        sb7NLsl7DkvjjxTz7I98xaGbfhofgYympeKT6UO+tmc=\n
        -----END CERTIFICATE-----\n",
        "-----BEGIN CERTIFICATE-----\n
        MIIDHDCCAgSgAwIBAgIIW0NcfzWxMhswDQYJKoZIhvcNAQEFBQAwMTEvMC0GA1UE\n
        AxMmc2VjdXJldG9rZW4uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20wHhcNMjAw\n
        NzE2MDkxOTU4WhcNMjAwODAxMjEzNDU4WjAxMS8wLQYDVQQDEyZzZWN1cmV0b2tl\n
        bi5zeXN0ZW0uZ3NlcnZpY2VhY2NvdW50LmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD\n
        ggEPADCCAQoCggEBAKOv8OhUvAjT6sivBM26YV95oz/hdxbclLgNrJY6MFDrCy1A\n
        tDLw5UxBISkT1VkoqtcwdRdtVbxbvcZrq+XF9IK4zez/YjXC3PRKd4CpQbdcQZWQ\n
        VYlY8hTmtSiHD8554vpn1etM2625L5Ts3gGno58y3lGbdxv8AfvBdiI/Y+JUwTep\n
        lRPLfPyPsufGLCCY7tT4B2P6o18L4jv815Tv9ZdkVRRT3v9I6Po+WQ8ojBByX50B\n
        WhhRhMunTZ7lvcNvvYTcmXAgGPxGq7uuA+HXj3kO5X9MQsuGRsBFhV9WrM8QyAgA\n
        BFfgDVcQAWIKGp2/8Tnb/jDONL0Phonw3D1ooUUCAwEAAaM4MDYwDAYDVR0TAQH/\n
        BAIwADAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwIwDQYJ\n
        KoZIhvcNAQEFBQADggEBAE3Bk/OViYN6+B64VQVcVI+GHWzs/1qua3rqA9MxwVPF\n
        D4tSiM31262PpMfQn1CdzZ0gpLKJ3awuWe9tnkK5X9LGqYshwYnYKmyir1rZ5Rww\n
        prex1V080w8vb41IJWzv2iG3LJ0rB8qEkLrsYZX0slRg+g12FTvwwyYzKr+Xt0hE\n
        QB4P5FNL+VLkZgO6ZNgSK0lR8qa6h3jJJHIgTkqL0YGeflcYms37+aE9EtRx/8OD\n
        cB5ni3KY744gFWZw8tG+LKjGHf5HRlIX6iCojXhMHRSy3wbb66sSGyqqyE9tod/z\n
        qo9DuE3rsINE8/2wIvxNEkx3+MKPT+z6eX5Snmv7klM=\n
        -----END CERTIFICATE-----\n",
    ];

#[derive(Clone)]
pub struct FirebaseConfig {
    pub project_id: String,
    pub admin_uids: Vec<String>,
}

pub fn load_firebase_config<P: AsRef<Path>>(path: Option<P>) -> Option<FirebaseConfig>{
    match path {
        Some(p) => { 
            let mut lines = BufReader::new(File::open(p.as_ref()).ok()?).lines();
            let project_id = lines.next()?.ok()?;
            let admin_uids: Vec<_> = lines.filter_map(|result| match result {
                Ok(line) if (1..=36).contains(&line.len()) => Some(line),
                _ => None,
            }).collect();
            if admin_uids.is_empty() { 
                return None; 
            }
            Some(FirebaseConfig {
                project_id,
                admin_uids,
            })  
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
    //#[serde(deserialize_with = "deserialize_from_str")]
    pub auth_time: Timestamp,
    pub sub: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderExtras {
    pub kid: Option<String>,
}

// You can use this deserializer for any type that implements FromStr
// and the FromStr::Err implements Display
fn deserialize_from_str<'de, S, D>(deserializer: D) -> Result<S, D::Error>
where
    S: FromStr,      // Required for S::from_str...
    S::Err: Display, // Required for .map_err(de::Error::custom)
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    S::from_str(&s).map_err(de::Error::custom)
}

pub fn authenticate(token: &str, firebase_config: &FirebaseConfig) -> Result<AuthenticateFirebaseStatus, biscuit::errors::Error> {
    let token = JWT::<PayloadExtras, HeaderExtras>::new_encoded(&token);

    // get header before verifying signature 
    // (because we need "kid" from header to get public key)
    let Header { 
        registered: rfc_header, 
        private: HeaderExtras { kid },
    } = token.unverified_header()?;

    if kid.is_none() {
        return Ok(AuthenticateFirebaseStatus::InvalidHeader("Invalid header, no \"kid\" field".to_string()));
    }
    let kid = kid.unwrap();
    // expected header 
    let expected_rfc_header = RegisteredHeader {
        algorithm: SignatureAlgorithm::RS256,
        ..Default::default()
    };

    // verify header
    let key_id_idx = PUBLIC_FIREBASE_KEY_IDS.iter()
        .position(|&id| id == kid.as_str());
    let header_verification = 
        rfc_header == expected_rfc_header &&
        key_id_idx.is_some();
    if !header_verification {
        let status = AuthenticateFirebaseStatus::InvalidHeader(format!("Invalid header constraints - received key_id = {:?}, algorithm = {:?}", 
            kid, rfc_header.algorithm));
        return Ok(status);
    }

    // verify signature and decode payload
    let public_key = Secret::PublicKey(PUBLIC_FIREBASE_KEYS[key_id_idx.unwrap()].into());
    let (_, payload) = match token.decode(&public_key, SignatureAlgorithm::RS256) {
        Err(jwt_e) => return Ok(AuthenticateFirebaseStatus::InvalidSignature(
            format!("Invalid signature or its parse error: {}", jwt_e.to_string()))),
        Ok(compact) => compact.unwrap_decoded()
    };

    let ClaimsSet {
        registered: rfc_payload,
        private: PayloadExtras { auth_time, sub },
    } = payload;

    // expected payload
    let issuer = Some(FromStr::from_str(
        format!("https://securetoken.google.com/{}", firebase_config.project_id).as_str()
        ).unwrap());
    let audience = Some(SingleOrMultiple::Single(
        FromStr::from_str(
            firebase_config.project_id.as_str()
        ).unwrap()));

    let expected_rfc_payload = RegisteredClaims {
        expiry: Some(Utc::now().into()),
        issued_at: Some(Utc::now().into()),
        audience,
        issuer,
        ..Default::default()
    };

    // verify payload
    let payload_verification = 
        rfc_payload == expected_rfc_payload &&
        auth_time.timestamp() < Utc::now().timestamp() &&
        firebase_config.admin_uids.contains(&sub);
    if !payload_verification {
        let status = AuthenticateFirebaseStatus::InvalidPayload(format!("Invalid payload constraints - received auth_time = {:?}, expiry = {:?}, issued_at = {:?}, audience = {:?}, issuer = {:?}", 
            auth_time.to_rfc3339(), 
            rfc_payload.expiry.and_then(|t| Some(t.to_rfc3339())), 
            rfc_payload.issued_at.and_then(|t| Some(t.to_rfc3339())), 
            rfc_payload.audience, 
            rfc_payload.issuer));
        return Ok(status);
    }

    Ok(AuthenticateFirebaseStatus::Uid(sub.clone()))
}

