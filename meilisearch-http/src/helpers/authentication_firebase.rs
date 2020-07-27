use serde::{Serialize, Deserialize};
use biscuit::*;
use biscuit::jws::*;
use biscuit::jwa::*;
use chrono::Utc;

use std::io::{ BufRead, BufReader };
use std::fs::File;
use std::path::Path;
use std::convert::AsRef;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadExtras {
    auth_time: Timestamp,
    sub: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderExtras {
    key_id: String,
}

// // this is a hack to check if token has one of permitted sub's
// // this is NOT a usable and intuitive PartialEq
// impl<'a, 'b> PartialEq for PrivateClaims<'a> {
//     fn eq(&self, expectation: &'b Self) -> bool {
//         use SingleOrMultiple::*;
//         self.auth_time < expectation.auth_time && match (self.sub, expectation.sub) { 
//             (Single(uid), Multiple(variants)) => variants.iter().any(|variant| variant == uid),
//             _ => false,
//         }
//     }
// }

// impl<'a> Eq for PrivateClaims<'a> { }

// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct PrivateHeader<'a> {
//     key_id: SingleOrMultiple(&'a str),
// }

// // this is a hack to check if token has one of permitted key_id's
// // this is NOT a usable and intuitive PartialEq
// impl<'a, 'b> PartialEq for PrivateHeader<'a> {
//     fn eq(&self, expectation: &'b Self) -> bool {
//         use SingleOrMultiple::*;
//         match (self.key_id, expectation.key_id) { 
//             (Single(key_id), Multiple(variants)) => variants.iter().any(|variant| variant == key_id),
//             _ => false,
//         }
//     }
// }

// impl<'a> Eq for PrivateHeader<'a> { }

pub fn load_admin_uids<P: AsRef<Path>>(path: Option<P>) -> Option<Vec<String>>{
    match path {
        Some(p) => { 
            let uids: Vec<_> = BufReader::new(File::open(p.as_ref()).ok()?).lines()
            .filter_map(|result| match result {
                Ok(line) if (1..=36).contains(&line.len()) => Some(line),
                _ => None,
            })
            .collect();
            if uids.is_empty() { None } else { Some(uids) }  
        },
        _ => None,
    }
}

pub fn authenticate(token: &str, admin_uids: &Vec<String>) -> Result<bool, biscuit::errors::Error> {
    // TODO(laralex): these keys theoretically can be changed, should sometimes check
    // https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com
    let public_firebase_keys = vec![
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
    
    let expected_rfc_header = RegisteredHeader {
        algorithm: SignatureAlgorithm::RS256,
        ..Default::default()
    };
    
    let expected_rfc_payload = RegisteredClaims {
        expiry: Some(Utc::now().into()),
        issued_at: Some(Utc::now().into()),
        // TODO(laralex): 
        // audience: Some(FromStr::from_str("<PROJECT_ID>")),
        // TODO(laralex): 
        // issuer: Some(FromStr::from_str("https://securetoken.google.com/<PROJECT_ID>").unwrap()),
        ..Default::default()
    };

    let token = JWT::<PayloadExtras, HeaderExtras>::new_encoded(&token);

    let Header::<HeaderExtras> { 
        registered: rfc_header, 
        private: HeaderExtras { key_id },
    } = token.header()?;
    let header_verification = 
        rfc_header == &expected_rfc_header &&
        public_firebase_keys.contains(&key_id.as_str());
    if !header_verification {
        return Ok( false )
    }
    
    let ClaimsSet::<PayloadExtras> {
        registered: rfc_payload,
        private: PayloadExtras { auth_time, sub },
    } = token.payload()?;
    let payload_verification = 
        rfc_payload == &expected_rfc_payload &&
        auth_time.timestamp() < Utc::now().timestamp() &&
        admin_uids.contains(&sub);
    if !payload_verification {
        return Ok( false )
    }

    let signature_verification = token.decode(&Secret::bytes_from_str(&key_id), SignatureAlgorithm::RS256).is_ok();
    
    Ok( signature_verification )
}