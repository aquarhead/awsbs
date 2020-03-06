use hmac::{Hmac, Mac};
use http::{
  header::{HeaderValue, AUTHORIZATION},
  Request,
};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::Configuration;

type HmacSha256 = Hmac<Sha256>;

/// body must be UTF-8 encoded, Query string values must be URL-encoded (e.g. space=%20)
pub fn sign<T>(req: &mut Request<T>, conf: &Configuration, service: &str)
where
  T: AsRef<[u8]>,
{
  let utc_dt = OffsetDateTime::now();
  let datetime = utc_dt.format("%Y%m%dT%H%M%SZ");
  let date = utc_dt.format("%Y%m%d");

  let method = req.method().as_str();
  let canonical_uri = req.uri().path();

  let canonical_query_string = {
    let mut queries: Vec<(&str, &str)> = req
      .uri()
      .query()
      .unwrap_or("")
      .split("&")
      .map(|x| {
        let mut parts = x.split("=");
        (parts.next().unwrap_or(""), parts.next().unwrap_or(""))
      })
      .collect();

    queries.sort();

    queries
      .iter()
      .map(|(k, v)| format!("{}={}", k, v))
      .collect::<Vec<_>>()
      .join("&")
  };

  let canonical_headers = format!("host:{}\nx-amz-date:{}\n", req.uri().host().unwrap_or(""), datetime);
  let signed_headers = "host;x-amz-date";
  let payload_digest = format!("{:x}", Sha256::digest(req.body().as_ref()));

  let canonical_request = format!(
    "{}\n{}\n{}\n{}\n{}\n{}",
    method, canonical_uri, canonical_query_string, canonical_headers, signed_headers, payload_digest
  );

  let hashed_canoniacl_request = format!("{:x}", Sha256::digest(canonical_request.as_bytes()));

  let algorithm = "AWS4-HMAC-SHA256";
  let request_datetime = datetime;
  let credential_scope = format!("{}/{}/{}/aws4_request", date, conf.region, service);
  let string_to_sign = format!(
    "{}\n{}\n{}\n{}",
    algorithm, request_datetime, credential_scope, hashed_canoniacl_request
  );

  let derived_sign_key = derive_sign_key(conf, service, &date);
  let signature = hs256_hex(derived_sign_key.as_bytes(), &string_to_sign);

  let hv = format!(
    "{} Credential={}, SignedHeaders={}, Signature={}",
    algorithm, credential_scope, signed_headers, signature
  );

  req
    .headers_mut()
    .insert(AUTHORIZATION, HeaderValue::from_str(&hv).unwrap());
}

fn derive_sign_key(conf: &Configuration, service: &str, date: &str) -> String {
  let k_date = {
    let mut k_init = "AWS4".to_owned();
    k_init.push_str(&conf.secret);
    hs256(k_init.as_bytes(), date)
  };
  let k_region = hs256(&k_date, &conf.region);
  let k_service = hs256(&k_region, service);
  hs256_hex(&k_service, "aws4_request")
}

fn hs256(key: &[u8], data: &str) -> Vec<u8> {
  let mut h = HmacSha256::new_varkey(key).unwrap();
  h.input(data.as_bytes());
  h.result().code().iter().map(|x| x.to_owned()).collect()
}

fn hs256_hex(key: &[u8], data: &str) -> String {
  let mut h = HmacSha256::new_varkey(key).unwrap();
  h.input(data.as_bytes());
  format!("{:x}", h.result().code())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_derive_sign_key() {
    assert_eq!(
      "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9",
      &derive_sign_key(
        &Configuration {
          region: "us-east-1".to_owned(),
          key: "".to_owned(),
          secret: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_owned(),
        },
        "iam",
        "20150830",
      )
    )
  }

  #[test]
  fn test_sign_request() {
    //
  }
}
