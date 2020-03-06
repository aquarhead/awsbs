use hmac::{Hmac, Mac};
use http::{
  header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE, HOST},
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
  // let utc_dt = OffsetDateTime::now();
  // let datetime = utc_dt.format("%Y%m%dT%H%M%SZ");
  // let date = utc_dt.format("%Y%m%d");

  // req
  //   .headers_mut()
  //   .insert("x-amz-date", HeaderValue::from_str(&datetime).unwrap());
  let datetime = req.headers().get("x-amz-date").unwrap().to_str().unwrap();
  let date = datetime.split("T").next().unwrap();

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

  let canonical_headers = format!(
    "content-type:{}\nhost:{}\nx-amz-date:{}\n",
    req.headers().get(CONTENT_TYPE).unwrap().to_str().unwrap(),
    req.headers().get(HOST).unwrap().to_str().unwrap(),
    datetime
  );
  let signed_headers = "content-type;host;x-amz-date";
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
  let signature = hs256_hex(&derived_sign_key, &string_to_sign);

  let hv = format!(
    "{} Credential={}/{}, SignedHeaders={}, Signature={}",
    algorithm, &conf.key, credential_scope, signed_headers, signature
  );

  req
    .headers_mut()
    .insert(AUTHORIZATION, HeaderValue::from_str(&hv).unwrap());
}

fn derive_sign_key(conf: &Configuration, service: &str, date: &str) -> Vec<u8> {
  let k_date = {
    let mut k_init = "AWS4".to_owned();
    k_init.push_str(&conf.secret);
    hs256(k_init.as_bytes(), date)
  };
  let k_region = hs256(&k_date, &conf.region);
  let k_service = hs256(&k_region, service);
  hs256(&k_service, "aws4_request")
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
    let k = derive_sign_key(
      &Configuration {
        region: "us-east-1".to_owned(),
        key: "".to_owned(),
        secret: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_owned(),
      },
      "iam",
      "20150830",
    );

    assert_eq!(
      "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9",
      hex::encode(k)
    )
  }

  #[test]
  fn test_sign_request() {
    let conf = Configuration {
      region: "us-east-1".to_owned(),
      key: "AKIDEXAMPLE".to_owned(),
      secret: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_owned(),
    };

    let mut req = Request::get("https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08")
      .header(HOST, "iam.amazonaws.com")
      .header(CONTENT_TYPE, "application/x-www-form-urlencoded; charset=utf-8")
      .header("x-amz-date", "20150830T123600Z")
      .body("")
      .unwrap();

    sign(&mut req, &conf, "iam");

    assert_eq!(req.headers().get(AUTHORIZATION).unwrap(), "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7");
  }
}
