use anyhow::Result;
use http::{
  header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE, HOST},
  request::Builder,
  Request, Uri,
};
use time::OffsetDateTime;

use crate::{consts::*, Configuration};

/// Usage:
///
/// ```ignore
/// Request::builder()
/// .method("GET")
/// .uri("https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08")
/// .sign("", "application/json", conf, "iam")
/// .unwrap();
/// ```
pub trait SignSupported {
  fn sign<'a>(
    self,
    body: &'a str,
    content_type: &str,
    conf: &Configuration,
    service: &str,
  ) -> Result<Request<&'a str>>;
}

impl SignSupported for Builder {
  fn sign<'a>(
    self,
    body: &'a str,
    content_type: &str,
    conf: &Configuration,
    service: &str,
  ) -> Result<Request<&'a str>> {
    let datetime = OffsetDateTime::now().format("%Y%m%dT%H%M%SZ");
    let host = self.uri_ref().unwrap().host().unwrap().to_owned();
    let auth = create_signed_auth_header(
      self.method_ref().unwrap().as_str(),
      self.uri_ref().unwrap(),
      body,
      content_type,
      &datetime,
      conf,
      service,
    );

    let res = self
      .header(HOST, &host)
      .header(CONTENT_TYPE, content_type)
      .header(AMZ_DATE, datetime)
      .header(AUTHORIZATION, auth)
      .body(body)?;

    Ok(res)
  }
}

/// Sign a "prepared" `Request`, which:
///   - Has these headers correctly filled:
///     - `host`
///     - `content-type`
///     - `x-amz-date`
///   - Had a body, need to be an empty string for empty body, must be UTF-8 encoded
///   - Query string values must be URL-encoded (e.g. space=%20)
pub fn sign_prepared<T>(
  req: &mut Request<T>,
  conf: &Configuration,
  service: &str,
) where
  T: AsRef<[u8]>,
{
  let datetime = req.headers().get(AMZ_DATE).unwrap().to_str().unwrap();

  let hv = create_signed_auth_header(
    req.method().as_str(),
    req.uri(),
    req.body(),
    req.headers().get(CONTENT_TYPE).unwrap().to_str().unwrap(),
    datetime,
    conf,
    service,
  );

  req
    .headers_mut()
    .insert(AUTHORIZATION, HeaderValue::from_str(&hv).unwrap());
}

fn create_signed_auth_header<T>(
  method: &str,
  uri: &Uri,
  body: T,
  content_type: &str,
  datetime: &str,
  conf: &Configuration,
  service: &str,
) -> String
where
  T: AsRef<[u8]>,
{
  use internal::*;

  let date = datetime.split("T").next().unwrap();

  let derived_sign_key = derive_sign_key(conf, service, &date);

  let cr = build_canonical_request(method, uri, datetime, body, content_type);
  let cs = build_credential_scope(date, &conf.region, service);
  let sts = create_string_to_sign(&cr, datetime, &cs);
  signed_auth_header(&derived_sign_key, &conf.key, &sts, &cs)
}

mod internal {
  use hmac::{Hmac, Mac};
  use http::Uri;
  use sha2::{Digest, Sha256};

  use crate::{consts::*, Configuration};

  type HmacSha256 = Hmac<Sha256>;

  pub fn build_canonical_request<T>(
    method: &str,
    uri: &Uri,
    dt: &str,
    body: T,
    content_type: &str,
  ) -> String
  where
    T: AsRef<[u8]>,
  {
    let canonical_uri = uri.path();

    let canonical_query_string = {
      let mut queries: Vec<(&str, &str)> = uri
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
      content_type,
      uri.host().unwrap(),
      dt
    );

    let payload_digest = format!("{:x}", Sha256::digest(body.as_ref()));

    format!(
      "{}\n{}\n{}\n{}\n{}\n{}",
      method,
      canonical_uri,
      canonical_query_string,
      canonical_headers,
      SIGNED_HEADERS,
      payload_digest
    )
  }

  pub fn build_credential_scope(
    date: &str,
    region: &str,
    service: &str,
  ) -> String {
    format!("{}/{}/{}/aws4_request", date, region, service)
  }

  pub fn create_string_to_sign(cr: &str, datetime: &str, cs: &str) -> String {
    let hashed_canoniacl_request =
      format!("{:x}", Sha256::digest(cr.as_bytes()));

    format!(
      "{}\n{}\n{}\n{}",
      ALGORITHM, datetime, cs, hashed_canoniacl_request
    )
  }

  pub fn signed_auth_header(
    sign_key: &[u8],
    aws_key: &str,
    sts: &str,
    cs: &str,
  ) -> String {
    let signature = hs256_hex(sign_key, sts);

    format!(
      "{} Credential={}/{}, SignedHeaders={}, Signature={}",
      ALGORITHM, aws_key, cs, SIGNED_HEADERS, signature
    )
  }

  pub fn derive_sign_key(
    conf: &Configuration,
    service: &str,
    date: &str,
  ) -> Vec<u8> {
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
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_sign_request() {
    let conf = Configuration {
      region: "us-east-1".to_owned(),
      key: "AKIDEXAMPLE".to_owned(),
      secret: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_owned(),
    };

    let mut req = Request::get(
      "https://iam.amazonaws.com/?Version=2010-05-08&Action=ListUsers",
    )
    .header(HOST, "iam.amazonaws.com")
    .header(
      CONTENT_TYPE,
      "application/x-www-form-urlencoded; charset=utf-8",
    )
    .header(AMZ_DATE, "20150830T123600Z")
    .body("")
    .unwrap();

    sign_prepared(&mut req, &conf, "iam");

    assert_eq!(req.headers().get(AUTHORIZATION).unwrap(), "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7");
  }
}
