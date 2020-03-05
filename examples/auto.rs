use anyhow::Result;

use awsbs::Configuration;

fn main() -> Result<()> {
  println!("{:?}", Configuration::auto()?);
  Ok(())
}
