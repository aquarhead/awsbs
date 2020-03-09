# awsbs

AWS **B**asics, **S**ynchronously.

A simple crate providing 2 general things needed to call AWS APIs:

- [x] Load configuration
- [x] Sign request ([Version 4](https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html) only)

Loading configuration requires reading files, this crate (currently) makes some basic guesses and read files synchronously.

Signing request is more involved:

- Enabled by default features, this crate can work with `Request` type from `http` crate, and can generate date and time automatically from `time` crate
- Another option is to disable the default features and pass in all required data manually, which ensures minimum dependencies
