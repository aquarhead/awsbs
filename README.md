# awsbs

AWS **B**asics, **S**ynchronously.

A simple crate providing 2 general things needed to call AWS APIs:

- [x] Load configuration
- [ ] Sign request

Loading configuration requires reading files, this crate (currently) makes some basic guesses and read files synchronously.

Signing request requires a "Date", which can either:

- Automatically generate from `chrono` crate, enabled in default features
- Manually supplied when calling the sign function, making it possible to opt out of the `chrono` crate and ensure minimum dependencies.
