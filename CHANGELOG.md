# Change Log

## [2.0.0]
### Changed
- compatibility with JWT library version 2.0. This library covers an important security vulnerability, 
see here: https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries. The middleware now requires 
algorithm parameter to be used when decoding incoming tokens. See spec/authenticate_options_spec.rb for examples. 