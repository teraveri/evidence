//! Shared parsing and consistency checks for the supported evidence profile.
//!
//! A collector can reject an inconsistent snapshot before sending it. A
//! verifier must still appraise the evidence independently against its own
//! endorsements, policy, and reference values.

pub mod formats;

pub use formats::verify_snapshot;
