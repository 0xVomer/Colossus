// Test utilities - only used in tests
#![allow(dead_code)]

use crate::{
    access_control::{AccessControl, CapabilityAuthority, CapabilityAuthorityPublicKey},
    policy::Error,
};

/// Creates a basic capability authority for testing with blinded mode.
///
/// The authority is set up with identity (required for blinded mode) but
/// without any issuers registered yet. Tests should register blinded issuers
/// and add dimensions/attributes as needed.
pub fn gen_blinded_auth(
    api: &AccessControl,
) -> Result<(CapabilityAuthority, CapabilityAuthorityPublicKey), Error> {
    let mut auth = api.setup_blinded_authority()?.with_identity();
    auth.init_blinded_structure()?;
    let rpk = auth.rpk()?;
    Ok((auth, rpk))
}
