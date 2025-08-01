// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeprovisionIpamPoolCidrOutput {
    /// <p>The deprovisioned pool CIDR.</p>
    pub ipam_pool_cidr: ::std::option::Option<crate::types::IpamPoolCidr>,
    _request_id: Option<String>,
}
impl DeprovisionIpamPoolCidrOutput {
    /// <p>The deprovisioned pool CIDR.</p>
    pub fn ipam_pool_cidr(&self) -> ::std::option::Option<&crate::types::IpamPoolCidr> {
        self.ipam_pool_cidr.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DeprovisionIpamPoolCidrOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeprovisionIpamPoolCidrOutput {
    /// Creates a new builder-style object to manufacture [`DeprovisionIpamPoolCidrOutput`](crate::operation::deprovision_ipam_pool_cidr::DeprovisionIpamPoolCidrOutput).
    pub fn builder() -> crate::operation::deprovision_ipam_pool_cidr::builders::DeprovisionIpamPoolCidrOutputBuilder {
        crate::operation::deprovision_ipam_pool_cidr::builders::DeprovisionIpamPoolCidrOutputBuilder::default()
    }
}

/// A builder for [`DeprovisionIpamPoolCidrOutput`](crate::operation::deprovision_ipam_pool_cidr::DeprovisionIpamPoolCidrOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeprovisionIpamPoolCidrOutputBuilder {
    pub(crate) ipam_pool_cidr: ::std::option::Option<crate::types::IpamPoolCidr>,
    _request_id: Option<String>,
}
impl DeprovisionIpamPoolCidrOutputBuilder {
    /// <p>The deprovisioned pool CIDR.</p>
    pub fn ipam_pool_cidr(mut self, input: crate::types::IpamPoolCidr) -> Self {
        self.ipam_pool_cidr = ::std::option::Option::Some(input);
        self
    }
    /// <p>The deprovisioned pool CIDR.</p>
    pub fn set_ipam_pool_cidr(mut self, input: ::std::option::Option<crate::types::IpamPoolCidr>) -> Self {
        self.ipam_pool_cidr = input;
        self
    }
    /// <p>The deprovisioned pool CIDR.</p>
    pub fn get_ipam_pool_cidr(&self) -> &::std::option::Option<crate::types::IpamPoolCidr> {
        &self.ipam_pool_cidr
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeprovisionIpamPoolCidrOutput`](crate::operation::deprovision_ipam_pool_cidr::DeprovisionIpamPoolCidrOutput).
    pub fn build(self) -> crate::operation::deprovision_ipam_pool_cidr::DeprovisionIpamPoolCidrOutput {
        crate::operation::deprovision_ipam_pool_cidr::DeprovisionIpamPoolCidrOutput {
            ipam_pool_cidr: self.ipam_pool_cidr,
            _request_id: self._request_id,
        }
    }
}
