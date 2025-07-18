// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ReleaseIpamPoolAllocationOutput {
    /// <p>Indicates if the release was successful.</p>
    pub success: ::std::option::Option<bool>,
    _request_id: Option<String>,
}
impl ReleaseIpamPoolAllocationOutput {
    /// <p>Indicates if the release was successful.</p>
    pub fn success(&self) -> ::std::option::Option<bool> {
        self.success
    }
}
impl ::aws_types::request_id::RequestId for ReleaseIpamPoolAllocationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ReleaseIpamPoolAllocationOutput {
    /// Creates a new builder-style object to manufacture [`ReleaseIpamPoolAllocationOutput`](crate::operation::release_ipam_pool_allocation::ReleaseIpamPoolAllocationOutput).
    pub fn builder() -> crate::operation::release_ipam_pool_allocation::builders::ReleaseIpamPoolAllocationOutputBuilder {
        crate::operation::release_ipam_pool_allocation::builders::ReleaseIpamPoolAllocationOutputBuilder::default()
    }
}

/// A builder for [`ReleaseIpamPoolAllocationOutput`](crate::operation::release_ipam_pool_allocation::ReleaseIpamPoolAllocationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ReleaseIpamPoolAllocationOutputBuilder {
    pub(crate) success: ::std::option::Option<bool>,
    _request_id: Option<String>,
}
impl ReleaseIpamPoolAllocationOutputBuilder {
    /// <p>Indicates if the release was successful.</p>
    pub fn success(mut self, input: bool) -> Self {
        self.success = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates if the release was successful.</p>
    pub fn set_success(mut self, input: ::std::option::Option<bool>) -> Self {
        self.success = input;
        self
    }
    /// <p>Indicates if the release was successful.</p>
    pub fn get_success(&self) -> &::std::option::Option<bool> {
        &self.success
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ReleaseIpamPoolAllocationOutput`](crate::operation::release_ipam_pool_allocation::ReleaseIpamPoolAllocationOutput).
    pub fn build(self) -> crate::operation::release_ipam_pool_allocation::ReleaseIpamPoolAllocationOutput {
        crate::operation::release_ipam_pool_allocation::ReleaseIpamPoolAllocationOutput {
            success: self.success,
            _request_id: self._request_id,
        }
    }
}
