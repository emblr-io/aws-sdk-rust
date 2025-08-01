// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteIpamExternalResourceVerificationTokenOutput {
    /// <p>The verification token.</p>
    pub ipam_external_resource_verification_token: ::std::option::Option<crate::types::IpamExternalResourceVerificationToken>,
    _request_id: Option<String>,
}
impl DeleteIpamExternalResourceVerificationTokenOutput {
    /// <p>The verification token.</p>
    pub fn ipam_external_resource_verification_token(&self) -> ::std::option::Option<&crate::types::IpamExternalResourceVerificationToken> {
        self.ipam_external_resource_verification_token.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DeleteIpamExternalResourceVerificationTokenOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteIpamExternalResourceVerificationTokenOutput {
    /// Creates a new builder-style object to manufacture [`DeleteIpamExternalResourceVerificationTokenOutput`](crate::operation::delete_ipam_external_resource_verification_token::DeleteIpamExternalResourceVerificationTokenOutput).
    pub fn builder(
    ) -> crate::operation::delete_ipam_external_resource_verification_token::builders::DeleteIpamExternalResourceVerificationTokenOutputBuilder {
        crate::operation::delete_ipam_external_resource_verification_token::builders::DeleteIpamExternalResourceVerificationTokenOutputBuilder::default()
    }
}

/// A builder for [`DeleteIpamExternalResourceVerificationTokenOutput`](crate::operation::delete_ipam_external_resource_verification_token::DeleteIpamExternalResourceVerificationTokenOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteIpamExternalResourceVerificationTokenOutputBuilder {
    pub(crate) ipam_external_resource_verification_token: ::std::option::Option<crate::types::IpamExternalResourceVerificationToken>,
    _request_id: Option<String>,
}
impl DeleteIpamExternalResourceVerificationTokenOutputBuilder {
    /// <p>The verification token.</p>
    pub fn ipam_external_resource_verification_token(mut self, input: crate::types::IpamExternalResourceVerificationToken) -> Self {
        self.ipam_external_resource_verification_token = ::std::option::Option::Some(input);
        self
    }
    /// <p>The verification token.</p>
    pub fn set_ipam_external_resource_verification_token(
        mut self,
        input: ::std::option::Option<crate::types::IpamExternalResourceVerificationToken>,
    ) -> Self {
        self.ipam_external_resource_verification_token = input;
        self
    }
    /// <p>The verification token.</p>
    pub fn get_ipam_external_resource_verification_token(&self) -> &::std::option::Option<crate::types::IpamExternalResourceVerificationToken> {
        &self.ipam_external_resource_verification_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteIpamExternalResourceVerificationTokenOutput`](crate::operation::delete_ipam_external_resource_verification_token::DeleteIpamExternalResourceVerificationTokenOutput).
    pub fn build(self) -> crate::operation::delete_ipam_external_resource_verification_token::DeleteIpamExternalResourceVerificationTokenOutput {
        crate::operation::delete_ipam_external_resource_verification_token::DeleteIpamExternalResourceVerificationTokenOutput {
            ipam_external_resource_verification_token: self.ipam_external_resource_verification_token,
            _request_id: self._request_id,
        }
    }
}
