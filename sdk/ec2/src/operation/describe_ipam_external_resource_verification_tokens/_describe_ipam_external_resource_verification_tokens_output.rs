// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeIpamExternalResourceVerificationTokensOutput {
    /// <p>The token to use to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>Verification tokens.</p>
    pub ipam_external_resource_verification_tokens: ::std::option::Option<::std::vec::Vec<crate::types::IpamExternalResourceVerificationToken>>,
    _request_id: Option<String>,
}
impl DescribeIpamExternalResourceVerificationTokensOutput {
    /// <p>The token to use to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>Verification tokens.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.ipam_external_resource_verification_tokens.is_none()`.
    pub fn ipam_external_resource_verification_tokens(&self) -> &[crate::types::IpamExternalResourceVerificationToken] {
        self.ipam_external_resource_verification_tokens.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for DescribeIpamExternalResourceVerificationTokensOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeIpamExternalResourceVerificationTokensOutput {
    /// Creates a new builder-style object to manufacture [`DescribeIpamExternalResourceVerificationTokensOutput`](crate::operation::describe_ipam_external_resource_verification_tokens::DescribeIpamExternalResourceVerificationTokensOutput).
    pub fn builder(
    ) -> crate::operation::describe_ipam_external_resource_verification_tokens::builders::DescribeIpamExternalResourceVerificationTokensOutputBuilder
    {
        crate::operation::describe_ipam_external_resource_verification_tokens::builders::DescribeIpamExternalResourceVerificationTokensOutputBuilder::default()
    }
}

/// A builder for [`DescribeIpamExternalResourceVerificationTokensOutput`](crate::operation::describe_ipam_external_resource_verification_tokens::DescribeIpamExternalResourceVerificationTokensOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeIpamExternalResourceVerificationTokensOutputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) ipam_external_resource_verification_tokens:
        ::std::option::Option<::std::vec::Vec<crate::types::IpamExternalResourceVerificationToken>>,
    _request_id: Option<String>,
}
impl DescribeIpamExternalResourceVerificationTokensOutputBuilder {
    /// <p>The token to use to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to use to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token to use to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Appends an item to `ipam_external_resource_verification_tokens`.
    ///
    /// To override the contents of this collection use [`set_ipam_external_resource_verification_tokens`](Self::set_ipam_external_resource_verification_tokens).
    ///
    /// <p>Verification tokens.</p>
    pub fn ipam_external_resource_verification_tokens(mut self, input: crate::types::IpamExternalResourceVerificationToken) -> Self {
        let mut v = self.ipam_external_resource_verification_tokens.unwrap_or_default();
        v.push(input);
        self.ipam_external_resource_verification_tokens = ::std::option::Option::Some(v);
        self
    }
    /// <p>Verification tokens.</p>
    pub fn set_ipam_external_resource_verification_tokens(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::IpamExternalResourceVerificationToken>>,
    ) -> Self {
        self.ipam_external_resource_verification_tokens = input;
        self
    }
    /// <p>Verification tokens.</p>
    pub fn get_ipam_external_resource_verification_tokens(
        &self,
    ) -> &::std::option::Option<::std::vec::Vec<crate::types::IpamExternalResourceVerificationToken>> {
        &self.ipam_external_resource_verification_tokens
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeIpamExternalResourceVerificationTokensOutput`](crate::operation::describe_ipam_external_resource_verification_tokens::DescribeIpamExternalResourceVerificationTokensOutput).
    pub fn build(
        self,
    ) -> crate::operation::describe_ipam_external_resource_verification_tokens::DescribeIpamExternalResourceVerificationTokensOutput {
        crate::operation::describe_ipam_external_resource_verification_tokens::DescribeIpamExternalResourceVerificationTokensOutput {
            next_token: self.next_token,
            ipam_external_resource_verification_tokens: self.ipam_external_resource_verification_tokens,
            _request_id: self._request_id,
        }
    }
}
