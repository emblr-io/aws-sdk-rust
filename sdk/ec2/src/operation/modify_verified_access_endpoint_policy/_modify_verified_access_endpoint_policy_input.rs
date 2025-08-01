// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ModifyVerifiedAccessEndpointPolicyInput {
    /// <p>The ID of the Verified Access endpoint.</p>
    pub verified_access_endpoint_id: ::std::option::Option<::std::string::String>,
    /// <p>The status of the Verified Access policy.</p>
    pub policy_enabled: ::std::option::Option<bool>,
    /// <p>The Verified Access policy document.</p>
    pub policy_document: ::std::option::Option<::std::string::String>,
    /// <p>A unique, case-sensitive token that you provide to ensure idempotency of your modification request. For more information, see <a href="https://docs.aws.amazon.com/ec2/latest/devguide/ec2-api-idempotency.html">Ensuring idempotency</a>.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub dry_run: ::std::option::Option<bool>,
    /// <p>The options for server side encryption.</p>
    pub sse_specification: ::std::option::Option<crate::types::VerifiedAccessSseSpecificationRequest>,
}
impl ModifyVerifiedAccessEndpointPolicyInput {
    /// <p>The ID of the Verified Access endpoint.</p>
    pub fn verified_access_endpoint_id(&self) -> ::std::option::Option<&str> {
        self.verified_access_endpoint_id.as_deref()
    }
    /// <p>The status of the Verified Access policy.</p>
    pub fn policy_enabled(&self) -> ::std::option::Option<bool> {
        self.policy_enabled
    }
    /// <p>The Verified Access policy document.</p>
    pub fn policy_document(&self) -> ::std::option::Option<&str> {
        self.policy_document.as_deref()
    }
    /// <p>A unique, case-sensitive token that you provide to ensure idempotency of your modification request. For more information, see <a href="https://docs.aws.amazon.com/ec2/latest/devguide/ec2-api-idempotency.html">Ensuring idempotency</a>.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(&self) -> ::std::option::Option<bool> {
        self.dry_run
    }
    /// <p>The options for server side encryption.</p>
    pub fn sse_specification(&self) -> ::std::option::Option<&crate::types::VerifiedAccessSseSpecificationRequest> {
        self.sse_specification.as_ref()
    }
}
impl ModifyVerifiedAccessEndpointPolicyInput {
    /// Creates a new builder-style object to manufacture [`ModifyVerifiedAccessEndpointPolicyInput`](crate::operation::modify_verified_access_endpoint_policy::ModifyVerifiedAccessEndpointPolicyInput).
    pub fn builder() -> crate::operation::modify_verified_access_endpoint_policy::builders::ModifyVerifiedAccessEndpointPolicyInputBuilder {
        crate::operation::modify_verified_access_endpoint_policy::builders::ModifyVerifiedAccessEndpointPolicyInputBuilder::default()
    }
}

/// A builder for [`ModifyVerifiedAccessEndpointPolicyInput`](crate::operation::modify_verified_access_endpoint_policy::ModifyVerifiedAccessEndpointPolicyInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ModifyVerifiedAccessEndpointPolicyInputBuilder {
    pub(crate) verified_access_endpoint_id: ::std::option::Option<::std::string::String>,
    pub(crate) policy_enabled: ::std::option::Option<bool>,
    pub(crate) policy_document: ::std::option::Option<::std::string::String>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    pub(crate) dry_run: ::std::option::Option<bool>,
    pub(crate) sse_specification: ::std::option::Option<crate::types::VerifiedAccessSseSpecificationRequest>,
}
impl ModifyVerifiedAccessEndpointPolicyInputBuilder {
    /// <p>The ID of the Verified Access endpoint.</p>
    /// This field is required.
    pub fn verified_access_endpoint_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.verified_access_endpoint_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Verified Access endpoint.</p>
    pub fn set_verified_access_endpoint_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.verified_access_endpoint_id = input;
        self
    }
    /// <p>The ID of the Verified Access endpoint.</p>
    pub fn get_verified_access_endpoint_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.verified_access_endpoint_id
    }
    /// <p>The status of the Verified Access policy.</p>
    pub fn policy_enabled(mut self, input: bool) -> Self {
        self.policy_enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the Verified Access policy.</p>
    pub fn set_policy_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.policy_enabled = input;
        self
    }
    /// <p>The status of the Verified Access policy.</p>
    pub fn get_policy_enabled(&self) -> &::std::option::Option<bool> {
        &self.policy_enabled
    }
    /// <p>The Verified Access policy document.</p>
    pub fn policy_document(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.policy_document = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Verified Access policy document.</p>
    pub fn set_policy_document(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.policy_document = input;
        self
    }
    /// <p>The Verified Access policy document.</p>
    pub fn get_policy_document(&self) -> &::std::option::Option<::std::string::String> {
        &self.policy_document
    }
    /// <p>A unique, case-sensitive token that you provide to ensure idempotency of your modification request. For more information, see <a href="https://docs.aws.amazon.com/ec2/latest/devguide/ec2-api-idempotency.html">Ensuring idempotency</a>.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique, case-sensitive token that you provide to ensure idempotency of your modification request. For more information, see <a href="https://docs.aws.amazon.com/ec2/latest/devguide/ec2-api-idempotency.html">Ensuring idempotency</a>.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>A unique, case-sensitive token that you provide to ensure idempotency of your modification request. For more information, see <a href="https://docs.aws.amazon.com/ec2/latest/devguide/ec2-api-idempotency.html">Ensuring idempotency</a>.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(mut self, input: bool) -> Self {
        self.dry_run = ::std::option::Option::Some(input);
        self
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn set_dry_run(mut self, input: ::std::option::Option<bool>) -> Self {
        self.dry_run = input;
        self
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn get_dry_run(&self) -> &::std::option::Option<bool> {
        &self.dry_run
    }
    /// <p>The options for server side encryption.</p>
    pub fn sse_specification(mut self, input: crate::types::VerifiedAccessSseSpecificationRequest) -> Self {
        self.sse_specification = ::std::option::Option::Some(input);
        self
    }
    /// <p>The options for server side encryption.</p>
    pub fn set_sse_specification(mut self, input: ::std::option::Option<crate::types::VerifiedAccessSseSpecificationRequest>) -> Self {
        self.sse_specification = input;
        self
    }
    /// <p>The options for server side encryption.</p>
    pub fn get_sse_specification(&self) -> &::std::option::Option<crate::types::VerifiedAccessSseSpecificationRequest> {
        &self.sse_specification
    }
    /// Consumes the builder and constructs a [`ModifyVerifiedAccessEndpointPolicyInput`](crate::operation::modify_verified_access_endpoint_policy::ModifyVerifiedAccessEndpointPolicyInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::modify_verified_access_endpoint_policy::ModifyVerifiedAccessEndpointPolicyInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::modify_verified_access_endpoint_policy::ModifyVerifiedAccessEndpointPolicyInput {
                verified_access_endpoint_id: self.verified_access_endpoint_id,
                policy_enabled: self.policy_enabled,
                policy_document: self.policy_document,
                client_token: self.client_token,
                dry_run: self.dry_run,
                sse_specification: self.sse_specification,
            },
        )
    }
}
