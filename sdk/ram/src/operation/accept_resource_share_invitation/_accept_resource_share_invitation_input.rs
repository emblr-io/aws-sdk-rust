// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AcceptResourceShareInvitationInput {
    /// <p>The <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Name (ARN)</a> of the invitation that you want to accept.</p>
    pub resource_share_invitation_arn: ::std::option::Option<::std::string::String>,
    /// <p>Specifies a unique, case-sensitive identifier that you provide to ensure the idempotency of the request. This lets you safely retry the request without accidentally performing the same operation a second time. Passing the same value to a later call to an operation requires that you also pass the same value for all other parameters. We recommend that you use a <a href="https://wikipedia.org/wiki/Universally_unique_identifier">UUID type of value.</a>.</p>
    /// <p>If you don't provide this value, then Amazon Web Services generates a random one for you.</p>
    /// <p>If you retry the operation with the same <code>ClientToken</code>, but with different parameters, the retry fails with an <code>IdempotentParameterMismatch</code> error.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
}
impl AcceptResourceShareInvitationInput {
    /// <p>The <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Name (ARN)</a> of the invitation that you want to accept.</p>
    pub fn resource_share_invitation_arn(&self) -> ::std::option::Option<&str> {
        self.resource_share_invitation_arn.as_deref()
    }
    /// <p>Specifies a unique, case-sensitive identifier that you provide to ensure the idempotency of the request. This lets you safely retry the request without accidentally performing the same operation a second time. Passing the same value to a later call to an operation requires that you also pass the same value for all other parameters. We recommend that you use a <a href="https://wikipedia.org/wiki/Universally_unique_identifier">UUID type of value.</a>.</p>
    /// <p>If you don't provide this value, then Amazon Web Services generates a random one for you.</p>
    /// <p>If you retry the operation with the same <code>ClientToken</code>, but with different parameters, the retry fails with an <code>IdempotentParameterMismatch</code> error.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
}
impl AcceptResourceShareInvitationInput {
    /// Creates a new builder-style object to manufacture [`AcceptResourceShareInvitationInput`](crate::operation::accept_resource_share_invitation::AcceptResourceShareInvitationInput).
    pub fn builder() -> crate::operation::accept_resource_share_invitation::builders::AcceptResourceShareInvitationInputBuilder {
        crate::operation::accept_resource_share_invitation::builders::AcceptResourceShareInvitationInputBuilder::default()
    }
}

/// A builder for [`AcceptResourceShareInvitationInput`](crate::operation::accept_resource_share_invitation::AcceptResourceShareInvitationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AcceptResourceShareInvitationInputBuilder {
    pub(crate) resource_share_invitation_arn: ::std::option::Option<::std::string::String>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
}
impl AcceptResourceShareInvitationInputBuilder {
    /// <p>The <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Name (ARN)</a> of the invitation that you want to accept.</p>
    /// This field is required.
    pub fn resource_share_invitation_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_share_invitation_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Name (ARN)</a> of the invitation that you want to accept.</p>
    pub fn set_resource_share_invitation_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_share_invitation_arn = input;
        self
    }
    /// <p>The <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Name (ARN)</a> of the invitation that you want to accept.</p>
    pub fn get_resource_share_invitation_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_share_invitation_arn
    }
    /// <p>Specifies a unique, case-sensitive identifier that you provide to ensure the idempotency of the request. This lets you safely retry the request without accidentally performing the same operation a second time. Passing the same value to a later call to an operation requires that you also pass the same value for all other parameters. We recommend that you use a <a href="https://wikipedia.org/wiki/Universally_unique_identifier">UUID type of value.</a>.</p>
    /// <p>If you don't provide this value, then Amazon Web Services generates a random one for you.</p>
    /// <p>If you retry the operation with the same <code>ClientToken</code>, but with different parameters, the retry fails with an <code>IdempotentParameterMismatch</code> error.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies a unique, case-sensitive identifier that you provide to ensure the idempotency of the request. This lets you safely retry the request without accidentally performing the same operation a second time. Passing the same value to a later call to an operation requires that you also pass the same value for all other parameters. We recommend that you use a <a href="https://wikipedia.org/wiki/Universally_unique_identifier">UUID type of value.</a>.</p>
    /// <p>If you don't provide this value, then Amazon Web Services generates a random one for you.</p>
    /// <p>If you retry the operation with the same <code>ClientToken</code>, but with different parameters, the retry fails with an <code>IdempotentParameterMismatch</code> error.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>Specifies a unique, case-sensitive identifier that you provide to ensure the idempotency of the request. This lets you safely retry the request without accidentally performing the same operation a second time. Passing the same value to a later call to an operation requires that you also pass the same value for all other parameters. We recommend that you use a <a href="https://wikipedia.org/wiki/Universally_unique_identifier">UUID type of value.</a>.</p>
    /// <p>If you don't provide this value, then Amazon Web Services generates a random one for you.</p>
    /// <p>If you retry the operation with the same <code>ClientToken</code>, but with different parameters, the retry fails with an <code>IdempotentParameterMismatch</code> error.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// Consumes the builder and constructs a [`AcceptResourceShareInvitationInput`](crate::operation::accept_resource_share_invitation::AcceptResourceShareInvitationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::accept_resource_share_invitation::AcceptResourceShareInvitationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::accept_resource_share_invitation::AcceptResourceShareInvitationInput {
            resource_share_invitation_arn: self.resource_share_invitation_arn,
            client_token: self.client_token,
        })
    }
}
