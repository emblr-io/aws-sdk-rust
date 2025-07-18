// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DisassociateMembershipInput {
    /// <p>The ARN of the behavior graph to remove the member account from.</p>
    /// <p>The member account's member status in the behavior graph must be <code>ENABLED</code>.</p>
    pub graph_arn: ::std::option::Option<::std::string::String>,
}
impl DisassociateMembershipInput {
    /// <p>The ARN of the behavior graph to remove the member account from.</p>
    /// <p>The member account's member status in the behavior graph must be <code>ENABLED</code>.</p>
    pub fn graph_arn(&self) -> ::std::option::Option<&str> {
        self.graph_arn.as_deref()
    }
}
impl DisassociateMembershipInput {
    /// Creates a new builder-style object to manufacture [`DisassociateMembershipInput`](crate::operation::disassociate_membership::DisassociateMembershipInput).
    pub fn builder() -> crate::operation::disassociate_membership::builders::DisassociateMembershipInputBuilder {
        crate::operation::disassociate_membership::builders::DisassociateMembershipInputBuilder::default()
    }
}

/// A builder for [`DisassociateMembershipInput`](crate::operation::disassociate_membership::DisassociateMembershipInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DisassociateMembershipInputBuilder {
    pub(crate) graph_arn: ::std::option::Option<::std::string::String>,
}
impl DisassociateMembershipInputBuilder {
    /// <p>The ARN of the behavior graph to remove the member account from.</p>
    /// <p>The member account's member status in the behavior graph must be <code>ENABLED</code>.</p>
    /// This field is required.
    pub fn graph_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.graph_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the behavior graph to remove the member account from.</p>
    /// <p>The member account's member status in the behavior graph must be <code>ENABLED</code>.</p>
    pub fn set_graph_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.graph_arn = input;
        self
    }
    /// <p>The ARN of the behavior graph to remove the member account from.</p>
    /// <p>The member account's member status in the behavior graph must be <code>ENABLED</code>.</p>
    pub fn get_graph_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.graph_arn
    }
    /// Consumes the builder and constructs a [`DisassociateMembershipInput`](crate::operation::disassociate_membership::DisassociateMembershipInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::disassociate_membership::DisassociateMembershipInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::disassociate_membership::DisassociateMembershipInput { graph_arn: self.graph_arn })
    }
}
