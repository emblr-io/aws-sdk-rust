// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteResourcePolicyStatementInput {
    /// <p>The Amazon Resource Name (ARN) of the bot or bot alias that the resource policy is attached to.</p>
    pub resource_arn: ::std::option::Option<::std::string::String>,
    /// <p>The name of the statement (SID) to delete from the policy.</p>
    pub statement_id: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the revision of the policy to delete the statement from. If this revision ID doesn't match the current revision ID, Amazon Lex throws an exception.</p>
    /// <p>If you don't specify a revision, Amazon Lex removes the current contents of the statement.</p>
    pub expected_revision_id: ::std::option::Option<::std::string::String>,
}
impl DeleteResourcePolicyStatementInput {
    /// <p>The Amazon Resource Name (ARN) of the bot or bot alias that the resource policy is attached to.</p>
    pub fn resource_arn(&self) -> ::std::option::Option<&str> {
        self.resource_arn.as_deref()
    }
    /// <p>The name of the statement (SID) to delete from the policy.</p>
    pub fn statement_id(&self) -> ::std::option::Option<&str> {
        self.statement_id.as_deref()
    }
    /// <p>The identifier of the revision of the policy to delete the statement from. If this revision ID doesn't match the current revision ID, Amazon Lex throws an exception.</p>
    /// <p>If you don't specify a revision, Amazon Lex removes the current contents of the statement.</p>
    pub fn expected_revision_id(&self) -> ::std::option::Option<&str> {
        self.expected_revision_id.as_deref()
    }
}
impl DeleteResourcePolicyStatementInput {
    /// Creates a new builder-style object to manufacture [`DeleteResourcePolicyStatementInput`](crate::operation::delete_resource_policy_statement::DeleteResourcePolicyStatementInput).
    pub fn builder() -> crate::operation::delete_resource_policy_statement::builders::DeleteResourcePolicyStatementInputBuilder {
        crate::operation::delete_resource_policy_statement::builders::DeleteResourcePolicyStatementInputBuilder::default()
    }
}

/// A builder for [`DeleteResourcePolicyStatementInput`](crate::operation::delete_resource_policy_statement::DeleteResourcePolicyStatementInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteResourcePolicyStatementInputBuilder {
    pub(crate) resource_arn: ::std::option::Option<::std::string::String>,
    pub(crate) statement_id: ::std::option::Option<::std::string::String>,
    pub(crate) expected_revision_id: ::std::option::Option<::std::string::String>,
}
impl DeleteResourcePolicyStatementInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the bot or bot alias that the resource policy is attached to.</p>
    /// This field is required.
    pub fn resource_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the bot or bot alias that the resource policy is attached to.</p>
    pub fn set_resource_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the bot or bot alias that the resource policy is attached to.</p>
    pub fn get_resource_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_arn
    }
    /// <p>The name of the statement (SID) to delete from the policy.</p>
    /// This field is required.
    pub fn statement_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.statement_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the statement (SID) to delete from the policy.</p>
    pub fn set_statement_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.statement_id = input;
        self
    }
    /// <p>The name of the statement (SID) to delete from the policy.</p>
    pub fn get_statement_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.statement_id
    }
    /// <p>The identifier of the revision of the policy to delete the statement from. If this revision ID doesn't match the current revision ID, Amazon Lex throws an exception.</p>
    /// <p>If you don't specify a revision, Amazon Lex removes the current contents of the statement.</p>
    pub fn expected_revision_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.expected_revision_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the revision of the policy to delete the statement from. If this revision ID doesn't match the current revision ID, Amazon Lex throws an exception.</p>
    /// <p>If you don't specify a revision, Amazon Lex removes the current contents of the statement.</p>
    pub fn set_expected_revision_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.expected_revision_id = input;
        self
    }
    /// <p>The identifier of the revision of the policy to delete the statement from. If this revision ID doesn't match the current revision ID, Amazon Lex throws an exception.</p>
    /// <p>If you don't specify a revision, Amazon Lex removes the current contents of the statement.</p>
    pub fn get_expected_revision_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.expected_revision_id
    }
    /// Consumes the builder and constructs a [`DeleteResourcePolicyStatementInput`](crate::operation::delete_resource_policy_statement::DeleteResourcePolicyStatementInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_resource_policy_statement::DeleteResourcePolicyStatementInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_resource_policy_statement::DeleteResourcePolicyStatementInput {
            resource_arn: self.resource_arn,
            statement_id: self.statement_id,
            expected_revision_id: self.expected_revision_id,
        })
    }
}
