// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListLensSharesInput {
    /// <p>The alias of the lens.</p>
    /// <p>For Amazon Web Services official lenses, this is either the lens alias, such as <code>serverless</code>, or the lens ARN, such as <code>arn:aws:wellarchitected:us-east-1::lens/serverless</code>. Note that some operations (such as ExportLens and CreateLensShare) are not permitted on Amazon Web Services official lenses.</p>
    /// <p>For custom lenses, this is the lens ARN, such as <code>arn:aws:wellarchitected:us-west-2:123456789012:lens/0123456789abcdef01234567890abcdef</code>.</p>
    /// <p>Each lens is identified by its <code>LensSummary$LensAlias</code>.</p>
    pub lens_alias: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Web Services account ID, organization ID, or organizational unit (OU) ID with which the lens is shared.</p>
    pub shared_with_prefix: ::std::option::Option<::std::string::String>,
    /// <p>The token to use to retrieve the next set of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results to return for this request.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The status of the share request.</p>
    pub status: ::std::option::Option<crate::types::ShareStatus>,
}
impl ListLensSharesInput {
    /// <p>The alias of the lens.</p>
    /// <p>For Amazon Web Services official lenses, this is either the lens alias, such as <code>serverless</code>, or the lens ARN, such as <code>arn:aws:wellarchitected:us-east-1::lens/serverless</code>. Note that some operations (such as ExportLens and CreateLensShare) are not permitted on Amazon Web Services official lenses.</p>
    /// <p>For custom lenses, this is the lens ARN, such as <code>arn:aws:wellarchitected:us-west-2:123456789012:lens/0123456789abcdef01234567890abcdef</code>.</p>
    /// <p>Each lens is identified by its <code>LensSummary$LensAlias</code>.</p>
    pub fn lens_alias(&self) -> ::std::option::Option<&str> {
        self.lens_alias.as_deref()
    }
    /// <p>The Amazon Web Services account ID, organization ID, or organizational unit (OU) ID with which the lens is shared.</p>
    pub fn shared_with_prefix(&self) -> ::std::option::Option<&str> {
        self.shared_with_prefix.as_deref()
    }
    /// <p>The token to use to retrieve the next set of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of results to return for this request.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The status of the share request.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::ShareStatus> {
        self.status.as_ref()
    }
}
impl ListLensSharesInput {
    /// Creates a new builder-style object to manufacture [`ListLensSharesInput`](crate::operation::list_lens_shares::ListLensSharesInput).
    pub fn builder() -> crate::operation::list_lens_shares::builders::ListLensSharesInputBuilder {
        crate::operation::list_lens_shares::builders::ListLensSharesInputBuilder::default()
    }
}

/// A builder for [`ListLensSharesInput`](crate::operation::list_lens_shares::ListLensSharesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListLensSharesInputBuilder {
    pub(crate) lens_alias: ::std::option::Option<::std::string::String>,
    pub(crate) shared_with_prefix: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) status: ::std::option::Option<crate::types::ShareStatus>,
}
impl ListLensSharesInputBuilder {
    /// <p>The alias of the lens.</p>
    /// <p>For Amazon Web Services official lenses, this is either the lens alias, such as <code>serverless</code>, or the lens ARN, such as <code>arn:aws:wellarchitected:us-east-1::lens/serverless</code>. Note that some operations (such as ExportLens and CreateLensShare) are not permitted on Amazon Web Services official lenses.</p>
    /// <p>For custom lenses, this is the lens ARN, such as <code>arn:aws:wellarchitected:us-west-2:123456789012:lens/0123456789abcdef01234567890abcdef</code>.</p>
    /// <p>Each lens is identified by its <code>LensSummary$LensAlias</code>.</p>
    /// This field is required.
    pub fn lens_alias(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.lens_alias = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The alias of the lens.</p>
    /// <p>For Amazon Web Services official lenses, this is either the lens alias, such as <code>serverless</code>, or the lens ARN, such as <code>arn:aws:wellarchitected:us-east-1::lens/serverless</code>. Note that some operations (such as ExportLens and CreateLensShare) are not permitted on Amazon Web Services official lenses.</p>
    /// <p>For custom lenses, this is the lens ARN, such as <code>arn:aws:wellarchitected:us-west-2:123456789012:lens/0123456789abcdef01234567890abcdef</code>.</p>
    /// <p>Each lens is identified by its <code>LensSummary$LensAlias</code>.</p>
    pub fn set_lens_alias(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.lens_alias = input;
        self
    }
    /// <p>The alias of the lens.</p>
    /// <p>For Amazon Web Services official lenses, this is either the lens alias, such as <code>serverless</code>, or the lens ARN, such as <code>arn:aws:wellarchitected:us-east-1::lens/serverless</code>. Note that some operations (such as ExportLens and CreateLensShare) are not permitted on Amazon Web Services official lenses.</p>
    /// <p>For custom lenses, this is the lens ARN, such as <code>arn:aws:wellarchitected:us-west-2:123456789012:lens/0123456789abcdef01234567890abcdef</code>.</p>
    /// <p>Each lens is identified by its <code>LensSummary$LensAlias</code>.</p>
    pub fn get_lens_alias(&self) -> &::std::option::Option<::std::string::String> {
        &self.lens_alias
    }
    /// <p>The Amazon Web Services account ID, organization ID, or organizational unit (OU) ID with which the lens is shared.</p>
    pub fn shared_with_prefix(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.shared_with_prefix = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services account ID, organization ID, or organizational unit (OU) ID with which the lens is shared.</p>
    pub fn set_shared_with_prefix(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.shared_with_prefix = input;
        self
    }
    /// <p>The Amazon Web Services account ID, organization ID, or organizational unit (OU) ID with which the lens is shared.</p>
    pub fn get_shared_with_prefix(&self) -> &::std::option::Option<::std::string::String> {
        &self.shared_with_prefix
    }
    /// <p>The token to use to retrieve the next set of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to use to retrieve the next set of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token to use to retrieve the next set of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of results to return for this request.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to return for this request.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to return for this request.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>The status of the share request.</p>
    pub fn status(mut self, input: crate::types::ShareStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the share request.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::ShareStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the share request.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::ShareStatus> {
        &self.status
    }
    /// Consumes the builder and constructs a [`ListLensSharesInput`](crate::operation::list_lens_shares::ListLensSharesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_lens_shares::ListLensSharesInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_lens_shares::ListLensSharesInput {
            lens_alias: self.lens_alias,
            shared_with_prefix: self.shared_with_prefix,
            next_token: self.next_token,
            max_results: self.max_results,
            status: self.status,
        })
    }
}
