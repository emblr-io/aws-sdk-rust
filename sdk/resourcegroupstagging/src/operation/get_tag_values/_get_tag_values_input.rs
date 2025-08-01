// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetTagValuesInput {
    /// <p>Specifies a <code>PaginationToken</code> response value from a previous request to indicate that you want the next page of results. Leave this parameter empty in your initial request.</p>
    pub pagination_token: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the tag key for which you want to list all existing values that are currently used in the specified Amazon Web Services Region for the calling account.</p>
    pub key: ::std::option::Option<::std::string::String>,
}
impl GetTagValuesInput {
    /// <p>Specifies a <code>PaginationToken</code> response value from a previous request to indicate that you want the next page of results. Leave this parameter empty in your initial request.</p>
    pub fn pagination_token(&self) -> ::std::option::Option<&str> {
        self.pagination_token.as_deref()
    }
    /// <p>Specifies the tag key for which you want to list all existing values that are currently used in the specified Amazon Web Services Region for the calling account.</p>
    pub fn key(&self) -> ::std::option::Option<&str> {
        self.key.as_deref()
    }
}
impl GetTagValuesInput {
    /// Creates a new builder-style object to manufacture [`GetTagValuesInput`](crate::operation::get_tag_values::GetTagValuesInput).
    pub fn builder() -> crate::operation::get_tag_values::builders::GetTagValuesInputBuilder {
        crate::operation::get_tag_values::builders::GetTagValuesInputBuilder::default()
    }
}

/// A builder for [`GetTagValuesInput`](crate::operation::get_tag_values::GetTagValuesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetTagValuesInputBuilder {
    pub(crate) pagination_token: ::std::option::Option<::std::string::String>,
    pub(crate) key: ::std::option::Option<::std::string::String>,
}
impl GetTagValuesInputBuilder {
    /// <p>Specifies a <code>PaginationToken</code> response value from a previous request to indicate that you want the next page of results. Leave this parameter empty in your initial request.</p>
    pub fn pagination_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.pagination_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies a <code>PaginationToken</code> response value from a previous request to indicate that you want the next page of results. Leave this parameter empty in your initial request.</p>
    pub fn set_pagination_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.pagination_token = input;
        self
    }
    /// <p>Specifies a <code>PaginationToken</code> response value from a previous request to indicate that you want the next page of results. Leave this parameter empty in your initial request.</p>
    pub fn get_pagination_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.pagination_token
    }
    /// <p>Specifies the tag key for which you want to list all existing values that are currently used in the specified Amazon Web Services Region for the calling account.</p>
    /// This field is required.
    pub fn key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the tag key for which you want to list all existing values that are currently used in the specified Amazon Web Services Region for the calling account.</p>
    pub fn set_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.key = input;
        self
    }
    /// <p>Specifies the tag key for which you want to list all existing values that are currently used in the specified Amazon Web Services Region for the calling account.</p>
    pub fn get_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.key
    }
    /// Consumes the builder and constructs a [`GetTagValuesInput`](crate::operation::get_tag_values::GetTagValuesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_tag_values::GetTagValuesInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_tag_values::GetTagValuesInput {
            pagination_token: self.pagination_token,
            key: self.key,
        })
    }
}
