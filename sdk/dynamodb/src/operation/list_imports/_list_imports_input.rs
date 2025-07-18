// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListImportsInput {
    /// <p>The Amazon Resource Name (ARN) associated with the table that was imported to.</p>
    pub table_arn: ::std::option::Option<::std::string::String>,
    /// <p>The number of <code>ImportSummary </code>objects returned in a single page.</p>
    pub page_size: ::std::option::Option<i32>,
    /// <p>An optional string that, if supplied, must be copied from the output of a previous call to <code>ListImports</code>. When provided in this manner, the API fetches the next page of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl ListImportsInput {
    /// <p>The Amazon Resource Name (ARN) associated with the table that was imported to.</p>
    pub fn table_arn(&self) -> ::std::option::Option<&str> {
        self.table_arn.as_deref()
    }
    /// <p>The number of <code>ImportSummary </code>objects returned in a single page.</p>
    pub fn page_size(&self) -> ::std::option::Option<i32> {
        self.page_size
    }
    /// <p>An optional string that, if supplied, must be copied from the output of a previous call to <code>ListImports</code>. When provided in this manner, the API fetches the next page of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ListImportsInput {
    /// Creates a new builder-style object to manufacture [`ListImportsInput`](crate::operation::list_imports::ListImportsInput).
    pub fn builder() -> crate::operation::list_imports::builders::ListImportsInputBuilder {
        crate::operation::list_imports::builders::ListImportsInputBuilder::default()
    }
}

/// A builder for [`ListImportsInput`](crate::operation::list_imports::ListImportsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListImportsInputBuilder {
    pub(crate) table_arn: ::std::option::Option<::std::string::String>,
    pub(crate) page_size: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl ListImportsInputBuilder {
    /// <p>The Amazon Resource Name (ARN) associated with the table that was imported to.</p>
    pub fn table_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.table_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) associated with the table that was imported to.</p>
    pub fn set_table_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.table_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) associated with the table that was imported to.</p>
    pub fn get_table_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.table_arn
    }
    /// <p>The number of <code>ImportSummary </code>objects returned in a single page.</p>
    pub fn page_size(mut self, input: i32) -> Self {
        self.page_size = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of <code>ImportSummary </code>objects returned in a single page.</p>
    pub fn set_page_size(mut self, input: ::std::option::Option<i32>) -> Self {
        self.page_size = input;
        self
    }
    /// <p>The number of <code>ImportSummary </code>objects returned in a single page.</p>
    pub fn get_page_size(&self) -> &::std::option::Option<i32> {
        &self.page_size
    }
    /// <p>An optional string that, if supplied, must be copied from the output of a previous call to <code>ListImports</code>. When provided in this manner, the API fetches the next page of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An optional string that, if supplied, must be copied from the output of a previous call to <code>ListImports</code>. When provided in this manner, the API fetches the next page of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>An optional string that, if supplied, must be copied from the output of a previous call to <code>ListImports</code>. When provided in this manner, the API fetches the next page of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`ListImportsInput`](crate::operation::list_imports::ListImportsInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::list_imports::ListImportsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_imports::ListImportsInput {
            table_arn: self.table_arn,
            page_size: self.page_size,
            next_token: self.next_token,
        })
    }
}
