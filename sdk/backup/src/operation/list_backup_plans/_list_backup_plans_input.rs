// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListBackupPlansInput {
    /// <p>The next item following a partial list of returned items. For example, if a request is made to return <code>MaxResults</code> number of items, <code>NextToken</code> allows you to return more items in your list starting at the location pointed to by the next token.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of items to be returned.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>A Boolean value with a default value of <code>FALSE</code> that returns deleted backup plans when set to <code>TRUE</code>.</p>
    pub include_deleted: ::std::option::Option<bool>,
}
impl ListBackupPlansInput {
    /// <p>The next item following a partial list of returned items. For example, if a request is made to return <code>MaxResults</code> number of items, <code>NextToken</code> allows you to return more items in your list starting at the location pointed to by the next token.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of items to be returned.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>A Boolean value with a default value of <code>FALSE</code> that returns deleted backup plans when set to <code>TRUE</code>.</p>
    pub fn include_deleted(&self) -> ::std::option::Option<bool> {
        self.include_deleted
    }
}
impl ListBackupPlansInput {
    /// Creates a new builder-style object to manufacture [`ListBackupPlansInput`](crate::operation::list_backup_plans::ListBackupPlansInput).
    pub fn builder() -> crate::operation::list_backup_plans::builders::ListBackupPlansInputBuilder {
        crate::operation::list_backup_plans::builders::ListBackupPlansInputBuilder::default()
    }
}

/// A builder for [`ListBackupPlansInput`](crate::operation::list_backup_plans::ListBackupPlansInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListBackupPlansInputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) include_deleted: ::std::option::Option<bool>,
}
impl ListBackupPlansInputBuilder {
    /// <p>The next item following a partial list of returned items. For example, if a request is made to return <code>MaxResults</code> number of items, <code>NextToken</code> allows you to return more items in your list starting at the location pointed to by the next token.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The next item following a partial list of returned items. For example, if a request is made to return <code>MaxResults</code> number of items, <code>NextToken</code> allows you to return more items in your list starting at the location pointed to by the next token.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The next item following a partial list of returned items. For example, if a request is made to return <code>MaxResults</code> number of items, <code>NextToken</code> allows you to return more items in your list starting at the location pointed to by the next token.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of items to be returned.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of items to be returned.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of items to be returned.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>A Boolean value with a default value of <code>FALSE</code> that returns deleted backup plans when set to <code>TRUE</code>.</p>
    pub fn include_deleted(mut self, input: bool) -> Self {
        self.include_deleted = ::std::option::Option::Some(input);
        self
    }
    /// <p>A Boolean value with a default value of <code>FALSE</code> that returns deleted backup plans when set to <code>TRUE</code>.</p>
    pub fn set_include_deleted(mut self, input: ::std::option::Option<bool>) -> Self {
        self.include_deleted = input;
        self
    }
    /// <p>A Boolean value with a default value of <code>FALSE</code> that returns deleted backup plans when set to <code>TRUE</code>.</p>
    pub fn get_include_deleted(&self) -> &::std::option::Option<bool> {
        &self.include_deleted
    }
    /// Consumes the builder and constructs a [`ListBackupPlansInput`](crate::operation::list_backup_plans::ListBackupPlansInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_backup_plans::ListBackupPlansInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_backup_plans::ListBackupPlansInput {
            next_token: self.next_token,
            max_results: self.max_results,
            include_deleted: self.include_deleted,
        })
    }
}
