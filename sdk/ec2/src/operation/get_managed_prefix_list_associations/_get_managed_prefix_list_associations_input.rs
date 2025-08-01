// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetManagedPrefixListAssociationsInput {
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub dry_run: ::std::option::Option<bool>,
    /// <p>The ID of the prefix list.</p>
    pub prefix_list_id: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results to return with a single call. To retrieve the remaining results, make another call with the returned <code>nextToken</code> value.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The token for the next page of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl GetManagedPrefixListAssociationsInput {
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(&self) -> ::std::option::Option<bool> {
        self.dry_run
    }
    /// <p>The ID of the prefix list.</p>
    pub fn prefix_list_id(&self) -> ::std::option::Option<&str> {
        self.prefix_list_id.as_deref()
    }
    /// <p>The maximum number of results to return with a single call. To retrieve the remaining results, make another call with the returned <code>nextToken</code> value.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The token for the next page of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl GetManagedPrefixListAssociationsInput {
    /// Creates a new builder-style object to manufacture [`GetManagedPrefixListAssociationsInput`](crate::operation::get_managed_prefix_list_associations::GetManagedPrefixListAssociationsInput).
    pub fn builder() -> crate::operation::get_managed_prefix_list_associations::builders::GetManagedPrefixListAssociationsInputBuilder {
        crate::operation::get_managed_prefix_list_associations::builders::GetManagedPrefixListAssociationsInputBuilder::default()
    }
}

/// A builder for [`GetManagedPrefixListAssociationsInput`](crate::operation::get_managed_prefix_list_associations::GetManagedPrefixListAssociationsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetManagedPrefixListAssociationsInputBuilder {
    pub(crate) dry_run: ::std::option::Option<bool>,
    pub(crate) prefix_list_id: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl GetManagedPrefixListAssociationsInputBuilder {
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
    /// <p>The ID of the prefix list.</p>
    /// This field is required.
    pub fn prefix_list_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.prefix_list_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the prefix list.</p>
    pub fn set_prefix_list_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.prefix_list_id = input;
        self
    }
    /// <p>The ID of the prefix list.</p>
    pub fn get_prefix_list_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.prefix_list_id
    }
    /// <p>The maximum number of results to return with a single call. To retrieve the remaining results, make another call with the returned <code>nextToken</code> value.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to return with a single call. To retrieve the remaining results, make another call with the returned <code>nextToken</code> value.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to return with a single call. To retrieve the remaining results, make another call with the returned <code>nextToken</code> value.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>The token for the next page of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token for the next page of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token for the next page of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`GetManagedPrefixListAssociationsInput`](crate::operation::get_managed_prefix_list_associations::GetManagedPrefixListAssociationsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_managed_prefix_list_associations::GetManagedPrefixListAssociationsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::get_managed_prefix_list_associations::GetManagedPrefixListAssociationsInput {
                dry_run: self.dry_run,
                prefix_list_id: self.prefix_list_id,
                max_results: self.max_results,
                next_token: self.next_token,
            },
        )
    }
}
