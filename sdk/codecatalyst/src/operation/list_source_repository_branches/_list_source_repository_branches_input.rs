// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListSourceRepositoryBranchesInput {
    /// <p>The name of the space.</p>
    pub space_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the project in the space.</p>
    pub project_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the source repository.</p>
    pub source_repository_name: ::std::option::Option<::std::string::String>,
    /// <p>A token returned from a call to this API to indicate the next batch of results to return, if any.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results to show in a single call to this API. If the number of results is larger than the number you specified, the response will include a <code>NextToken</code> element, which you can use to obtain additional results.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl ListSourceRepositoryBranchesInput {
    /// <p>The name of the space.</p>
    pub fn space_name(&self) -> ::std::option::Option<&str> {
        self.space_name.as_deref()
    }
    /// <p>The name of the project in the space.</p>
    pub fn project_name(&self) -> ::std::option::Option<&str> {
        self.project_name.as_deref()
    }
    /// <p>The name of the source repository.</p>
    pub fn source_repository_name(&self) -> ::std::option::Option<&str> {
        self.source_repository_name.as_deref()
    }
    /// <p>A token returned from a call to this API to indicate the next batch of results to return, if any.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of results to show in a single call to this API. If the number of results is larger than the number you specified, the response will include a <code>NextToken</code> element, which you can use to obtain additional results.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl ListSourceRepositoryBranchesInput {
    /// Creates a new builder-style object to manufacture [`ListSourceRepositoryBranchesInput`](crate::operation::list_source_repository_branches::ListSourceRepositoryBranchesInput).
    pub fn builder() -> crate::operation::list_source_repository_branches::builders::ListSourceRepositoryBranchesInputBuilder {
        crate::operation::list_source_repository_branches::builders::ListSourceRepositoryBranchesInputBuilder::default()
    }
}

/// A builder for [`ListSourceRepositoryBranchesInput`](crate::operation::list_source_repository_branches::ListSourceRepositoryBranchesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListSourceRepositoryBranchesInputBuilder {
    pub(crate) space_name: ::std::option::Option<::std::string::String>,
    pub(crate) project_name: ::std::option::Option<::std::string::String>,
    pub(crate) source_repository_name: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl ListSourceRepositoryBranchesInputBuilder {
    /// <p>The name of the space.</p>
    /// This field is required.
    pub fn space_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.space_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the space.</p>
    pub fn set_space_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.space_name = input;
        self
    }
    /// <p>The name of the space.</p>
    pub fn get_space_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.space_name
    }
    /// <p>The name of the project in the space.</p>
    /// This field is required.
    pub fn project_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.project_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the project in the space.</p>
    pub fn set_project_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.project_name = input;
        self
    }
    /// <p>The name of the project in the space.</p>
    pub fn get_project_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.project_name
    }
    /// <p>The name of the source repository.</p>
    /// This field is required.
    pub fn source_repository_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_repository_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the source repository.</p>
    pub fn set_source_repository_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_repository_name = input;
        self
    }
    /// <p>The name of the source repository.</p>
    pub fn get_source_repository_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_repository_name
    }
    /// <p>A token returned from a call to this API to indicate the next batch of results to return, if any.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token returned from a call to this API to indicate the next batch of results to return, if any.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A token returned from a call to this API to indicate the next batch of results to return, if any.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of results to show in a single call to this API. If the number of results is larger than the number you specified, the response will include a <code>NextToken</code> element, which you can use to obtain additional results.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to show in a single call to this API. If the number of results is larger than the number you specified, the response will include a <code>NextToken</code> element, which you can use to obtain additional results.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to show in a single call to this API. If the number of results is larger than the number you specified, the response will include a <code>NextToken</code> element, which you can use to obtain additional results.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`ListSourceRepositoryBranchesInput`](crate::operation::list_source_repository_branches::ListSourceRepositoryBranchesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_source_repository_branches::ListSourceRepositoryBranchesInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_source_repository_branches::ListSourceRepositoryBranchesInput {
            space_name: self.space_name,
            project_name: self.project_name,
            source_repository_name: self.source_repository_name,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
