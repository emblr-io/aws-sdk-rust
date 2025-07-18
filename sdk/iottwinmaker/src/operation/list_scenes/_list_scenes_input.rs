// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListScenesInput {
    /// <p>The ID of the workspace that contains the scenes.</p>
    pub workspace_id: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the maximum number of results to display.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The string that specifies the next page of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl ListScenesInput {
    /// <p>The ID of the workspace that contains the scenes.</p>
    pub fn workspace_id(&self) -> ::std::option::Option<&str> {
        self.workspace_id.as_deref()
    }
    /// <p>Specifies the maximum number of results to display.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The string that specifies the next page of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ListScenesInput {
    /// Creates a new builder-style object to manufacture [`ListScenesInput`](crate::operation::list_scenes::ListScenesInput).
    pub fn builder() -> crate::operation::list_scenes::builders::ListScenesInputBuilder {
        crate::operation::list_scenes::builders::ListScenesInputBuilder::default()
    }
}

/// A builder for [`ListScenesInput`](crate::operation::list_scenes::ListScenesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListScenesInputBuilder {
    pub(crate) workspace_id: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl ListScenesInputBuilder {
    /// <p>The ID of the workspace that contains the scenes.</p>
    /// This field is required.
    pub fn workspace_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.workspace_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the workspace that contains the scenes.</p>
    pub fn set_workspace_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.workspace_id = input;
        self
    }
    /// <p>The ID of the workspace that contains the scenes.</p>
    pub fn get_workspace_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.workspace_id
    }
    /// <p>Specifies the maximum number of results to display.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the maximum number of results to display.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>Specifies the maximum number of results to display.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>The string that specifies the next page of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The string that specifies the next page of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The string that specifies the next page of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`ListScenesInput`](crate::operation::list_scenes::ListScenesInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::list_scenes::ListScenesInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_scenes::ListScenesInput {
            workspace_id: self.workspace_id,
            max_results: self.max_results,
            next_token: self.next_token,
        })
    }
}
