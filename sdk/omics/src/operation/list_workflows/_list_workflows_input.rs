// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListWorkflowsInput {
    /// <p>Filter the list by workflow type.</p>
    pub r#type: ::std::option::Option<crate::types::WorkflowType>,
    /// <p>Filter the list by workflow name.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>Specify the pagination token from a previous request to retrieve the next page of results.</p>
    pub starting_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of workflows to return in one page of results.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl ListWorkflowsInput {
    /// <p>Filter the list by workflow type.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::WorkflowType> {
        self.r#type.as_ref()
    }
    /// <p>Filter the list by workflow name.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>Specify the pagination token from a previous request to retrieve the next page of results.</p>
    pub fn starting_token(&self) -> ::std::option::Option<&str> {
        self.starting_token.as_deref()
    }
    /// <p>The maximum number of workflows to return in one page of results.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl ListWorkflowsInput {
    /// Creates a new builder-style object to manufacture [`ListWorkflowsInput`](crate::operation::list_workflows::ListWorkflowsInput).
    pub fn builder() -> crate::operation::list_workflows::builders::ListWorkflowsInputBuilder {
        crate::operation::list_workflows::builders::ListWorkflowsInputBuilder::default()
    }
}

/// A builder for [`ListWorkflowsInput`](crate::operation::list_workflows::ListWorkflowsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListWorkflowsInputBuilder {
    pub(crate) r#type: ::std::option::Option<crate::types::WorkflowType>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) starting_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl ListWorkflowsInputBuilder {
    /// <p>Filter the list by workflow type.</p>
    pub fn r#type(mut self, input: crate::types::WorkflowType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Filter the list by workflow type.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::WorkflowType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>Filter the list by workflow type.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::WorkflowType> {
        &self.r#type
    }
    /// <p>Filter the list by workflow name.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Filter the list by workflow name.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>Filter the list by workflow name.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>Specify the pagination token from a previous request to retrieve the next page of results.</p>
    pub fn starting_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.starting_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specify the pagination token from a previous request to retrieve the next page of results.</p>
    pub fn set_starting_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.starting_token = input;
        self
    }
    /// <p>Specify the pagination token from a previous request to retrieve the next page of results.</p>
    pub fn get_starting_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.starting_token
    }
    /// <p>The maximum number of workflows to return in one page of results.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of workflows to return in one page of results.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of workflows to return in one page of results.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`ListWorkflowsInput`](crate::operation::list_workflows::ListWorkflowsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_workflows::ListWorkflowsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_workflows::ListWorkflowsInput {
            r#type: self.r#type,
            name: self.name,
            starting_token: self.starting_token,
            max_results: self.max_results,
        })
    }
}
