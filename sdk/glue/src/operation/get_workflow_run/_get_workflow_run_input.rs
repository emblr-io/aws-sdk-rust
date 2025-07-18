// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetWorkflowRunInput {
    /// <p>Name of the workflow being run.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the workflow run.</p>
    pub run_id: ::std::option::Option<::std::string::String>,
    /// <p>Specifies whether to include the workflow graph in response or not.</p>
    pub include_graph: ::std::option::Option<bool>,
}
impl GetWorkflowRunInput {
    /// <p>Name of the workflow being run.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The ID of the workflow run.</p>
    pub fn run_id(&self) -> ::std::option::Option<&str> {
        self.run_id.as_deref()
    }
    /// <p>Specifies whether to include the workflow graph in response or not.</p>
    pub fn include_graph(&self) -> ::std::option::Option<bool> {
        self.include_graph
    }
}
impl GetWorkflowRunInput {
    /// Creates a new builder-style object to manufacture [`GetWorkflowRunInput`](crate::operation::get_workflow_run::GetWorkflowRunInput).
    pub fn builder() -> crate::operation::get_workflow_run::builders::GetWorkflowRunInputBuilder {
        crate::operation::get_workflow_run::builders::GetWorkflowRunInputBuilder::default()
    }
}

/// A builder for [`GetWorkflowRunInput`](crate::operation::get_workflow_run::GetWorkflowRunInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetWorkflowRunInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) run_id: ::std::option::Option<::std::string::String>,
    pub(crate) include_graph: ::std::option::Option<bool>,
}
impl GetWorkflowRunInputBuilder {
    /// <p>Name of the workflow being run.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Name of the workflow being run.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>Name of the workflow being run.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The ID of the workflow run.</p>
    /// This field is required.
    pub fn run_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.run_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the workflow run.</p>
    pub fn set_run_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.run_id = input;
        self
    }
    /// <p>The ID of the workflow run.</p>
    pub fn get_run_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.run_id
    }
    /// <p>Specifies whether to include the workflow graph in response or not.</p>
    pub fn include_graph(mut self, input: bool) -> Self {
        self.include_graph = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether to include the workflow graph in response or not.</p>
    pub fn set_include_graph(mut self, input: ::std::option::Option<bool>) -> Self {
        self.include_graph = input;
        self
    }
    /// <p>Specifies whether to include the workflow graph in response or not.</p>
    pub fn get_include_graph(&self) -> &::std::option::Option<bool> {
        &self.include_graph
    }
    /// Consumes the builder and constructs a [`GetWorkflowRunInput`](crate::operation::get_workflow_run::GetWorkflowRunInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_workflow_run::GetWorkflowRunInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_workflow_run::GetWorkflowRunInput {
            name: self.name,
            run_id: self.run_id,
            include_graph: self.include_graph,
        })
    }
}
