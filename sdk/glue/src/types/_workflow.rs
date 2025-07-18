// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A workflow is a collection of multiple dependent Glue jobs and crawlers that are run to complete a complex ETL task. A workflow manages the execution and monitoring of all its jobs and crawlers.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Workflow {
    /// <p>The name of the workflow.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>A description of the workflow.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>A collection of properties to be used as part of each execution of the workflow. The run properties are made available to each job in the workflow. A job can modify the properties for the next jobs in the flow.</p>
    pub default_run_properties: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The date and time when the workflow was created.</p>
    pub created_on: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The date and time when the workflow was last modified.</p>
    pub last_modified_on: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The information about the last execution of the workflow.</p>
    pub last_run: ::std::option::Option<crate::types::WorkflowRun>,
    /// <p>The graph representing all the Glue components that belong to the workflow as nodes and directed connections between them as edges.</p>
    pub graph: ::std::option::Option<crate::types::WorkflowGraph>,
    /// <p>You can use this parameter to prevent unwanted multiple updates to data, to control costs, or in some cases, to prevent exceeding the maximum number of concurrent runs of any of the component jobs. If you leave this parameter blank, there is no limit to the number of concurrent workflow runs.</p>
    pub max_concurrent_runs: ::std::option::Option<i32>,
    /// <p>This structure indicates the details of the blueprint that this particular workflow is created from.</p>
    pub blueprint_details: ::std::option::Option<crate::types::BlueprintDetails>,
}
impl Workflow {
    /// <p>The name of the workflow.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>A description of the workflow.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>A collection of properties to be used as part of each execution of the workflow. The run properties are made available to each job in the workflow. A job can modify the properties for the next jobs in the flow.</p>
    pub fn default_run_properties(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.default_run_properties.as_ref()
    }
    /// <p>The date and time when the workflow was created.</p>
    pub fn created_on(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_on.as_ref()
    }
    /// <p>The date and time when the workflow was last modified.</p>
    pub fn last_modified_on(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_modified_on.as_ref()
    }
    /// <p>The information about the last execution of the workflow.</p>
    pub fn last_run(&self) -> ::std::option::Option<&crate::types::WorkflowRun> {
        self.last_run.as_ref()
    }
    /// <p>The graph representing all the Glue components that belong to the workflow as nodes and directed connections between them as edges.</p>
    pub fn graph(&self) -> ::std::option::Option<&crate::types::WorkflowGraph> {
        self.graph.as_ref()
    }
    /// <p>You can use this parameter to prevent unwanted multiple updates to data, to control costs, or in some cases, to prevent exceeding the maximum number of concurrent runs of any of the component jobs. If you leave this parameter blank, there is no limit to the number of concurrent workflow runs.</p>
    pub fn max_concurrent_runs(&self) -> ::std::option::Option<i32> {
        self.max_concurrent_runs
    }
    /// <p>This structure indicates the details of the blueprint that this particular workflow is created from.</p>
    pub fn blueprint_details(&self) -> ::std::option::Option<&crate::types::BlueprintDetails> {
        self.blueprint_details.as_ref()
    }
}
impl Workflow {
    /// Creates a new builder-style object to manufacture [`Workflow`](crate::types::Workflow).
    pub fn builder() -> crate::types::builders::WorkflowBuilder {
        crate::types::builders::WorkflowBuilder::default()
    }
}

/// A builder for [`Workflow`](crate::types::Workflow).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct WorkflowBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) default_run_properties: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) created_on: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_modified_on: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_run: ::std::option::Option<crate::types::WorkflowRun>,
    pub(crate) graph: ::std::option::Option<crate::types::WorkflowGraph>,
    pub(crate) max_concurrent_runs: ::std::option::Option<i32>,
    pub(crate) blueprint_details: ::std::option::Option<crate::types::BlueprintDetails>,
}
impl WorkflowBuilder {
    /// <p>The name of the workflow.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the workflow.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the workflow.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>A description of the workflow.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description of the workflow.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A description of the workflow.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Adds a key-value pair to `default_run_properties`.
    ///
    /// To override the contents of this collection use [`set_default_run_properties`](Self::set_default_run_properties).
    ///
    /// <p>A collection of properties to be used as part of each execution of the workflow. The run properties are made available to each job in the workflow. A job can modify the properties for the next jobs in the flow.</p>
    pub fn default_run_properties(
        mut self,
        k: impl ::std::convert::Into<::std::string::String>,
        v: impl ::std::convert::Into<::std::string::String>,
    ) -> Self {
        let mut hash_map = self.default_run_properties.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.default_run_properties = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A collection of properties to be used as part of each execution of the workflow. The run properties are made available to each job in the workflow. A job can modify the properties for the next jobs in the flow.</p>
    pub fn set_default_run_properties(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    ) -> Self {
        self.default_run_properties = input;
        self
    }
    /// <p>A collection of properties to be used as part of each execution of the workflow. The run properties are made available to each job in the workflow. A job can modify the properties for the next jobs in the flow.</p>
    pub fn get_default_run_properties(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.default_run_properties
    }
    /// <p>The date and time when the workflow was created.</p>
    pub fn created_on(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_on = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time when the workflow was created.</p>
    pub fn set_created_on(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_on = input;
        self
    }
    /// <p>The date and time when the workflow was created.</p>
    pub fn get_created_on(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_on
    }
    /// <p>The date and time when the workflow was last modified.</p>
    pub fn last_modified_on(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_modified_on = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time when the workflow was last modified.</p>
    pub fn set_last_modified_on(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_modified_on = input;
        self
    }
    /// <p>The date and time when the workflow was last modified.</p>
    pub fn get_last_modified_on(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_modified_on
    }
    /// <p>The information about the last execution of the workflow.</p>
    pub fn last_run(mut self, input: crate::types::WorkflowRun) -> Self {
        self.last_run = ::std::option::Option::Some(input);
        self
    }
    /// <p>The information about the last execution of the workflow.</p>
    pub fn set_last_run(mut self, input: ::std::option::Option<crate::types::WorkflowRun>) -> Self {
        self.last_run = input;
        self
    }
    /// <p>The information about the last execution of the workflow.</p>
    pub fn get_last_run(&self) -> &::std::option::Option<crate::types::WorkflowRun> {
        &self.last_run
    }
    /// <p>The graph representing all the Glue components that belong to the workflow as nodes and directed connections between them as edges.</p>
    pub fn graph(mut self, input: crate::types::WorkflowGraph) -> Self {
        self.graph = ::std::option::Option::Some(input);
        self
    }
    /// <p>The graph representing all the Glue components that belong to the workflow as nodes and directed connections between them as edges.</p>
    pub fn set_graph(mut self, input: ::std::option::Option<crate::types::WorkflowGraph>) -> Self {
        self.graph = input;
        self
    }
    /// <p>The graph representing all the Glue components that belong to the workflow as nodes and directed connections between them as edges.</p>
    pub fn get_graph(&self) -> &::std::option::Option<crate::types::WorkflowGraph> {
        &self.graph
    }
    /// <p>You can use this parameter to prevent unwanted multiple updates to data, to control costs, or in some cases, to prevent exceeding the maximum number of concurrent runs of any of the component jobs. If you leave this parameter blank, there is no limit to the number of concurrent workflow runs.</p>
    pub fn max_concurrent_runs(mut self, input: i32) -> Self {
        self.max_concurrent_runs = ::std::option::Option::Some(input);
        self
    }
    /// <p>You can use this parameter to prevent unwanted multiple updates to data, to control costs, or in some cases, to prevent exceeding the maximum number of concurrent runs of any of the component jobs. If you leave this parameter blank, there is no limit to the number of concurrent workflow runs.</p>
    pub fn set_max_concurrent_runs(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_concurrent_runs = input;
        self
    }
    /// <p>You can use this parameter to prevent unwanted multiple updates to data, to control costs, or in some cases, to prevent exceeding the maximum number of concurrent runs of any of the component jobs. If you leave this parameter blank, there is no limit to the number of concurrent workflow runs.</p>
    pub fn get_max_concurrent_runs(&self) -> &::std::option::Option<i32> {
        &self.max_concurrent_runs
    }
    /// <p>This structure indicates the details of the blueprint that this particular workflow is created from.</p>
    pub fn blueprint_details(mut self, input: crate::types::BlueprintDetails) -> Self {
        self.blueprint_details = ::std::option::Option::Some(input);
        self
    }
    /// <p>This structure indicates the details of the blueprint that this particular workflow is created from.</p>
    pub fn set_blueprint_details(mut self, input: ::std::option::Option<crate::types::BlueprintDetails>) -> Self {
        self.blueprint_details = input;
        self
    }
    /// <p>This structure indicates the details of the blueprint that this particular workflow is created from.</p>
    pub fn get_blueprint_details(&self) -> &::std::option::Option<crate::types::BlueprintDetails> {
        &self.blueprint_details
    }
    /// Consumes the builder and constructs a [`Workflow`](crate::types::Workflow).
    pub fn build(self) -> crate::types::Workflow {
        crate::types::Workflow {
            name: self.name,
            description: self.description,
            default_run_properties: self.default_run_properties,
            created_on: self.created_on,
            last_modified_on: self.last_modified_on,
            last_run: self.last_run,
            graph: self.graph,
            max_concurrent_runs: self.max_concurrent_runs,
            blueprint_details: self.blueprint_details,
        }
    }
}
