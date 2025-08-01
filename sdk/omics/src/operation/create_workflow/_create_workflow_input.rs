// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateWorkflowInput {
    /// <p>A name for the workflow.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>A description for the workflow.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The workflow engine for the workflow.</p>
    pub engine: ::std::option::Option<crate::types::WorkflowEngine>,
    /// <p>A ZIP archive for the workflow.</p>
    pub definition_zip: ::std::option::Option<::aws_smithy_types::Blob>,
    /// <p>The URI of a definition for the workflow.</p>
    pub definition_uri: ::std::option::Option<::std::string::String>,
    /// <p>The path of the main definition file for the workflow.</p>
    pub main: ::std::option::Option<::std::string::String>,
    /// <p>A parameter template for the workflow.</p>
    pub parameter_template: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::WorkflowParameter>>,
    /// <p>The default static storage capacity (in gibibytes) for runs that use this workflow or workflow version.</p>
    pub storage_capacity: ::std::option::Option<i32>,
    /// <p>Tags for the workflow.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>To ensure that requests don't run multiple times, specify a unique ID for each request.</p>
    pub request_id: ::std::option::Option<::std::string::String>,
    /// <p>The computational accelerator specified to run the workflow.</p>
    pub accelerators: ::std::option::Option<crate::types::Accelerators>,
    /// <p>The default storage type for runs that use this workflow. STATIC storage allocates a fixed amount of storage. DYNAMIC storage dynamically scales the storage up or down, based on file system utilization. For more information about static and dynamic storage, see <a href="https://docs.aws.amazon.com/omics/latest/dev/Using-workflows.html">Running workflows</a> in the <i>Amazon Web Services HealthOmics User Guide</i>.</p>
    pub storage_type: ::std::option::Option<crate::types::StorageType>,
}
impl CreateWorkflowInput {
    /// <p>A name for the workflow.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>A description for the workflow.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The workflow engine for the workflow.</p>
    pub fn engine(&self) -> ::std::option::Option<&crate::types::WorkflowEngine> {
        self.engine.as_ref()
    }
    /// <p>A ZIP archive for the workflow.</p>
    pub fn definition_zip(&self) -> ::std::option::Option<&::aws_smithy_types::Blob> {
        self.definition_zip.as_ref()
    }
    /// <p>The URI of a definition for the workflow.</p>
    pub fn definition_uri(&self) -> ::std::option::Option<&str> {
        self.definition_uri.as_deref()
    }
    /// <p>The path of the main definition file for the workflow.</p>
    pub fn main(&self) -> ::std::option::Option<&str> {
        self.main.as_deref()
    }
    /// <p>A parameter template for the workflow.</p>
    pub fn parameter_template(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, crate::types::WorkflowParameter>> {
        self.parameter_template.as_ref()
    }
    /// <p>The default static storage capacity (in gibibytes) for runs that use this workflow or workflow version.</p>
    pub fn storage_capacity(&self) -> ::std::option::Option<i32> {
        self.storage_capacity
    }
    /// <p>Tags for the workflow.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
    /// <p>To ensure that requests don't run multiple times, specify a unique ID for each request.</p>
    pub fn request_id(&self) -> ::std::option::Option<&str> {
        self.request_id.as_deref()
    }
    /// <p>The computational accelerator specified to run the workflow.</p>
    pub fn accelerators(&self) -> ::std::option::Option<&crate::types::Accelerators> {
        self.accelerators.as_ref()
    }
    /// <p>The default storage type for runs that use this workflow. STATIC storage allocates a fixed amount of storage. DYNAMIC storage dynamically scales the storage up or down, based on file system utilization. For more information about static and dynamic storage, see <a href="https://docs.aws.amazon.com/omics/latest/dev/Using-workflows.html">Running workflows</a> in the <i>Amazon Web Services HealthOmics User Guide</i>.</p>
    pub fn storage_type(&self) -> ::std::option::Option<&crate::types::StorageType> {
        self.storage_type.as_ref()
    }
}
impl CreateWorkflowInput {
    /// Creates a new builder-style object to manufacture [`CreateWorkflowInput`](crate::operation::create_workflow::CreateWorkflowInput).
    pub fn builder() -> crate::operation::create_workflow::builders::CreateWorkflowInputBuilder {
        crate::operation::create_workflow::builders::CreateWorkflowInputBuilder::default()
    }
}

/// A builder for [`CreateWorkflowInput`](crate::operation::create_workflow::CreateWorkflowInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateWorkflowInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) engine: ::std::option::Option<crate::types::WorkflowEngine>,
    pub(crate) definition_zip: ::std::option::Option<::aws_smithy_types::Blob>,
    pub(crate) definition_uri: ::std::option::Option<::std::string::String>,
    pub(crate) main: ::std::option::Option<::std::string::String>,
    pub(crate) parameter_template: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::WorkflowParameter>>,
    pub(crate) storage_capacity: ::std::option::Option<i32>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) request_id: ::std::option::Option<::std::string::String>,
    pub(crate) accelerators: ::std::option::Option<crate::types::Accelerators>,
    pub(crate) storage_type: ::std::option::Option<crate::types::StorageType>,
}
impl CreateWorkflowInputBuilder {
    /// <p>A name for the workflow.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A name for the workflow.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>A name for the workflow.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>A description for the workflow.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description for the workflow.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A description for the workflow.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The workflow engine for the workflow.</p>
    pub fn engine(mut self, input: crate::types::WorkflowEngine) -> Self {
        self.engine = ::std::option::Option::Some(input);
        self
    }
    /// <p>The workflow engine for the workflow.</p>
    pub fn set_engine(mut self, input: ::std::option::Option<crate::types::WorkflowEngine>) -> Self {
        self.engine = input;
        self
    }
    /// <p>The workflow engine for the workflow.</p>
    pub fn get_engine(&self) -> &::std::option::Option<crate::types::WorkflowEngine> {
        &self.engine
    }
    /// <p>A ZIP archive for the workflow.</p>
    pub fn definition_zip(mut self, input: ::aws_smithy_types::Blob) -> Self {
        self.definition_zip = ::std::option::Option::Some(input);
        self
    }
    /// <p>A ZIP archive for the workflow.</p>
    pub fn set_definition_zip(mut self, input: ::std::option::Option<::aws_smithy_types::Blob>) -> Self {
        self.definition_zip = input;
        self
    }
    /// <p>A ZIP archive for the workflow.</p>
    pub fn get_definition_zip(&self) -> &::std::option::Option<::aws_smithy_types::Blob> {
        &self.definition_zip
    }
    /// <p>The URI of a definition for the workflow.</p>
    pub fn definition_uri(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.definition_uri = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The URI of a definition for the workflow.</p>
    pub fn set_definition_uri(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.definition_uri = input;
        self
    }
    /// <p>The URI of a definition for the workflow.</p>
    pub fn get_definition_uri(&self) -> &::std::option::Option<::std::string::String> {
        &self.definition_uri
    }
    /// <p>The path of the main definition file for the workflow.</p>
    pub fn main(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.main = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The path of the main definition file for the workflow.</p>
    pub fn set_main(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.main = input;
        self
    }
    /// <p>The path of the main definition file for the workflow.</p>
    pub fn get_main(&self) -> &::std::option::Option<::std::string::String> {
        &self.main
    }
    /// Adds a key-value pair to `parameter_template`.
    ///
    /// To override the contents of this collection use [`set_parameter_template`](Self::set_parameter_template).
    ///
    /// <p>A parameter template for the workflow.</p>
    pub fn parameter_template(mut self, k: impl ::std::convert::Into<::std::string::String>, v: crate::types::WorkflowParameter) -> Self {
        let mut hash_map = self.parameter_template.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.parameter_template = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A parameter template for the workflow.</p>
    pub fn set_parameter_template(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::WorkflowParameter>>,
    ) -> Self {
        self.parameter_template = input;
        self
    }
    /// <p>A parameter template for the workflow.</p>
    pub fn get_parameter_template(
        &self,
    ) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::WorkflowParameter>> {
        &self.parameter_template
    }
    /// <p>The default static storage capacity (in gibibytes) for runs that use this workflow or workflow version.</p>
    pub fn storage_capacity(mut self, input: i32) -> Self {
        self.storage_capacity = ::std::option::Option::Some(input);
        self
    }
    /// <p>The default static storage capacity (in gibibytes) for runs that use this workflow or workflow version.</p>
    pub fn set_storage_capacity(mut self, input: ::std::option::Option<i32>) -> Self {
        self.storage_capacity = input;
        self
    }
    /// <p>The default static storage capacity (in gibibytes) for runs that use this workflow or workflow version.</p>
    pub fn get_storage_capacity(&self) -> &::std::option::Option<i32> {
        &self.storage_capacity
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>Tags for the workflow.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Tags for the workflow.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>Tags for the workflow.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// <p>To ensure that requests don't run multiple times, specify a unique ID for each request.</p>
    /// This field is required.
    pub fn request_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.request_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>To ensure that requests don't run multiple times, specify a unique ID for each request.</p>
    pub fn set_request_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.request_id = input;
        self
    }
    /// <p>To ensure that requests don't run multiple times, specify a unique ID for each request.</p>
    pub fn get_request_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.request_id
    }
    /// <p>The computational accelerator specified to run the workflow.</p>
    pub fn accelerators(mut self, input: crate::types::Accelerators) -> Self {
        self.accelerators = ::std::option::Option::Some(input);
        self
    }
    /// <p>The computational accelerator specified to run the workflow.</p>
    pub fn set_accelerators(mut self, input: ::std::option::Option<crate::types::Accelerators>) -> Self {
        self.accelerators = input;
        self
    }
    /// <p>The computational accelerator specified to run the workflow.</p>
    pub fn get_accelerators(&self) -> &::std::option::Option<crate::types::Accelerators> {
        &self.accelerators
    }
    /// <p>The default storage type for runs that use this workflow. STATIC storage allocates a fixed amount of storage. DYNAMIC storage dynamically scales the storage up or down, based on file system utilization. For more information about static and dynamic storage, see <a href="https://docs.aws.amazon.com/omics/latest/dev/Using-workflows.html">Running workflows</a> in the <i>Amazon Web Services HealthOmics User Guide</i>.</p>
    pub fn storage_type(mut self, input: crate::types::StorageType) -> Self {
        self.storage_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The default storage type for runs that use this workflow. STATIC storage allocates a fixed amount of storage. DYNAMIC storage dynamically scales the storage up or down, based on file system utilization. For more information about static and dynamic storage, see <a href="https://docs.aws.amazon.com/omics/latest/dev/Using-workflows.html">Running workflows</a> in the <i>Amazon Web Services HealthOmics User Guide</i>.</p>
    pub fn set_storage_type(mut self, input: ::std::option::Option<crate::types::StorageType>) -> Self {
        self.storage_type = input;
        self
    }
    /// <p>The default storage type for runs that use this workflow. STATIC storage allocates a fixed amount of storage. DYNAMIC storage dynamically scales the storage up or down, based on file system utilization. For more information about static and dynamic storage, see <a href="https://docs.aws.amazon.com/omics/latest/dev/Using-workflows.html">Running workflows</a> in the <i>Amazon Web Services HealthOmics User Guide</i>.</p>
    pub fn get_storage_type(&self) -> &::std::option::Option<crate::types::StorageType> {
        &self.storage_type
    }
    /// Consumes the builder and constructs a [`CreateWorkflowInput`](crate::operation::create_workflow::CreateWorkflowInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_workflow::CreateWorkflowInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_workflow::CreateWorkflowInput {
            name: self.name,
            description: self.description,
            engine: self.engine,
            definition_zip: self.definition_zip,
            definition_uri: self.definition_uri,
            main: self.main,
            parameter_template: self.parameter_template,
            storage_capacity: self.storage_capacity,
            tags: self.tags,
            request_id: self.request_id,
            accelerators: self.accelerators,
            storage_type: self.storage_type,
        })
    }
}
