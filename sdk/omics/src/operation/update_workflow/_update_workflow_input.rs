// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateWorkflowInput {
    /// <p>The workflow's ID.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>A name for the workflow.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>A description for the workflow.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The default storage type for runs that use this workflow. STATIC storage allocates a fixed amount of storage. DYNAMIC storage dynamically scales the storage up or down, based on file system utilization. For more information about static and dynamic storage, see <a href="https://docs.aws.amazon.com/omics/latest/dev/Using-workflows.html">Running workflows</a> in the <i>Amazon Web Services HealthOmics User Guide</i>.</p>
    pub storage_type: ::std::option::Option<crate::types::StorageType>,
    /// <p>The default static storage capacity (in gibibytes) for runs that use this workflow or workflow version.</p>
    pub storage_capacity: ::std::option::Option<i32>,
}
impl UpdateWorkflowInput {
    /// <p>The workflow's ID.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>A name for the workflow.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>A description for the workflow.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The default storage type for runs that use this workflow. STATIC storage allocates a fixed amount of storage. DYNAMIC storage dynamically scales the storage up or down, based on file system utilization. For more information about static and dynamic storage, see <a href="https://docs.aws.amazon.com/omics/latest/dev/Using-workflows.html">Running workflows</a> in the <i>Amazon Web Services HealthOmics User Guide</i>.</p>
    pub fn storage_type(&self) -> ::std::option::Option<&crate::types::StorageType> {
        self.storage_type.as_ref()
    }
    /// <p>The default static storage capacity (in gibibytes) for runs that use this workflow or workflow version.</p>
    pub fn storage_capacity(&self) -> ::std::option::Option<i32> {
        self.storage_capacity
    }
}
impl UpdateWorkflowInput {
    /// Creates a new builder-style object to manufacture [`UpdateWorkflowInput`](crate::operation::update_workflow::UpdateWorkflowInput).
    pub fn builder() -> crate::operation::update_workflow::builders::UpdateWorkflowInputBuilder {
        crate::operation::update_workflow::builders::UpdateWorkflowInputBuilder::default()
    }
}

/// A builder for [`UpdateWorkflowInput`](crate::operation::update_workflow::UpdateWorkflowInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateWorkflowInputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) storage_type: ::std::option::Option<crate::types::StorageType>,
    pub(crate) storage_capacity: ::std::option::Option<i32>,
}
impl UpdateWorkflowInputBuilder {
    /// <p>The workflow's ID.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The workflow's ID.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The workflow's ID.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
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
    /// Consumes the builder and constructs a [`UpdateWorkflowInput`](crate::operation::update_workflow::UpdateWorkflowInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_workflow::UpdateWorkflowInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_workflow::UpdateWorkflowInput {
            id: self.id,
            name: self.name,
            description: self.description,
            storage_type: self.storage_type,
            storage_capacity: self.storage_capacity,
        })
    }
}
