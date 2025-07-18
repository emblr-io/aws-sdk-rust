// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateWorkloadInput {
    /// <p>The name of the resource group.</p>
    pub resource_group_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the component.</p>
    pub component_name: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the workload.</p>
    pub workload_id: ::std::option::Option<::std::string::String>,
    /// <p>The configuration settings of the workload. The value is the escaped JSON of the configuration.</p>
    pub workload_configuration: ::std::option::Option<crate::types::WorkloadConfiguration>,
}
impl UpdateWorkloadInput {
    /// <p>The name of the resource group.</p>
    pub fn resource_group_name(&self) -> ::std::option::Option<&str> {
        self.resource_group_name.as_deref()
    }
    /// <p>The name of the component.</p>
    pub fn component_name(&self) -> ::std::option::Option<&str> {
        self.component_name.as_deref()
    }
    /// <p>The ID of the workload.</p>
    pub fn workload_id(&self) -> ::std::option::Option<&str> {
        self.workload_id.as_deref()
    }
    /// <p>The configuration settings of the workload. The value is the escaped JSON of the configuration.</p>
    pub fn workload_configuration(&self) -> ::std::option::Option<&crate::types::WorkloadConfiguration> {
        self.workload_configuration.as_ref()
    }
}
impl UpdateWorkloadInput {
    /// Creates a new builder-style object to manufacture [`UpdateWorkloadInput`](crate::operation::update_workload::UpdateWorkloadInput).
    pub fn builder() -> crate::operation::update_workload::builders::UpdateWorkloadInputBuilder {
        crate::operation::update_workload::builders::UpdateWorkloadInputBuilder::default()
    }
}

/// A builder for [`UpdateWorkloadInput`](crate::operation::update_workload::UpdateWorkloadInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateWorkloadInputBuilder {
    pub(crate) resource_group_name: ::std::option::Option<::std::string::String>,
    pub(crate) component_name: ::std::option::Option<::std::string::String>,
    pub(crate) workload_id: ::std::option::Option<::std::string::String>,
    pub(crate) workload_configuration: ::std::option::Option<crate::types::WorkloadConfiguration>,
}
impl UpdateWorkloadInputBuilder {
    /// <p>The name of the resource group.</p>
    /// This field is required.
    pub fn resource_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the resource group.</p>
    pub fn set_resource_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_group_name = input;
        self
    }
    /// <p>The name of the resource group.</p>
    pub fn get_resource_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_group_name
    }
    /// <p>The name of the component.</p>
    /// This field is required.
    pub fn component_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.component_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the component.</p>
    pub fn set_component_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.component_name = input;
        self
    }
    /// <p>The name of the component.</p>
    pub fn get_component_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.component_name
    }
    /// <p>The ID of the workload.</p>
    pub fn workload_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.workload_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the workload.</p>
    pub fn set_workload_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.workload_id = input;
        self
    }
    /// <p>The ID of the workload.</p>
    pub fn get_workload_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.workload_id
    }
    /// <p>The configuration settings of the workload. The value is the escaped JSON of the configuration.</p>
    /// This field is required.
    pub fn workload_configuration(mut self, input: crate::types::WorkloadConfiguration) -> Self {
        self.workload_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration settings of the workload. The value is the escaped JSON of the configuration.</p>
    pub fn set_workload_configuration(mut self, input: ::std::option::Option<crate::types::WorkloadConfiguration>) -> Self {
        self.workload_configuration = input;
        self
    }
    /// <p>The configuration settings of the workload. The value is the escaped JSON of the configuration.</p>
    pub fn get_workload_configuration(&self) -> &::std::option::Option<crate::types::WorkloadConfiguration> {
        &self.workload_configuration
    }
    /// Consumes the builder and constructs a [`UpdateWorkloadInput`](crate::operation::update_workload::UpdateWorkloadInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_workload::UpdateWorkloadInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_workload::UpdateWorkloadInput {
            resource_group_name: self.resource_group_name,
            component_name: self.component_name,
            workload_id: self.workload_id,
            workload_configuration: self.workload_configuration,
        })
    }
}
