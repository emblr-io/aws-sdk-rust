// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Indicates the resource that will be grouped in the recommended Application Component (AppComponent).</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GroupingResource {
    /// <p>Indicates the resource name.</p>
    pub resource_name: ::std::string::String,
    /// <p>Indicates the resource type.</p>
    pub resource_type: ::std::string::String,
    /// <p>Indicates the physical identifier of the resource.</p>
    pub physical_resource_id: ::std::option::Option<crate::types::PhysicalResourceId>,
    /// <p>Indicates the logical identifier of the resource.</p>
    pub logical_resource_id: ::std::option::Option<crate::types::LogicalResourceId>,
    /// <p>Indicates the identifier of the source AppComponents in which the resources were previously grouped into.</p>
    pub source_app_component_ids: ::std::vec::Vec<::std::string::String>,
}
impl GroupingResource {
    /// <p>Indicates the resource name.</p>
    pub fn resource_name(&self) -> &str {
        use std::ops::Deref;
        self.resource_name.deref()
    }
    /// <p>Indicates the resource type.</p>
    pub fn resource_type(&self) -> &str {
        use std::ops::Deref;
        self.resource_type.deref()
    }
    /// <p>Indicates the physical identifier of the resource.</p>
    pub fn physical_resource_id(&self) -> ::std::option::Option<&crate::types::PhysicalResourceId> {
        self.physical_resource_id.as_ref()
    }
    /// <p>Indicates the logical identifier of the resource.</p>
    pub fn logical_resource_id(&self) -> ::std::option::Option<&crate::types::LogicalResourceId> {
        self.logical_resource_id.as_ref()
    }
    /// <p>Indicates the identifier of the source AppComponents in which the resources were previously grouped into.</p>
    pub fn source_app_component_ids(&self) -> &[::std::string::String] {
        use std::ops::Deref;
        self.source_app_component_ids.deref()
    }
}
impl GroupingResource {
    /// Creates a new builder-style object to manufacture [`GroupingResource`](crate::types::GroupingResource).
    pub fn builder() -> crate::types::builders::GroupingResourceBuilder {
        crate::types::builders::GroupingResourceBuilder::default()
    }
}

/// A builder for [`GroupingResource`](crate::types::GroupingResource).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GroupingResourceBuilder {
    pub(crate) resource_name: ::std::option::Option<::std::string::String>,
    pub(crate) resource_type: ::std::option::Option<::std::string::String>,
    pub(crate) physical_resource_id: ::std::option::Option<crate::types::PhysicalResourceId>,
    pub(crate) logical_resource_id: ::std::option::Option<crate::types::LogicalResourceId>,
    pub(crate) source_app_component_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl GroupingResourceBuilder {
    /// <p>Indicates the resource name.</p>
    /// This field is required.
    pub fn resource_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Indicates the resource name.</p>
    pub fn set_resource_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_name = input;
        self
    }
    /// <p>Indicates the resource name.</p>
    pub fn get_resource_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_name
    }
    /// <p>Indicates the resource type.</p>
    /// This field is required.
    pub fn resource_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Indicates the resource type.</p>
    pub fn set_resource_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_type = input;
        self
    }
    /// <p>Indicates the resource type.</p>
    pub fn get_resource_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_type
    }
    /// <p>Indicates the physical identifier of the resource.</p>
    /// This field is required.
    pub fn physical_resource_id(mut self, input: crate::types::PhysicalResourceId) -> Self {
        self.physical_resource_id = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates the physical identifier of the resource.</p>
    pub fn set_physical_resource_id(mut self, input: ::std::option::Option<crate::types::PhysicalResourceId>) -> Self {
        self.physical_resource_id = input;
        self
    }
    /// <p>Indicates the physical identifier of the resource.</p>
    pub fn get_physical_resource_id(&self) -> &::std::option::Option<crate::types::PhysicalResourceId> {
        &self.physical_resource_id
    }
    /// <p>Indicates the logical identifier of the resource.</p>
    /// This field is required.
    pub fn logical_resource_id(mut self, input: crate::types::LogicalResourceId) -> Self {
        self.logical_resource_id = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates the logical identifier of the resource.</p>
    pub fn set_logical_resource_id(mut self, input: ::std::option::Option<crate::types::LogicalResourceId>) -> Self {
        self.logical_resource_id = input;
        self
    }
    /// <p>Indicates the logical identifier of the resource.</p>
    pub fn get_logical_resource_id(&self) -> &::std::option::Option<crate::types::LogicalResourceId> {
        &self.logical_resource_id
    }
    /// Appends an item to `source_app_component_ids`.
    ///
    /// To override the contents of this collection use [`set_source_app_component_ids`](Self::set_source_app_component_ids).
    ///
    /// <p>Indicates the identifier of the source AppComponents in which the resources were previously grouped into.</p>
    pub fn source_app_component_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.source_app_component_ids.unwrap_or_default();
        v.push(input.into());
        self.source_app_component_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>Indicates the identifier of the source AppComponents in which the resources were previously grouped into.</p>
    pub fn set_source_app_component_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.source_app_component_ids = input;
        self
    }
    /// <p>Indicates the identifier of the source AppComponents in which the resources were previously grouped into.</p>
    pub fn get_source_app_component_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.source_app_component_ids
    }
    /// Consumes the builder and constructs a [`GroupingResource`](crate::types::GroupingResource).
    /// This method will fail if any of the following fields are not set:
    /// - [`resource_name`](crate::types::builders::GroupingResourceBuilder::resource_name)
    /// - [`resource_type`](crate::types::builders::GroupingResourceBuilder::resource_type)
    /// - [`source_app_component_ids`](crate::types::builders::GroupingResourceBuilder::source_app_component_ids)
    pub fn build(self) -> ::std::result::Result<crate::types::GroupingResource, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::GroupingResource {
            resource_name: self.resource_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "resource_name",
                    "resource_name was not specified but it is required when building GroupingResource",
                )
            })?,
            resource_type: self.resource_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "resource_type",
                    "resource_type was not specified but it is required when building GroupingResource",
                )
            })?,
            physical_resource_id: self.physical_resource_id,
            logical_resource_id: self.logical_resource_id,
            source_app_component_ids: self.source_app_component_ids.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "source_app_component_ids",
                    "source_app_component_ids was not specified but it is required when building GroupingResource",
                )
            })?,
        })
    }
}
