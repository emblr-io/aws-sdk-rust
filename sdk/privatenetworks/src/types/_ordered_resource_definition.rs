// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details of the network resources in the order.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct OrderedResourceDefinition {
    /// <p>The type of network resource in the order.</p>
    pub r#type: crate::types::NetworkResourceDefinitionType,
    /// <p>The number of network resources in the order.</p>
    pub count: i32,
    /// <p>The duration and renewal status of the commitment period for each radio unit in the order. Does not show details if the resource type is DEVICE_IDENTIFIER.</p>
    pub commitment_configuration: ::std::option::Option<crate::types::CommitmentConfiguration>,
}
impl OrderedResourceDefinition {
    /// <p>The type of network resource in the order.</p>
    pub fn r#type(&self) -> &crate::types::NetworkResourceDefinitionType {
        &self.r#type
    }
    /// <p>The number of network resources in the order.</p>
    pub fn count(&self) -> i32 {
        self.count
    }
    /// <p>The duration and renewal status of the commitment period for each radio unit in the order. Does not show details if the resource type is DEVICE_IDENTIFIER.</p>
    pub fn commitment_configuration(&self) -> ::std::option::Option<&crate::types::CommitmentConfiguration> {
        self.commitment_configuration.as_ref()
    }
}
impl OrderedResourceDefinition {
    /// Creates a new builder-style object to manufacture [`OrderedResourceDefinition`](crate::types::OrderedResourceDefinition).
    pub fn builder() -> crate::types::builders::OrderedResourceDefinitionBuilder {
        crate::types::builders::OrderedResourceDefinitionBuilder::default()
    }
}

/// A builder for [`OrderedResourceDefinition`](crate::types::OrderedResourceDefinition).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct OrderedResourceDefinitionBuilder {
    pub(crate) r#type: ::std::option::Option<crate::types::NetworkResourceDefinitionType>,
    pub(crate) count: ::std::option::Option<i32>,
    pub(crate) commitment_configuration: ::std::option::Option<crate::types::CommitmentConfiguration>,
}
impl OrderedResourceDefinitionBuilder {
    /// <p>The type of network resource in the order.</p>
    /// This field is required.
    pub fn r#type(mut self, input: crate::types::NetworkResourceDefinitionType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of network resource in the order.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::NetworkResourceDefinitionType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of network resource in the order.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::NetworkResourceDefinitionType> {
        &self.r#type
    }
    /// <p>The number of network resources in the order.</p>
    /// This field is required.
    pub fn count(mut self, input: i32) -> Self {
        self.count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of network resources in the order.</p>
    pub fn set_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.count = input;
        self
    }
    /// <p>The number of network resources in the order.</p>
    pub fn get_count(&self) -> &::std::option::Option<i32> {
        &self.count
    }
    /// <p>The duration and renewal status of the commitment period for each radio unit in the order. Does not show details if the resource type is DEVICE_IDENTIFIER.</p>
    pub fn commitment_configuration(mut self, input: crate::types::CommitmentConfiguration) -> Self {
        self.commitment_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The duration and renewal status of the commitment period for each radio unit in the order. Does not show details if the resource type is DEVICE_IDENTIFIER.</p>
    pub fn set_commitment_configuration(mut self, input: ::std::option::Option<crate::types::CommitmentConfiguration>) -> Self {
        self.commitment_configuration = input;
        self
    }
    /// <p>The duration and renewal status of the commitment period for each radio unit in the order. Does not show details if the resource type is DEVICE_IDENTIFIER.</p>
    pub fn get_commitment_configuration(&self) -> &::std::option::Option<crate::types::CommitmentConfiguration> {
        &self.commitment_configuration
    }
    /// Consumes the builder and constructs a [`OrderedResourceDefinition`](crate::types::OrderedResourceDefinition).
    /// This method will fail if any of the following fields are not set:
    /// - [`r#type`](crate::types::builders::OrderedResourceDefinitionBuilder::type)
    /// - [`count`](crate::types::builders::OrderedResourceDefinitionBuilder::count)
    pub fn build(self) -> ::std::result::Result<crate::types::OrderedResourceDefinition, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::OrderedResourceDefinition {
            r#type: self.r#type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "r#type",
                    "r#type was not specified but it is required when building OrderedResourceDefinition",
                )
            })?,
            count: self.count.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "count",
                    "count was not specified but it is required when building OrderedResourceDefinition",
                )
            })?,
            commitment_configuration: self.commitment_configuration,
        })
    }
}
