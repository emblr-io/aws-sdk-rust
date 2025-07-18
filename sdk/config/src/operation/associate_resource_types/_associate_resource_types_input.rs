// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssociateResourceTypesInput {
    /// <p>The Amazon Resource Name (ARN) of the specified configuration recorder.</p>
    pub configuration_recorder_arn: ::std::option::Option<::std::string::String>,
    /// <p>The list of resource types you want to add to the recording group of the specified configuration recorder.</p>
    pub resource_types: ::std::option::Option<::std::vec::Vec<crate::types::ResourceType>>,
}
impl AssociateResourceTypesInput {
    /// <p>The Amazon Resource Name (ARN) of the specified configuration recorder.</p>
    pub fn configuration_recorder_arn(&self) -> ::std::option::Option<&str> {
        self.configuration_recorder_arn.as_deref()
    }
    /// <p>The list of resource types you want to add to the recording group of the specified configuration recorder.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.resource_types.is_none()`.
    pub fn resource_types(&self) -> &[crate::types::ResourceType] {
        self.resource_types.as_deref().unwrap_or_default()
    }
}
impl AssociateResourceTypesInput {
    /// Creates a new builder-style object to manufacture [`AssociateResourceTypesInput`](crate::operation::associate_resource_types::AssociateResourceTypesInput).
    pub fn builder() -> crate::operation::associate_resource_types::builders::AssociateResourceTypesInputBuilder {
        crate::operation::associate_resource_types::builders::AssociateResourceTypesInputBuilder::default()
    }
}

/// A builder for [`AssociateResourceTypesInput`](crate::operation::associate_resource_types::AssociateResourceTypesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssociateResourceTypesInputBuilder {
    pub(crate) configuration_recorder_arn: ::std::option::Option<::std::string::String>,
    pub(crate) resource_types: ::std::option::Option<::std::vec::Vec<crate::types::ResourceType>>,
}
impl AssociateResourceTypesInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the specified configuration recorder.</p>
    /// This field is required.
    pub fn configuration_recorder_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.configuration_recorder_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the specified configuration recorder.</p>
    pub fn set_configuration_recorder_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.configuration_recorder_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the specified configuration recorder.</p>
    pub fn get_configuration_recorder_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.configuration_recorder_arn
    }
    /// Appends an item to `resource_types`.
    ///
    /// To override the contents of this collection use [`set_resource_types`](Self::set_resource_types).
    ///
    /// <p>The list of resource types you want to add to the recording group of the specified configuration recorder.</p>
    pub fn resource_types(mut self, input: crate::types::ResourceType) -> Self {
        let mut v = self.resource_types.unwrap_or_default();
        v.push(input);
        self.resource_types = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of resource types you want to add to the recording group of the specified configuration recorder.</p>
    pub fn set_resource_types(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ResourceType>>) -> Self {
        self.resource_types = input;
        self
    }
    /// <p>The list of resource types you want to add to the recording group of the specified configuration recorder.</p>
    pub fn get_resource_types(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ResourceType>> {
        &self.resource_types
    }
    /// Consumes the builder and constructs a [`AssociateResourceTypesInput`](crate::operation::associate_resource_types::AssociateResourceTypesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::associate_resource_types::AssociateResourceTypesInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::associate_resource_types::AssociateResourceTypesInput {
            configuration_recorder_arn: self.configuration_recorder_arn,
            resource_types: self.resource_types,
        })
    }
}
