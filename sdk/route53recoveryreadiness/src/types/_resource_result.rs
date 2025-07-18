// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The result of a successful Resource request, with status for an individual resource.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ResourceResult {
    /// <p>The component id of the resource.</p>
    pub component_id: ::std::option::Option<::std::string::String>,
    /// <p>The time (UTC) that the resource was last checked for readiness, in ISO-8601 format.</p>
    pub last_checked_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The readiness of a resource.</p>
    pub readiness: ::std::option::Option<crate::types::Readiness>,
    /// <p>The Amazon Resource Name (ARN) of the resource.</p>
    pub resource_arn: ::std::option::Option<::std::string::String>,
}
impl ResourceResult {
    /// <p>The component id of the resource.</p>
    pub fn component_id(&self) -> ::std::option::Option<&str> {
        self.component_id.as_deref()
    }
    /// <p>The time (UTC) that the resource was last checked for readiness, in ISO-8601 format.</p>
    pub fn last_checked_timestamp(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_checked_timestamp.as_ref()
    }
    /// <p>The readiness of a resource.</p>
    pub fn readiness(&self) -> ::std::option::Option<&crate::types::Readiness> {
        self.readiness.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) of the resource.</p>
    pub fn resource_arn(&self) -> ::std::option::Option<&str> {
        self.resource_arn.as_deref()
    }
}
impl ResourceResult {
    /// Creates a new builder-style object to manufacture [`ResourceResult`](crate::types::ResourceResult).
    pub fn builder() -> crate::types::builders::ResourceResultBuilder {
        crate::types::builders::ResourceResultBuilder::default()
    }
}

/// A builder for [`ResourceResult`](crate::types::ResourceResult).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ResourceResultBuilder {
    pub(crate) component_id: ::std::option::Option<::std::string::String>,
    pub(crate) last_checked_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) readiness: ::std::option::Option<crate::types::Readiness>,
    pub(crate) resource_arn: ::std::option::Option<::std::string::String>,
}
impl ResourceResultBuilder {
    /// <p>The component id of the resource.</p>
    pub fn component_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.component_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The component id of the resource.</p>
    pub fn set_component_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.component_id = input;
        self
    }
    /// <p>The component id of the resource.</p>
    pub fn get_component_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.component_id
    }
    /// <p>The time (UTC) that the resource was last checked for readiness, in ISO-8601 format.</p>
    /// This field is required.
    pub fn last_checked_timestamp(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_checked_timestamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time (UTC) that the resource was last checked for readiness, in ISO-8601 format.</p>
    pub fn set_last_checked_timestamp(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_checked_timestamp = input;
        self
    }
    /// <p>The time (UTC) that the resource was last checked for readiness, in ISO-8601 format.</p>
    pub fn get_last_checked_timestamp(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_checked_timestamp
    }
    /// <p>The readiness of a resource.</p>
    /// This field is required.
    pub fn readiness(mut self, input: crate::types::Readiness) -> Self {
        self.readiness = ::std::option::Option::Some(input);
        self
    }
    /// <p>The readiness of a resource.</p>
    pub fn set_readiness(mut self, input: ::std::option::Option<crate::types::Readiness>) -> Self {
        self.readiness = input;
        self
    }
    /// <p>The readiness of a resource.</p>
    pub fn get_readiness(&self) -> &::std::option::Option<crate::types::Readiness> {
        &self.readiness
    }
    /// <p>The Amazon Resource Name (ARN) of the resource.</p>
    pub fn resource_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the resource.</p>
    pub fn set_resource_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the resource.</p>
    pub fn get_resource_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_arn
    }
    /// Consumes the builder and constructs a [`ResourceResult`](crate::types::ResourceResult).
    pub fn build(self) -> crate::types::ResourceResult {
        crate::types::ResourceResult {
            component_id: self.component_id,
            last_checked_timestamp: self.last_checked_timestamp,
            readiness: self.readiness,
            resource_arn: self.resource_arn,
        }
    }
}
