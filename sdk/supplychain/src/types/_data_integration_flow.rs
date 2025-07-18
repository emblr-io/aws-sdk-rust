// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The DataIntegrationFlow details.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DataIntegrationFlow {
    /// <p>The DataIntegrationFlow instance ID.</p>
    pub instance_id: ::std::string::String,
    /// <p>The DataIntegrationFlow name.</p>
    pub name: ::std::string::String,
    /// <p>The DataIntegrationFlow source configurations.</p>
    pub sources: ::std::vec::Vec<crate::types::DataIntegrationFlowSource>,
    /// <p>The DataIntegrationFlow transformation configurations.</p>
    pub transformation: ::std::option::Option<crate::types::DataIntegrationFlowTransformation>,
    /// <p>The DataIntegrationFlow target configuration.</p>
    pub target: ::std::option::Option<crate::types::DataIntegrationFlowTarget>,
    /// <p>The DataIntegrationFlow creation timestamp.</p>
    pub created_time: ::aws_smithy_types::DateTime,
    /// <p>The DataIntegrationFlow last modified timestamp.</p>
    pub last_modified_time: ::aws_smithy_types::DateTime,
}
impl DataIntegrationFlow {
    /// <p>The DataIntegrationFlow instance ID.</p>
    pub fn instance_id(&self) -> &str {
        use std::ops::Deref;
        self.instance_id.deref()
    }
    /// <p>The DataIntegrationFlow name.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The DataIntegrationFlow source configurations.</p>
    pub fn sources(&self) -> &[crate::types::DataIntegrationFlowSource] {
        use std::ops::Deref;
        self.sources.deref()
    }
    /// <p>The DataIntegrationFlow transformation configurations.</p>
    pub fn transformation(&self) -> ::std::option::Option<&crate::types::DataIntegrationFlowTransformation> {
        self.transformation.as_ref()
    }
    /// <p>The DataIntegrationFlow target configuration.</p>
    pub fn target(&self) -> ::std::option::Option<&crate::types::DataIntegrationFlowTarget> {
        self.target.as_ref()
    }
    /// <p>The DataIntegrationFlow creation timestamp.</p>
    pub fn created_time(&self) -> &::aws_smithy_types::DateTime {
        &self.created_time
    }
    /// <p>The DataIntegrationFlow last modified timestamp.</p>
    pub fn last_modified_time(&self) -> &::aws_smithy_types::DateTime {
        &self.last_modified_time
    }
}
impl DataIntegrationFlow {
    /// Creates a new builder-style object to manufacture [`DataIntegrationFlow`](crate::types::DataIntegrationFlow).
    pub fn builder() -> crate::types::builders::DataIntegrationFlowBuilder {
        crate::types::builders::DataIntegrationFlowBuilder::default()
    }
}

/// A builder for [`DataIntegrationFlow`](crate::types::DataIntegrationFlow).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DataIntegrationFlowBuilder {
    pub(crate) instance_id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) sources: ::std::option::Option<::std::vec::Vec<crate::types::DataIntegrationFlowSource>>,
    pub(crate) transformation: ::std::option::Option<crate::types::DataIntegrationFlowTransformation>,
    pub(crate) target: ::std::option::Option<crate::types::DataIntegrationFlowTarget>,
    pub(crate) created_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_modified_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl DataIntegrationFlowBuilder {
    /// <p>The DataIntegrationFlow instance ID.</p>
    /// This field is required.
    pub fn instance_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The DataIntegrationFlow instance ID.</p>
    pub fn set_instance_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_id = input;
        self
    }
    /// <p>The DataIntegrationFlow instance ID.</p>
    pub fn get_instance_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_id
    }
    /// <p>The DataIntegrationFlow name.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The DataIntegrationFlow name.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The DataIntegrationFlow name.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Appends an item to `sources`.
    ///
    /// To override the contents of this collection use [`set_sources`](Self::set_sources).
    ///
    /// <p>The DataIntegrationFlow source configurations.</p>
    pub fn sources(mut self, input: crate::types::DataIntegrationFlowSource) -> Self {
        let mut v = self.sources.unwrap_or_default();
        v.push(input);
        self.sources = ::std::option::Option::Some(v);
        self
    }
    /// <p>The DataIntegrationFlow source configurations.</p>
    pub fn set_sources(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DataIntegrationFlowSource>>) -> Self {
        self.sources = input;
        self
    }
    /// <p>The DataIntegrationFlow source configurations.</p>
    pub fn get_sources(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DataIntegrationFlowSource>> {
        &self.sources
    }
    /// <p>The DataIntegrationFlow transformation configurations.</p>
    /// This field is required.
    pub fn transformation(mut self, input: crate::types::DataIntegrationFlowTransformation) -> Self {
        self.transformation = ::std::option::Option::Some(input);
        self
    }
    /// <p>The DataIntegrationFlow transformation configurations.</p>
    pub fn set_transformation(mut self, input: ::std::option::Option<crate::types::DataIntegrationFlowTransformation>) -> Self {
        self.transformation = input;
        self
    }
    /// <p>The DataIntegrationFlow transformation configurations.</p>
    pub fn get_transformation(&self) -> &::std::option::Option<crate::types::DataIntegrationFlowTransformation> {
        &self.transformation
    }
    /// <p>The DataIntegrationFlow target configuration.</p>
    /// This field is required.
    pub fn target(mut self, input: crate::types::DataIntegrationFlowTarget) -> Self {
        self.target = ::std::option::Option::Some(input);
        self
    }
    /// <p>The DataIntegrationFlow target configuration.</p>
    pub fn set_target(mut self, input: ::std::option::Option<crate::types::DataIntegrationFlowTarget>) -> Self {
        self.target = input;
        self
    }
    /// <p>The DataIntegrationFlow target configuration.</p>
    pub fn get_target(&self) -> &::std::option::Option<crate::types::DataIntegrationFlowTarget> {
        &self.target
    }
    /// <p>The DataIntegrationFlow creation timestamp.</p>
    /// This field is required.
    pub fn created_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The DataIntegrationFlow creation timestamp.</p>
    pub fn set_created_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_time = input;
        self
    }
    /// <p>The DataIntegrationFlow creation timestamp.</p>
    pub fn get_created_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_time
    }
    /// <p>The DataIntegrationFlow last modified timestamp.</p>
    /// This field is required.
    pub fn last_modified_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_modified_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The DataIntegrationFlow last modified timestamp.</p>
    pub fn set_last_modified_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_modified_time = input;
        self
    }
    /// <p>The DataIntegrationFlow last modified timestamp.</p>
    pub fn get_last_modified_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_modified_time
    }
    /// Consumes the builder and constructs a [`DataIntegrationFlow`](crate::types::DataIntegrationFlow).
    /// This method will fail if any of the following fields are not set:
    /// - [`instance_id`](crate::types::builders::DataIntegrationFlowBuilder::instance_id)
    /// - [`name`](crate::types::builders::DataIntegrationFlowBuilder::name)
    /// - [`sources`](crate::types::builders::DataIntegrationFlowBuilder::sources)
    /// - [`created_time`](crate::types::builders::DataIntegrationFlowBuilder::created_time)
    /// - [`last_modified_time`](crate::types::builders::DataIntegrationFlowBuilder::last_modified_time)
    pub fn build(self) -> ::std::result::Result<crate::types::DataIntegrationFlow, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::DataIntegrationFlow {
            instance_id: self.instance_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "instance_id",
                    "instance_id was not specified but it is required when building DataIntegrationFlow",
                )
            })?,
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building DataIntegrationFlow",
                )
            })?,
            sources: self.sources.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "sources",
                    "sources was not specified but it is required when building DataIntegrationFlow",
                )
            })?,
            transformation: self.transformation,
            target: self.target,
            created_time: self.created_time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "created_time",
                    "created_time was not specified but it is required when building DataIntegrationFlow",
                )
            })?,
            last_modified_time: self.last_modified_time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "last_modified_time",
                    "last_modified_time was not specified but it is required when building DataIntegrationFlow",
                )
            })?,
        })
    }
}
