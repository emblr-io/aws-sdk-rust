// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The details of the worker attribute capability.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct WorkerAttributeCapability {
    /// <p>The name of the worker attribute capability.</p>
    pub name: ::std::string::String,
    /// <p>The values of the worker amount capability.</p>
    pub values: ::std::vec::Vec<::std::string::String>,
}
impl WorkerAttributeCapability {
    /// <p>The name of the worker attribute capability.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The values of the worker amount capability.</p>
    pub fn values(&self) -> &[::std::string::String] {
        use std::ops::Deref;
        self.values.deref()
    }
}
impl WorkerAttributeCapability {
    /// Creates a new builder-style object to manufacture [`WorkerAttributeCapability`](crate::types::WorkerAttributeCapability).
    pub fn builder() -> crate::types::builders::WorkerAttributeCapabilityBuilder {
        crate::types::builders::WorkerAttributeCapabilityBuilder::default()
    }
}

/// A builder for [`WorkerAttributeCapability`](crate::types::WorkerAttributeCapability).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct WorkerAttributeCapabilityBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl WorkerAttributeCapabilityBuilder {
    /// <p>The name of the worker attribute capability.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the worker attribute capability.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the worker attribute capability.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Appends an item to `values`.
    ///
    /// To override the contents of this collection use [`set_values`](Self::set_values).
    ///
    /// <p>The values of the worker amount capability.</p>
    pub fn values(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.values.unwrap_or_default();
        v.push(input.into());
        self.values = ::std::option::Option::Some(v);
        self
    }
    /// <p>The values of the worker amount capability.</p>
    pub fn set_values(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.values = input;
        self
    }
    /// <p>The values of the worker amount capability.</p>
    pub fn get_values(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.values
    }
    /// Consumes the builder and constructs a [`WorkerAttributeCapability`](crate::types::WorkerAttributeCapability).
    /// This method will fail if any of the following fields are not set:
    /// - [`name`](crate::types::builders::WorkerAttributeCapabilityBuilder::name)
    /// - [`values`](crate::types::builders::WorkerAttributeCapabilityBuilder::values)
    pub fn build(self) -> ::std::result::Result<crate::types::WorkerAttributeCapability, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::WorkerAttributeCapability {
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building WorkerAttributeCapability",
                )
            })?,
            values: self.values.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "values",
                    "values was not specified but it is required when building WorkerAttributeCapability",
                )
            })?,
        })
    }
}
