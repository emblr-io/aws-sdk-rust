// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies a Snowflake target.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SnowflakeTarget {
    /// <p>The name of the Snowflake target.</p>
    pub name: ::std::string::String,
    /// <p>Specifies the data of the Snowflake target node.</p>
    pub data: ::std::option::Option<crate::types::SnowflakeNodeData>,
    /// <p>The nodes that are inputs to the data target.</p>
    pub inputs: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl SnowflakeTarget {
    /// <p>The name of the Snowflake target.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>Specifies the data of the Snowflake target node.</p>
    pub fn data(&self) -> ::std::option::Option<&crate::types::SnowflakeNodeData> {
        self.data.as_ref()
    }
    /// <p>The nodes that are inputs to the data target.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.inputs.is_none()`.
    pub fn inputs(&self) -> &[::std::string::String] {
        self.inputs.as_deref().unwrap_or_default()
    }
}
impl SnowflakeTarget {
    /// Creates a new builder-style object to manufacture [`SnowflakeTarget`](crate::types::SnowflakeTarget).
    pub fn builder() -> crate::types::builders::SnowflakeTargetBuilder {
        crate::types::builders::SnowflakeTargetBuilder::default()
    }
}

/// A builder for [`SnowflakeTarget`](crate::types::SnowflakeTarget).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SnowflakeTargetBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) data: ::std::option::Option<crate::types::SnowflakeNodeData>,
    pub(crate) inputs: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl SnowflakeTargetBuilder {
    /// <p>The name of the Snowflake target.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the Snowflake target.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the Snowflake target.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>Specifies the data of the Snowflake target node.</p>
    /// This field is required.
    pub fn data(mut self, input: crate::types::SnowflakeNodeData) -> Self {
        self.data = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the data of the Snowflake target node.</p>
    pub fn set_data(mut self, input: ::std::option::Option<crate::types::SnowflakeNodeData>) -> Self {
        self.data = input;
        self
    }
    /// <p>Specifies the data of the Snowflake target node.</p>
    pub fn get_data(&self) -> &::std::option::Option<crate::types::SnowflakeNodeData> {
        &self.data
    }
    /// Appends an item to `inputs`.
    ///
    /// To override the contents of this collection use [`set_inputs`](Self::set_inputs).
    ///
    /// <p>The nodes that are inputs to the data target.</p>
    pub fn inputs(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.inputs.unwrap_or_default();
        v.push(input.into());
        self.inputs = ::std::option::Option::Some(v);
        self
    }
    /// <p>The nodes that are inputs to the data target.</p>
    pub fn set_inputs(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.inputs = input;
        self
    }
    /// <p>The nodes that are inputs to the data target.</p>
    pub fn get_inputs(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.inputs
    }
    /// Consumes the builder and constructs a [`SnowflakeTarget`](crate::types::SnowflakeTarget).
    /// This method will fail if any of the following fields are not set:
    /// - [`name`](crate::types::builders::SnowflakeTargetBuilder::name)
    pub fn build(self) -> ::std::result::Result<crate::types::SnowflakeTarget, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::SnowflakeTarget {
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building SnowflakeTarget",
                )
            })?,
            data: self.data,
            inputs: self.inputs,
        })
    }
}
