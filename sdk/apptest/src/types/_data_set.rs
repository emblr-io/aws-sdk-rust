// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Defines a data set.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DataSet {
    /// <p>The type of the data set.</p>
    pub r#type: crate::types::DataSetType,
    /// <p>The name of the data set.</p>
    pub name: ::std::string::String,
    /// <p>The CCSID of the data set.</p>
    pub ccsid: ::std::string::String,
    /// <p>The format of the data set.</p>
    pub format: crate::types::Format,
    /// <p>The length of the data set.</p>
    pub length: i32,
}
impl DataSet {
    /// <p>The type of the data set.</p>
    pub fn r#type(&self) -> &crate::types::DataSetType {
        &self.r#type
    }
    /// <p>The name of the data set.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The CCSID of the data set.</p>
    pub fn ccsid(&self) -> &str {
        use std::ops::Deref;
        self.ccsid.deref()
    }
    /// <p>The format of the data set.</p>
    pub fn format(&self) -> &crate::types::Format {
        &self.format
    }
    /// <p>The length of the data set.</p>
    pub fn length(&self) -> i32 {
        self.length
    }
}
impl DataSet {
    /// Creates a new builder-style object to manufacture [`DataSet`](crate::types::DataSet).
    pub fn builder() -> crate::types::builders::DataSetBuilder {
        crate::types::builders::DataSetBuilder::default()
    }
}

/// A builder for [`DataSet`](crate::types::DataSet).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DataSetBuilder {
    pub(crate) r#type: ::std::option::Option<crate::types::DataSetType>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) ccsid: ::std::option::Option<::std::string::String>,
    pub(crate) format: ::std::option::Option<crate::types::Format>,
    pub(crate) length: ::std::option::Option<i32>,
}
impl DataSetBuilder {
    /// <p>The type of the data set.</p>
    /// This field is required.
    pub fn r#type(mut self, input: crate::types::DataSetType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of the data set.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::DataSetType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of the data set.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::DataSetType> {
        &self.r#type
    }
    /// <p>The name of the data set.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the data set.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the data set.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The CCSID of the data set.</p>
    /// This field is required.
    pub fn ccsid(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ccsid = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The CCSID of the data set.</p>
    pub fn set_ccsid(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ccsid = input;
        self
    }
    /// <p>The CCSID of the data set.</p>
    pub fn get_ccsid(&self) -> &::std::option::Option<::std::string::String> {
        &self.ccsid
    }
    /// <p>The format of the data set.</p>
    /// This field is required.
    pub fn format(mut self, input: crate::types::Format) -> Self {
        self.format = ::std::option::Option::Some(input);
        self
    }
    /// <p>The format of the data set.</p>
    pub fn set_format(mut self, input: ::std::option::Option<crate::types::Format>) -> Self {
        self.format = input;
        self
    }
    /// <p>The format of the data set.</p>
    pub fn get_format(&self) -> &::std::option::Option<crate::types::Format> {
        &self.format
    }
    /// <p>The length of the data set.</p>
    /// This field is required.
    pub fn length(mut self, input: i32) -> Self {
        self.length = ::std::option::Option::Some(input);
        self
    }
    /// <p>The length of the data set.</p>
    pub fn set_length(mut self, input: ::std::option::Option<i32>) -> Self {
        self.length = input;
        self
    }
    /// <p>The length of the data set.</p>
    pub fn get_length(&self) -> &::std::option::Option<i32> {
        &self.length
    }
    /// Consumes the builder and constructs a [`DataSet`](crate::types::DataSet).
    /// This method will fail if any of the following fields are not set:
    /// - [`r#type`](crate::types::builders::DataSetBuilder::type)
    /// - [`name`](crate::types::builders::DataSetBuilder::name)
    /// - [`ccsid`](crate::types::builders::DataSetBuilder::ccsid)
    /// - [`format`](crate::types::builders::DataSetBuilder::format)
    /// - [`length`](crate::types::builders::DataSetBuilder::length)
    pub fn build(self) -> ::std::result::Result<crate::types::DataSet, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::DataSet {
            r#type: self.r#type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "r#type",
                    "r#type was not specified but it is required when building DataSet",
                )
            })?,
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building DataSet",
                )
            })?,
            ccsid: self.ccsid.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "ccsid",
                    "ccsid was not specified but it is required when building DataSet",
                )
            })?,
            format: self.format.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "format",
                    "format was not specified but it is required when building DataSet",
                )
            })?,
            length: self.length.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "length",
                    "length was not specified but it is required when building DataSet",
                )
            })?,
        })
    }
}
