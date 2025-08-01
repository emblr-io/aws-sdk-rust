// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The registered Amazon Timestream resources that Amazon Web Services IoT FleetWise edge agent software can transfer your vehicle data to.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TimestreamResources {
    /// <p>The name of the registered Amazon Timestream database.</p>
    pub timestream_database_name: ::std::string::String,
    /// <p>The name of the registered Amazon Timestream database table.</p>
    pub timestream_table_name: ::std::string::String,
}
impl TimestreamResources {
    /// <p>The name of the registered Amazon Timestream database.</p>
    pub fn timestream_database_name(&self) -> &str {
        use std::ops::Deref;
        self.timestream_database_name.deref()
    }
    /// <p>The name of the registered Amazon Timestream database table.</p>
    pub fn timestream_table_name(&self) -> &str {
        use std::ops::Deref;
        self.timestream_table_name.deref()
    }
}
impl TimestreamResources {
    /// Creates a new builder-style object to manufacture [`TimestreamResources`](crate::types::TimestreamResources).
    pub fn builder() -> crate::types::builders::TimestreamResourcesBuilder {
        crate::types::builders::TimestreamResourcesBuilder::default()
    }
}

/// A builder for [`TimestreamResources`](crate::types::TimestreamResources).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TimestreamResourcesBuilder {
    pub(crate) timestream_database_name: ::std::option::Option<::std::string::String>,
    pub(crate) timestream_table_name: ::std::option::Option<::std::string::String>,
}
impl TimestreamResourcesBuilder {
    /// <p>The name of the registered Amazon Timestream database.</p>
    /// This field is required.
    pub fn timestream_database_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.timestream_database_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the registered Amazon Timestream database.</p>
    pub fn set_timestream_database_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.timestream_database_name = input;
        self
    }
    /// <p>The name of the registered Amazon Timestream database.</p>
    pub fn get_timestream_database_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.timestream_database_name
    }
    /// <p>The name of the registered Amazon Timestream database table.</p>
    /// This field is required.
    pub fn timestream_table_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.timestream_table_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the registered Amazon Timestream database table.</p>
    pub fn set_timestream_table_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.timestream_table_name = input;
        self
    }
    /// <p>The name of the registered Amazon Timestream database table.</p>
    pub fn get_timestream_table_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.timestream_table_name
    }
    /// Consumes the builder and constructs a [`TimestreamResources`](crate::types::TimestreamResources).
    /// This method will fail if any of the following fields are not set:
    /// - [`timestream_database_name`](crate::types::builders::TimestreamResourcesBuilder::timestream_database_name)
    /// - [`timestream_table_name`](crate::types::builders::TimestreamResourcesBuilder::timestream_table_name)
    pub fn build(self) -> ::std::result::Result<crate::types::TimestreamResources, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::TimestreamResources {
            timestream_database_name: self.timestream_database_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "timestream_database_name",
                    "timestream_database_name was not specified but it is required when building TimestreamResources",
                )
            })?,
            timestream_table_name: self.timestream_table_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "timestream_table_name",
                    "timestream_table_name was not specified but it is required when building TimestreamResources",
                )
            })?,
        })
    }
}
