// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The parameters for Amazon RDS.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RdsParameters {
    /// <p>Instance ID.</p>
    pub instance_id: ::std::string::String,
    /// <p>Database.</p>
    pub database: ::std::string::String,
}
impl RdsParameters {
    /// <p>Instance ID.</p>
    pub fn instance_id(&self) -> &str {
        use std::ops::Deref;
        self.instance_id.deref()
    }
    /// <p>Database.</p>
    pub fn database(&self) -> &str {
        use std::ops::Deref;
        self.database.deref()
    }
}
impl RdsParameters {
    /// Creates a new builder-style object to manufacture [`RdsParameters`](crate::types::RdsParameters).
    pub fn builder() -> crate::types::builders::RdsParametersBuilder {
        crate::types::builders::RdsParametersBuilder::default()
    }
}

/// A builder for [`RdsParameters`](crate::types::RdsParameters).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RdsParametersBuilder {
    pub(crate) instance_id: ::std::option::Option<::std::string::String>,
    pub(crate) database: ::std::option::Option<::std::string::String>,
}
impl RdsParametersBuilder {
    /// <p>Instance ID.</p>
    /// This field is required.
    pub fn instance_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Instance ID.</p>
    pub fn set_instance_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_id = input;
        self
    }
    /// <p>Instance ID.</p>
    pub fn get_instance_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_id
    }
    /// <p>Database.</p>
    /// This field is required.
    pub fn database(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.database = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Database.</p>
    pub fn set_database(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.database = input;
        self
    }
    /// <p>Database.</p>
    pub fn get_database(&self) -> &::std::option::Option<::std::string::String> {
        &self.database
    }
    /// Consumes the builder and constructs a [`RdsParameters`](crate::types::RdsParameters).
    /// This method will fail if any of the following fields are not set:
    /// - [`instance_id`](crate::types::builders::RdsParametersBuilder::instance_id)
    /// - [`database`](crate::types::builders::RdsParametersBuilder::database)
    pub fn build(self) -> ::std::result::Result<crate::types::RdsParameters, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::RdsParameters {
            instance_id: self.instance_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "instance_id",
                    "instance_id was not specified but it is required when building RdsParameters",
                )
            })?,
            database: self.database.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "database",
                    "database was not specified but it is required when building RdsParameters",
                )
            })?,
        })
    }
}
