// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides information about a parameter group for a DB instance.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AwsRdsDbParameterGroup {
    /// <p>The name of the parameter group.</p>
    pub db_parameter_group_name: ::std::option::Option<::std::string::String>,
    /// <p>The status of parameter updates.</p>
    pub parameter_apply_status: ::std::option::Option<::std::string::String>,
}
impl AwsRdsDbParameterGroup {
    /// <p>The name of the parameter group.</p>
    pub fn db_parameter_group_name(&self) -> ::std::option::Option<&str> {
        self.db_parameter_group_name.as_deref()
    }
    /// <p>The status of parameter updates.</p>
    pub fn parameter_apply_status(&self) -> ::std::option::Option<&str> {
        self.parameter_apply_status.as_deref()
    }
}
impl AwsRdsDbParameterGroup {
    /// Creates a new builder-style object to manufacture [`AwsRdsDbParameterGroup`](crate::types::AwsRdsDbParameterGroup).
    pub fn builder() -> crate::types::builders::AwsRdsDbParameterGroupBuilder {
        crate::types::builders::AwsRdsDbParameterGroupBuilder::default()
    }
}

/// A builder for [`AwsRdsDbParameterGroup`](crate::types::AwsRdsDbParameterGroup).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AwsRdsDbParameterGroupBuilder {
    pub(crate) db_parameter_group_name: ::std::option::Option<::std::string::String>,
    pub(crate) parameter_apply_status: ::std::option::Option<::std::string::String>,
}
impl AwsRdsDbParameterGroupBuilder {
    /// <p>The name of the parameter group.</p>
    pub fn db_parameter_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.db_parameter_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the parameter group.</p>
    pub fn set_db_parameter_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.db_parameter_group_name = input;
        self
    }
    /// <p>The name of the parameter group.</p>
    pub fn get_db_parameter_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.db_parameter_group_name
    }
    /// <p>The status of parameter updates.</p>
    pub fn parameter_apply_status(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.parameter_apply_status = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The status of parameter updates.</p>
    pub fn set_parameter_apply_status(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.parameter_apply_status = input;
        self
    }
    /// <p>The status of parameter updates.</p>
    pub fn get_parameter_apply_status(&self) -> &::std::option::Option<::std::string::String> {
        &self.parameter_apply_status
    }
    /// Consumes the builder and constructs a [`AwsRdsDbParameterGroup`](crate::types::AwsRdsDbParameterGroup).
    pub fn build(self) -> crate::types::AwsRdsDbParameterGroup {
        crate::types::AwsRdsDbParameterGroup {
            db_parameter_group_name: self.db_parameter_group_name,
            parameter_apply_status: self.parameter_apply_status,
        }
    }
}
