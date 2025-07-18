// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the details of an Amazon Neptune DB parameter group.</p>
/// <p>This data type is used as a response element in the <code>DescribeDBParameterGroups</code> action.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DbParameterGroup {
    /// <p>Provides the name of the DB parameter group.</p>
    pub db_parameter_group_name: ::std::option::Option<::std::string::String>,
    /// <p>Provides the name of the DB parameter group family that this DB parameter group is compatible with.</p>
    pub db_parameter_group_family: ::std::option::Option<::std::string::String>,
    /// <p>Provides the customer-specified description for this DB parameter group.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) for the DB parameter group.</p>
    pub db_parameter_group_arn: ::std::option::Option<::std::string::String>,
}
impl DbParameterGroup {
    /// <p>Provides the name of the DB parameter group.</p>
    pub fn db_parameter_group_name(&self) -> ::std::option::Option<&str> {
        self.db_parameter_group_name.as_deref()
    }
    /// <p>Provides the name of the DB parameter group family that this DB parameter group is compatible with.</p>
    pub fn db_parameter_group_family(&self) -> ::std::option::Option<&str> {
        self.db_parameter_group_family.as_deref()
    }
    /// <p>Provides the customer-specified description for this DB parameter group.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) for the DB parameter group.</p>
    pub fn db_parameter_group_arn(&self) -> ::std::option::Option<&str> {
        self.db_parameter_group_arn.as_deref()
    }
}
impl DbParameterGroup {
    /// Creates a new builder-style object to manufacture [`DbParameterGroup`](crate::types::DbParameterGroup).
    pub fn builder() -> crate::types::builders::DbParameterGroupBuilder {
        crate::types::builders::DbParameterGroupBuilder::default()
    }
}

/// A builder for [`DbParameterGroup`](crate::types::DbParameterGroup).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DbParameterGroupBuilder {
    pub(crate) db_parameter_group_name: ::std::option::Option<::std::string::String>,
    pub(crate) db_parameter_group_family: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) db_parameter_group_arn: ::std::option::Option<::std::string::String>,
}
impl DbParameterGroupBuilder {
    /// <p>Provides the name of the DB parameter group.</p>
    pub fn db_parameter_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.db_parameter_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Provides the name of the DB parameter group.</p>
    pub fn set_db_parameter_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.db_parameter_group_name = input;
        self
    }
    /// <p>Provides the name of the DB parameter group.</p>
    pub fn get_db_parameter_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.db_parameter_group_name
    }
    /// <p>Provides the name of the DB parameter group family that this DB parameter group is compatible with.</p>
    pub fn db_parameter_group_family(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.db_parameter_group_family = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Provides the name of the DB parameter group family that this DB parameter group is compatible with.</p>
    pub fn set_db_parameter_group_family(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.db_parameter_group_family = input;
        self
    }
    /// <p>Provides the name of the DB parameter group family that this DB parameter group is compatible with.</p>
    pub fn get_db_parameter_group_family(&self) -> &::std::option::Option<::std::string::String> {
        &self.db_parameter_group_family
    }
    /// <p>Provides the customer-specified description for this DB parameter group.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Provides the customer-specified description for this DB parameter group.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>Provides the customer-specified description for this DB parameter group.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The Amazon Resource Name (ARN) for the DB parameter group.</p>
    pub fn db_parameter_group_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.db_parameter_group_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the DB parameter group.</p>
    pub fn set_db_parameter_group_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.db_parameter_group_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the DB parameter group.</p>
    pub fn get_db_parameter_group_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.db_parameter_group_arn
    }
    /// Consumes the builder and constructs a [`DbParameterGroup`](crate::types::DbParameterGroup).
    pub fn build(self) -> crate::types::DbParameterGroup {
        crate::types::DbParameterGroup {
            db_parameter_group_name: self.db_parameter_group_name,
            db_parameter_group_family: self.db_parameter_group_family,
            description: self.description,
            db_parameter_group_arn: self.db_parameter_group_arn,
        }
    }
}
