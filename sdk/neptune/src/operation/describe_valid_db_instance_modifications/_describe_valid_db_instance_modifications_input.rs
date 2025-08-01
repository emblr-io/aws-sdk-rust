// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeValidDbInstanceModificationsInput {
    /// <p>The customer identifier or the ARN of your DB instance.</p>
    pub db_instance_identifier: ::std::option::Option<::std::string::String>,
}
impl DescribeValidDbInstanceModificationsInput {
    /// <p>The customer identifier or the ARN of your DB instance.</p>
    pub fn db_instance_identifier(&self) -> ::std::option::Option<&str> {
        self.db_instance_identifier.as_deref()
    }
}
impl DescribeValidDbInstanceModificationsInput {
    /// Creates a new builder-style object to manufacture [`DescribeValidDbInstanceModificationsInput`](crate::operation::describe_valid_db_instance_modifications::DescribeValidDbInstanceModificationsInput).
    pub fn builder() -> crate::operation::describe_valid_db_instance_modifications::builders::DescribeValidDbInstanceModificationsInputBuilder {
        crate::operation::describe_valid_db_instance_modifications::builders::DescribeValidDbInstanceModificationsInputBuilder::default()
    }
}

/// A builder for [`DescribeValidDbInstanceModificationsInput`](crate::operation::describe_valid_db_instance_modifications::DescribeValidDbInstanceModificationsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeValidDbInstanceModificationsInputBuilder {
    pub(crate) db_instance_identifier: ::std::option::Option<::std::string::String>,
}
impl DescribeValidDbInstanceModificationsInputBuilder {
    /// <p>The customer identifier or the ARN of your DB instance.</p>
    /// This field is required.
    pub fn db_instance_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.db_instance_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The customer identifier or the ARN of your DB instance.</p>
    pub fn set_db_instance_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.db_instance_identifier = input;
        self
    }
    /// <p>The customer identifier or the ARN of your DB instance.</p>
    pub fn get_db_instance_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.db_instance_identifier
    }
    /// Consumes the builder and constructs a [`DescribeValidDbInstanceModificationsInput`](crate::operation::describe_valid_db_instance_modifications::DescribeValidDbInstanceModificationsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_valid_db_instance_modifications::DescribeValidDbInstanceModificationsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::describe_valid_db_instance_modifications::DescribeValidDbInstanceModificationsInput {
                db_instance_identifier: self.db_instance_identifier,
            },
        )
    }
}
