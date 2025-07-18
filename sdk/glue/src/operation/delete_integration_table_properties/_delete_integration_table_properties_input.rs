// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteIntegrationTablePropertiesInput {
    /// <p>The connection ARN of the source, or the database ARN of the target.</p>
    pub resource_arn: ::std::option::Option<::std::string::String>,
    /// <p>The name of the table to be replicated.</p>
    pub table_name: ::std::option::Option<::std::string::String>,
}
impl DeleteIntegrationTablePropertiesInput {
    /// <p>The connection ARN of the source, or the database ARN of the target.</p>
    pub fn resource_arn(&self) -> ::std::option::Option<&str> {
        self.resource_arn.as_deref()
    }
    /// <p>The name of the table to be replicated.</p>
    pub fn table_name(&self) -> ::std::option::Option<&str> {
        self.table_name.as_deref()
    }
}
impl DeleteIntegrationTablePropertiesInput {
    /// Creates a new builder-style object to manufacture [`DeleteIntegrationTablePropertiesInput`](crate::operation::delete_integration_table_properties::DeleteIntegrationTablePropertiesInput).
    pub fn builder() -> crate::operation::delete_integration_table_properties::builders::DeleteIntegrationTablePropertiesInputBuilder {
        crate::operation::delete_integration_table_properties::builders::DeleteIntegrationTablePropertiesInputBuilder::default()
    }
}

/// A builder for [`DeleteIntegrationTablePropertiesInput`](crate::operation::delete_integration_table_properties::DeleteIntegrationTablePropertiesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteIntegrationTablePropertiesInputBuilder {
    pub(crate) resource_arn: ::std::option::Option<::std::string::String>,
    pub(crate) table_name: ::std::option::Option<::std::string::String>,
}
impl DeleteIntegrationTablePropertiesInputBuilder {
    /// <p>The connection ARN of the source, or the database ARN of the target.</p>
    /// This field is required.
    pub fn resource_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The connection ARN of the source, or the database ARN of the target.</p>
    pub fn set_resource_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_arn = input;
        self
    }
    /// <p>The connection ARN of the source, or the database ARN of the target.</p>
    pub fn get_resource_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_arn
    }
    /// <p>The name of the table to be replicated.</p>
    /// This field is required.
    pub fn table_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.table_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the table to be replicated.</p>
    pub fn set_table_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.table_name = input;
        self
    }
    /// <p>The name of the table to be replicated.</p>
    pub fn get_table_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.table_name
    }
    /// Consumes the builder and constructs a [`DeleteIntegrationTablePropertiesInput`](crate::operation::delete_integration_table_properties::DeleteIntegrationTablePropertiesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_integration_table_properties::DeleteIntegrationTablePropertiesInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::delete_integration_table_properties::DeleteIntegrationTablePropertiesInput {
                resource_arn: self.resource_arn,
                table_name: self.table_name,
            },
        )
    }
}
