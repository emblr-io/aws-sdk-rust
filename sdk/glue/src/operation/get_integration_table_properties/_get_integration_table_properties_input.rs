// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetIntegrationTablePropertiesInput {
    /// <p>The Amazon Resource Name (ARN) of the target table for which to retrieve integration table properties. Currently, this API only supports retrieving properties for target tables, and the provided ARN should be the ARN of the target table in the Glue Data Catalog. Support for retrieving integration table properties for source connections (using the connection ARN) is not yet implemented and will be added in a future release.</p>
    pub resource_arn: ::std::option::Option<::std::string::String>,
    /// <p>The name of the table to be replicated.</p>
    pub table_name: ::std::option::Option<::std::string::String>,
}
impl GetIntegrationTablePropertiesInput {
    /// <p>The Amazon Resource Name (ARN) of the target table for which to retrieve integration table properties. Currently, this API only supports retrieving properties for target tables, and the provided ARN should be the ARN of the target table in the Glue Data Catalog. Support for retrieving integration table properties for source connections (using the connection ARN) is not yet implemented and will be added in a future release.</p>
    pub fn resource_arn(&self) -> ::std::option::Option<&str> {
        self.resource_arn.as_deref()
    }
    /// <p>The name of the table to be replicated.</p>
    pub fn table_name(&self) -> ::std::option::Option<&str> {
        self.table_name.as_deref()
    }
}
impl GetIntegrationTablePropertiesInput {
    /// Creates a new builder-style object to manufacture [`GetIntegrationTablePropertiesInput`](crate::operation::get_integration_table_properties::GetIntegrationTablePropertiesInput).
    pub fn builder() -> crate::operation::get_integration_table_properties::builders::GetIntegrationTablePropertiesInputBuilder {
        crate::operation::get_integration_table_properties::builders::GetIntegrationTablePropertiesInputBuilder::default()
    }
}

/// A builder for [`GetIntegrationTablePropertiesInput`](crate::operation::get_integration_table_properties::GetIntegrationTablePropertiesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetIntegrationTablePropertiesInputBuilder {
    pub(crate) resource_arn: ::std::option::Option<::std::string::String>,
    pub(crate) table_name: ::std::option::Option<::std::string::String>,
}
impl GetIntegrationTablePropertiesInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the target table for which to retrieve integration table properties. Currently, this API only supports retrieving properties for target tables, and the provided ARN should be the ARN of the target table in the Glue Data Catalog. Support for retrieving integration table properties for source connections (using the connection ARN) is not yet implemented and will be added in a future release.</p>
    /// This field is required.
    pub fn resource_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the target table for which to retrieve integration table properties. Currently, this API only supports retrieving properties for target tables, and the provided ARN should be the ARN of the target table in the Glue Data Catalog. Support for retrieving integration table properties for source connections (using the connection ARN) is not yet implemented and will be added in a future release.</p>
    pub fn set_resource_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the target table for which to retrieve integration table properties. Currently, this API only supports retrieving properties for target tables, and the provided ARN should be the ARN of the target table in the Glue Data Catalog. Support for retrieving integration table properties for source connections (using the connection ARN) is not yet implemented and will be added in a future release.</p>
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
    /// Consumes the builder and constructs a [`GetIntegrationTablePropertiesInput`](crate::operation::get_integration_table_properties::GetIntegrationTablePropertiesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_integration_table_properties::GetIntegrationTablePropertiesInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_integration_table_properties::GetIntegrationTablePropertiesInput {
            resource_arn: self.resource_arn,
            table_name: self.table_name,
        })
    }
}
