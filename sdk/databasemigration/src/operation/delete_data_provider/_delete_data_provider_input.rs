// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteDataProviderInput {
    /// <p>The identifier of the data provider to delete.</p>
    pub data_provider_identifier: ::std::option::Option<::std::string::String>,
}
impl DeleteDataProviderInput {
    /// <p>The identifier of the data provider to delete.</p>
    pub fn data_provider_identifier(&self) -> ::std::option::Option<&str> {
        self.data_provider_identifier.as_deref()
    }
}
impl DeleteDataProviderInput {
    /// Creates a new builder-style object to manufacture [`DeleteDataProviderInput`](crate::operation::delete_data_provider::DeleteDataProviderInput).
    pub fn builder() -> crate::operation::delete_data_provider::builders::DeleteDataProviderInputBuilder {
        crate::operation::delete_data_provider::builders::DeleteDataProviderInputBuilder::default()
    }
}

/// A builder for [`DeleteDataProviderInput`](crate::operation::delete_data_provider::DeleteDataProviderInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteDataProviderInputBuilder {
    pub(crate) data_provider_identifier: ::std::option::Option<::std::string::String>,
}
impl DeleteDataProviderInputBuilder {
    /// <p>The identifier of the data provider to delete.</p>
    /// This field is required.
    pub fn data_provider_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.data_provider_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the data provider to delete.</p>
    pub fn set_data_provider_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.data_provider_identifier = input;
        self
    }
    /// <p>The identifier of the data provider to delete.</p>
    pub fn get_data_provider_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.data_provider_identifier
    }
    /// Consumes the builder and constructs a [`DeleteDataProviderInput`](crate::operation::delete_data_provider::DeleteDataProviderInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_data_provider::DeleteDataProviderInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::delete_data_provider::DeleteDataProviderInput {
            data_provider_identifier: self.data_provider_identifier,
        })
    }
}
