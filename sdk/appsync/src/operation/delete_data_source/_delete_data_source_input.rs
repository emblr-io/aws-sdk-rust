// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteDataSourceInput {
    /// <p>The API ID.</p>
    pub api_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the data source.</p>
    pub name: ::std::option::Option<::std::string::String>,
}
impl DeleteDataSourceInput {
    /// <p>The API ID.</p>
    pub fn api_id(&self) -> ::std::option::Option<&str> {
        self.api_id.as_deref()
    }
    /// <p>The name of the data source.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
}
impl DeleteDataSourceInput {
    /// Creates a new builder-style object to manufacture [`DeleteDataSourceInput`](crate::operation::delete_data_source::DeleteDataSourceInput).
    pub fn builder() -> crate::operation::delete_data_source::builders::DeleteDataSourceInputBuilder {
        crate::operation::delete_data_source::builders::DeleteDataSourceInputBuilder::default()
    }
}

/// A builder for [`DeleteDataSourceInput`](crate::operation::delete_data_source::DeleteDataSourceInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteDataSourceInputBuilder {
    pub(crate) api_id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
}
impl DeleteDataSourceInputBuilder {
    /// <p>The API ID.</p>
    /// This field is required.
    pub fn api_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.api_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The API ID.</p>
    pub fn set_api_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.api_id = input;
        self
    }
    /// <p>The API ID.</p>
    pub fn get_api_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.api_id
    }
    /// <p>The name of the data source.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the data source.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the data source.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Consumes the builder and constructs a [`DeleteDataSourceInput`](crate::operation::delete_data_source::DeleteDataSourceInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_data_source::DeleteDataSourceInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_data_source::DeleteDataSourceInput {
            api_id: self.api_id,
            name: self.name,
        })
    }
}
