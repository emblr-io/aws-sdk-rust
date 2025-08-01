// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Container for the parameters to the <code>DeleteDataSource</code> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteDataSourceInput {
    /// <p>The name of the domain.</p>
    pub domain_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the data source to delete.</p>
    pub name: ::std::option::Option<::std::string::String>,
}
impl DeleteDataSourceInput {
    /// <p>The name of the domain.</p>
    pub fn domain_name(&self) -> ::std::option::Option<&str> {
        self.domain_name.as_deref()
    }
    /// <p>The name of the data source to delete.</p>
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
    pub(crate) domain_name: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
}
impl DeleteDataSourceInputBuilder {
    /// <p>The name of the domain.</p>
    /// This field is required.
    pub fn domain_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the domain.</p>
    pub fn set_domain_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_name = input;
        self
    }
    /// <p>The name of the domain.</p>
    pub fn get_domain_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_name
    }
    /// <p>The name of the data source to delete.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the data source to delete.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the data source to delete.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Consumes the builder and constructs a [`DeleteDataSourceInput`](crate::operation::delete_data_source::DeleteDataSourceInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_data_source::DeleteDataSourceInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_data_source::DeleteDataSourceInput {
            domain_name: self.domain_name,
            name: self.name,
        })
    }
}
