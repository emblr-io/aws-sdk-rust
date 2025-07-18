// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A structure for the database object.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DatabaseResource {
    /// <p>The identifier for the Data Catalog. By default, it is the account ID of the caller.</p>
    pub catalog_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the database resource. Unique to the Data Catalog.</p>
    pub name: ::std::string::String,
}
impl DatabaseResource {
    /// <p>The identifier for the Data Catalog. By default, it is the account ID of the caller.</p>
    pub fn catalog_id(&self) -> ::std::option::Option<&str> {
        self.catalog_id.as_deref()
    }
    /// <p>The name of the database resource. Unique to the Data Catalog.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
}
impl DatabaseResource {
    /// Creates a new builder-style object to manufacture [`DatabaseResource`](crate::types::DatabaseResource).
    pub fn builder() -> crate::types::builders::DatabaseResourceBuilder {
        crate::types::builders::DatabaseResourceBuilder::default()
    }
}

/// A builder for [`DatabaseResource`](crate::types::DatabaseResource).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DatabaseResourceBuilder {
    pub(crate) catalog_id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
}
impl DatabaseResourceBuilder {
    /// <p>The identifier for the Data Catalog. By default, it is the account ID of the caller.</p>
    pub fn catalog_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.catalog_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier for the Data Catalog. By default, it is the account ID of the caller.</p>
    pub fn set_catalog_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.catalog_id = input;
        self
    }
    /// <p>The identifier for the Data Catalog. By default, it is the account ID of the caller.</p>
    pub fn get_catalog_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.catalog_id
    }
    /// <p>The name of the database resource. Unique to the Data Catalog.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the database resource. Unique to the Data Catalog.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the database resource. Unique to the Data Catalog.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Consumes the builder and constructs a [`DatabaseResource`](crate::types::DatabaseResource).
    /// This method will fail if any of the following fields are not set:
    /// - [`name`](crate::types::builders::DatabaseResourceBuilder::name)
    pub fn build(self) -> ::std::result::Result<crate::types::DatabaseResource, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::DatabaseResource {
            catalog_id: self.catalog_id,
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building DatabaseResource",
                )
            })?,
        })
    }
}
