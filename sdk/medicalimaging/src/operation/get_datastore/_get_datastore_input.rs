// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetDatastoreInput {
    /// <p>The data store identifier.</p>
    pub datastore_id: ::std::option::Option<::std::string::String>,
}
impl GetDatastoreInput {
    /// <p>The data store identifier.</p>
    pub fn datastore_id(&self) -> ::std::option::Option<&str> {
        self.datastore_id.as_deref()
    }
}
impl GetDatastoreInput {
    /// Creates a new builder-style object to manufacture [`GetDatastoreInput`](crate::operation::get_datastore::GetDatastoreInput).
    pub fn builder() -> crate::operation::get_datastore::builders::GetDatastoreInputBuilder {
        crate::operation::get_datastore::builders::GetDatastoreInputBuilder::default()
    }
}

/// A builder for [`GetDatastoreInput`](crate::operation::get_datastore::GetDatastoreInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetDatastoreInputBuilder {
    pub(crate) datastore_id: ::std::option::Option<::std::string::String>,
}
impl GetDatastoreInputBuilder {
    /// <p>The data store identifier.</p>
    /// This field is required.
    pub fn datastore_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.datastore_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The data store identifier.</p>
    pub fn set_datastore_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.datastore_id = input;
        self
    }
    /// <p>The data store identifier.</p>
    pub fn get_datastore_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.datastore_id
    }
    /// Consumes the builder and constructs a [`GetDatastoreInput`](crate::operation::get_datastore::GetDatastoreInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_datastore::GetDatastoreInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_datastore::GetDatastoreInput {
            datastore_id: self.datastore_id,
        })
    }
}
