// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteAccessPointInput {
    /// <p>The ID of the access point that you want to delete.</p>
    pub access_point_id: ::std::option::Option<::std::string::String>,
}
impl DeleteAccessPointInput {
    /// <p>The ID of the access point that you want to delete.</p>
    pub fn access_point_id(&self) -> ::std::option::Option<&str> {
        self.access_point_id.as_deref()
    }
}
impl DeleteAccessPointInput {
    /// Creates a new builder-style object to manufacture [`DeleteAccessPointInput`](crate::operation::delete_access_point::DeleteAccessPointInput).
    pub fn builder() -> crate::operation::delete_access_point::builders::DeleteAccessPointInputBuilder {
        crate::operation::delete_access_point::builders::DeleteAccessPointInputBuilder::default()
    }
}

/// A builder for [`DeleteAccessPointInput`](crate::operation::delete_access_point::DeleteAccessPointInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteAccessPointInputBuilder {
    pub(crate) access_point_id: ::std::option::Option<::std::string::String>,
}
impl DeleteAccessPointInputBuilder {
    /// <p>The ID of the access point that you want to delete.</p>
    /// This field is required.
    pub fn access_point_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.access_point_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the access point that you want to delete.</p>
    pub fn set_access_point_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.access_point_id = input;
        self
    }
    /// <p>The ID of the access point that you want to delete.</p>
    pub fn get_access_point_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.access_point_id
    }
    /// Consumes the builder and constructs a [`DeleteAccessPointInput`](crate::operation::delete_access_point::DeleteAccessPointInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_access_point::DeleteAccessPointInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_access_point::DeleteAccessPointInput {
            access_point_id: self.access_point_id,
        })
    }
}
