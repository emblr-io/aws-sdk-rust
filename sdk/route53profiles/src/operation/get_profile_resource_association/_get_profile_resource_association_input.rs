// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetProfileResourceAssociationInput {
    /// <p>The ID of the profile resource association that you want to get information about.</p>
    pub profile_resource_association_id: ::std::option::Option<::std::string::String>,
}
impl GetProfileResourceAssociationInput {
    /// <p>The ID of the profile resource association that you want to get information about.</p>
    pub fn profile_resource_association_id(&self) -> ::std::option::Option<&str> {
        self.profile_resource_association_id.as_deref()
    }
}
impl GetProfileResourceAssociationInput {
    /// Creates a new builder-style object to manufacture [`GetProfileResourceAssociationInput`](crate::operation::get_profile_resource_association::GetProfileResourceAssociationInput).
    pub fn builder() -> crate::operation::get_profile_resource_association::builders::GetProfileResourceAssociationInputBuilder {
        crate::operation::get_profile_resource_association::builders::GetProfileResourceAssociationInputBuilder::default()
    }
}

/// A builder for [`GetProfileResourceAssociationInput`](crate::operation::get_profile_resource_association::GetProfileResourceAssociationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetProfileResourceAssociationInputBuilder {
    pub(crate) profile_resource_association_id: ::std::option::Option<::std::string::String>,
}
impl GetProfileResourceAssociationInputBuilder {
    /// <p>The ID of the profile resource association that you want to get information about.</p>
    /// This field is required.
    pub fn profile_resource_association_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.profile_resource_association_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the profile resource association that you want to get information about.</p>
    pub fn set_profile_resource_association_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.profile_resource_association_id = input;
        self
    }
    /// <p>The ID of the profile resource association that you want to get information about.</p>
    pub fn get_profile_resource_association_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.profile_resource_association_id
    }
    /// Consumes the builder and constructs a [`GetProfileResourceAssociationInput`](crate::operation::get_profile_resource_association::GetProfileResourceAssociationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_profile_resource_association::GetProfileResourceAssociationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_profile_resource_association::GetProfileResourceAssociationInput {
            profile_resource_association_id: self.profile_resource_association_id,
        })
    }
}
