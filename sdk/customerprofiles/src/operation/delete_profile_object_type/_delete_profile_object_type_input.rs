// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteProfileObjectTypeInput {
    /// <p>The unique name of the domain.</p>
    pub domain_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the profile object type.</p>
    pub object_type_name: ::std::option::Option<::std::string::String>,
}
impl DeleteProfileObjectTypeInput {
    /// <p>The unique name of the domain.</p>
    pub fn domain_name(&self) -> ::std::option::Option<&str> {
        self.domain_name.as_deref()
    }
    /// <p>The name of the profile object type.</p>
    pub fn object_type_name(&self) -> ::std::option::Option<&str> {
        self.object_type_name.as_deref()
    }
}
impl DeleteProfileObjectTypeInput {
    /// Creates a new builder-style object to manufacture [`DeleteProfileObjectTypeInput`](crate::operation::delete_profile_object_type::DeleteProfileObjectTypeInput).
    pub fn builder() -> crate::operation::delete_profile_object_type::builders::DeleteProfileObjectTypeInputBuilder {
        crate::operation::delete_profile_object_type::builders::DeleteProfileObjectTypeInputBuilder::default()
    }
}

/// A builder for [`DeleteProfileObjectTypeInput`](crate::operation::delete_profile_object_type::DeleteProfileObjectTypeInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteProfileObjectTypeInputBuilder {
    pub(crate) domain_name: ::std::option::Option<::std::string::String>,
    pub(crate) object_type_name: ::std::option::Option<::std::string::String>,
}
impl DeleteProfileObjectTypeInputBuilder {
    /// <p>The unique name of the domain.</p>
    /// This field is required.
    pub fn domain_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique name of the domain.</p>
    pub fn set_domain_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_name = input;
        self
    }
    /// <p>The unique name of the domain.</p>
    pub fn get_domain_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_name
    }
    /// <p>The name of the profile object type.</p>
    /// This field is required.
    pub fn object_type_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.object_type_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the profile object type.</p>
    pub fn set_object_type_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.object_type_name = input;
        self
    }
    /// <p>The name of the profile object type.</p>
    pub fn get_object_type_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.object_type_name
    }
    /// Consumes the builder and constructs a [`DeleteProfileObjectTypeInput`](crate::operation::delete_profile_object_type::DeleteProfileObjectTypeInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_profile_object_type::DeleteProfileObjectTypeInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_profile_object_type::DeleteProfileObjectTypeInput {
            domain_name: self.domain_name,
            object_type_name: self.object_type_name,
        })
    }
}
