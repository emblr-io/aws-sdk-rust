// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteProfileObjectInput {
    /// <p>The unique identifier of a customer profile.</p>
    pub profile_id: ::std::option::Option<::std::string::String>,
    /// <p>The unique identifier of the profile object generated by the service.</p>
    pub profile_object_unique_key: ::std::option::Option<::std::string::String>,
    /// <p>The name of the profile object type.</p>
    pub object_type_name: ::std::option::Option<::std::string::String>,
    /// <p>The unique name of the domain.</p>
    pub domain_name: ::std::option::Option<::std::string::String>,
}
impl DeleteProfileObjectInput {
    /// <p>The unique identifier of a customer profile.</p>
    pub fn profile_id(&self) -> ::std::option::Option<&str> {
        self.profile_id.as_deref()
    }
    /// <p>The unique identifier of the profile object generated by the service.</p>
    pub fn profile_object_unique_key(&self) -> ::std::option::Option<&str> {
        self.profile_object_unique_key.as_deref()
    }
    /// <p>The name of the profile object type.</p>
    pub fn object_type_name(&self) -> ::std::option::Option<&str> {
        self.object_type_name.as_deref()
    }
    /// <p>The unique name of the domain.</p>
    pub fn domain_name(&self) -> ::std::option::Option<&str> {
        self.domain_name.as_deref()
    }
}
impl DeleteProfileObjectInput {
    /// Creates a new builder-style object to manufacture [`DeleteProfileObjectInput`](crate::operation::delete_profile_object::DeleteProfileObjectInput).
    pub fn builder() -> crate::operation::delete_profile_object::builders::DeleteProfileObjectInputBuilder {
        crate::operation::delete_profile_object::builders::DeleteProfileObjectInputBuilder::default()
    }
}

/// A builder for [`DeleteProfileObjectInput`](crate::operation::delete_profile_object::DeleteProfileObjectInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteProfileObjectInputBuilder {
    pub(crate) profile_id: ::std::option::Option<::std::string::String>,
    pub(crate) profile_object_unique_key: ::std::option::Option<::std::string::String>,
    pub(crate) object_type_name: ::std::option::Option<::std::string::String>,
    pub(crate) domain_name: ::std::option::Option<::std::string::String>,
}
impl DeleteProfileObjectInputBuilder {
    /// <p>The unique identifier of a customer profile.</p>
    /// This field is required.
    pub fn profile_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.profile_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of a customer profile.</p>
    pub fn set_profile_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.profile_id = input;
        self
    }
    /// <p>The unique identifier of a customer profile.</p>
    pub fn get_profile_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.profile_id
    }
    /// <p>The unique identifier of the profile object generated by the service.</p>
    /// This field is required.
    pub fn profile_object_unique_key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.profile_object_unique_key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the profile object generated by the service.</p>
    pub fn set_profile_object_unique_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.profile_object_unique_key = input;
        self
    }
    /// <p>The unique identifier of the profile object generated by the service.</p>
    pub fn get_profile_object_unique_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.profile_object_unique_key
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
    /// Consumes the builder and constructs a [`DeleteProfileObjectInput`](crate::operation::delete_profile_object::DeleteProfileObjectInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_profile_object::DeleteProfileObjectInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::delete_profile_object::DeleteProfileObjectInput {
            profile_id: self.profile_id,
            profile_object_unique_key: self.profile_object_unique_key,
            object_type_name: self.object_type_name,
            domain_name: self.domain_name,
        })
    }
}
