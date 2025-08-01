// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteInstanceProfileInput {
    /// <p>The name of the instance profile to delete.</p>
    /// <p>This parameter allows (through its <a href="http://wikipedia.org/wiki/regex">regex pattern</a>) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-</p>
    pub instance_profile_name: ::std::option::Option<::std::string::String>,
}
impl DeleteInstanceProfileInput {
    /// <p>The name of the instance profile to delete.</p>
    /// <p>This parameter allows (through its <a href="http://wikipedia.org/wiki/regex">regex pattern</a>) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-</p>
    pub fn instance_profile_name(&self) -> ::std::option::Option<&str> {
        self.instance_profile_name.as_deref()
    }
}
impl DeleteInstanceProfileInput {
    /// Creates a new builder-style object to manufacture [`DeleteInstanceProfileInput`](crate::operation::delete_instance_profile::DeleteInstanceProfileInput).
    pub fn builder() -> crate::operation::delete_instance_profile::builders::DeleteInstanceProfileInputBuilder {
        crate::operation::delete_instance_profile::builders::DeleteInstanceProfileInputBuilder::default()
    }
}

/// A builder for [`DeleteInstanceProfileInput`](crate::operation::delete_instance_profile::DeleteInstanceProfileInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteInstanceProfileInputBuilder {
    pub(crate) instance_profile_name: ::std::option::Option<::std::string::String>,
}
impl DeleteInstanceProfileInputBuilder {
    /// <p>The name of the instance profile to delete.</p>
    /// <p>This parameter allows (through its <a href="http://wikipedia.org/wiki/regex">regex pattern</a>) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-</p>
    /// This field is required.
    pub fn instance_profile_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_profile_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the instance profile to delete.</p>
    /// <p>This parameter allows (through its <a href="http://wikipedia.org/wiki/regex">regex pattern</a>) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-</p>
    pub fn set_instance_profile_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_profile_name = input;
        self
    }
    /// <p>The name of the instance profile to delete.</p>
    /// <p>This parameter allows (through its <a href="http://wikipedia.org/wiki/regex">regex pattern</a>) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-</p>
    pub fn get_instance_profile_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_profile_name
    }
    /// Consumes the builder and constructs a [`DeleteInstanceProfileInput`](crate::operation::delete_instance_profile::DeleteInstanceProfileInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_instance_profile::DeleteInstanceProfileInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::delete_instance_profile::DeleteInstanceProfileInput {
            instance_profile_name: self.instance_profile_name,
        })
    }
}
