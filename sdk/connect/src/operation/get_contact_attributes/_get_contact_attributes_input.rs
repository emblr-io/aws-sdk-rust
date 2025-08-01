// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetContactAttributesInput {
    /// <p>The identifier of the Amazon Connect instance.</p>
    pub instance_id: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the initial contact.</p>
    pub initial_contact_id: ::std::option::Option<::std::string::String>,
}
impl GetContactAttributesInput {
    /// <p>The identifier of the Amazon Connect instance.</p>
    pub fn instance_id(&self) -> ::std::option::Option<&str> {
        self.instance_id.as_deref()
    }
    /// <p>The identifier of the initial contact.</p>
    pub fn initial_contact_id(&self) -> ::std::option::Option<&str> {
        self.initial_contact_id.as_deref()
    }
}
impl GetContactAttributesInput {
    /// Creates a new builder-style object to manufacture [`GetContactAttributesInput`](crate::operation::get_contact_attributes::GetContactAttributesInput).
    pub fn builder() -> crate::operation::get_contact_attributes::builders::GetContactAttributesInputBuilder {
        crate::operation::get_contact_attributes::builders::GetContactAttributesInputBuilder::default()
    }
}

/// A builder for [`GetContactAttributesInput`](crate::operation::get_contact_attributes::GetContactAttributesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetContactAttributesInputBuilder {
    pub(crate) instance_id: ::std::option::Option<::std::string::String>,
    pub(crate) initial_contact_id: ::std::option::Option<::std::string::String>,
}
impl GetContactAttributesInputBuilder {
    /// <p>The identifier of the Amazon Connect instance.</p>
    /// This field is required.
    pub fn instance_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the Amazon Connect instance.</p>
    pub fn set_instance_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_id = input;
        self
    }
    /// <p>The identifier of the Amazon Connect instance.</p>
    pub fn get_instance_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_id
    }
    /// <p>The identifier of the initial contact.</p>
    /// This field is required.
    pub fn initial_contact_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.initial_contact_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the initial contact.</p>
    pub fn set_initial_contact_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.initial_contact_id = input;
        self
    }
    /// <p>The identifier of the initial contact.</p>
    pub fn get_initial_contact_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.initial_contact_id
    }
    /// Consumes the builder and constructs a [`GetContactAttributesInput`](crate::operation::get_contact_attributes::GetContactAttributesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_contact_attributes::GetContactAttributesInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_contact_attributes::GetContactAttributesInput {
            instance_id: self.instance_id,
            initial_contact_id: self.initial_contact_id,
        })
    }
}
