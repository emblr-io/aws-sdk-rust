// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetSlotTypeInput {
    /// <p>The name of the slot type. The name is case sensitive.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The version of the slot type.</p>
    pub version: ::std::option::Option<::std::string::String>,
}
impl GetSlotTypeInput {
    /// <p>The name of the slot type. The name is case sensitive.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The version of the slot type.</p>
    pub fn version(&self) -> ::std::option::Option<&str> {
        self.version.as_deref()
    }
}
impl GetSlotTypeInput {
    /// Creates a new builder-style object to manufacture [`GetSlotTypeInput`](crate::operation::get_slot_type::GetSlotTypeInput).
    pub fn builder() -> crate::operation::get_slot_type::builders::GetSlotTypeInputBuilder {
        crate::operation::get_slot_type::builders::GetSlotTypeInputBuilder::default()
    }
}

/// A builder for [`GetSlotTypeInput`](crate::operation::get_slot_type::GetSlotTypeInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetSlotTypeInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) version: ::std::option::Option<::std::string::String>,
}
impl GetSlotTypeInputBuilder {
    /// <p>The name of the slot type. The name is case sensitive.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the slot type. The name is case sensitive.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the slot type. The name is case sensitive.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The version of the slot type.</p>
    /// This field is required.
    pub fn version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version of the slot type.</p>
    pub fn set_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version = input;
        self
    }
    /// <p>The version of the slot type.</p>
    pub fn get_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.version
    }
    /// Consumes the builder and constructs a [`GetSlotTypeInput`](crate::operation::get_slot_type::GetSlotTypeInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::get_slot_type::GetSlotTypeInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_slot_type::GetSlotTypeInput {
            name: self.name,
            version: self.version,
        })
    }
}
