// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Get an SdkType instance.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetSdkTypeInput {
    /// <p>The identifier of the queried SdkType instance.</p>
    pub id: ::std::option::Option<::std::string::String>,
}
impl GetSdkTypeInput {
    /// <p>The identifier of the queried SdkType instance.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
}
impl GetSdkTypeInput {
    /// Creates a new builder-style object to manufacture [`GetSdkTypeInput`](crate::operation::get_sdk_type::GetSdkTypeInput).
    pub fn builder() -> crate::operation::get_sdk_type::builders::GetSdkTypeInputBuilder {
        crate::operation::get_sdk_type::builders::GetSdkTypeInputBuilder::default()
    }
}

/// A builder for [`GetSdkTypeInput`](crate::operation::get_sdk_type::GetSdkTypeInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetSdkTypeInputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
}
impl GetSdkTypeInputBuilder {
    /// <p>The identifier of the queried SdkType instance.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the queried SdkType instance.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The identifier of the queried SdkType instance.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// Consumes the builder and constructs a [`GetSdkTypeInput`](crate::operation::get_sdk_type::GetSdkTypeInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::get_sdk_type::GetSdkTypeInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_sdk_type::GetSdkTypeInput { id: self.id })
    }
}
