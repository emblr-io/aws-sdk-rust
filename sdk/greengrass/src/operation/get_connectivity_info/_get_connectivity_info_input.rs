// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetConnectivityInfoInput {
    /// The thing name.
    pub thing_name: ::std::option::Option<::std::string::String>,
}
impl GetConnectivityInfoInput {
    /// The thing name.
    pub fn thing_name(&self) -> ::std::option::Option<&str> {
        self.thing_name.as_deref()
    }
}
impl GetConnectivityInfoInput {
    /// Creates a new builder-style object to manufacture [`GetConnectivityInfoInput`](crate::operation::get_connectivity_info::GetConnectivityInfoInput).
    pub fn builder() -> crate::operation::get_connectivity_info::builders::GetConnectivityInfoInputBuilder {
        crate::operation::get_connectivity_info::builders::GetConnectivityInfoInputBuilder::default()
    }
}

/// A builder for [`GetConnectivityInfoInput`](crate::operation::get_connectivity_info::GetConnectivityInfoInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetConnectivityInfoInputBuilder {
    pub(crate) thing_name: ::std::option::Option<::std::string::String>,
}
impl GetConnectivityInfoInputBuilder {
    /// The thing name.
    /// This field is required.
    pub fn thing_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.thing_name = ::std::option::Option::Some(input.into());
        self
    }
    /// The thing name.
    pub fn set_thing_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.thing_name = input;
        self
    }
    /// The thing name.
    pub fn get_thing_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.thing_name
    }
    /// Consumes the builder and constructs a [`GetConnectivityInfoInput`](crate::operation::get_connectivity_info::GetConnectivityInfoInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_connectivity_info::GetConnectivityInfoInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_connectivity_info::GetConnectivityInfoInput { thing_name: self.thing_name })
    }
}
