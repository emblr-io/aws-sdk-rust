// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetStaticIpInput {
    /// <p>The name of the static IP in Lightsail.</p>
    pub static_ip_name: ::std::option::Option<::std::string::String>,
}
impl GetStaticIpInput {
    /// <p>The name of the static IP in Lightsail.</p>
    pub fn static_ip_name(&self) -> ::std::option::Option<&str> {
        self.static_ip_name.as_deref()
    }
}
impl GetStaticIpInput {
    /// Creates a new builder-style object to manufacture [`GetStaticIpInput`](crate::operation::get_static_ip::GetStaticIpInput).
    pub fn builder() -> crate::operation::get_static_ip::builders::GetStaticIpInputBuilder {
        crate::operation::get_static_ip::builders::GetStaticIpInputBuilder::default()
    }
}

/// A builder for [`GetStaticIpInput`](crate::operation::get_static_ip::GetStaticIpInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetStaticIpInputBuilder {
    pub(crate) static_ip_name: ::std::option::Option<::std::string::String>,
}
impl GetStaticIpInputBuilder {
    /// <p>The name of the static IP in Lightsail.</p>
    /// This field is required.
    pub fn static_ip_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.static_ip_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the static IP in Lightsail.</p>
    pub fn set_static_ip_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.static_ip_name = input;
        self
    }
    /// <p>The name of the static IP in Lightsail.</p>
    pub fn get_static_ip_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.static_ip_name
    }
    /// Consumes the builder and constructs a [`GetStaticIpInput`](crate::operation::get_static_ip::GetStaticIpInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::get_static_ip::GetStaticIpInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_static_ip::GetStaticIpInput {
            static_ip_name: self.static_ip_name,
        })
    }
}
