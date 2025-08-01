// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about the endpoint.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Endpoint {
    /// <p>Type of the endpoint.</p>
    pub r#type: ::std::option::Option<crate::types::EndpointType>,
    /// <p>Address of the endpoint.</p>
    pub address: ::std::option::Option<::std::string::String>,
}
impl Endpoint {
    /// <p>Type of the endpoint.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::EndpointType> {
        self.r#type.as_ref()
    }
    /// <p>Address of the endpoint.</p>
    pub fn address(&self) -> ::std::option::Option<&str> {
        self.address.as_deref()
    }
}
impl Endpoint {
    /// Creates a new builder-style object to manufacture [`Endpoint`](crate::types::Endpoint).
    pub fn builder() -> crate::types::builders::EndpointBuilder {
        crate::types::builders::EndpointBuilder::default()
    }
}

/// A builder for [`Endpoint`](crate::types::Endpoint).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EndpointBuilder {
    pub(crate) r#type: ::std::option::Option<crate::types::EndpointType>,
    pub(crate) address: ::std::option::Option<::std::string::String>,
}
impl EndpointBuilder {
    /// <p>Type of the endpoint.</p>
    pub fn r#type(mut self, input: crate::types::EndpointType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Type of the endpoint.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::EndpointType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>Type of the endpoint.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::EndpointType> {
        &self.r#type
    }
    /// <p>Address of the endpoint.</p>
    pub fn address(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.address = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Address of the endpoint.</p>
    pub fn set_address(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.address = input;
        self
    }
    /// <p>Address of the endpoint.</p>
    pub fn get_address(&self) -> &::std::option::Option<::std::string::String> {
        &self.address
    }
    /// Consumes the builder and constructs a [`Endpoint`](crate::types::Endpoint).
    pub fn build(self) -> crate::types::Endpoint {
        crate::types::Endpoint {
            r#type: self.r#type,
            address: self.address,
        }
    }
}
