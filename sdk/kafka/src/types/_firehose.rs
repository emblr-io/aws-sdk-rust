// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Firehose {
    #[allow(missing_docs)] // documentation missing in model
    pub delivery_stream: ::std::option::Option<::std::string::String>,
    #[allow(missing_docs)] // documentation missing in model
    pub enabled: ::std::option::Option<bool>,
}
impl Firehose {
    #[allow(missing_docs)] // documentation missing in model
    pub fn delivery_stream(&self) -> ::std::option::Option<&str> {
        self.delivery_stream.as_deref()
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn enabled(&self) -> ::std::option::Option<bool> {
        self.enabled
    }
}
impl Firehose {
    /// Creates a new builder-style object to manufacture [`Firehose`](crate::types::Firehose).
    pub fn builder() -> crate::types::builders::FirehoseBuilder {
        crate::types::builders::FirehoseBuilder::default()
    }
}

/// A builder for [`Firehose`](crate::types::Firehose).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FirehoseBuilder {
    pub(crate) delivery_stream: ::std::option::Option<::std::string::String>,
    pub(crate) enabled: ::std::option::Option<bool>,
}
impl FirehoseBuilder {
    #[allow(missing_docs)] // documentation missing in model
    pub fn delivery_stream(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.delivery_stream = ::std::option::Option::Some(input.into());
        self
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn set_delivery_stream(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.delivery_stream = input;
        self
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn get_delivery_stream(&self) -> &::std::option::Option<::std::string::String> {
        &self.delivery_stream
    }
    #[allow(missing_docs)] // documentation missing in model
    /// This field is required.
    pub fn enabled(mut self, input: bool) -> Self {
        self.enabled = ::std::option::Option::Some(input);
        self
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn set_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enabled = input;
        self
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn get_enabled(&self) -> &::std::option::Option<bool> {
        &self.enabled
    }
    /// Consumes the builder and constructs a [`Firehose`](crate::types::Firehose).
    pub fn build(self) -> crate::types::Firehose {
        crate::types::Firehose {
            delivery_stream: self.delivery_stream,
            enabled: self.enabled,
        }
    }
}
