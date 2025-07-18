// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A structure describing the source of an action.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ActionSource {
    /// <p>The URI of the source.</p>
    pub source_uri: ::std::option::Option<::std::string::String>,
    /// <p>The type of the source.</p>
    pub source_type: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the source.</p>
    pub source_id: ::std::option::Option<::std::string::String>,
}
impl ActionSource {
    /// <p>The URI of the source.</p>
    pub fn source_uri(&self) -> ::std::option::Option<&str> {
        self.source_uri.as_deref()
    }
    /// <p>The type of the source.</p>
    pub fn source_type(&self) -> ::std::option::Option<&str> {
        self.source_type.as_deref()
    }
    /// <p>The ID of the source.</p>
    pub fn source_id(&self) -> ::std::option::Option<&str> {
        self.source_id.as_deref()
    }
}
impl ActionSource {
    /// Creates a new builder-style object to manufacture [`ActionSource`](crate::types::ActionSource).
    pub fn builder() -> crate::types::builders::ActionSourceBuilder {
        crate::types::builders::ActionSourceBuilder::default()
    }
}

/// A builder for [`ActionSource`](crate::types::ActionSource).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ActionSourceBuilder {
    pub(crate) source_uri: ::std::option::Option<::std::string::String>,
    pub(crate) source_type: ::std::option::Option<::std::string::String>,
    pub(crate) source_id: ::std::option::Option<::std::string::String>,
}
impl ActionSourceBuilder {
    /// <p>The URI of the source.</p>
    /// This field is required.
    pub fn source_uri(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_uri = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The URI of the source.</p>
    pub fn set_source_uri(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_uri = input;
        self
    }
    /// <p>The URI of the source.</p>
    pub fn get_source_uri(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_uri
    }
    /// <p>The type of the source.</p>
    pub fn source_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The type of the source.</p>
    pub fn set_source_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_type = input;
        self
    }
    /// <p>The type of the source.</p>
    pub fn get_source_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_type
    }
    /// <p>The ID of the source.</p>
    pub fn source_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the source.</p>
    pub fn set_source_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_id = input;
        self
    }
    /// <p>The ID of the source.</p>
    pub fn get_source_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_id
    }
    /// Consumes the builder and constructs a [`ActionSource`](crate::types::ActionSource).
    pub fn build(self) -> crate::types::ActionSource {
        crate::types::ActionSource {
            source_uri: self.source_uri,
            source_type: self.source_type,
            source_id: self.source_id,
        }
    }
}
