// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes a web-based, remote graphical user interface (GUI), Amazon DCV session. The session is used to access a virtual computer’s operating system or application.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct Session {
    /// <p>The session name.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The session URL.</p>
    pub url: ::std::option::Option<::std::string::String>,
    /// <p>When true, this Boolean value indicates the primary session for the specified resource.</p>
    pub is_primary: ::std::option::Option<bool>,
}
impl Session {
    /// <p>The session name.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The session URL.</p>
    pub fn url(&self) -> ::std::option::Option<&str> {
        self.url.as_deref()
    }
    /// <p>When true, this Boolean value indicates the primary session for the specified resource.</p>
    pub fn is_primary(&self) -> ::std::option::Option<bool> {
        self.is_primary
    }
}
impl ::std::fmt::Debug for Session {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("Session");
        formatter.field("name", &self.name);
        formatter.field("url", &"*** Sensitive Data Redacted ***");
        formatter.field("is_primary", &self.is_primary);
        formatter.finish()
    }
}
impl Session {
    /// Creates a new builder-style object to manufacture [`Session`](crate::types::Session).
    pub fn builder() -> crate::types::builders::SessionBuilder {
        crate::types::builders::SessionBuilder::default()
    }
}

/// A builder for [`Session`](crate::types::Session).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct SessionBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) url: ::std::option::Option<::std::string::String>,
    pub(crate) is_primary: ::std::option::Option<bool>,
}
impl SessionBuilder {
    /// <p>The session name.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The session name.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The session name.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The session URL.</p>
    pub fn url(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.url = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The session URL.</p>
    pub fn set_url(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.url = input;
        self
    }
    /// <p>The session URL.</p>
    pub fn get_url(&self) -> &::std::option::Option<::std::string::String> {
        &self.url
    }
    /// <p>When true, this Boolean value indicates the primary session for the specified resource.</p>
    pub fn is_primary(mut self, input: bool) -> Self {
        self.is_primary = ::std::option::Option::Some(input);
        self
    }
    /// <p>When true, this Boolean value indicates the primary session for the specified resource.</p>
    pub fn set_is_primary(mut self, input: ::std::option::Option<bool>) -> Self {
        self.is_primary = input;
        self
    }
    /// <p>When true, this Boolean value indicates the primary session for the specified resource.</p>
    pub fn get_is_primary(&self) -> &::std::option::Option<bool> {
        &self.is_primary
    }
    /// Consumes the builder and constructs a [`Session`](crate::types::Session).
    pub fn build(self) -> crate::types::Session {
        crate::types::Session {
            name: self.name,
            url: self.url,
            is_primary: self.is_primary,
        }
    }
}
impl ::std::fmt::Debug for SessionBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("SessionBuilder");
        formatter.field("name", &self.name);
        formatter.field("url", &"*** Sensitive Data Redacted ***");
        formatter.field("is_primary", &self.is_primary);
        formatter.finish()
    }
}
