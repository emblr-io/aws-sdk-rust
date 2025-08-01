// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A structure that contains information about the RUM app monitor.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AppMonitorDetails {
    /// <p>The name of the app monitor.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The unique ID of the app monitor.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The version of the app monitor.</p>
    pub version: ::std::option::Option<::std::string::String>,
}
impl AppMonitorDetails {
    /// <p>The name of the app monitor.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The unique ID of the app monitor.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The version of the app monitor.</p>
    pub fn version(&self) -> ::std::option::Option<&str> {
        self.version.as_deref()
    }
}
impl AppMonitorDetails {
    /// Creates a new builder-style object to manufacture [`AppMonitorDetails`](crate::types::AppMonitorDetails).
    pub fn builder() -> crate::types::builders::AppMonitorDetailsBuilder {
        crate::types::builders::AppMonitorDetailsBuilder::default()
    }
}

/// A builder for [`AppMonitorDetails`](crate::types::AppMonitorDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AppMonitorDetailsBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) version: ::std::option::Option<::std::string::String>,
}
impl AppMonitorDetailsBuilder {
    /// <p>The name of the app monitor.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the app monitor.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the app monitor.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The unique ID of the app monitor.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique ID of the app monitor.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The unique ID of the app monitor.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The version of the app monitor.</p>
    pub fn version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version of the app monitor.</p>
    pub fn set_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version = input;
        self
    }
    /// <p>The version of the app monitor.</p>
    pub fn get_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.version
    }
    /// Consumes the builder and constructs a [`AppMonitorDetails`](crate::types::AppMonitorDetails).
    pub fn build(self) -> crate::types::AppMonitorDetails {
        crate::types::AppMonitorDetails {
            name: self.name,
            id: self.id,
            version: self.version,
        }
    }
}
