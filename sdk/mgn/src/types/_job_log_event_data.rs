// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Job log data</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct JobLogEventData {
    /// <p>Job Event Source Server ID.</p>
    pub source_server_id: ::std::option::Option<::std::string::String>,
    /// <p>Job Event conversion Server ID.</p>
    pub conversion_server_id: ::std::option::Option<::std::string::String>,
    /// <p>Job Event Target instance ID.</p>
    pub target_instance_id: ::std::option::Option<::std::string::String>,
    /// <p>Job error.</p>
    pub raw_error: ::std::option::Option<::std::string::String>,
}
impl JobLogEventData {
    /// <p>Job Event Source Server ID.</p>
    pub fn source_server_id(&self) -> ::std::option::Option<&str> {
        self.source_server_id.as_deref()
    }
    /// <p>Job Event conversion Server ID.</p>
    pub fn conversion_server_id(&self) -> ::std::option::Option<&str> {
        self.conversion_server_id.as_deref()
    }
    /// <p>Job Event Target instance ID.</p>
    pub fn target_instance_id(&self) -> ::std::option::Option<&str> {
        self.target_instance_id.as_deref()
    }
    /// <p>Job error.</p>
    pub fn raw_error(&self) -> ::std::option::Option<&str> {
        self.raw_error.as_deref()
    }
}
impl JobLogEventData {
    /// Creates a new builder-style object to manufacture [`JobLogEventData`](crate::types::JobLogEventData).
    pub fn builder() -> crate::types::builders::JobLogEventDataBuilder {
        crate::types::builders::JobLogEventDataBuilder::default()
    }
}

/// A builder for [`JobLogEventData`](crate::types::JobLogEventData).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct JobLogEventDataBuilder {
    pub(crate) source_server_id: ::std::option::Option<::std::string::String>,
    pub(crate) conversion_server_id: ::std::option::Option<::std::string::String>,
    pub(crate) target_instance_id: ::std::option::Option<::std::string::String>,
    pub(crate) raw_error: ::std::option::Option<::std::string::String>,
}
impl JobLogEventDataBuilder {
    /// <p>Job Event Source Server ID.</p>
    pub fn source_server_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_server_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Job Event Source Server ID.</p>
    pub fn set_source_server_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_server_id = input;
        self
    }
    /// <p>Job Event Source Server ID.</p>
    pub fn get_source_server_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_server_id
    }
    /// <p>Job Event conversion Server ID.</p>
    pub fn conversion_server_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.conversion_server_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Job Event conversion Server ID.</p>
    pub fn set_conversion_server_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.conversion_server_id = input;
        self
    }
    /// <p>Job Event conversion Server ID.</p>
    pub fn get_conversion_server_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.conversion_server_id
    }
    /// <p>Job Event Target instance ID.</p>
    pub fn target_instance_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.target_instance_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Job Event Target instance ID.</p>
    pub fn set_target_instance_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.target_instance_id = input;
        self
    }
    /// <p>Job Event Target instance ID.</p>
    pub fn get_target_instance_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.target_instance_id
    }
    /// <p>Job error.</p>
    pub fn raw_error(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.raw_error = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Job error.</p>
    pub fn set_raw_error(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.raw_error = input;
        self
    }
    /// <p>Job error.</p>
    pub fn get_raw_error(&self) -> &::std::option::Option<::std::string::String> {
        &self.raw_error
    }
    /// Consumes the builder and constructs a [`JobLogEventData`](crate::types::JobLogEventData).
    pub fn build(self) -> crate::types::JobLogEventData {
        crate::types::JobLogEventData {
            source_server_id: self.source_server_id,
            conversion_server_id: self.conversion_server_id,
            target_instance_id: self.target_instance_id,
            raw_error: self.raw_error,
        }
    }
}
