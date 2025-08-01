// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about the server configured for source code analysis.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RemoteSourceCodeAnalysisServerInfo {
    /// <p>The time when the remote source code server was configured.</p>
    pub remote_source_code_analysis_server_configuration_timestamp: ::std::option::Option<::std::string::String>,
}
impl RemoteSourceCodeAnalysisServerInfo {
    /// <p>The time when the remote source code server was configured.</p>
    pub fn remote_source_code_analysis_server_configuration_timestamp(&self) -> ::std::option::Option<&str> {
        self.remote_source_code_analysis_server_configuration_timestamp.as_deref()
    }
}
impl RemoteSourceCodeAnalysisServerInfo {
    /// Creates a new builder-style object to manufacture [`RemoteSourceCodeAnalysisServerInfo`](crate::types::RemoteSourceCodeAnalysisServerInfo).
    pub fn builder() -> crate::types::builders::RemoteSourceCodeAnalysisServerInfoBuilder {
        crate::types::builders::RemoteSourceCodeAnalysisServerInfoBuilder::default()
    }
}

/// A builder for [`RemoteSourceCodeAnalysisServerInfo`](crate::types::RemoteSourceCodeAnalysisServerInfo).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RemoteSourceCodeAnalysisServerInfoBuilder {
    pub(crate) remote_source_code_analysis_server_configuration_timestamp: ::std::option::Option<::std::string::String>,
}
impl RemoteSourceCodeAnalysisServerInfoBuilder {
    /// <p>The time when the remote source code server was configured.</p>
    pub fn remote_source_code_analysis_server_configuration_timestamp(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.remote_source_code_analysis_server_configuration_timestamp = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The time when the remote source code server was configured.</p>
    pub fn set_remote_source_code_analysis_server_configuration_timestamp(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.remote_source_code_analysis_server_configuration_timestamp = input;
        self
    }
    /// <p>The time when the remote source code server was configured.</p>
    pub fn get_remote_source_code_analysis_server_configuration_timestamp(&self) -> &::std::option::Option<::std::string::String> {
        &self.remote_source_code_analysis_server_configuration_timestamp
    }
    /// Consumes the builder and constructs a [`RemoteSourceCodeAnalysisServerInfo`](crate::types::RemoteSourceCodeAnalysisServerInfo).
    pub fn build(self) -> crate::types::RemoteSourceCodeAnalysisServerInfo {
        crate::types::RemoteSourceCodeAnalysisServerInfo {
            remote_source_code_analysis_server_configuration_timestamp: self.remote_source_code_analysis_server_configuration_timestamp,
        }
    }
}
