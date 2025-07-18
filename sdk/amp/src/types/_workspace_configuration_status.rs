// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>This structure displays the current status of the workspace configuration, and might also contain a reason for that status.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct WorkspaceConfigurationStatus {
    /// <p>The current status of the workspace configuration.</p>
    pub status_code: crate::types::WorkspaceConfigurationStatusCode,
    /// <p>The reason for the current status, if a reason is available.</p>
    pub status_reason: ::std::option::Option<::std::string::String>,
}
impl WorkspaceConfigurationStatus {
    /// <p>The current status of the workspace configuration.</p>
    pub fn status_code(&self) -> &crate::types::WorkspaceConfigurationStatusCode {
        &self.status_code
    }
    /// <p>The reason for the current status, if a reason is available.</p>
    pub fn status_reason(&self) -> ::std::option::Option<&str> {
        self.status_reason.as_deref()
    }
}
impl WorkspaceConfigurationStatus {
    /// Creates a new builder-style object to manufacture [`WorkspaceConfigurationStatus`](crate::types::WorkspaceConfigurationStatus).
    pub fn builder() -> crate::types::builders::WorkspaceConfigurationStatusBuilder {
        crate::types::builders::WorkspaceConfigurationStatusBuilder::default()
    }
}

/// A builder for [`WorkspaceConfigurationStatus`](crate::types::WorkspaceConfigurationStatus).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct WorkspaceConfigurationStatusBuilder {
    pub(crate) status_code: ::std::option::Option<crate::types::WorkspaceConfigurationStatusCode>,
    pub(crate) status_reason: ::std::option::Option<::std::string::String>,
}
impl WorkspaceConfigurationStatusBuilder {
    /// <p>The current status of the workspace configuration.</p>
    /// This field is required.
    pub fn status_code(mut self, input: crate::types::WorkspaceConfigurationStatusCode) -> Self {
        self.status_code = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current status of the workspace configuration.</p>
    pub fn set_status_code(mut self, input: ::std::option::Option<crate::types::WorkspaceConfigurationStatusCode>) -> Self {
        self.status_code = input;
        self
    }
    /// <p>The current status of the workspace configuration.</p>
    pub fn get_status_code(&self) -> &::std::option::Option<crate::types::WorkspaceConfigurationStatusCode> {
        &self.status_code
    }
    /// <p>The reason for the current status, if a reason is available.</p>
    pub fn status_reason(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status_reason = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The reason for the current status, if a reason is available.</p>
    pub fn set_status_reason(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status_reason = input;
        self
    }
    /// <p>The reason for the current status, if a reason is available.</p>
    pub fn get_status_reason(&self) -> &::std::option::Option<::std::string::String> {
        &self.status_reason
    }
    /// Consumes the builder and constructs a [`WorkspaceConfigurationStatus`](crate::types::WorkspaceConfigurationStatus).
    /// This method will fail if any of the following fields are not set:
    /// - [`status_code`](crate::types::builders::WorkspaceConfigurationStatusBuilder::status_code)
    pub fn build(self) -> ::std::result::Result<crate::types::WorkspaceConfigurationStatus, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::WorkspaceConfigurationStatus {
            status_code: self.status_code.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "status_code",
                    "status_code was not specified but it is required when building WorkspaceConfigurationStatus",
                )
            })?,
            status_reason: self.status_reason,
        })
    }
}
