// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Diagnostic information about executable scripts that are part of a deployment.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Diagnostics {
    /// <p>The associated error code:</p>
    /// <ul>
    /// <li>
    /// <p>Success: The specified script ran.</p></li>
    /// <li>
    /// <p>ScriptMissing: The specified script was not found in the specified location.</p></li>
    /// <li>
    /// <p>ScriptNotExecutable: The specified script is not a recognized executable file type.</p></li>
    /// <li>
    /// <p>ScriptTimedOut: The specified script did not finish running in the specified time period.</p></li>
    /// <li>
    /// <p>ScriptFailed: The specified script failed to run as expected.</p></li>
    /// <li>
    /// <p>UnknownError: The specified script did not run for an unknown reason.</p></li>
    /// </ul>
    pub error_code: ::std::option::Option<crate::types::LifecycleErrorCode>,
    /// <p>The name of the script.</p>
    pub script_name: ::std::option::Option<::std::string::String>,
    /// <p>The message associated with the error.</p>
    pub message: ::std::option::Option<::std::string::String>,
    /// <p>The last portion of the diagnostic log.</p>
    /// <p>If available, CodeDeploy returns up to the last 4 KB of the diagnostic log.</p>
    pub log_tail: ::std::option::Option<::std::string::String>,
}
impl Diagnostics {
    /// <p>The associated error code:</p>
    /// <ul>
    /// <li>
    /// <p>Success: The specified script ran.</p></li>
    /// <li>
    /// <p>ScriptMissing: The specified script was not found in the specified location.</p></li>
    /// <li>
    /// <p>ScriptNotExecutable: The specified script is not a recognized executable file type.</p></li>
    /// <li>
    /// <p>ScriptTimedOut: The specified script did not finish running in the specified time period.</p></li>
    /// <li>
    /// <p>ScriptFailed: The specified script failed to run as expected.</p></li>
    /// <li>
    /// <p>UnknownError: The specified script did not run for an unknown reason.</p></li>
    /// </ul>
    pub fn error_code(&self) -> ::std::option::Option<&crate::types::LifecycleErrorCode> {
        self.error_code.as_ref()
    }
    /// <p>The name of the script.</p>
    pub fn script_name(&self) -> ::std::option::Option<&str> {
        self.script_name.as_deref()
    }
    /// <p>The message associated with the error.</p>
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
    /// <p>The last portion of the diagnostic log.</p>
    /// <p>If available, CodeDeploy returns up to the last 4 KB of the diagnostic log.</p>
    pub fn log_tail(&self) -> ::std::option::Option<&str> {
        self.log_tail.as_deref()
    }
}
impl Diagnostics {
    /// Creates a new builder-style object to manufacture [`Diagnostics`](crate::types::Diagnostics).
    pub fn builder() -> crate::types::builders::DiagnosticsBuilder {
        crate::types::builders::DiagnosticsBuilder::default()
    }
}

/// A builder for [`Diagnostics`](crate::types::Diagnostics).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DiagnosticsBuilder {
    pub(crate) error_code: ::std::option::Option<crate::types::LifecycleErrorCode>,
    pub(crate) script_name: ::std::option::Option<::std::string::String>,
    pub(crate) message: ::std::option::Option<::std::string::String>,
    pub(crate) log_tail: ::std::option::Option<::std::string::String>,
}
impl DiagnosticsBuilder {
    /// <p>The associated error code:</p>
    /// <ul>
    /// <li>
    /// <p>Success: The specified script ran.</p></li>
    /// <li>
    /// <p>ScriptMissing: The specified script was not found in the specified location.</p></li>
    /// <li>
    /// <p>ScriptNotExecutable: The specified script is not a recognized executable file type.</p></li>
    /// <li>
    /// <p>ScriptTimedOut: The specified script did not finish running in the specified time period.</p></li>
    /// <li>
    /// <p>ScriptFailed: The specified script failed to run as expected.</p></li>
    /// <li>
    /// <p>UnknownError: The specified script did not run for an unknown reason.</p></li>
    /// </ul>
    pub fn error_code(mut self, input: crate::types::LifecycleErrorCode) -> Self {
        self.error_code = ::std::option::Option::Some(input);
        self
    }
    /// <p>The associated error code:</p>
    /// <ul>
    /// <li>
    /// <p>Success: The specified script ran.</p></li>
    /// <li>
    /// <p>ScriptMissing: The specified script was not found in the specified location.</p></li>
    /// <li>
    /// <p>ScriptNotExecutable: The specified script is not a recognized executable file type.</p></li>
    /// <li>
    /// <p>ScriptTimedOut: The specified script did not finish running in the specified time period.</p></li>
    /// <li>
    /// <p>ScriptFailed: The specified script failed to run as expected.</p></li>
    /// <li>
    /// <p>UnknownError: The specified script did not run for an unknown reason.</p></li>
    /// </ul>
    pub fn set_error_code(mut self, input: ::std::option::Option<crate::types::LifecycleErrorCode>) -> Self {
        self.error_code = input;
        self
    }
    /// <p>The associated error code:</p>
    /// <ul>
    /// <li>
    /// <p>Success: The specified script ran.</p></li>
    /// <li>
    /// <p>ScriptMissing: The specified script was not found in the specified location.</p></li>
    /// <li>
    /// <p>ScriptNotExecutable: The specified script is not a recognized executable file type.</p></li>
    /// <li>
    /// <p>ScriptTimedOut: The specified script did not finish running in the specified time period.</p></li>
    /// <li>
    /// <p>ScriptFailed: The specified script failed to run as expected.</p></li>
    /// <li>
    /// <p>UnknownError: The specified script did not run for an unknown reason.</p></li>
    /// </ul>
    pub fn get_error_code(&self) -> &::std::option::Option<crate::types::LifecycleErrorCode> {
        &self.error_code
    }
    /// <p>The name of the script.</p>
    pub fn script_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.script_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the script.</p>
    pub fn set_script_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.script_name = input;
        self
    }
    /// <p>The name of the script.</p>
    pub fn get_script_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.script_name
    }
    /// <p>The message associated with the error.</p>
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The message associated with the error.</p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p>The message associated with the error.</p>
    pub fn get_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.message
    }
    /// <p>The last portion of the diagnostic log.</p>
    /// <p>If available, CodeDeploy returns up to the last 4 KB of the diagnostic log.</p>
    pub fn log_tail(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.log_tail = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The last portion of the diagnostic log.</p>
    /// <p>If available, CodeDeploy returns up to the last 4 KB of the diagnostic log.</p>
    pub fn set_log_tail(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.log_tail = input;
        self
    }
    /// <p>The last portion of the diagnostic log.</p>
    /// <p>If available, CodeDeploy returns up to the last 4 KB of the diagnostic log.</p>
    pub fn get_log_tail(&self) -> &::std::option::Option<::std::string::String> {
        &self.log_tail
    }
    /// Consumes the builder and constructs a [`Diagnostics`](crate::types::Diagnostics).
    pub fn build(self) -> crate::types::Diagnostics {
        crate::types::Diagnostics {
            error_code: self.error_code,
            script_name: self.script_name,
            message: self.message,
            log_tail: self.log_tail,
        }
    }
}
