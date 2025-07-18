// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies an array of up to 5 conditions to be met, and an action to take (<code>RETRY</code> or <code>EXIT</code>) if all conditions are met. If none of the <code>EvaluateOnExit</code> conditions in a <code>RetryStrategy</code> match, then the job is retried.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EvaluateOnExit {
    /// <p>Contains a glob pattern to match against the <code>StatusReason</code> returned for a job. The pattern can contain up to 512 characters. It can contain letters, numbers, periods (.), colons (:), and white spaces (including spaces or tabs). It can optionally end with an asterisk (*) so that only the start of the string needs to be an exact match.</p>
    pub on_status_reason: ::std::option::Option<::std::string::String>,
    /// <p>Contains a glob pattern to match against the <code>Reason</code> returned for a job. The pattern can contain up to 512 characters. It can contain letters, numbers, periods (.), colons (:), and white space (including spaces and tabs). It can optionally end with an asterisk (*) so that only the start of the string needs to be an exact match.</p>
    pub on_reason: ::std::option::Option<::std::string::String>,
    /// <p>Contains a glob pattern to match against the decimal representation of the <code>ExitCode</code> returned for a job. The pattern can be up to 512 characters long. It can contain only numbers, and can end with an asterisk (*) so that only the start of the string needs to be an exact match.</p>
    /// <p>The string can contain up to 512 characters.</p>
    pub on_exit_code: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the action to take if all of the specified conditions (<code>onStatusReason</code>, <code>onReason</code>, and <code>onExitCode</code>) are met. The values aren't case sensitive.</p>
    pub action: ::std::option::Option<crate::types::RetryAction>,
}
impl EvaluateOnExit {
    /// <p>Contains a glob pattern to match against the <code>StatusReason</code> returned for a job. The pattern can contain up to 512 characters. It can contain letters, numbers, periods (.), colons (:), and white spaces (including spaces or tabs). It can optionally end with an asterisk (*) so that only the start of the string needs to be an exact match.</p>
    pub fn on_status_reason(&self) -> ::std::option::Option<&str> {
        self.on_status_reason.as_deref()
    }
    /// <p>Contains a glob pattern to match against the <code>Reason</code> returned for a job. The pattern can contain up to 512 characters. It can contain letters, numbers, periods (.), colons (:), and white space (including spaces and tabs). It can optionally end with an asterisk (*) so that only the start of the string needs to be an exact match.</p>
    pub fn on_reason(&self) -> ::std::option::Option<&str> {
        self.on_reason.as_deref()
    }
    /// <p>Contains a glob pattern to match against the decimal representation of the <code>ExitCode</code> returned for a job. The pattern can be up to 512 characters long. It can contain only numbers, and can end with an asterisk (*) so that only the start of the string needs to be an exact match.</p>
    /// <p>The string can contain up to 512 characters.</p>
    pub fn on_exit_code(&self) -> ::std::option::Option<&str> {
        self.on_exit_code.as_deref()
    }
    /// <p>Specifies the action to take if all of the specified conditions (<code>onStatusReason</code>, <code>onReason</code>, and <code>onExitCode</code>) are met. The values aren't case sensitive.</p>
    pub fn action(&self) -> ::std::option::Option<&crate::types::RetryAction> {
        self.action.as_ref()
    }
}
impl EvaluateOnExit {
    /// Creates a new builder-style object to manufacture [`EvaluateOnExit`](crate::types::EvaluateOnExit).
    pub fn builder() -> crate::types::builders::EvaluateOnExitBuilder {
        crate::types::builders::EvaluateOnExitBuilder::default()
    }
}

/// A builder for [`EvaluateOnExit`](crate::types::EvaluateOnExit).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EvaluateOnExitBuilder {
    pub(crate) on_status_reason: ::std::option::Option<::std::string::String>,
    pub(crate) on_reason: ::std::option::Option<::std::string::String>,
    pub(crate) on_exit_code: ::std::option::Option<::std::string::String>,
    pub(crate) action: ::std::option::Option<crate::types::RetryAction>,
}
impl EvaluateOnExitBuilder {
    /// <p>Contains a glob pattern to match against the <code>StatusReason</code> returned for a job. The pattern can contain up to 512 characters. It can contain letters, numbers, periods (.), colons (:), and white spaces (including spaces or tabs). It can optionally end with an asterisk (*) so that only the start of the string needs to be an exact match.</p>
    pub fn on_status_reason(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.on_status_reason = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Contains a glob pattern to match against the <code>StatusReason</code> returned for a job. The pattern can contain up to 512 characters. It can contain letters, numbers, periods (.), colons (:), and white spaces (including spaces or tabs). It can optionally end with an asterisk (*) so that only the start of the string needs to be an exact match.</p>
    pub fn set_on_status_reason(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.on_status_reason = input;
        self
    }
    /// <p>Contains a glob pattern to match against the <code>StatusReason</code> returned for a job. The pattern can contain up to 512 characters. It can contain letters, numbers, periods (.), colons (:), and white spaces (including spaces or tabs). It can optionally end with an asterisk (*) so that only the start of the string needs to be an exact match.</p>
    pub fn get_on_status_reason(&self) -> &::std::option::Option<::std::string::String> {
        &self.on_status_reason
    }
    /// <p>Contains a glob pattern to match against the <code>Reason</code> returned for a job. The pattern can contain up to 512 characters. It can contain letters, numbers, periods (.), colons (:), and white space (including spaces and tabs). It can optionally end with an asterisk (*) so that only the start of the string needs to be an exact match.</p>
    pub fn on_reason(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.on_reason = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Contains a glob pattern to match against the <code>Reason</code> returned for a job. The pattern can contain up to 512 characters. It can contain letters, numbers, periods (.), colons (:), and white space (including spaces and tabs). It can optionally end with an asterisk (*) so that only the start of the string needs to be an exact match.</p>
    pub fn set_on_reason(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.on_reason = input;
        self
    }
    /// <p>Contains a glob pattern to match against the <code>Reason</code> returned for a job. The pattern can contain up to 512 characters. It can contain letters, numbers, periods (.), colons (:), and white space (including spaces and tabs). It can optionally end with an asterisk (*) so that only the start of the string needs to be an exact match.</p>
    pub fn get_on_reason(&self) -> &::std::option::Option<::std::string::String> {
        &self.on_reason
    }
    /// <p>Contains a glob pattern to match against the decimal representation of the <code>ExitCode</code> returned for a job. The pattern can be up to 512 characters long. It can contain only numbers, and can end with an asterisk (*) so that only the start of the string needs to be an exact match.</p>
    /// <p>The string can contain up to 512 characters.</p>
    pub fn on_exit_code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.on_exit_code = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Contains a glob pattern to match against the decimal representation of the <code>ExitCode</code> returned for a job. The pattern can be up to 512 characters long. It can contain only numbers, and can end with an asterisk (*) so that only the start of the string needs to be an exact match.</p>
    /// <p>The string can contain up to 512 characters.</p>
    pub fn set_on_exit_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.on_exit_code = input;
        self
    }
    /// <p>Contains a glob pattern to match against the decimal representation of the <code>ExitCode</code> returned for a job. The pattern can be up to 512 characters long. It can contain only numbers, and can end with an asterisk (*) so that only the start of the string needs to be an exact match.</p>
    /// <p>The string can contain up to 512 characters.</p>
    pub fn get_on_exit_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.on_exit_code
    }
    /// <p>Specifies the action to take if all of the specified conditions (<code>onStatusReason</code>, <code>onReason</code>, and <code>onExitCode</code>) are met. The values aren't case sensitive.</p>
    /// This field is required.
    pub fn action(mut self, input: crate::types::RetryAction) -> Self {
        self.action = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the action to take if all of the specified conditions (<code>onStatusReason</code>, <code>onReason</code>, and <code>onExitCode</code>) are met. The values aren't case sensitive.</p>
    pub fn set_action(mut self, input: ::std::option::Option<crate::types::RetryAction>) -> Self {
        self.action = input;
        self
    }
    /// <p>Specifies the action to take if all of the specified conditions (<code>onStatusReason</code>, <code>onReason</code>, and <code>onExitCode</code>) are met. The values aren't case sensitive.</p>
    pub fn get_action(&self) -> &::std::option::Option<crate::types::RetryAction> {
        &self.action
    }
    /// Consumes the builder and constructs a [`EvaluateOnExit`](crate::types::EvaluateOnExit).
    pub fn build(self) -> crate::types::EvaluateOnExit {
        crate::types::EvaluateOnExit {
            on_status_reason: self.on_status_reason,
            on_reason: self.on_reason,
            on_exit_code: self.on_exit_code,
            action: self.action,
        }
    }
}
