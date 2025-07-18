// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Returns the dry run configurations set for a canary.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DryRunConfigOutput {
    /// <p>The DryRunId associated with an existing canary’s dry run. You can use this DryRunId to retrieve information about the dry run.</p>
    pub dry_run_id: ::std::option::Option<::std::string::String>,
    /// <p>Returns the last execution status for a canary's dry run.</p>
    pub last_dry_run_execution_status: ::std::option::Option<::std::string::String>,
}
impl DryRunConfigOutput {
    /// <p>The DryRunId associated with an existing canary’s dry run. You can use this DryRunId to retrieve information about the dry run.</p>
    pub fn dry_run_id(&self) -> ::std::option::Option<&str> {
        self.dry_run_id.as_deref()
    }
    /// <p>Returns the last execution status for a canary's dry run.</p>
    pub fn last_dry_run_execution_status(&self) -> ::std::option::Option<&str> {
        self.last_dry_run_execution_status.as_deref()
    }
}
impl DryRunConfigOutput {
    /// Creates a new builder-style object to manufacture [`DryRunConfigOutput`](crate::types::DryRunConfigOutput).
    pub fn builder() -> crate::types::builders::DryRunConfigOutputBuilder {
        crate::types::builders::DryRunConfigOutputBuilder::default()
    }
}

/// A builder for [`DryRunConfigOutput`](crate::types::DryRunConfigOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DryRunConfigOutputBuilder {
    pub(crate) dry_run_id: ::std::option::Option<::std::string::String>,
    pub(crate) last_dry_run_execution_status: ::std::option::Option<::std::string::String>,
}
impl DryRunConfigOutputBuilder {
    /// <p>The DryRunId associated with an existing canary’s dry run. You can use this DryRunId to retrieve information about the dry run.</p>
    pub fn dry_run_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.dry_run_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The DryRunId associated with an existing canary’s dry run. You can use this DryRunId to retrieve information about the dry run.</p>
    pub fn set_dry_run_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.dry_run_id = input;
        self
    }
    /// <p>The DryRunId associated with an existing canary’s dry run. You can use this DryRunId to retrieve information about the dry run.</p>
    pub fn get_dry_run_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.dry_run_id
    }
    /// <p>Returns the last execution status for a canary's dry run.</p>
    pub fn last_dry_run_execution_status(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.last_dry_run_execution_status = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Returns the last execution status for a canary's dry run.</p>
    pub fn set_last_dry_run_execution_status(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.last_dry_run_execution_status = input;
        self
    }
    /// <p>Returns the last execution status for a canary's dry run.</p>
    pub fn get_last_dry_run_execution_status(&self) -> &::std::option::Option<::std::string::String> {
        &self.last_dry_run_execution_status
    }
    /// Consumes the builder and constructs a [`DryRunConfigOutput`](crate::types::DryRunConfigOutput).
    pub fn build(self) -> crate::types::DryRunConfigOutput {
        crate::types::DryRunConfigOutput {
            dry_run_id: self.dry_run_id,
            last_dry_run_execution_status: self.last_dry_run_execution_status,
        }
    }
}
