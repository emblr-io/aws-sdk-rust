// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetCanaryInput {
    /// <p>The name of the canary that you want details for.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The DryRunId associated with an existing canary’s dry run. You can use this DryRunId to retrieve information about the dry run.</p>
    pub dry_run_id: ::std::option::Option<::std::string::String>,
}
impl GetCanaryInput {
    /// <p>The name of the canary that you want details for.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The DryRunId associated with an existing canary’s dry run. You can use this DryRunId to retrieve information about the dry run.</p>
    pub fn dry_run_id(&self) -> ::std::option::Option<&str> {
        self.dry_run_id.as_deref()
    }
}
impl GetCanaryInput {
    /// Creates a new builder-style object to manufacture [`GetCanaryInput`](crate::operation::get_canary::GetCanaryInput).
    pub fn builder() -> crate::operation::get_canary::builders::GetCanaryInputBuilder {
        crate::operation::get_canary::builders::GetCanaryInputBuilder::default()
    }
}

/// A builder for [`GetCanaryInput`](crate::operation::get_canary::GetCanaryInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetCanaryInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) dry_run_id: ::std::option::Option<::std::string::String>,
}
impl GetCanaryInputBuilder {
    /// <p>The name of the canary that you want details for.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the canary that you want details for.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the canary that you want details for.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
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
    /// Consumes the builder and constructs a [`GetCanaryInput`](crate::operation::get_canary::GetCanaryInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::get_canary::GetCanaryInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_canary::GetCanaryInput {
            name: self.name,
            dry_run_id: self.dry_run_id,
        })
    }
}
