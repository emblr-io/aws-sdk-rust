// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A summary of information about a scope, including the ARN, target ID, and Amazon Web Services Region.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ScopeSummary {
    /// <p>The identifier for the scope that includes the resources you want to get data results for. A scope ID is an internally-generated identifier that includes all the resources for a specific root account.</p>
    pub scope_id: ::std::string::String,
    /// <p>The status of a scope. The status can be one of the following, depending on the state of scope creation: <code>SUCCEEDED</code>, <code>IN_PROGRESS</code>, or <code>FAILED</code>.</p>
    pub status: crate::types::ScopeStatus,
    /// <p>The Amazon Resource Name (ARN) of the scope.</p>
    pub scope_arn: ::std::string::String,
}
impl ScopeSummary {
    /// <p>The identifier for the scope that includes the resources you want to get data results for. A scope ID is an internally-generated identifier that includes all the resources for a specific root account.</p>
    pub fn scope_id(&self) -> &str {
        use std::ops::Deref;
        self.scope_id.deref()
    }
    /// <p>The status of a scope. The status can be one of the following, depending on the state of scope creation: <code>SUCCEEDED</code>, <code>IN_PROGRESS</code>, or <code>FAILED</code>.</p>
    pub fn status(&self) -> &crate::types::ScopeStatus {
        &self.status
    }
    /// <p>The Amazon Resource Name (ARN) of the scope.</p>
    pub fn scope_arn(&self) -> &str {
        use std::ops::Deref;
        self.scope_arn.deref()
    }
}
impl ScopeSummary {
    /// Creates a new builder-style object to manufacture [`ScopeSummary`](crate::types::ScopeSummary).
    pub fn builder() -> crate::types::builders::ScopeSummaryBuilder {
        crate::types::builders::ScopeSummaryBuilder::default()
    }
}

/// A builder for [`ScopeSummary`](crate::types::ScopeSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ScopeSummaryBuilder {
    pub(crate) scope_id: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::ScopeStatus>,
    pub(crate) scope_arn: ::std::option::Option<::std::string::String>,
}
impl ScopeSummaryBuilder {
    /// <p>The identifier for the scope that includes the resources you want to get data results for. A scope ID is an internally-generated identifier that includes all the resources for a specific root account.</p>
    /// This field is required.
    pub fn scope_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.scope_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier for the scope that includes the resources you want to get data results for. A scope ID is an internally-generated identifier that includes all the resources for a specific root account.</p>
    pub fn set_scope_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.scope_id = input;
        self
    }
    /// <p>The identifier for the scope that includes the resources you want to get data results for. A scope ID is an internally-generated identifier that includes all the resources for a specific root account.</p>
    pub fn get_scope_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.scope_id
    }
    /// <p>The status of a scope. The status can be one of the following, depending on the state of scope creation: <code>SUCCEEDED</code>, <code>IN_PROGRESS</code>, or <code>FAILED</code>.</p>
    /// This field is required.
    pub fn status(mut self, input: crate::types::ScopeStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of a scope. The status can be one of the following, depending on the state of scope creation: <code>SUCCEEDED</code>, <code>IN_PROGRESS</code>, or <code>FAILED</code>.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::ScopeStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of a scope. The status can be one of the following, depending on the state of scope creation: <code>SUCCEEDED</code>, <code>IN_PROGRESS</code>, or <code>FAILED</code>.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::ScopeStatus> {
        &self.status
    }
    /// <p>The Amazon Resource Name (ARN) of the scope.</p>
    /// This field is required.
    pub fn scope_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.scope_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the scope.</p>
    pub fn set_scope_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.scope_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the scope.</p>
    pub fn get_scope_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.scope_arn
    }
    /// Consumes the builder and constructs a [`ScopeSummary`](crate::types::ScopeSummary).
    /// This method will fail if any of the following fields are not set:
    /// - [`scope_id`](crate::types::builders::ScopeSummaryBuilder::scope_id)
    /// - [`status`](crate::types::builders::ScopeSummaryBuilder::status)
    /// - [`scope_arn`](crate::types::builders::ScopeSummaryBuilder::scope_arn)
    pub fn build(self) -> ::std::result::Result<crate::types::ScopeSummary, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ScopeSummary {
            scope_id: self.scope_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "scope_id",
                    "scope_id was not specified but it is required when building ScopeSummary",
                )
            })?,
            status: self.status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "status",
                    "status was not specified but it is required when building ScopeSummary",
                )
            })?,
            scope_arn: self.scope_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "scope_arn",
                    "scope_arn was not specified but it is required when building ScopeSummary",
                )
            })?,
        })
    }
}
