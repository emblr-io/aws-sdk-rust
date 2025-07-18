// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains a summary of an ingestion.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct IngestionSummary {
    /// <p>The Amazon Resource Name (ARN) of the ingestion.</p>
    pub arn: ::std::string::String,
    /// <p>The name of the application.</p>
    pub app: ::std::string::String,
    /// <p>The ID of the application tenant.</p>
    pub tenant_id: ::std::string::String,
    /// <p>The status of the ingestion.</p>
    pub state: crate::types::IngestionState,
}
impl IngestionSummary {
    /// <p>The Amazon Resource Name (ARN) of the ingestion.</p>
    pub fn arn(&self) -> &str {
        use std::ops::Deref;
        self.arn.deref()
    }
    /// <p>The name of the application.</p>
    pub fn app(&self) -> &str {
        use std::ops::Deref;
        self.app.deref()
    }
    /// <p>The ID of the application tenant.</p>
    pub fn tenant_id(&self) -> &str {
        use std::ops::Deref;
        self.tenant_id.deref()
    }
    /// <p>The status of the ingestion.</p>
    pub fn state(&self) -> &crate::types::IngestionState {
        &self.state
    }
}
impl IngestionSummary {
    /// Creates a new builder-style object to manufacture [`IngestionSummary`](crate::types::IngestionSummary).
    pub fn builder() -> crate::types::builders::IngestionSummaryBuilder {
        crate::types::builders::IngestionSummaryBuilder::default()
    }
}

/// A builder for [`IngestionSummary`](crate::types::IngestionSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct IngestionSummaryBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) app: ::std::option::Option<::std::string::String>,
    pub(crate) tenant_id: ::std::option::Option<::std::string::String>,
    pub(crate) state: ::std::option::Option<crate::types::IngestionState>,
}
impl IngestionSummaryBuilder {
    /// <p>The Amazon Resource Name (ARN) of the ingestion.</p>
    /// This field is required.
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the ingestion.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the ingestion.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The name of the application.</p>
    /// This field is required.
    pub fn app(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.app = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the application.</p>
    pub fn set_app(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.app = input;
        self
    }
    /// <p>The name of the application.</p>
    pub fn get_app(&self) -> &::std::option::Option<::std::string::String> {
        &self.app
    }
    /// <p>The ID of the application tenant.</p>
    /// This field is required.
    pub fn tenant_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.tenant_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the application tenant.</p>
    pub fn set_tenant_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.tenant_id = input;
        self
    }
    /// <p>The ID of the application tenant.</p>
    pub fn get_tenant_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.tenant_id
    }
    /// <p>The status of the ingestion.</p>
    /// This field is required.
    pub fn state(mut self, input: crate::types::IngestionState) -> Self {
        self.state = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the ingestion.</p>
    pub fn set_state(mut self, input: ::std::option::Option<crate::types::IngestionState>) -> Self {
        self.state = input;
        self
    }
    /// <p>The status of the ingestion.</p>
    pub fn get_state(&self) -> &::std::option::Option<crate::types::IngestionState> {
        &self.state
    }
    /// Consumes the builder and constructs a [`IngestionSummary`](crate::types::IngestionSummary).
    /// This method will fail if any of the following fields are not set:
    /// - [`arn`](crate::types::builders::IngestionSummaryBuilder::arn)
    /// - [`app`](crate::types::builders::IngestionSummaryBuilder::app)
    /// - [`tenant_id`](crate::types::builders::IngestionSummaryBuilder::tenant_id)
    /// - [`state`](crate::types::builders::IngestionSummaryBuilder::state)
    pub fn build(self) -> ::std::result::Result<crate::types::IngestionSummary, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::IngestionSummary {
            arn: self.arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "arn",
                    "arn was not specified but it is required when building IngestionSummary",
                )
            })?,
            app: self.app.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "app",
                    "app was not specified but it is required when building IngestionSummary",
                )
            })?,
            tenant_id: self.tenant_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "tenant_id",
                    "tenant_id was not specified but it is required when building IngestionSummary",
                )
            })?,
            state: self.state.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "state",
                    "state was not specified but it is required when building IngestionSummary",
                )
            })?,
        })
    }
}
