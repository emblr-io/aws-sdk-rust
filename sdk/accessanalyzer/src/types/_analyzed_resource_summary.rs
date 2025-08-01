// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the ARN of the analyzed resource.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AnalyzedResourceSummary {
    /// <p>The ARN of the analyzed resource.</p>
    pub resource_arn: ::std::string::String,
    /// <p>The Amazon Web Services account ID that owns the resource.</p>
    pub resource_owner_account: ::std::string::String,
    /// <p>The type of resource that was analyzed.</p>
    pub resource_type: crate::types::ResourceType,
}
impl AnalyzedResourceSummary {
    /// <p>The ARN of the analyzed resource.</p>
    pub fn resource_arn(&self) -> &str {
        use std::ops::Deref;
        self.resource_arn.deref()
    }
    /// <p>The Amazon Web Services account ID that owns the resource.</p>
    pub fn resource_owner_account(&self) -> &str {
        use std::ops::Deref;
        self.resource_owner_account.deref()
    }
    /// <p>The type of resource that was analyzed.</p>
    pub fn resource_type(&self) -> &crate::types::ResourceType {
        &self.resource_type
    }
}
impl AnalyzedResourceSummary {
    /// Creates a new builder-style object to manufacture [`AnalyzedResourceSummary`](crate::types::AnalyzedResourceSummary).
    pub fn builder() -> crate::types::builders::AnalyzedResourceSummaryBuilder {
        crate::types::builders::AnalyzedResourceSummaryBuilder::default()
    }
}

/// A builder for [`AnalyzedResourceSummary`](crate::types::AnalyzedResourceSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AnalyzedResourceSummaryBuilder {
    pub(crate) resource_arn: ::std::option::Option<::std::string::String>,
    pub(crate) resource_owner_account: ::std::option::Option<::std::string::String>,
    pub(crate) resource_type: ::std::option::Option<crate::types::ResourceType>,
}
impl AnalyzedResourceSummaryBuilder {
    /// <p>The ARN of the analyzed resource.</p>
    /// This field is required.
    pub fn resource_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the analyzed resource.</p>
    pub fn set_resource_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_arn = input;
        self
    }
    /// <p>The ARN of the analyzed resource.</p>
    pub fn get_resource_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_arn
    }
    /// <p>The Amazon Web Services account ID that owns the resource.</p>
    /// This field is required.
    pub fn resource_owner_account(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_owner_account = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services account ID that owns the resource.</p>
    pub fn set_resource_owner_account(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_owner_account = input;
        self
    }
    /// <p>The Amazon Web Services account ID that owns the resource.</p>
    pub fn get_resource_owner_account(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_owner_account
    }
    /// <p>The type of resource that was analyzed.</p>
    /// This field is required.
    pub fn resource_type(mut self, input: crate::types::ResourceType) -> Self {
        self.resource_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of resource that was analyzed.</p>
    pub fn set_resource_type(mut self, input: ::std::option::Option<crate::types::ResourceType>) -> Self {
        self.resource_type = input;
        self
    }
    /// <p>The type of resource that was analyzed.</p>
    pub fn get_resource_type(&self) -> &::std::option::Option<crate::types::ResourceType> {
        &self.resource_type
    }
    /// Consumes the builder and constructs a [`AnalyzedResourceSummary`](crate::types::AnalyzedResourceSummary).
    /// This method will fail if any of the following fields are not set:
    /// - [`resource_arn`](crate::types::builders::AnalyzedResourceSummaryBuilder::resource_arn)
    /// - [`resource_owner_account`](crate::types::builders::AnalyzedResourceSummaryBuilder::resource_owner_account)
    /// - [`resource_type`](crate::types::builders::AnalyzedResourceSummaryBuilder::resource_type)
    pub fn build(self) -> ::std::result::Result<crate::types::AnalyzedResourceSummary, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::AnalyzedResourceSummary {
            resource_arn: self.resource_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "resource_arn",
                    "resource_arn was not specified but it is required when building AnalyzedResourceSummary",
                )
            })?,
            resource_owner_account: self.resource_owner_account.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "resource_owner_account",
                    "resource_owner_account was not specified but it is required when building AnalyzedResourceSummary",
                )
            })?,
            resource_type: self.resource_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "resource_type",
                    "resource_type was not specified but it is required when building AnalyzedResourceSummary",
                )
            })?,
        })
    }
}
