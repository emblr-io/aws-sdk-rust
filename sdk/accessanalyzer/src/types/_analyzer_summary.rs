// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about the analyzer.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AnalyzerSummary {
    /// <p>The ARN of the analyzer.</p>
    pub arn: ::std::string::String,
    /// <p>The name of the analyzer.</p>
    pub name: ::std::string::String,
    /// <p>The type of analyzer, which corresponds to the zone of trust chosen for the analyzer.</p>
    pub r#type: crate::types::Type,
    /// <p>A timestamp for the time at which the analyzer was created.</p>
    pub created_at: ::aws_smithy_types::DateTime,
    /// <p>The resource that was most recently analyzed by the analyzer.</p>
    pub last_resource_analyzed: ::std::option::Option<::std::string::String>,
    /// <p>The time at which the most recently analyzed resource was analyzed.</p>
    pub last_resource_analyzed_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The tags added to the analyzer.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The status of the analyzer. An <code>Active</code> analyzer successfully monitors supported resources and generates new findings. The analyzer is <code>Disabled</code> when a user action, such as removing trusted access for Identity and Access Management Access Analyzer from Organizations, causes the analyzer to stop generating new findings. The status is <code>Creating</code> when the analyzer creation is in progress and <code>Failed</code> when the analyzer creation has failed.</p>
    pub status: crate::types::AnalyzerStatus,
    /// <p>The <code>statusReason</code> provides more details about the current status of the analyzer. For example, if the creation for the analyzer fails, a <code>Failed</code> status is returned. For an analyzer with organization as the type, this failure can be due to an issue with creating the service-linked roles required in the member accounts of the Amazon Web Services organization.</p>
    pub status_reason: ::std::option::Option<crate::types::StatusReason>,
    /// <p>Specifies if the analyzer is an external access, unused access, or internal access analyzer.</p>
    pub configuration: ::std::option::Option<crate::types::AnalyzerConfiguration>,
}
impl AnalyzerSummary {
    /// <p>The ARN of the analyzer.</p>
    pub fn arn(&self) -> &str {
        use std::ops::Deref;
        self.arn.deref()
    }
    /// <p>The name of the analyzer.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The type of analyzer, which corresponds to the zone of trust chosen for the analyzer.</p>
    pub fn r#type(&self) -> &crate::types::Type {
        &self.r#type
    }
    /// <p>A timestamp for the time at which the analyzer was created.</p>
    pub fn created_at(&self) -> &::aws_smithy_types::DateTime {
        &self.created_at
    }
    /// <p>The resource that was most recently analyzed by the analyzer.</p>
    pub fn last_resource_analyzed(&self) -> ::std::option::Option<&str> {
        self.last_resource_analyzed.as_deref()
    }
    /// <p>The time at which the most recently analyzed resource was analyzed.</p>
    pub fn last_resource_analyzed_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_resource_analyzed_at.as_ref()
    }
    /// <p>The tags added to the analyzer.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
    /// <p>The status of the analyzer. An <code>Active</code> analyzer successfully monitors supported resources and generates new findings. The analyzer is <code>Disabled</code> when a user action, such as removing trusted access for Identity and Access Management Access Analyzer from Organizations, causes the analyzer to stop generating new findings. The status is <code>Creating</code> when the analyzer creation is in progress and <code>Failed</code> when the analyzer creation has failed.</p>
    pub fn status(&self) -> &crate::types::AnalyzerStatus {
        &self.status
    }
    /// <p>The <code>statusReason</code> provides more details about the current status of the analyzer. For example, if the creation for the analyzer fails, a <code>Failed</code> status is returned. For an analyzer with organization as the type, this failure can be due to an issue with creating the service-linked roles required in the member accounts of the Amazon Web Services organization.</p>
    pub fn status_reason(&self) -> ::std::option::Option<&crate::types::StatusReason> {
        self.status_reason.as_ref()
    }
    /// <p>Specifies if the analyzer is an external access, unused access, or internal access analyzer.</p>
    pub fn configuration(&self) -> ::std::option::Option<&crate::types::AnalyzerConfiguration> {
        self.configuration.as_ref()
    }
}
impl AnalyzerSummary {
    /// Creates a new builder-style object to manufacture [`AnalyzerSummary`](crate::types::AnalyzerSummary).
    pub fn builder() -> crate::types::builders::AnalyzerSummaryBuilder {
        crate::types::builders::AnalyzerSummaryBuilder::default()
    }
}

/// A builder for [`AnalyzerSummary`](crate::types::AnalyzerSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AnalyzerSummaryBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<crate::types::Type>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_resource_analyzed: ::std::option::Option<::std::string::String>,
    pub(crate) last_resource_analyzed_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) status: ::std::option::Option<crate::types::AnalyzerStatus>,
    pub(crate) status_reason: ::std::option::Option<crate::types::StatusReason>,
    pub(crate) configuration: ::std::option::Option<crate::types::AnalyzerConfiguration>,
}
impl AnalyzerSummaryBuilder {
    /// <p>The ARN of the analyzer.</p>
    /// This field is required.
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the analyzer.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The ARN of the analyzer.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The name of the analyzer.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the analyzer.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the analyzer.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The type of analyzer, which corresponds to the zone of trust chosen for the analyzer.</p>
    /// This field is required.
    pub fn r#type(mut self, input: crate::types::Type) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of analyzer, which corresponds to the zone of trust chosen for the analyzer.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::Type>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of analyzer, which corresponds to the zone of trust chosen for the analyzer.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::Type> {
        &self.r#type
    }
    /// <p>A timestamp for the time at which the analyzer was created.</p>
    /// This field is required.
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>A timestamp for the time at which the analyzer was created.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>A timestamp for the time at which the analyzer was created.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// <p>The resource that was most recently analyzed by the analyzer.</p>
    pub fn last_resource_analyzed(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.last_resource_analyzed = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The resource that was most recently analyzed by the analyzer.</p>
    pub fn set_last_resource_analyzed(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.last_resource_analyzed = input;
        self
    }
    /// <p>The resource that was most recently analyzed by the analyzer.</p>
    pub fn get_last_resource_analyzed(&self) -> &::std::option::Option<::std::string::String> {
        &self.last_resource_analyzed
    }
    /// <p>The time at which the most recently analyzed resource was analyzed.</p>
    pub fn last_resource_analyzed_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_resource_analyzed_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time at which the most recently analyzed resource was analyzed.</p>
    pub fn set_last_resource_analyzed_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_resource_analyzed_at = input;
        self
    }
    /// <p>The time at which the most recently analyzed resource was analyzed.</p>
    pub fn get_last_resource_analyzed_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_resource_analyzed_at
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags added to the analyzer.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The tags added to the analyzer.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags added to the analyzer.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// <p>The status of the analyzer. An <code>Active</code> analyzer successfully monitors supported resources and generates new findings. The analyzer is <code>Disabled</code> when a user action, such as removing trusted access for Identity and Access Management Access Analyzer from Organizations, causes the analyzer to stop generating new findings. The status is <code>Creating</code> when the analyzer creation is in progress and <code>Failed</code> when the analyzer creation has failed.</p>
    /// This field is required.
    pub fn status(mut self, input: crate::types::AnalyzerStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the analyzer. An <code>Active</code> analyzer successfully monitors supported resources and generates new findings. The analyzer is <code>Disabled</code> when a user action, such as removing trusted access for Identity and Access Management Access Analyzer from Organizations, causes the analyzer to stop generating new findings. The status is <code>Creating</code> when the analyzer creation is in progress and <code>Failed</code> when the analyzer creation has failed.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::AnalyzerStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the analyzer. An <code>Active</code> analyzer successfully monitors supported resources and generates new findings. The analyzer is <code>Disabled</code> when a user action, such as removing trusted access for Identity and Access Management Access Analyzer from Organizations, causes the analyzer to stop generating new findings. The status is <code>Creating</code> when the analyzer creation is in progress and <code>Failed</code> when the analyzer creation has failed.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::AnalyzerStatus> {
        &self.status
    }
    /// <p>The <code>statusReason</code> provides more details about the current status of the analyzer. For example, if the creation for the analyzer fails, a <code>Failed</code> status is returned. For an analyzer with organization as the type, this failure can be due to an issue with creating the service-linked roles required in the member accounts of the Amazon Web Services organization.</p>
    pub fn status_reason(mut self, input: crate::types::StatusReason) -> Self {
        self.status_reason = ::std::option::Option::Some(input);
        self
    }
    /// <p>The <code>statusReason</code> provides more details about the current status of the analyzer. For example, if the creation for the analyzer fails, a <code>Failed</code> status is returned. For an analyzer with organization as the type, this failure can be due to an issue with creating the service-linked roles required in the member accounts of the Amazon Web Services organization.</p>
    pub fn set_status_reason(mut self, input: ::std::option::Option<crate::types::StatusReason>) -> Self {
        self.status_reason = input;
        self
    }
    /// <p>The <code>statusReason</code> provides more details about the current status of the analyzer. For example, if the creation for the analyzer fails, a <code>Failed</code> status is returned. For an analyzer with organization as the type, this failure can be due to an issue with creating the service-linked roles required in the member accounts of the Amazon Web Services organization.</p>
    pub fn get_status_reason(&self) -> &::std::option::Option<crate::types::StatusReason> {
        &self.status_reason
    }
    /// <p>Specifies if the analyzer is an external access, unused access, or internal access analyzer.</p>
    pub fn configuration(mut self, input: crate::types::AnalyzerConfiguration) -> Self {
        self.configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies if the analyzer is an external access, unused access, or internal access analyzer.</p>
    pub fn set_configuration(mut self, input: ::std::option::Option<crate::types::AnalyzerConfiguration>) -> Self {
        self.configuration = input;
        self
    }
    /// <p>Specifies if the analyzer is an external access, unused access, or internal access analyzer.</p>
    pub fn get_configuration(&self) -> &::std::option::Option<crate::types::AnalyzerConfiguration> {
        &self.configuration
    }
    /// Consumes the builder and constructs a [`AnalyzerSummary`](crate::types::AnalyzerSummary).
    /// This method will fail if any of the following fields are not set:
    /// - [`arn`](crate::types::builders::AnalyzerSummaryBuilder::arn)
    /// - [`name`](crate::types::builders::AnalyzerSummaryBuilder::name)
    /// - [`r#type`](crate::types::builders::AnalyzerSummaryBuilder::type)
    /// - [`created_at`](crate::types::builders::AnalyzerSummaryBuilder::created_at)
    /// - [`status`](crate::types::builders::AnalyzerSummaryBuilder::status)
    pub fn build(self) -> ::std::result::Result<crate::types::AnalyzerSummary, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::AnalyzerSummary {
            arn: self.arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "arn",
                    "arn was not specified but it is required when building AnalyzerSummary",
                )
            })?,
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building AnalyzerSummary",
                )
            })?,
            r#type: self.r#type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "r#type",
                    "r#type was not specified but it is required when building AnalyzerSummary",
                )
            })?,
            created_at: self.created_at.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "created_at",
                    "created_at was not specified but it is required when building AnalyzerSummary",
                )
            })?,
            last_resource_analyzed: self.last_resource_analyzed,
            last_resource_analyzed_at: self.last_resource_analyzed_at,
            tags: self.tags,
            status: self.status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "status",
                    "status was not specified but it is required when building AnalyzerSummary",
                )
            })?,
            status_reason: self.status_reason,
            configuration: self.configuration,
        })
    }
}
