// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The summary metadata that describes an analysis.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AnalysisSummary {
    /// <p>The Amazon Resource Name (ARN) for the analysis.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the analysis. This ID displays in the URL.</p>
    pub analysis_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the analysis. This name is displayed in the Amazon QuickSight console.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The last known status for the analysis.</p>
    pub status: ::std::option::Option<crate::types::ResourceStatus>,
    /// <p>The time that the analysis was created.</p>
    pub created_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The time that the analysis was last updated.</p>
    pub last_updated_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl AnalysisSummary {
    /// <p>The Amazon Resource Name (ARN) for the analysis.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The ID of the analysis. This ID displays in the URL.</p>
    pub fn analysis_id(&self) -> ::std::option::Option<&str> {
        self.analysis_id.as_deref()
    }
    /// <p>The name of the analysis. This name is displayed in the Amazon QuickSight console.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The last known status for the analysis.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::ResourceStatus> {
        self.status.as_ref()
    }
    /// <p>The time that the analysis was created.</p>
    pub fn created_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_time.as_ref()
    }
    /// <p>The time that the analysis was last updated.</p>
    pub fn last_updated_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_updated_time.as_ref()
    }
}
impl AnalysisSummary {
    /// Creates a new builder-style object to manufacture [`AnalysisSummary`](crate::types::AnalysisSummary).
    pub fn builder() -> crate::types::builders::AnalysisSummaryBuilder {
        crate::types::builders::AnalysisSummaryBuilder::default()
    }
}

/// A builder for [`AnalysisSummary`](crate::types::AnalysisSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AnalysisSummaryBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) analysis_id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::ResourceStatus>,
    pub(crate) created_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_updated_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl AnalysisSummaryBuilder {
    /// <p>The Amazon Resource Name (ARN) for the analysis.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the analysis.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the analysis.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The ID of the analysis. This ID displays in the URL.</p>
    pub fn analysis_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.analysis_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the analysis. This ID displays in the URL.</p>
    pub fn set_analysis_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.analysis_id = input;
        self
    }
    /// <p>The ID of the analysis. This ID displays in the URL.</p>
    pub fn get_analysis_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.analysis_id
    }
    /// <p>The name of the analysis. This name is displayed in the Amazon QuickSight console.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the analysis. This name is displayed in the Amazon QuickSight console.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the analysis. This name is displayed in the Amazon QuickSight console.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The last known status for the analysis.</p>
    pub fn status(mut self, input: crate::types::ResourceStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The last known status for the analysis.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::ResourceStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The last known status for the analysis.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::ResourceStatus> {
        &self.status
    }
    /// <p>The time that the analysis was created.</p>
    pub fn created_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time that the analysis was created.</p>
    pub fn set_created_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_time = input;
        self
    }
    /// <p>The time that the analysis was created.</p>
    pub fn get_created_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_time
    }
    /// <p>The time that the analysis was last updated.</p>
    pub fn last_updated_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_updated_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time that the analysis was last updated.</p>
    pub fn set_last_updated_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_updated_time = input;
        self
    }
    /// <p>The time that the analysis was last updated.</p>
    pub fn get_last_updated_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_updated_time
    }
    /// Consumes the builder and constructs a [`AnalysisSummary`](crate::types::AnalysisSummary).
    pub fn build(self) -> crate::types::AnalysisSummary {
        crate::types::AnalysisSummary {
            arn: self.arn,
            analysis_id: self.analysis_id,
            name: self.name,
            status: self.status,
            created_time: self.created_time,
            last_updated_time: self.last_updated_time,
        }
    }
}
