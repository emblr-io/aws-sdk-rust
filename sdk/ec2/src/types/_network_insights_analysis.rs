// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes a network insights analysis.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct NetworkInsightsAnalysis {
    /// <p>The ID of the network insights analysis.</p>
    pub network_insights_analysis_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the network insights analysis.</p>
    pub network_insights_analysis_arn: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the path.</p>
    pub network_insights_path_id: ::std::option::Option<::std::string::String>,
    /// <p>The member accounts that contain resources that the path can traverse.</p>
    pub additional_accounts: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The Amazon Resource Names (ARN) of the resources that the path must traverse.</p>
    pub filter_in_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The Amazon Resource Names (ARN) of the resources that the path must ignore.</p>
    pub filter_out_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The time the analysis started.</p>
    pub start_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The status of the network insights analysis.</p>
    pub status: ::std::option::Option<crate::types::AnalysisStatus>,
    /// <p>The status message, if the status is <code>failed</code>.</p>
    pub status_message: ::std::option::Option<::std::string::String>,
    /// <p>The warning message.</p>
    pub warning_message: ::std::option::Option<::std::string::String>,
    /// <p>Indicates whether the destination is reachable from the source.</p>
    pub network_path_found: ::std::option::Option<bool>,
    /// <p>The components in the path from source to destination.</p>
    pub forward_path_components: ::std::option::Option<::std::vec::Vec<crate::types::PathComponent>>,
    /// <p>The components in the path from destination to source.</p>
    pub return_path_components: ::std::option::Option<::std::vec::Vec<crate::types::PathComponent>>,
    /// <p>The explanations. For more information, see <a href="https://docs.aws.amazon.com/vpc/latest/reachability/explanation-codes.html">Reachability Analyzer explanation codes</a>.</p>
    pub explanations: ::std::option::Option<::std::vec::Vec<crate::types::Explanation>>,
    /// <p>Potential intermediate components.</p>
    pub alternate_path_hints: ::std::option::Option<::std::vec::Vec<crate::types::AlternatePathHint>>,
    /// <p>Potential intermediate accounts.</p>
    pub suggested_accounts: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The tags.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl NetworkInsightsAnalysis {
    /// <p>The ID of the network insights analysis.</p>
    pub fn network_insights_analysis_id(&self) -> ::std::option::Option<&str> {
        self.network_insights_analysis_id.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the network insights analysis.</p>
    pub fn network_insights_analysis_arn(&self) -> ::std::option::Option<&str> {
        self.network_insights_analysis_arn.as_deref()
    }
    /// <p>The ID of the path.</p>
    pub fn network_insights_path_id(&self) -> ::std::option::Option<&str> {
        self.network_insights_path_id.as_deref()
    }
    /// <p>The member accounts that contain resources that the path can traverse.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.additional_accounts.is_none()`.
    pub fn additional_accounts(&self) -> &[::std::string::String] {
        self.additional_accounts.as_deref().unwrap_or_default()
    }
    /// <p>The Amazon Resource Names (ARN) of the resources that the path must traverse.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.filter_in_arns.is_none()`.
    pub fn filter_in_arns(&self) -> &[::std::string::String] {
        self.filter_in_arns.as_deref().unwrap_or_default()
    }
    /// <p>The Amazon Resource Names (ARN) of the resources that the path must ignore.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.filter_out_arns.is_none()`.
    pub fn filter_out_arns(&self) -> &[::std::string::String] {
        self.filter_out_arns.as_deref().unwrap_or_default()
    }
    /// <p>The time the analysis started.</p>
    pub fn start_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.start_date.as_ref()
    }
    /// <p>The status of the network insights analysis.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::AnalysisStatus> {
        self.status.as_ref()
    }
    /// <p>The status message, if the status is <code>failed</code>.</p>
    pub fn status_message(&self) -> ::std::option::Option<&str> {
        self.status_message.as_deref()
    }
    /// <p>The warning message.</p>
    pub fn warning_message(&self) -> ::std::option::Option<&str> {
        self.warning_message.as_deref()
    }
    /// <p>Indicates whether the destination is reachable from the source.</p>
    pub fn network_path_found(&self) -> ::std::option::Option<bool> {
        self.network_path_found
    }
    /// <p>The components in the path from source to destination.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.forward_path_components.is_none()`.
    pub fn forward_path_components(&self) -> &[crate::types::PathComponent] {
        self.forward_path_components.as_deref().unwrap_or_default()
    }
    /// <p>The components in the path from destination to source.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.return_path_components.is_none()`.
    pub fn return_path_components(&self) -> &[crate::types::PathComponent] {
        self.return_path_components.as_deref().unwrap_or_default()
    }
    /// <p>The explanations. For more information, see <a href="https://docs.aws.amazon.com/vpc/latest/reachability/explanation-codes.html">Reachability Analyzer explanation codes</a>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.explanations.is_none()`.
    pub fn explanations(&self) -> &[crate::types::Explanation] {
        self.explanations.as_deref().unwrap_or_default()
    }
    /// <p>Potential intermediate components.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.alternate_path_hints.is_none()`.
    pub fn alternate_path_hints(&self) -> &[crate::types::AlternatePathHint] {
        self.alternate_path_hints.as_deref().unwrap_or_default()
    }
    /// <p>Potential intermediate accounts.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.suggested_accounts.is_none()`.
    pub fn suggested_accounts(&self) -> &[::std::string::String] {
        self.suggested_accounts.as_deref().unwrap_or_default()
    }
    /// <p>The tags.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl NetworkInsightsAnalysis {
    /// Creates a new builder-style object to manufacture [`NetworkInsightsAnalysis`](crate::types::NetworkInsightsAnalysis).
    pub fn builder() -> crate::types::builders::NetworkInsightsAnalysisBuilder {
        crate::types::builders::NetworkInsightsAnalysisBuilder::default()
    }
}

/// A builder for [`NetworkInsightsAnalysis`](crate::types::NetworkInsightsAnalysis).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct NetworkInsightsAnalysisBuilder {
    pub(crate) network_insights_analysis_id: ::std::option::Option<::std::string::String>,
    pub(crate) network_insights_analysis_arn: ::std::option::Option<::std::string::String>,
    pub(crate) network_insights_path_id: ::std::option::Option<::std::string::String>,
    pub(crate) additional_accounts: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) filter_in_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) filter_out_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) start_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) status: ::std::option::Option<crate::types::AnalysisStatus>,
    pub(crate) status_message: ::std::option::Option<::std::string::String>,
    pub(crate) warning_message: ::std::option::Option<::std::string::String>,
    pub(crate) network_path_found: ::std::option::Option<bool>,
    pub(crate) forward_path_components: ::std::option::Option<::std::vec::Vec<crate::types::PathComponent>>,
    pub(crate) return_path_components: ::std::option::Option<::std::vec::Vec<crate::types::PathComponent>>,
    pub(crate) explanations: ::std::option::Option<::std::vec::Vec<crate::types::Explanation>>,
    pub(crate) alternate_path_hints: ::std::option::Option<::std::vec::Vec<crate::types::AlternatePathHint>>,
    pub(crate) suggested_accounts: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl NetworkInsightsAnalysisBuilder {
    /// <p>The ID of the network insights analysis.</p>
    pub fn network_insights_analysis_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.network_insights_analysis_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the network insights analysis.</p>
    pub fn set_network_insights_analysis_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.network_insights_analysis_id = input;
        self
    }
    /// <p>The ID of the network insights analysis.</p>
    pub fn get_network_insights_analysis_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.network_insights_analysis_id
    }
    /// <p>The Amazon Resource Name (ARN) of the network insights analysis.</p>
    pub fn network_insights_analysis_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.network_insights_analysis_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the network insights analysis.</p>
    pub fn set_network_insights_analysis_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.network_insights_analysis_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the network insights analysis.</p>
    pub fn get_network_insights_analysis_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.network_insights_analysis_arn
    }
    /// <p>The ID of the path.</p>
    pub fn network_insights_path_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.network_insights_path_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the path.</p>
    pub fn set_network_insights_path_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.network_insights_path_id = input;
        self
    }
    /// <p>The ID of the path.</p>
    pub fn get_network_insights_path_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.network_insights_path_id
    }
    /// Appends an item to `additional_accounts`.
    ///
    /// To override the contents of this collection use [`set_additional_accounts`](Self::set_additional_accounts).
    ///
    /// <p>The member accounts that contain resources that the path can traverse.</p>
    pub fn additional_accounts(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.additional_accounts.unwrap_or_default();
        v.push(input.into());
        self.additional_accounts = ::std::option::Option::Some(v);
        self
    }
    /// <p>The member accounts that contain resources that the path can traverse.</p>
    pub fn set_additional_accounts(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.additional_accounts = input;
        self
    }
    /// <p>The member accounts that contain resources that the path can traverse.</p>
    pub fn get_additional_accounts(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.additional_accounts
    }
    /// Appends an item to `filter_in_arns`.
    ///
    /// To override the contents of this collection use [`set_filter_in_arns`](Self::set_filter_in_arns).
    ///
    /// <p>The Amazon Resource Names (ARN) of the resources that the path must traverse.</p>
    pub fn filter_in_arns(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.filter_in_arns.unwrap_or_default();
        v.push(input.into());
        self.filter_in_arns = ::std::option::Option::Some(v);
        self
    }
    /// <p>The Amazon Resource Names (ARN) of the resources that the path must traverse.</p>
    pub fn set_filter_in_arns(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.filter_in_arns = input;
        self
    }
    /// <p>The Amazon Resource Names (ARN) of the resources that the path must traverse.</p>
    pub fn get_filter_in_arns(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.filter_in_arns
    }
    /// Appends an item to `filter_out_arns`.
    ///
    /// To override the contents of this collection use [`set_filter_out_arns`](Self::set_filter_out_arns).
    ///
    /// <p>The Amazon Resource Names (ARN) of the resources that the path must ignore.</p>
    pub fn filter_out_arns(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.filter_out_arns.unwrap_or_default();
        v.push(input.into());
        self.filter_out_arns = ::std::option::Option::Some(v);
        self
    }
    /// <p>The Amazon Resource Names (ARN) of the resources that the path must ignore.</p>
    pub fn set_filter_out_arns(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.filter_out_arns = input;
        self
    }
    /// <p>The Amazon Resource Names (ARN) of the resources that the path must ignore.</p>
    pub fn get_filter_out_arns(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.filter_out_arns
    }
    /// <p>The time the analysis started.</p>
    pub fn start_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.start_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time the analysis started.</p>
    pub fn set_start_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.start_date = input;
        self
    }
    /// <p>The time the analysis started.</p>
    pub fn get_start_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.start_date
    }
    /// <p>The status of the network insights analysis.</p>
    pub fn status(mut self, input: crate::types::AnalysisStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the network insights analysis.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::AnalysisStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the network insights analysis.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::AnalysisStatus> {
        &self.status
    }
    /// <p>The status message, if the status is <code>failed</code>.</p>
    pub fn status_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The status message, if the status is <code>failed</code>.</p>
    pub fn set_status_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status_message = input;
        self
    }
    /// <p>The status message, if the status is <code>failed</code>.</p>
    pub fn get_status_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.status_message
    }
    /// <p>The warning message.</p>
    pub fn warning_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.warning_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The warning message.</p>
    pub fn set_warning_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.warning_message = input;
        self
    }
    /// <p>The warning message.</p>
    pub fn get_warning_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.warning_message
    }
    /// <p>Indicates whether the destination is reachable from the source.</p>
    pub fn network_path_found(mut self, input: bool) -> Self {
        self.network_path_found = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether the destination is reachable from the source.</p>
    pub fn set_network_path_found(mut self, input: ::std::option::Option<bool>) -> Self {
        self.network_path_found = input;
        self
    }
    /// <p>Indicates whether the destination is reachable from the source.</p>
    pub fn get_network_path_found(&self) -> &::std::option::Option<bool> {
        &self.network_path_found
    }
    /// Appends an item to `forward_path_components`.
    ///
    /// To override the contents of this collection use [`set_forward_path_components`](Self::set_forward_path_components).
    ///
    /// <p>The components in the path from source to destination.</p>
    pub fn forward_path_components(mut self, input: crate::types::PathComponent) -> Self {
        let mut v = self.forward_path_components.unwrap_or_default();
        v.push(input);
        self.forward_path_components = ::std::option::Option::Some(v);
        self
    }
    /// <p>The components in the path from source to destination.</p>
    pub fn set_forward_path_components(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::PathComponent>>) -> Self {
        self.forward_path_components = input;
        self
    }
    /// <p>The components in the path from source to destination.</p>
    pub fn get_forward_path_components(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::PathComponent>> {
        &self.forward_path_components
    }
    /// Appends an item to `return_path_components`.
    ///
    /// To override the contents of this collection use [`set_return_path_components`](Self::set_return_path_components).
    ///
    /// <p>The components in the path from destination to source.</p>
    pub fn return_path_components(mut self, input: crate::types::PathComponent) -> Self {
        let mut v = self.return_path_components.unwrap_or_default();
        v.push(input);
        self.return_path_components = ::std::option::Option::Some(v);
        self
    }
    /// <p>The components in the path from destination to source.</p>
    pub fn set_return_path_components(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::PathComponent>>) -> Self {
        self.return_path_components = input;
        self
    }
    /// <p>The components in the path from destination to source.</p>
    pub fn get_return_path_components(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::PathComponent>> {
        &self.return_path_components
    }
    /// Appends an item to `explanations`.
    ///
    /// To override the contents of this collection use [`set_explanations`](Self::set_explanations).
    ///
    /// <p>The explanations. For more information, see <a href="https://docs.aws.amazon.com/vpc/latest/reachability/explanation-codes.html">Reachability Analyzer explanation codes</a>.</p>
    pub fn explanations(mut self, input: crate::types::Explanation) -> Self {
        let mut v = self.explanations.unwrap_or_default();
        v.push(input);
        self.explanations = ::std::option::Option::Some(v);
        self
    }
    /// <p>The explanations. For more information, see <a href="https://docs.aws.amazon.com/vpc/latest/reachability/explanation-codes.html">Reachability Analyzer explanation codes</a>.</p>
    pub fn set_explanations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Explanation>>) -> Self {
        self.explanations = input;
        self
    }
    /// <p>The explanations. For more information, see <a href="https://docs.aws.amazon.com/vpc/latest/reachability/explanation-codes.html">Reachability Analyzer explanation codes</a>.</p>
    pub fn get_explanations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Explanation>> {
        &self.explanations
    }
    /// Appends an item to `alternate_path_hints`.
    ///
    /// To override the contents of this collection use [`set_alternate_path_hints`](Self::set_alternate_path_hints).
    ///
    /// <p>Potential intermediate components.</p>
    pub fn alternate_path_hints(mut self, input: crate::types::AlternatePathHint) -> Self {
        let mut v = self.alternate_path_hints.unwrap_or_default();
        v.push(input);
        self.alternate_path_hints = ::std::option::Option::Some(v);
        self
    }
    /// <p>Potential intermediate components.</p>
    pub fn set_alternate_path_hints(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AlternatePathHint>>) -> Self {
        self.alternate_path_hints = input;
        self
    }
    /// <p>Potential intermediate components.</p>
    pub fn get_alternate_path_hints(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AlternatePathHint>> {
        &self.alternate_path_hints
    }
    /// Appends an item to `suggested_accounts`.
    ///
    /// To override the contents of this collection use [`set_suggested_accounts`](Self::set_suggested_accounts).
    ///
    /// <p>Potential intermediate accounts.</p>
    pub fn suggested_accounts(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.suggested_accounts.unwrap_or_default();
        v.push(input.into());
        self.suggested_accounts = ::std::option::Option::Some(v);
        self
    }
    /// <p>Potential intermediate accounts.</p>
    pub fn set_suggested_accounts(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.suggested_accounts = input;
        self
    }
    /// <p>Potential intermediate accounts.</p>
    pub fn get_suggested_accounts(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.suggested_accounts
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>The tags.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`NetworkInsightsAnalysis`](crate::types::NetworkInsightsAnalysis).
    pub fn build(self) -> crate::types::NetworkInsightsAnalysis {
        crate::types::NetworkInsightsAnalysis {
            network_insights_analysis_id: self.network_insights_analysis_id,
            network_insights_analysis_arn: self.network_insights_analysis_arn,
            network_insights_path_id: self.network_insights_path_id,
            additional_accounts: self.additional_accounts,
            filter_in_arns: self.filter_in_arns,
            filter_out_arns: self.filter_out_arns,
            start_date: self.start_date,
            status: self.status,
            status_message: self.status_message,
            warning_message: self.warning_message,
            network_path_found: self.network_path_found,
            forward_path_components: self.forward_path_components,
            return_path_components: self.return_path_components,
            explanations: self.explanations,
            alternate_path_hints: self.alternate_path_hints,
            suggested_accounts: self.suggested_accounts,
            tags: self.tags,
        }
    }
}
