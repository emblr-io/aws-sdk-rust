// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The recommendation for your DB instances, DB clusters, and DB parameter groups.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DbRecommendation {
    /// <p>The unique identifier of the recommendation.</p>
    pub recommendation_id: ::std::option::Option<::std::string::String>,
    /// <p>A value that indicates the type of recommendation. This value determines how the description is rendered.</p>
    pub type_id: ::std::option::Option<::std::string::String>,
    /// <p>The severity level of the recommendation. The severity level can help you decide the urgency with which to address the recommendation.</p>
    /// <p>Valid values:</p>
    /// <ul>
    /// <li>
    /// <p><code>high</code></p></li>
    /// <li>
    /// <p><code>medium</code></p></li>
    /// <li>
    /// <p><code>low</code></p></li>
    /// <li>
    /// <p><code>informational</code></p></li>
    /// </ul>
    pub severity: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the RDS resource associated with the recommendation.</p>
    pub resource_arn: ::std::option::Option<::std::string::String>,
    /// <p>The current status of the recommendation.</p>
    /// <p>Valid values:</p>
    /// <ul>
    /// <li>
    /// <p><code>active</code> - The recommendations which are ready for you to apply.</p></li>
    /// <li>
    /// <p><code>pending</code> - The applied or scheduled recommendations which are in progress.</p></li>
    /// <li>
    /// <p><code>resolved</code> - The recommendations which are completed.</p></li>
    /// <li>
    /// <p><code>dismissed</code> - The recommendations that you dismissed.</p></li>
    /// </ul>
    pub status: ::std::option::Option<::std::string::String>,
    /// <p>The time when the recommendation was created. For example, <code>2023-09-28T01:13:53.931000+00:00</code>.</p>
    pub created_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The time when the recommendation was last updated.</p>
    pub updated_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>A short description of the issue identified for this recommendation. The description might contain markdown.</p>
    pub detection: ::std::option::Option<::std::string::String>,
    /// <p>A short description of the recommendation to resolve an issue. The description might contain markdown.</p>
    pub recommendation: ::std::option::Option<::std::string::String>,
    /// <p>A detailed description of the recommendation. The description might contain markdown.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The reason why this recommendation was created. The information might contain markdown.</p>
    pub reason: ::std::option::Option<::std::string::String>,
    /// <p>A list of recommended actions.</p>
    pub recommended_actions: ::std::option::Option<::std::vec::Vec<crate::types::RecommendedAction>>,
    /// <p>The category of the recommendation.</p>
    /// <p>Valid values:</p>
    /// <ul>
    /// <li>
    /// <p><code>performance efficiency</code></p></li>
    /// <li>
    /// <p><code>security</code></p></li>
    /// <li>
    /// <p><code>reliability</code></p></li>
    /// <li>
    /// <p><code>cost optimization</code></p></li>
    /// <li>
    /// <p><code>operational excellence</code></p></li>
    /// <li>
    /// <p><code>sustainability</code></p></li>
    /// </ul>
    pub category: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Web Services service that generated the recommendations.</p>
    pub source: ::std::option::Option<::std::string::String>,
    /// <p>A short description of the recommendation type. The description might contain markdown.</p>
    pub type_detection: ::std::option::Option<::std::string::String>,
    /// <p>A short description that summarizes the recommendation to fix all the issues of the recommendation type. The description might contain markdown.</p>
    pub type_recommendation: ::std::option::Option<::std::string::String>,
    /// <p>A short description that explains the possible impact of an issue.</p>
    pub impact: ::std::option::Option<::std::string::String>,
    /// <p>Additional information about the recommendation. The information might contain markdown.</p>
    pub additional_info: ::std::option::Option<::std::string::String>,
    /// <p>A link to documentation that provides additional information about the recommendation.</p>
    pub links: ::std::option::Option<::std::vec::Vec<crate::types::DocLink>>,
    /// <p>Details of the issue that caused the recommendation.</p>
    pub issue_details: ::std::option::Option<crate::types::IssueDetails>,
}
impl DbRecommendation {
    /// <p>The unique identifier of the recommendation.</p>
    pub fn recommendation_id(&self) -> ::std::option::Option<&str> {
        self.recommendation_id.as_deref()
    }
    /// <p>A value that indicates the type of recommendation. This value determines how the description is rendered.</p>
    pub fn type_id(&self) -> ::std::option::Option<&str> {
        self.type_id.as_deref()
    }
    /// <p>The severity level of the recommendation. The severity level can help you decide the urgency with which to address the recommendation.</p>
    /// <p>Valid values:</p>
    /// <ul>
    /// <li>
    /// <p><code>high</code></p></li>
    /// <li>
    /// <p><code>medium</code></p></li>
    /// <li>
    /// <p><code>low</code></p></li>
    /// <li>
    /// <p><code>informational</code></p></li>
    /// </ul>
    pub fn severity(&self) -> ::std::option::Option<&str> {
        self.severity.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the RDS resource associated with the recommendation.</p>
    pub fn resource_arn(&self) -> ::std::option::Option<&str> {
        self.resource_arn.as_deref()
    }
    /// <p>The current status of the recommendation.</p>
    /// <p>Valid values:</p>
    /// <ul>
    /// <li>
    /// <p><code>active</code> - The recommendations which are ready for you to apply.</p></li>
    /// <li>
    /// <p><code>pending</code> - The applied or scheduled recommendations which are in progress.</p></li>
    /// <li>
    /// <p><code>resolved</code> - The recommendations which are completed.</p></li>
    /// <li>
    /// <p><code>dismissed</code> - The recommendations that you dismissed.</p></li>
    /// </ul>
    pub fn status(&self) -> ::std::option::Option<&str> {
        self.status.as_deref()
    }
    /// <p>The time when the recommendation was created. For example, <code>2023-09-28T01:13:53.931000+00:00</code>.</p>
    pub fn created_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_time.as_ref()
    }
    /// <p>The time when the recommendation was last updated.</p>
    pub fn updated_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.updated_time.as_ref()
    }
    /// <p>A short description of the issue identified for this recommendation. The description might contain markdown.</p>
    pub fn detection(&self) -> ::std::option::Option<&str> {
        self.detection.as_deref()
    }
    /// <p>A short description of the recommendation to resolve an issue. The description might contain markdown.</p>
    pub fn recommendation(&self) -> ::std::option::Option<&str> {
        self.recommendation.as_deref()
    }
    /// <p>A detailed description of the recommendation. The description might contain markdown.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The reason why this recommendation was created. The information might contain markdown.</p>
    pub fn reason(&self) -> ::std::option::Option<&str> {
        self.reason.as_deref()
    }
    /// <p>A list of recommended actions.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.recommended_actions.is_none()`.
    pub fn recommended_actions(&self) -> &[crate::types::RecommendedAction] {
        self.recommended_actions.as_deref().unwrap_or_default()
    }
    /// <p>The category of the recommendation.</p>
    /// <p>Valid values:</p>
    /// <ul>
    /// <li>
    /// <p><code>performance efficiency</code></p></li>
    /// <li>
    /// <p><code>security</code></p></li>
    /// <li>
    /// <p><code>reliability</code></p></li>
    /// <li>
    /// <p><code>cost optimization</code></p></li>
    /// <li>
    /// <p><code>operational excellence</code></p></li>
    /// <li>
    /// <p><code>sustainability</code></p></li>
    /// </ul>
    pub fn category(&self) -> ::std::option::Option<&str> {
        self.category.as_deref()
    }
    /// <p>The Amazon Web Services service that generated the recommendations.</p>
    pub fn source(&self) -> ::std::option::Option<&str> {
        self.source.as_deref()
    }
    /// <p>A short description of the recommendation type. The description might contain markdown.</p>
    pub fn type_detection(&self) -> ::std::option::Option<&str> {
        self.type_detection.as_deref()
    }
    /// <p>A short description that summarizes the recommendation to fix all the issues of the recommendation type. The description might contain markdown.</p>
    pub fn type_recommendation(&self) -> ::std::option::Option<&str> {
        self.type_recommendation.as_deref()
    }
    /// <p>A short description that explains the possible impact of an issue.</p>
    pub fn impact(&self) -> ::std::option::Option<&str> {
        self.impact.as_deref()
    }
    /// <p>Additional information about the recommendation. The information might contain markdown.</p>
    pub fn additional_info(&self) -> ::std::option::Option<&str> {
        self.additional_info.as_deref()
    }
    /// <p>A link to documentation that provides additional information about the recommendation.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.links.is_none()`.
    pub fn links(&self) -> &[crate::types::DocLink] {
        self.links.as_deref().unwrap_or_default()
    }
    /// <p>Details of the issue that caused the recommendation.</p>
    pub fn issue_details(&self) -> ::std::option::Option<&crate::types::IssueDetails> {
        self.issue_details.as_ref()
    }
}
impl DbRecommendation {
    /// Creates a new builder-style object to manufacture [`DbRecommendation`](crate::types::DbRecommendation).
    pub fn builder() -> crate::types::builders::DbRecommendationBuilder {
        crate::types::builders::DbRecommendationBuilder::default()
    }
}

/// A builder for [`DbRecommendation`](crate::types::DbRecommendation).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DbRecommendationBuilder {
    pub(crate) recommendation_id: ::std::option::Option<::std::string::String>,
    pub(crate) type_id: ::std::option::Option<::std::string::String>,
    pub(crate) severity: ::std::option::Option<::std::string::String>,
    pub(crate) resource_arn: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<::std::string::String>,
    pub(crate) created_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) updated_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) detection: ::std::option::Option<::std::string::String>,
    pub(crate) recommendation: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) reason: ::std::option::Option<::std::string::String>,
    pub(crate) recommended_actions: ::std::option::Option<::std::vec::Vec<crate::types::RecommendedAction>>,
    pub(crate) category: ::std::option::Option<::std::string::String>,
    pub(crate) source: ::std::option::Option<::std::string::String>,
    pub(crate) type_detection: ::std::option::Option<::std::string::String>,
    pub(crate) type_recommendation: ::std::option::Option<::std::string::String>,
    pub(crate) impact: ::std::option::Option<::std::string::String>,
    pub(crate) additional_info: ::std::option::Option<::std::string::String>,
    pub(crate) links: ::std::option::Option<::std::vec::Vec<crate::types::DocLink>>,
    pub(crate) issue_details: ::std::option::Option<crate::types::IssueDetails>,
}
impl DbRecommendationBuilder {
    /// <p>The unique identifier of the recommendation.</p>
    pub fn recommendation_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.recommendation_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the recommendation.</p>
    pub fn set_recommendation_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.recommendation_id = input;
        self
    }
    /// <p>The unique identifier of the recommendation.</p>
    pub fn get_recommendation_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.recommendation_id
    }
    /// <p>A value that indicates the type of recommendation. This value determines how the description is rendered.</p>
    pub fn type_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.type_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A value that indicates the type of recommendation. This value determines how the description is rendered.</p>
    pub fn set_type_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.type_id = input;
        self
    }
    /// <p>A value that indicates the type of recommendation. This value determines how the description is rendered.</p>
    pub fn get_type_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.type_id
    }
    /// <p>The severity level of the recommendation. The severity level can help you decide the urgency with which to address the recommendation.</p>
    /// <p>Valid values:</p>
    /// <ul>
    /// <li>
    /// <p><code>high</code></p></li>
    /// <li>
    /// <p><code>medium</code></p></li>
    /// <li>
    /// <p><code>low</code></p></li>
    /// <li>
    /// <p><code>informational</code></p></li>
    /// </ul>
    pub fn severity(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.severity = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The severity level of the recommendation. The severity level can help you decide the urgency with which to address the recommendation.</p>
    /// <p>Valid values:</p>
    /// <ul>
    /// <li>
    /// <p><code>high</code></p></li>
    /// <li>
    /// <p><code>medium</code></p></li>
    /// <li>
    /// <p><code>low</code></p></li>
    /// <li>
    /// <p><code>informational</code></p></li>
    /// </ul>
    pub fn set_severity(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.severity = input;
        self
    }
    /// <p>The severity level of the recommendation. The severity level can help you decide the urgency with which to address the recommendation.</p>
    /// <p>Valid values:</p>
    /// <ul>
    /// <li>
    /// <p><code>high</code></p></li>
    /// <li>
    /// <p><code>medium</code></p></li>
    /// <li>
    /// <p><code>low</code></p></li>
    /// <li>
    /// <p><code>informational</code></p></li>
    /// </ul>
    pub fn get_severity(&self) -> &::std::option::Option<::std::string::String> {
        &self.severity
    }
    /// <p>The Amazon Resource Name (ARN) of the RDS resource associated with the recommendation.</p>
    pub fn resource_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the RDS resource associated with the recommendation.</p>
    pub fn set_resource_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the RDS resource associated with the recommendation.</p>
    pub fn get_resource_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_arn
    }
    /// <p>The current status of the recommendation.</p>
    /// <p>Valid values:</p>
    /// <ul>
    /// <li>
    /// <p><code>active</code> - The recommendations which are ready for you to apply.</p></li>
    /// <li>
    /// <p><code>pending</code> - The applied or scheduled recommendations which are in progress.</p></li>
    /// <li>
    /// <p><code>resolved</code> - The recommendations which are completed.</p></li>
    /// <li>
    /// <p><code>dismissed</code> - The recommendations that you dismissed.</p></li>
    /// </ul>
    pub fn status(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The current status of the recommendation.</p>
    /// <p>Valid values:</p>
    /// <ul>
    /// <li>
    /// <p><code>active</code> - The recommendations which are ready for you to apply.</p></li>
    /// <li>
    /// <p><code>pending</code> - The applied or scheduled recommendations which are in progress.</p></li>
    /// <li>
    /// <p><code>resolved</code> - The recommendations which are completed.</p></li>
    /// <li>
    /// <p><code>dismissed</code> - The recommendations that you dismissed.</p></li>
    /// </ul>
    pub fn set_status(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status = input;
        self
    }
    /// <p>The current status of the recommendation.</p>
    /// <p>Valid values:</p>
    /// <ul>
    /// <li>
    /// <p><code>active</code> - The recommendations which are ready for you to apply.</p></li>
    /// <li>
    /// <p><code>pending</code> - The applied or scheduled recommendations which are in progress.</p></li>
    /// <li>
    /// <p><code>resolved</code> - The recommendations which are completed.</p></li>
    /// <li>
    /// <p><code>dismissed</code> - The recommendations that you dismissed.</p></li>
    /// </ul>
    pub fn get_status(&self) -> &::std::option::Option<::std::string::String> {
        &self.status
    }
    /// <p>The time when the recommendation was created. For example, <code>2023-09-28T01:13:53.931000+00:00</code>.</p>
    pub fn created_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time when the recommendation was created. For example, <code>2023-09-28T01:13:53.931000+00:00</code>.</p>
    pub fn set_created_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_time = input;
        self
    }
    /// <p>The time when the recommendation was created. For example, <code>2023-09-28T01:13:53.931000+00:00</code>.</p>
    pub fn get_created_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_time
    }
    /// <p>The time when the recommendation was last updated.</p>
    pub fn updated_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.updated_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time when the recommendation was last updated.</p>
    pub fn set_updated_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.updated_time = input;
        self
    }
    /// <p>The time when the recommendation was last updated.</p>
    pub fn get_updated_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.updated_time
    }
    /// <p>A short description of the issue identified for this recommendation. The description might contain markdown.</p>
    pub fn detection(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.detection = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A short description of the issue identified for this recommendation. The description might contain markdown.</p>
    pub fn set_detection(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.detection = input;
        self
    }
    /// <p>A short description of the issue identified for this recommendation. The description might contain markdown.</p>
    pub fn get_detection(&self) -> &::std::option::Option<::std::string::String> {
        &self.detection
    }
    /// <p>A short description of the recommendation to resolve an issue. The description might contain markdown.</p>
    pub fn recommendation(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.recommendation = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A short description of the recommendation to resolve an issue. The description might contain markdown.</p>
    pub fn set_recommendation(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.recommendation = input;
        self
    }
    /// <p>A short description of the recommendation to resolve an issue. The description might contain markdown.</p>
    pub fn get_recommendation(&self) -> &::std::option::Option<::std::string::String> {
        &self.recommendation
    }
    /// <p>A detailed description of the recommendation. The description might contain markdown.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A detailed description of the recommendation. The description might contain markdown.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A detailed description of the recommendation. The description might contain markdown.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The reason why this recommendation was created. The information might contain markdown.</p>
    pub fn reason(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.reason = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The reason why this recommendation was created. The information might contain markdown.</p>
    pub fn set_reason(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.reason = input;
        self
    }
    /// <p>The reason why this recommendation was created. The information might contain markdown.</p>
    pub fn get_reason(&self) -> &::std::option::Option<::std::string::String> {
        &self.reason
    }
    /// Appends an item to `recommended_actions`.
    ///
    /// To override the contents of this collection use [`set_recommended_actions`](Self::set_recommended_actions).
    ///
    /// <p>A list of recommended actions.</p>
    pub fn recommended_actions(mut self, input: crate::types::RecommendedAction) -> Self {
        let mut v = self.recommended_actions.unwrap_or_default();
        v.push(input);
        self.recommended_actions = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of recommended actions.</p>
    pub fn set_recommended_actions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::RecommendedAction>>) -> Self {
        self.recommended_actions = input;
        self
    }
    /// <p>A list of recommended actions.</p>
    pub fn get_recommended_actions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::RecommendedAction>> {
        &self.recommended_actions
    }
    /// <p>The category of the recommendation.</p>
    /// <p>Valid values:</p>
    /// <ul>
    /// <li>
    /// <p><code>performance efficiency</code></p></li>
    /// <li>
    /// <p><code>security</code></p></li>
    /// <li>
    /// <p><code>reliability</code></p></li>
    /// <li>
    /// <p><code>cost optimization</code></p></li>
    /// <li>
    /// <p><code>operational excellence</code></p></li>
    /// <li>
    /// <p><code>sustainability</code></p></li>
    /// </ul>
    pub fn category(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.category = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The category of the recommendation.</p>
    /// <p>Valid values:</p>
    /// <ul>
    /// <li>
    /// <p><code>performance efficiency</code></p></li>
    /// <li>
    /// <p><code>security</code></p></li>
    /// <li>
    /// <p><code>reliability</code></p></li>
    /// <li>
    /// <p><code>cost optimization</code></p></li>
    /// <li>
    /// <p><code>operational excellence</code></p></li>
    /// <li>
    /// <p><code>sustainability</code></p></li>
    /// </ul>
    pub fn set_category(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.category = input;
        self
    }
    /// <p>The category of the recommendation.</p>
    /// <p>Valid values:</p>
    /// <ul>
    /// <li>
    /// <p><code>performance efficiency</code></p></li>
    /// <li>
    /// <p><code>security</code></p></li>
    /// <li>
    /// <p><code>reliability</code></p></li>
    /// <li>
    /// <p><code>cost optimization</code></p></li>
    /// <li>
    /// <p><code>operational excellence</code></p></li>
    /// <li>
    /// <p><code>sustainability</code></p></li>
    /// </ul>
    pub fn get_category(&self) -> &::std::option::Option<::std::string::String> {
        &self.category
    }
    /// <p>The Amazon Web Services service that generated the recommendations.</p>
    pub fn source(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services service that generated the recommendations.</p>
    pub fn set_source(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source = input;
        self
    }
    /// <p>The Amazon Web Services service that generated the recommendations.</p>
    pub fn get_source(&self) -> &::std::option::Option<::std::string::String> {
        &self.source
    }
    /// <p>A short description of the recommendation type. The description might contain markdown.</p>
    pub fn type_detection(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.type_detection = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A short description of the recommendation type. The description might contain markdown.</p>
    pub fn set_type_detection(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.type_detection = input;
        self
    }
    /// <p>A short description of the recommendation type. The description might contain markdown.</p>
    pub fn get_type_detection(&self) -> &::std::option::Option<::std::string::String> {
        &self.type_detection
    }
    /// <p>A short description that summarizes the recommendation to fix all the issues of the recommendation type. The description might contain markdown.</p>
    pub fn type_recommendation(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.type_recommendation = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A short description that summarizes the recommendation to fix all the issues of the recommendation type. The description might contain markdown.</p>
    pub fn set_type_recommendation(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.type_recommendation = input;
        self
    }
    /// <p>A short description that summarizes the recommendation to fix all the issues of the recommendation type. The description might contain markdown.</p>
    pub fn get_type_recommendation(&self) -> &::std::option::Option<::std::string::String> {
        &self.type_recommendation
    }
    /// <p>A short description that explains the possible impact of an issue.</p>
    pub fn impact(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.impact = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A short description that explains the possible impact of an issue.</p>
    pub fn set_impact(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.impact = input;
        self
    }
    /// <p>A short description that explains the possible impact of an issue.</p>
    pub fn get_impact(&self) -> &::std::option::Option<::std::string::String> {
        &self.impact
    }
    /// <p>Additional information about the recommendation. The information might contain markdown.</p>
    pub fn additional_info(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.additional_info = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Additional information about the recommendation. The information might contain markdown.</p>
    pub fn set_additional_info(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.additional_info = input;
        self
    }
    /// <p>Additional information about the recommendation. The information might contain markdown.</p>
    pub fn get_additional_info(&self) -> &::std::option::Option<::std::string::String> {
        &self.additional_info
    }
    /// Appends an item to `links`.
    ///
    /// To override the contents of this collection use [`set_links`](Self::set_links).
    ///
    /// <p>A link to documentation that provides additional information about the recommendation.</p>
    pub fn links(mut self, input: crate::types::DocLink) -> Self {
        let mut v = self.links.unwrap_or_default();
        v.push(input);
        self.links = ::std::option::Option::Some(v);
        self
    }
    /// <p>A link to documentation that provides additional information about the recommendation.</p>
    pub fn set_links(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DocLink>>) -> Self {
        self.links = input;
        self
    }
    /// <p>A link to documentation that provides additional information about the recommendation.</p>
    pub fn get_links(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DocLink>> {
        &self.links
    }
    /// <p>Details of the issue that caused the recommendation.</p>
    pub fn issue_details(mut self, input: crate::types::IssueDetails) -> Self {
        self.issue_details = ::std::option::Option::Some(input);
        self
    }
    /// <p>Details of the issue that caused the recommendation.</p>
    pub fn set_issue_details(mut self, input: ::std::option::Option<crate::types::IssueDetails>) -> Self {
        self.issue_details = input;
        self
    }
    /// <p>Details of the issue that caused the recommendation.</p>
    pub fn get_issue_details(&self) -> &::std::option::Option<crate::types::IssueDetails> {
        &self.issue_details
    }
    /// Consumes the builder and constructs a [`DbRecommendation`](crate::types::DbRecommendation).
    pub fn build(self) -> crate::types::DbRecommendation {
        crate::types::DbRecommendation {
            recommendation_id: self.recommendation_id,
            type_id: self.type_id,
            severity: self.severity,
            resource_arn: self.resource_arn,
            status: self.status,
            created_time: self.created_time,
            updated_time: self.updated_time,
            detection: self.detection,
            recommendation: self.recommendation,
            description: self.description,
            reason: self.reason,
            recommended_actions: self.recommended_actions,
            category: self.category,
            source: self.source,
            type_detection: self.type_detection,
            type_recommendation: self.type_recommendation,
            impact: self.impact,
            additional_info: self.additional_info,
            links: self.links,
            issue_details: self.issue_details,
        }
    }
}
