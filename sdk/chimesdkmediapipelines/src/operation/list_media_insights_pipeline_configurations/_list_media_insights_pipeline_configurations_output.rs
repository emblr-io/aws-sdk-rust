// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListMediaInsightsPipelineConfigurationsOutput {
    /// <p>The requested list of media insights pipeline configurations.</p>
    pub media_insights_pipeline_configurations: ::std::option::Option<::std::vec::Vec<crate::types::MediaInsightsPipelineConfigurationSummary>>,
    /// <p>The token used to return the next page of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListMediaInsightsPipelineConfigurationsOutput {
    /// <p>The requested list of media insights pipeline configurations.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.media_insights_pipeline_configurations.is_none()`.
    pub fn media_insights_pipeline_configurations(&self) -> &[crate::types::MediaInsightsPipelineConfigurationSummary] {
        self.media_insights_pipeline_configurations.as_deref().unwrap_or_default()
    }
    /// <p>The token used to return the next page of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListMediaInsightsPipelineConfigurationsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListMediaInsightsPipelineConfigurationsOutput {
    /// Creates a new builder-style object to manufacture [`ListMediaInsightsPipelineConfigurationsOutput`](crate::operation::list_media_insights_pipeline_configurations::ListMediaInsightsPipelineConfigurationsOutput).
    pub fn builder() -> crate::operation::list_media_insights_pipeline_configurations::builders::ListMediaInsightsPipelineConfigurationsOutputBuilder
    {
        crate::operation::list_media_insights_pipeline_configurations::builders::ListMediaInsightsPipelineConfigurationsOutputBuilder::default()
    }
}

/// A builder for [`ListMediaInsightsPipelineConfigurationsOutput`](crate::operation::list_media_insights_pipeline_configurations::ListMediaInsightsPipelineConfigurationsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListMediaInsightsPipelineConfigurationsOutputBuilder {
    pub(crate) media_insights_pipeline_configurations:
        ::std::option::Option<::std::vec::Vec<crate::types::MediaInsightsPipelineConfigurationSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListMediaInsightsPipelineConfigurationsOutputBuilder {
    /// Appends an item to `media_insights_pipeline_configurations`.
    ///
    /// To override the contents of this collection use [`set_media_insights_pipeline_configurations`](Self::set_media_insights_pipeline_configurations).
    ///
    /// <p>The requested list of media insights pipeline configurations.</p>
    pub fn media_insights_pipeline_configurations(mut self, input: crate::types::MediaInsightsPipelineConfigurationSummary) -> Self {
        let mut v = self.media_insights_pipeline_configurations.unwrap_or_default();
        v.push(input);
        self.media_insights_pipeline_configurations = ::std::option::Option::Some(v);
        self
    }
    /// <p>The requested list of media insights pipeline configurations.</p>
    pub fn set_media_insights_pipeline_configurations(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::MediaInsightsPipelineConfigurationSummary>>,
    ) -> Self {
        self.media_insights_pipeline_configurations = input;
        self
    }
    /// <p>The requested list of media insights pipeline configurations.</p>
    pub fn get_media_insights_pipeline_configurations(
        &self,
    ) -> &::std::option::Option<::std::vec::Vec<crate::types::MediaInsightsPipelineConfigurationSummary>> {
        &self.media_insights_pipeline_configurations
    }
    /// <p>The token used to return the next page of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token used to return the next page of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token used to return the next page of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListMediaInsightsPipelineConfigurationsOutput`](crate::operation::list_media_insights_pipeline_configurations::ListMediaInsightsPipelineConfigurationsOutput).
    pub fn build(self) -> crate::operation::list_media_insights_pipeline_configurations::ListMediaInsightsPipelineConfigurationsOutput {
        crate::operation::list_media_insights_pipeline_configurations::ListMediaInsightsPipelineConfigurationsOutput {
            media_insights_pipeline_configurations: self.media_insights_pipeline_configurations,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
