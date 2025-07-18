// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetRecommenderConfigurationOutput {
    /// <p>Provides information about Amazon Pinpoint configuration settings for retrieving and processing data from a recommender model.</p>
    pub recommender_configuration_response: ::std::option::Option<crate::types::RecommenderConfigurationResponse>,
    _request_id: Option<String>,
}
impl GetRecommenderConfigurationOutput {
    /// <p>Provides information about Amazon Pinpoint configuration settings for retrieving and processing data from a recommender model.</p>
    pub fn recommender_configuration_response(&self) -> ::std::option::Option<&crate::types::RecommenderConfigurationResponse> {
        self.recommender_configuration_response.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetRecommenderConfigurationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetRecommenderConfigurationOutput {
    /// Creates a new builder-style object to manufacture [`GetRecommenderConfigurationOutput`](crate::operation::get_recommender_configuration::GetRecommenderConfigurationOutput).
    pub fn builder() -> crate::operation::get_recommender_configuration::builders::GetRecommenderConfigurationOutputBuilder {
        crate::operation::get_recommender_configuration::builders::GetRecommenderConfigurationOutputBuilder::default()
    }
}

/// A builder for [`GetRecommenderConfigurationOutput`](crate::operation::get_recommender_configuration::GetRecommenderConfigurationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetRecommenderConfigurationOutputBuilder {
    pub(crate) recommender_configuration_response: ::std::option::Option<crate::types::RecommenderConfigurationResponse>,
    _request_id: Option<String>,
}
impl GetRecommenderConfigurationOutputBuilder {
    /// <p>Provides information about Amazon Pinpoint configuration settings for retrieving and processing data from a recommender model.</p>
    /// This field is required.
    pub fn recommender_configuration_response(mut self, input: crate::types::RecommenderConfigurationResponse) -> Self {
        self.recommender_configuration_response = ::std::option::Option::Some(input);
        self
    }
    /// <p>Provides information about Amazon Pinpoint configuration settings for retrieving and processing data from a recommender model.</p>
    pub fn set_recommender_configuration_response(mut self, input: ::std::option::Option<crate::types::RecommenderConfigurationResponse>) -> Self {
        self.recommender_configuration_response = input;
        self
    }
    /// <p>Provides information about Amazon Pinpoint configuration settings for retrieving and processing data from a recommender model.</p>
    pub fn get_recommender_configuration_response(&self) -> &::std::option::Option<crate::types::RecommenderConfigurationResponse> {
        &self.recommender_configuration_response
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetRecommenderConfigurationOutput`](crate::operation::get_recommender_configuration::GetRecommenderConfigurationOutput).
    pub fn build(self) -> crate::operation::get_recommender_configuration::GetRecommenderConfigurationOutput {
        crate::operation::get_recommender_configuration::GetRecommenderConfigurationOutput {
            recommender_configuration_response: self.recommender_configuration_response,
            _request_id: self._request_id,
        }
    }
}
