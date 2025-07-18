// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateRecommenderConfigurationInput {
    /// <p>The unique identifier for the recommender model configuration. This identifier is displayed as the <b>Recommender ID</b> on the Amazon Pinpoint console.</p>
    pub recommender_id: ::std::option::Option<::std::string::String>,
    /// <p>Specifies Amazon Pinpoint configuration settings for retrieving and processing recommendation data from a recommender model.</p>
    pub update_recommender_configuration: ::std::option::Option<crate::types::UpdateRecommenderConfigurationShape>,
}
impl UpdateRecommenderConfigurationInput {
    /// <p>The unique identifier for the recommender model configuration. This identifier is displayed as the <b>Recommender ID</b> on the Amazon Pinpoint console.</p>
    pub fn recommender_id(&self) -> ::std::option::Option<&str> {
        self.recommender_id.as_deref()
    }
    /// <p>Specifies Amazon Pinpoint configuration settings for retrieving and processing recommendation data from a recommender model.</p>
    pub fn update_recommender_configuration(&self) -> ::std::option::Option<&crate::types::UpdateRecommenderConfigurationShape> {
        self.update_recommender_configuration.as_ref()
    }
}
impl UpdateRecommenderConfigurationInput {
    /// Creates a new builder-style object to manufacture [`UpdateRecommenderConfigurationInput`](crate::operation::update_recommender_configuration::UpdateRecommenderConfigurationInput).
    pub fn builder() -> crate::operation::update_recommender_configuration::builders::UpdateRecommenderConfigurationInputBuilder {
        crate::operation::update_recommender_configuration::builders::UpdateRecommenderConfigurationInputBuilder::default()
    }
}

/// A builder for [`UpdateRecommenderConfigurationInput`](crate::operation::update_recommender_configuration::UpdateRecommenderConfigurationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateRecommenderConfigurationInputBuilder {
    pub(crate) recommender_id: ::std::option::Option<::std::string::String>,
    pub(crate) update_recommender_configuration: ::std::option::Option<crate::types::UpdateRecommenderConfigurationShape>,
}
impl UpdateRecommenderConfigurationInputBuilder {
    /// <p>The unique identifier for the recommender model configuration. This identifier is displayed as the <b>Recommender ID</b> on the Amazon Pinpoint console.</p>
    /// This field is required.
    pub fn recommender_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.recommender_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the recommender model configuration. This identifier is displayed as the <b>Recommender ID</b> on the Amazon Pinpoint console.</p>
    pub fn set_recommender_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.recommender_id = input;
        self
    }
    /// <p>The unique identifier for the recommender model configuration. This identifier is displayed as the <b>Recommender ID</b> on the Amazon Pinpoint console.</p>
    pub fn get_recommender_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.recommender_id
    }
    /// <p>Specifies Amazon Pinpoint configuration settings for retrieving and processing recommendation data from a recommender model.</p>
    /// This field is required.
    pub fn update_recommender_configuration(mut self, input: crate::types::UpdateRecommenderConfigurationShape) -> Self {
        self.update_recommender_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies Amazon Pinpoint configuration settings for retrieving and processing recommendation data from a recommender model.</p>
    pub fn set_update_recommender_configuration(mut self, input: ::std::option::Option<crate::types::UpdateRecommenderConfigurationShape>) -> Self {
        self.update_recommender_configuration = input;
        self
    }
    /// <p>Specifies Amazon Pinpoint configuration settings for retrieving and processing recommendation data from a recommender model.</p>
    pub fn get_update_recommender_configuration(&self) -> &::std::option::Option<crate::types::UpdateRecommenderConfigurationShape> {
        &self.update_recommender_configuration
    }
    /// Consumes the builder and constructs a [`UpdateRecommenderConfigurationInput`](crate::operation::update_recommender_configuration::UpdateRecommenderConfigurationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_recommender_configuration::UpdateRecommenderConfigurationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::update_recommender_configuration::UpdateRecommenderConfigurationInput {
            recommender_id: self.recommender_id,
            update_recommender_configuration: self.update_recommender_configuration,
        })
    }
}
