// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies Amazon Pinpoint configuration settings for retrieving and processing recommendation data from a recommender model.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateRecommenderConfigurationShape {
    /// <p>A map of key-value pairs that defines 1-10 custom endpoint or user attributes, depending on the value for the RecommendationProviderIdType property. Each of these attributes temporarily stores a recommended item that's retrieved from the recommender model and sent to an AWS Lambda function for additional processing. Each attribute can be used as a message variable in a message template.</p>
    /// <p>In the map, the key is the name of a custom attribute and the value is a custom display name for that attribute. The display name appears in the <b>Attribute finder</b> of the template editor on the Amazon Pinpoint console. The following restrictions apply to these names:</p>
    /// <ul>
    /// <li>
    /// <p>An attribute name must start with a letter or number and it can contain up to 50 characters. The characters can be letters, numbers, underscores (_), or hyphens (-). Attribute names are case sensitive and must be unique.</p></li>
    /// <li>
    /// <p>An attribute display name must start with a letter or number and it can contain up to 25 characters. The characters can be letters, numbers, spaces, underscores (_), or hyphens (-).</p></li>
    /// </ul>
    /// <p>This object is required if the configuration invokes an AWS Lambda function (RecommendationTransformerUri) to process recommendation data. Otherwise, don't include this object in your request.</p>
    pub attributes: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>A custom description of the configuration for the recommender model. The description can contain up to 128 characters. The characters can be letters, numbers, spaces, or the following symbols: _ ; () , ‐.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>A custom name of the configuration for the recommender model. The name must start with a letter or number and it can contain up to 128 characters. The characters can be letters, numbers, spaces, underscores (_), or hyphens (-).</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The type of Amazon Pinpoint ID to associate with unique user IDs in the recommender model. This value enables the model to use attribute and event data that’s specific to a particular endpoint or user in an Amazon Pinpoint application. Valid values are:</p>
    /// <ul>
    /// <li>
    /// <p>PINPOINT_ENDPOINT_ID - Associate each user in the model with a particular endpoint in Amazon Pinpoint. The data is correlated based on endpoint IDs in Amazon Pinpoint. This is the default value.</p></li>
    /// <li>
    /// <p>PINPOINT_USER_ID - Associate each user in the model with a particular user and endpoint in Amazon Pinpoint. The data is correlated based on user IDs in Amazon Pinpoint. If you specify this value, an endpoint definition in Amazon Pinpoint has to specify both a user ID (UserId) and an endpoint ID. Otherwise, messages won’t be sent to the user's endpoint.</p></li>
    /// </ul>
    pub recommendation_provider_id_type: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the AWS Identity and Access Management (IAM) role that authorizes Amazon Pinpoint to retrieve recommendation data from the recommender model.</p>
    pub recommendation_provider_role_arn: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the recommender model to retrieve recommendation data from. This value must match the ARN of an Amazon Personalize campaign.</p>
    pub recommendation_provider_uri: ::std::option::Option<::std::string::String>,
    /// <p>The name or Amazon Resource Name (ARN) of the AWS Lambda function to invoke for additional processing of recommendation data that's retrieved from the recommender model.</p>
    pub recommendation_transformer_uri: ::std::option::Option<::std::string::String>,
    /// <p>A custom display name for the standard endpoint or user attribute (RecommendationItems) that temporarily stores recommended items for each endpoint or user, depending on the value for the RecommendationProviderIdType property. This value is required if the configuration doesn't invoke an AWS Lambda function (RecommendationTransformerUri) to perform additional processing of recommendation data.</p>
    /// <p>This name appears in the <b>Attribute finder</b> of the template editor on the Amazon Pinpoint console. The name can contain up to 25 characters. The characters can be letters, numbers, spaces, underscores (_), or hyphens (-). These restrictions don't apply to attribute values.</p>
    pub recommendations_display_name: ::std::option::Option<::std::string::String>,
    /// <p>The number of recommended items to retrieve from the model for each endpoint or user, depending on the value for the RecommendationProviderIdType property. This number determines how many recommended items are available for use in message variables. The minimum value is 1. The maximum value is 5. The default value is 5.</p>
    /// <p>To use multiple recommended items and custom attributes with message variables, you have to use an AWS Lambda function (RecommendationTransformerUri) to perform additional processing of recommendation data.</p>
    pub recommendations_per_message: ::std::option::Option<i32>,
}
impl UpdateRecommenderConfigurationShape {
    /// <p>A map of key-value pairs that defines 1-10 custom endpoint or user attributes, depending on the value for the RecommendationProviderIdType property. Each of these attributes temporarily stores a recommended item that's retrieved from the recommender model and sent to an AWS Lambda function for additional processing. Each attribute can be used as a message variable in a message template.</p>
    /// <p>In the map, the key is the name of a custom attribute and the value is a custom display name for that attribute. The display name appears in the <b>Attribute finder</b> of the template editor on the Amazon Pinpoint console. The following restrictions apply to these names:</p>
    /// <ul>
    /// <li>
    /// <p>An attribute name must start with a letter or number and it can contain up to 50 characters. The characters can be letters, numbers, underscores (_), or hyphens (-). Attribute names are case sensitive and must be unique.</p></li>
    /// <li>
    /// <p>An attribute display name must start with a letter or number and it can contain up to 25 characters. The characters can be letters, numbers, spaces, underscores (_), or hyphens (-).</p></li>
    /// </ul>
    /// <p>This object is required if the configuration invokes an AWS Lambda function (RecommendationTransformerUri) to process recommendation data. Otherwise, don't include this object in your request.</p>
    pub fn attributes(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.attributes.as_ref()
    }
    /// <p>A custom description of the configuration for the recommender model. The description can contain up to 128 characters. The characters can be letters, numbers, spaces, or the following symbols: _ ; () , ‐.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>A custom name of the configuration for the recommender model. The name must start with a letter or number and it can contain up to 128 characters. The characters can be letters, numbers, spaces, underscores (_), or hyphens (-).</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The type of Amazon Pinpoint ID to associate with unique user IDs in the recommender model. This value enables the model to use attribute and event data that’s specific to a particular endpoint or user in an Amazon Pinpoint application. Valid values are:</p>
    /// <ul>
    /// <li>
    /// <p>PINPOINT_ENDPOINT_ID - Associate each user in the model with a particular endpoint in Amazon Pinpoint. The data is correlated based on endpoint IDs in Amazon Pinpoint. This is the default value.</p></li>
    /// <li>
    /// <p>PINPOINT_USER_ID - Associate each user in the model with a particular user and endpoint in Amazon Pinpoint. The data is correlated based on user IDs in Amazon Pinpoint. If you specify this value, an endpoint definition in Amazon Pinpoint has to specify both a user ID (UserId) and an endpoint ID. Otherwise, messages won’t be sent to the user's endpoint.</p></li>
    /// </ul>
    pub fn recommendation_provider_id_type(&self) -> ::std::option::Option<&str> {
        self.recommendation_provider_id_type.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the AWS Identity and Access Management (IAM) role that authorizes Amazon Pinpoint to retrieve recommendation data from the recommender model.</p>
    pub fn recommendation_provider_role_arn(&self) -> ::std::option::Option<&str> {
        self.recommendation_provider_role_arn.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the recommender model to retrieve recommendation data from. This value must match the ARN of an Amazon Personalize campaign.</p>
    pub fn recommendation_provider_uri(&self) -> ::std::option::Option<&str> {
        self.recommendation_provider_uri.as_deref()
    }
    /// <p>The name or Amazon Resource Name (ARN) of the AWS Lambda function to invoke for additional processing of recommendation data that's retrieved from the recommender model.</p>
    pub fn recommendation_transformer_uri(&self) -> ::std::option::Option<&str> {
        self.recommendation_transformer_uri.as_deref()
    }
    /// <p>A custom display name for the standard endpoint or user attribute (RecommendationItems) that temporarily stores recommended items for each endpoint or user, depending on the value for the RecommendationProviderIdType property. This value is required if the configuration doesn't invoke an AWS Lambda function (RecommendationTransformerUri) to perform additional processing of recommendation data.</p>
    /// <p>This name appears in the <b>Attribute finder</b> of the template editor on the Amazon Pinpoint console. The name can contain up to 25 characters. The characters can be letters, numbers, spaces, underscores (_), or hyphens (-). These restrictions don't apply to attribute values.</p>
    pub fn recommendations_display_name(&self) -> ::std::option::Option<&str> {
        self.recommendations_display_name.as_deref()
    }
    /// <p>The number of recommended items to retrieve from the model for each endpoint or user, depending on the value for the RecommendationProviderIdType property. This number determines how many recommended items are available for use in message variables. The minimum value is 1. The maximum value is 5. The default value is 5.</p>
    /// <p>To use multiple recommended items and custom attributes with message variables, you have to use an AWS Lambda function (RecommendationTransformerUri) to perform additional processing of recommendation data.</p>
    pub fn recommendations_per_message(&self) -> ::std::option::Option<i32> {
        self.recommendations_per_message
    }
}
impl UpdateRecommenderConfigurationShape {
    /// Creates a new builder-style object to manufacture [`UpdateRecommenderConfigurationShape`](crate::types::UpdateRecommenderConfigurationShape).
    pub fn builder() -> crate::types::builders::UpdateRecommenderConfigurationShapeBuilder {
        crate::types::builders::UpdateRecommenderConfigurationShapeBuilder::default()
    }
}

/// A builder for [`UpdateRecommenderConfigurationShape`](crate::types::UpdateRecommenderConfigurationShape).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateRecommenderConfigurationShapeBuilder {
    pub(crate) attributes: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) recommendation_provider_id_type: ::std::option::Option<::std::string::String>,
    pub(crate) recommendation_provider_role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) recommendation_provider_uri: ::std::option::Option<::std::string::String>,
    pub(crate) recommendation_transformer_uri: ::std::option::Option<::std::string::String>,
    pub(crate) recommendations_display_name: ::std::option::Option<::std::string::String>,
    pub(crate) recommendations_per_message: ::std::option::Option<i32>,
}
impl UpdateRecommenderConfigurationShapeBuilder {
    /// Adds a key-value pair to `attributes`.
    ///
    /// To override the contents of this collection use [`set_attributes`](Self::set_attributes).
    ///
    /// <p>A map of key-value pairs that defines 1-10 custom endpoint or user attributes, depending on the value for the RecommendationProviderIdType property. Each of these attributes temporarily stores a recommended item that's retrieved from the recommender model and sent to an AWS Lambda function for additional processing. Each attribute can be used as a message variable in a message template.</p>
    /// <p>In the map, the key is the name of a custom attribute and the value is a custom display name for that attribute. The display name appears in the <b>Attribute finder</b> of the template editor on the Amazon Pinpoint console. The following restrictions apply to these names:</p>
    /// <ul>
    /// <li>
    /// <p>An attribute name must start with a letter or number and it can contain up to 50 characters. The characters can be letters, numbers, underscores (_), or hyphens (-). Attribute names are case sensitive and must be unique.</p></li>
    /// <li>
    /// <p>An attribute display name must start with a letter or number and it can contain up to 25 characters. The characters can be letters, numbers, spaces, underscores (_), or hyphens (-).</p></li>
    /// </ul>
    /// <p>This object is required if the configuration invokes an AWS Lambda function (RecommendationTransformerUri) to process recommendation data. Otherwise, don't include this object in your request.</p>
    pub fn attributes(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.attributes.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.attributes = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A map of key-value pairs that defines 1-10 custom endpoint or user attributes, depending on the value for the RecommendationProviderIdType property. Each of these attributes temporarily stores a recommended item that's retrieved from the recommender model and sent to an AWS Lambda function for additional processing. Each attribute can be used as a message variable in a message template.</p>
    /// <p>In the map, the key is the name of a custom attribute and the value is a custom display name for that attribute. The display name appears in the <b>Attribute finder</b> of the template editor on the Amazon Pinpoint console. The following restrictions apply to these names:</p>
    /// <ul>
    /// <li>
    /// <p>An attribute name must start with a letter or number and it can contain up to 50 characters. The characters can be letters, numbers, underscores (_), or hyphens (-). Attribute names are case sensitive and must be unique.</p></li>
    /// <li>
    /// <p>An attribute display name must start with a letter or number and it can contain up to 25 characters. The characters can be letters, numbers, spaces, underscores (_), or hyphens (-).</p></li>
    /// </ul>
    /// <p>This object is required if the configuration invokes an AWS Lambda function (RecommendationTransformerUri) to process recommendation data. Otherwise, don't include this object in your request.</p>
    pub fn set_attributes(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.attributes = input;
        self
    }
    /// <p>A map of key-value pairs that defines 1-10 custom endpoint or user attributes, depending on the value for the RecommendationProviderIdType property. Each of these attributes temporarily stores a recommended item that's retrieved from the recommender model and sent to an AWS Lambda function for additional processing. Each attribute can be used as a message variable in a message template.</p>
    /// <p>In the map, the key is the name of a custom attribute and the value is a custom display name for that attribute. The display name appears in the <b>Attribute finder</b> of the template editor on the Amazon Pinpoint console. The following restrictions apply to these names:</p>
    /// <ul>
    /// <li>
    /// <p>An attribute name must start with a letter or number and it can contain up to 50 characters. The characters can be letters, numbers, underscores (_), or hyphens (-). Attribute names are case sensitive and must be unique.</p></li>
    /// <li>
    /// <p>An attribute display name must start with a letter or number and it can contain up to 25 characters. The characters can be letters, numbers, spaces, underscores (_), or hyphens (-).</p></li>
    /// </ul>
    /// <p>This object is required if the configuration invokes an AWS Lambda function (RecommendationTransformerUri) to process recommendation data. Otherwise, don't include this object in your request.</p>
    pub fn get_attributes(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.attributes
    }
    /// <p>A custom description of the configuration for the recommender model. The description can contain up to 128 characters. The characters can be letters, numbers, spaces, or the following symbols: _ ; () , ‐.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A custom description of the configuration for the recommender model. The description can contain up to 128 characters. The characters can be letters, numbers, spaces, or the following symbols: _ ; () , ‐.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A custom description of the configuration for the recommender model. The description can contain up to 128 characters. The characters can be letters, numbers, spaces, or the following symbols: _ ; () , ‐.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>A custom name of the configuration for the recommender model. The name must start with a letter or number and it can contain up to 128 characters. The characters can be letters, numbers, spaces, underscores (_), or hyphens (-).</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A custom name of the configuration for the recommender model. The name must start with a letter or number and it can contain up to 128 characters. The characters can be letters, numbers, spaces, underscores (_), or hyphens (-).</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>A custom name of the configuration for the recommender model. The name must start with a letter or number and it can contain up to 128 characters. The characters can be letters, numbers, spaces, underscores (_), or hyphens (-).</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The type of Amazon Pinpoint ID to associate with unique user IDs in the recommender model. This value enables the model to use attribute and event data that’s specific to a particular endpoint or user in an Amazon Pinpoint application. Valid values are:</p>
    /// <ul>
    /// <li>
    /// <p>PINPOINT_ENDPOINT_ID - Associate each user in the model with a particular endpoint in Amazon Pinpoint. The data is correlated based on endpoint IDs in Amazon Pinpoint. This is the default value.</p></li>
    /// <li>
    /// <p>PINPOINT_USER_ID - Associate each user in the model with a particular user and endpoint in Amazon Pinpoint. The data is correlated based on user IDs in Amazon Pinpoint. If you specify this value, an endpoint definition in Amazon Pinpoint has to specify both a user ID (UserId) and an endpoint ID. Otherwise, messages won’t be sent to the user's endpoint.</p></li>
    /// </ul>
    pub fn recommendation_provider_id_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.recommendation_provider_id_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The type of Amazon Pinpoint ID to associate with unique user IDs in the recommender model. This value enables the model to use attribute and event data that’s specific to a particular endpoint or user in an Amazon Pinpoint application. Valid values are:</p>
    /// <ul>
    /// <li>
    /// <p>PINPOINT_ENDPOINT_ID - Associate each user in the model with a particular endpoint in Amazon Pinpoint. The data is correlated based on endpoint IDs in Amazon Pinpoint. This is the default value.</p></li>
    /// <li>
    /// <p>PINPOINT_USER_ID - Associate each user in the model with a particular user and endpoint in Amazon Pinpoint. The data is correlated based on user IDs in Amazon Pinpoint. If you specify this value, an endpoint definition in Amazon Pinpoint has to specify both a user ID (UserId) and an endpoint ID. Otherwise, messages won’t be sent to the user's endpoint.</p></li>
    /// </ul>
    pub fn set_recommendation_provider_id_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.recommendation_provider_id_type = input;
        self
    }
    /// <p>The type of Amazon Pinpoint ID to associate with unique user IDs in the recommender model. This value enables the model to use attribute and event data that’s specific to a particular endpoint or user in an Amazon Pinpoint application. Valid values are:</p>
    /// <ul>
    /// <li>
    /// <p>PINPOINT_ENDPOINT_ID - Associate each user in the model with a particular endpoint in Amazon Pinpoint. The data is correlated based on endpoint IDs in Amazon Pinpoint. This is the default value.</p></li>
    /// <li>
    /// <p>PINPOINT_USER_ID - Associate each user in the model with a particular user and endpoint in Amazon Pinpoint. The data is correlated based on user IDs in Amazon Pinpoint. If you specify this value, an endpoint definition in Amazon Pinpoint has to specify both a user ID (UserId) and an endpoint ID. Otherwise, messages won’t be sent to the user's endpoint.</p></li>
    /// </ul>
    pub fn get_recommendation_provider_id_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.recommendation_provider_id_type
    }
    /// <p>The Amazon Resource Name (ARN) of the AWS Identity and Access Management (IAM) role that authorizes Amazon Pinpoint to retrieve recommendation data from the recommender model.</p>
    /// This field is required.
    pub fn recommendation_provider_role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.recommendation_provider_role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the AWS Identity and Access Management (IAM) role that authorizes Amazon Pinpoint to retrieve recommendation data from the recommender model.</p>
    pub fn set_recommendation_provider_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.recommendation_provider_role_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the AWS Identity and Access Management (IAM) role that authorizes Amazon Pinpoint to retrieve recommendation data from the recommender model.</p>
    pub fn get_recommendation_provider_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.recommendation_provider_role_arn
    }
    /// <p>The Amazon Resource Name (ARN) of the recommender model to retrieve recommendation data from. This value must match the ARN of an Amazon Personalize campaign.</p>
    /// This field is required.
    pub fn recommendation_provider_uri(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.recommendation_provider_uri = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the recommender model to retrieve recommendation data from. This value must match the ARN of an Amazon Personalize campaign.</p>
    pub fn set_recommendation_provider_uri(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.recommendation_provider_uri = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the recommender model to retrieve recommendation data from. This value must match the ARN of an Amazon Personalize campaign.</p>
    pub fn get_recommendation_provider_uri(&self) -> &::std::option::Option<::std::string::String> {
        &self.recommendation_provider_uri
    }
    /// <p>The name or Amazon Resource Name (ARN) of the AWS Lambda function to invoke for additional processing of recommendation data that's retrieved from the recommender model.</p>
    pub fn recommendation_transformer_uri(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.recommendation_transformer_uri = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name or Amazon Resource Name (ARN) of the AWS Lambda function to invoke for additional processing of recommendation data that's retrieved from the recommender model.</p>
    pub fn set_recommendation_transformer_uri(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.recommendation_transformer_uri = input;
        self
    }
    /// <p>The name or Amazon Resource Name (ARN) of the AWS Lambda function to invoke for additional processing of recommendation data that's retrieved from the recommender model.</p>
    pub fn get_recommendation_transformer_uri(&self) -> &::std::option::Option<::std::string::String> {
        &self.recommendation_transformer_uri
    }
    /// <p>A custom display name for the standard endpoint or user attribute (RecommendationItems) that temporarily stores recommended items for each endpoint or user, depending on the value for the RecommendationProviderIdType property. This value is required if the configuration doesn't invoke an AWS Lambda function (RecommendationTransformerUri) to perform additional processing of recommendation data.</p>
    /// <p>This name appears in the <b>Attribute finder</b> of the template editor on the Amazon Pinpoint console. The name can contain up to 25 characters. The characters can be letters, numbers, spaces, underscores (_), or hyphens (-). These restrictions don't apply to attribute values.</p>
    pub fn recommendations_display_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.recommendations_display_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A custom display name for the standard endpoint or user attribute (RecommendationItems) that temporarily stores recommended items for each endpoint or user, depending on the value for the RecommendationProviderIdType property. This value is required if the configuration doesn't invoke an AWS Lambda function (RecommendationTransformerUri) to perform additional processing of recommendation data.</p>
    /// <p>This name appears in the <b>Attribute finder</b> of the template editor on the Amazon Pinpoint console. The name can contain up to 25 characters. The characters can be letters, numbers, spaces, underscores (_), or hyphens (-). These restrictions don't apply to attribute values.</p>
    pub fn set_recommendations_display_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.recommendations_display_name = input;
        self
    }
    /// <p>A custom display name for the standard endpoint or user attribute (RecommendationItems) that temporarily stores recommended items for each endpoint or user, depending on the value for the RecommendationProviderIdType property. This value is required if the configuration doesn't invoke an AWS Lambda function (RecommendationTransformerUri) to perform additional processing of recommendation data.</p>
    /// <p>This name appears in the <b>Attribute finder</b> of the template editor on the Amazon Pinpoint console. The name can contain up to 25 characters. The characters can be letters, numbers, spaces, underscores (_), or hyphens (-). These restrictions don't apply to attribute values.</p>
    pub fn get_recommendations_display_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.recommendations_display_name
    }
    /// <p>The number of recommended items to retrieve from the model for each endpoint or user, depending on the value for the RecommendationProviderIdType property. This number determines how many recommended items are available for use in message variables. The minimum value is 1. The maximum value is 5. The default value is 5.</p>
    /// <p>To use multiple recommended items and custom attributes with message variables, you have to use an AWS Lambda function (RecommendationTransformerUri) to perform additional processing of recommendation data.</p>
    pub fn recommendations_per_message(mut self, input: i32) -> Self {
        self.recommendations_per_message = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of recommended items to retrieve from the model for each endpoint or user, depending on the value for the RecommendationProviderIdType property. This number determines how many recommended items are available for use in message variables. The minimum value is 1. The maximum value is 5. The default value is 5.</p>
    /// <p>To use multiple recommended items and custom attributes with message variables, you have to use an AWS Lambda function (RecommendationTransformerUri) to perform additional processing of recommendation data.</p>
    pub fn set_recommendations_per_message(mut self, input: ::std::option::Option<i32>) -> Self {
        self.recommendations_per_message = input;
        self
    }
    /// <p>The number of recommended items to retrieve from the model for each endpoint or user, depending on the value for the RecommendationProviderIdType property. This number determines how many recommended items are available for use in message variables. The minimum value is 1. The maximum value is 5. The default value is 5.</p>
    /// <p>To use multiple recommended items and custom attributes with message variables, you have to use an AWS Lambda function (RecommendationTransformerUri) to perform additional processing of recommendation data.</p>
    pub fn get_recommendations_per_message(&self) -> &::std::option::Option<i32> {
        &self.recommendations_per_message
    }
    /// Consumes the builder and constructs a [`UpdateRecommenderConfigurationShape`](crate::types::UpdateRecommenderConfigurationShape).
    pub fn build(self) -> crate::types::UpdateRecommenderConfigurationShape {
        crate::types::UpdateRecommenderConfigurationShape {
            attributes: self.attributes,
            description: self.description,
            name: self.name,
            recommendation_provider_id_type: self.recommendation_provider_id_type,
            recommendation_provider_role_arn: self.recommendation_provider_role_arn,
            recommendation_provider_uri: self.recommendation_provider_uri,
            recommendation_transformer_uri: self.recommendation_transformer_uri,
            recommendations_display_name: self.recommendations_display_name,
            recommendations_per_message: self.recommendations_per_message,
        }
    }
}
