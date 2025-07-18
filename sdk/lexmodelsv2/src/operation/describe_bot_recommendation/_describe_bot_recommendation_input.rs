// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeBotRecommendationInput {
    /// <p>The unique identifier of the bot associated with the bot recommendation.</p>
    pub bot_id: ::std::option::Option<::std::string::String>,
    /// <p>The version of the bot associated with the bot recommendation.</p>
    pub bot_version: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the language and locale of the bot recommendation to describe. The string must match one of the supported locales. For more information, see <a href="https://docs.aws.amazon.com/lexv2/latest/dg/how-languages.html">Supported languages</a>.</p>
    pub locale_id: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the bot recommendation to describe.</p>
    pub bot_recommendation_id: ::std::option::Option<::std::string::String>,
}
impl DescribeBotRecommendationInput {
    /// <p>The unique identifier of the bot associated with the bot recommendation.</p>
    pub fn bot_id(&self) -> ::std::option::Option<&str> {
        self.bot_id.as_deref()
    }
    /// <p>The version of the bot associated with the bot recommendation.</p>
    pub fn bot_version(&self) -> ::std::option::Option<&str> {
        self.bot_version.as_deref()
    }
    /// <p>The identifier of the language and locale of the bot recommendation to describe. The string must match one of the supported locales. For more information, see <a href="https://docs.aws.amazon.com/lexv2/latest/dg/how-languages.html">Supported languages</a>.</p>
    pub fn locale_id(&self) -> ::std::option::Option<&str> {
        self.locale_id.as_deref()
    }
    /// <p>The identifier of the bot recommendation to describe.</p>
    pub fn bot_recommendation_id(&self) -> ::std::option::Option<&str> {
        self.bot_recommendation_id.as_deref()
    }
}
impl DescribeBotRecommendationInput {
    /// Creates a new builder-style object to manufacture [`DescribeBotRecommendationInput`](crate::operation::describe_bot_recommendation::DescribeBotRecommendationInput).
    pub fn builder() -> crate::operation::describe_bot_recommendation::builders::DescribeBotRecommendationInputBuilder {
        crate::operation::describe_bot_recommendation::builders::DescribeBotRecommendationInputBuilder::default()
    }
}

/// A builder for [`DescribeBotRecommendationInput`](crate::operation::describe_bot_recommendation::DescribeBotRecommendationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeBotRecommendationInputBuilder {
    pub(crate) bot_id: ::std::option::Option<::std::string::String>,
    pub(crate) bot_version: ::std::option::Option<::std::string::String>,
    pub(crate) locale_id: ::std::option::Option<::std::string::String>,
    pub(crate) bot_recommendation_id: ::std::option::Option<::std::string::String>,
}
impl DescribeBotRecommendationInputBuilder {
    /// <p>The unique identifier of the bot associated with the bot recommendation.</p>
    /// This field is required.
    pub fn bot_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bot_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the bot associated with the bot recommendation.</p>
    pub fn set_bot_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bot_id = input;
        self
    }
    /// <p>The unique identifier of the bot associated with the bot recommendation.</p>
    pub fn get_bot_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.bot_id
    }
    /// <p>The version of the bot associated with the bot recommendation.</p>
    /// This field is required.
    pub fn bot_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bot_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version of the bot associated with the bot recommendation.</p>
    pub fn set_bot_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bot_version = input;
        self
    }
    /// <p>The version of the bot associated with the bot recommendation.</p>
    pub fn get_bot_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.bot_version
    }
    /// <p>The identifier of the language and locale of the bot recommendation to describe. The string must match one of the supported locales. For more information, see <a href="https://docs.aws.amazon.com/lexv2/latest/dg/how-languages.html">Supported languages</a>.</p>
    /// This field is required.
    pub fn locale_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.locale_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the language and locale of the bot recommendation to describe. The string must match one of the supported locales. For more information, see <a href="https://docs.aws.amazon.com/lexv2/latest/dg/how-languages.html">Supported languages</a>.</p>
    pub fn set_locale_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.locale_id = input;
        self
    }
    /// <p>The identifier of the language and locale of the bot recommendation to describe. The string must match one of the supported locales. For more information, see <a href="https://docs.aws.amazon.com/lexv2/latest/dg/how-languages.html">Supported languages</a>.</p>
    pub fn get_locale_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.locale_id
    }
    /// <p>The identifier of the bot recommendation to describe.</p>
    /// This field is required.
    pub fn bot_recommendation_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bot_recommendation_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the bot recommendation to describe.</p>
    pub fn set_bot_recommendation_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bot_recommendation_id = input;
        self
    }
    /// <p>The identifier of the bot recommendation to describe.</p>
    pub fn get_bot_recommendation_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.bot_recommendation_id
    }
    /// Consumes the builder and constructs a [`DescribeBotRecommendationInput`](crate::operation::describe_bot_recommendation::DescribeBotRecommendationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_bot_recommendation::DescribeBotRecommendationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::describe_bot_recommendation::DescribeBotRecommendationInput {
            bot_id: self.bot_id,
            bot_version: self.bot_version,
            locale_id: self.locale_id,
            bot_recommendation_id: self.bot_recommendation_id,
        })
    }
}
