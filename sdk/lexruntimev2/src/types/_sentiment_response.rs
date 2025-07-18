// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides information about the sentiment expressed in a user's response in a conversation. Sentiments are determined using Amazon Comprehend. Sentiments are only returned if they are enabled for the bot.</p>
/// <p>For more information, see <a href="https://docs.aws.amazon.com/comprehend/latest/dg/how-sentiment.html"> Determine Sentiment </a> in the <i>Amazon Comprehend developer guide</i>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SentimentResponse {
    /// <p>The overall sentiment expressed in the user's response. This is the sentiment most likely expressed by the user based on the analysis by Amazon Comprehend.</p>
    pub sentiment: ::std::option::Option<crate::types::SentimentType>,
    /// <p>The individual sentiment responses for the utterance.</p>
    pub sentiment_score: ::std::option::Option<crate::types::SentimentScore>,
}
impl SentimentResponse {
    /// <p>The overall sentiment expressed in the user's response. This is the sentiment most likely expressed by the user based on the analysis by Amazon Comprehend.</p>
    pub fn sentiment(&self) -> ::std::option::Option<&crate::types::SentimentType> {
        self.sentiment.as_ref()
    }
    /// <p>The individual sentiment responses for the utterance.</p>
    pub fn sentiment_score(&self) -> ::std::option::Option<&crate::types::SentimentScore> {
        self.sentiment_score.as_ref()
    }
}
impl SentimentResponse {
    /// Creates a new builder-style object to manufacture [`SentimentResponse`](crate::types::SentimentResponse).
    pub fn builder() -> crate::types::builders::SentimentResponseBuilder {
        crate::types::builders::SentimentResponseBuilder::default()
    }
}

/// A builder for [`SentimentResponse`](crate::types::SentimentResponse).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SentimentResponseBuilder {
    pub(crate) sentiment: ::std::option::Option<crate::types::SentimentType>,
    pub(crate) sentiment_score: ::std::option::Option<crate::types::SentimentScore>,
}
impl SentimentResponseBuilder {
    /// <p>The overall sentiment expressed in the user's response. This is the sentiment most likely expressed by the user based on the analysis by Amazon Comprehend.</p>
    pub fn sentiment(mut self, input: crate::types::SentimentType) -> Self {
        self.sentiment = ::std::option::Option::Some(input);
        self
    }
    /// <p>The overall sentiment expressed in the user's response. This is the sentiment most likely expressed by the user based on the analysis by Amazon Comprehend.</p>
    pub fn set_sentiment(mut self, input: ::std::option::Option<crate::types::SentimentType>) -> Self {
        self.sentiment = input;
        self
    }
    /// <p>The overall sentiment expressed in the user's response. This is the sentiment most likely expressed by the user based on the analysis by Amazon Comprehend.</p>
    pub fn get_sentiment(&self) -> &::std::option::Option<crate::types::SentimentType> {
        &self.sentiment
    }
    /// <p>The individual sentiment responses for the utterance.</p>
    pub fn sentiment_score(mut self, input: crate::types::SentimentScore) -> Self {
        self.sentiment_score = ::std::option::Option::Some(input);
        self
    }
    /// <p>The individual sentiment responses for the utterance.</p>
    pub fn set_sentiment_score(mut self, input: ::std::option::Option<crate::types::SentimentScore>) -> Self {
        self.sentiment_score = input;
        self
    }
    /// <p>The individual sentiment responses for the utterance.</p>
    pub fn get_sentiment_score(&self) -> &::std::option::Option<crate::types::SentimentScore> {
        &self.sentiment_score
    }
    /// Consumes the builder and constructs a [`SentimentResponse`](crate::types::SentimentResponse).
    pub fn build(self) -> crate::types::SentimentResponse {
        crate::types::SentimentResponse {
            sentiment: self.sentiment,
            sentiment_score: self.sentiment_score,
        }
    }
}
