// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details about the content data.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ContentDataDetails {
    /// <p>Details about the content text data.</p>
    pub text_data: ::std::option::Option<crate::types::TextData>,
    /// <p>Details about the content ranking data.</p>
    pub ranking_data: ::std::option::Option<crate::types::RankingData>,
}
impl ContentDataDetails {
    /// <p>Details about the content text data.</p>
    pub fn text_data(&self) -> ::std::option::Option<&crate::types::TextData> {
        self.text_data.as_ref()
    }
    /// <p>Details about the content ranking data.</p>
    pub fn ranking_data(&self) -> ::std::option::Option<&crate::types::RankingData> {
        self.ranking_data.as_ref()
    }
}
impl ContentDataDetails {
    /// Creates a new builder-style object to manufacture [`ContentDataDetails`](crate::types::ContentDataDetails).
    pub fn builder() -> crate::types::builders::ContentDataDetailsBuilder {
        crate::types::builders::ContentDataDetailsBuilder::default()
    }
}

/// A builder for [`ContentDataDetails`](crate::types::ContentDataDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ContentDataDetailsBuilder {
    pub(crate) text_data: ::std::option::Option<crate::types::TextData>,
    pub(crate) ranking_data: ::std::option::Option<crate::types::RankingData>,
}
impl ContentDataDetailsBuilder {
    /// <p>Details about the content text data.</p>
    /// This field is required.
    pub fn text_data(mut self, input: crate::types::TextData) -> Self {
        self.text_data = ::std::option::Option::Some(input);
        self
    }
    /// <p>Details about the content text data.</p>
    pub fn set_text_data(mut self, input: ::std::option::Option<crate::types::TextData>) -> Self {
        self.text_data = input;
        self
    }
    /// <p>Details about the content text data.</p>
    pub fn get_text_data(&self) -> &::std::option::Option<crate::types::TextData> {
        &self.text_data
    }
    /// <p>Details about the content ranking data.</p>
    /// This field is required.
    pub fn ranking_data(mut self, input: crate::types::RankingData) -> Self {
        self.ranking_data = ::std::option::Option::Some(input);
        self
    }
    /// <p>Details about the content ranking data.</p>
    pub fn set_ranking_data(mut self, input: ::std::option::Option<crate::types::RankingData>) -> Self {
        self.ranking_data = input;
        self
    }
    /// <p>Details about the content ranking data.</p>
    pub fn get_ranking_data(&self) -> &::std::option::Option<crate::types::RankingData> {
        &self.ranking_data
    }
    /// Consumes the builder and constructs a [`ContentDataDetails`](crate::types::ContentDataDetails).
    pub fn build(self) -> crate::types::ContentDataDetails {
        crate::types::ContentDataDetails {
            text_data: self.text_data,
            ranking_data: self.ranking_data,
        }
    }
}
