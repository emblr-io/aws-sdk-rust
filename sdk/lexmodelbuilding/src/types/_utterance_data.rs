// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides information about a single utterance that was made to your bot.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UtteranceData {
    /// <p>The text that was entered by the user or the text representation of an audio clip.</p>
    pub utterance_string: ::std::option::Option<::std::string::String>,
    /// <p>The number of times that the utterance was processed.</p>
    pub count: ::std::option::Option<i32>,
    /// <p>The total number of individuals that used the utterance.</p>
    pub distinct_users: ::std::option::Option<i32>,
    /// <p>The date that the utterance was first recorded.</p>
    pub first_uttered_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The date that the utterance was last recorded.</p>
    pub last_uttered_date: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl UtteranceData {
    /// <p>The text that was entered by the user or the text representation of an audio clip.</p>
    pub fn utterance_string(&self) -> ::std::option::Option<&str> {
        self.utterance_string.as_deref()
    }
    /// <p>The number of times that the utterance was processed.</p>
    pub fn count(&self) -> ::std::option::Option<i32> {
        self.count
    }
    /// <p>The total number of individuals that used the utterance.</p>
    pub fn distinct_users(&self) -> ::std::option::Option<i32> {
        self.distinct_users
    }
    /// <p>The date that the utterance was first recorded.</p>
    pub fn first_uttered_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.first_uttered_date.as_ref()
    }
    /// <p>The date that the utterance was last recorded.</p>
    pub fn last_uttered_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_uttered_date.as_ref()
    }
}
impl UtteranceData {
    /// Creates a new builder-style object to manufacture [`UtteranceData`](crate::types::UtteranceData).
    pub fn builder() -> crate::types::builders::UtteranceDataBuilder {
        crate::types::builders::UtteranceDataBuilder::default()
    }
}

/// A builder for [`UtteranceData`](crate::types::UtteranceData).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UtteranceDataBuilder {
    pub(crate) utterance_string: ::std::option::Option<::std::string::String>,
    pub(crate) count: ::std::option::Option<i32>,
    pub(crate) distinct_users: ::std::option::Option<i32>,
    pub(crate) first_uttered_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_uttered_date: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl UtteranceDataBuilder {
    /// <p>The text that was entered by the user or the text representation of an audio clip.</p>
    pub fn utterance_string(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.utterance_string = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The text that was entered by the user or the text representation of an audio clip.</p>
    pub fn set_utterance_string(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.utterance_string = input;
        self
    }
    /// <p>The text that was entered by the user or the text representation of an audio clip.</p>
    pub fn get_utterance_string(&self) -> &::std::option::Option<::std::string::String> {
        &self.utterance_string
    }
    /// <p>The number of times that the utterance was processed.</p>
    pub fn count(mut self, input: i32) -> Self {
        self.count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of times that the utterance was processed.</p>
    pub fn set_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.count = input;
        self
    }
    /// <p>The number of times that the utterance was processed.</p>
    pub fn get_count(&self) -> &::std::option::Option<i32> {
        &self.count
    }
    /// <p>The total number of individuals that used the utterance.</p>
    pub fn distinct_users(mut self, input: i32) -> Self {
        self.distinct_users = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of individuals that used the utterance.</p>
    pub fn set_distinct_users(mut self, input: ::std::option::Option<i32>) -> Self {
        self.distinct_users = input;
        self
    }
    /// <p>The total number of individuals that used the utterance.</p>
    pub fn get_distinct_users(&self) -> &::std::option::Option<i32> {
        &self.distinct_users
    }
    /// <p>The date that the utterance was first recorded.</p>
    pub fn first_uttered_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.first_uttered_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date that the utterance was first recorded.</p>
    pub fn set_first_uttered_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.first_uttered_date = input;
        self
    }
    /// <p>The date that the utterance was first recorded.</p>
    pub fn get_first_uttered_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.first_uttered_date
    }
    /// <p>The date that the utterance was last recorded.</p>
    pub fn last_uttered_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_uttered_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date that the utterance was last recorded.</p>
    pub fn set_last_uttered_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_uttered_date = input;
        self
    }
    /// <p>The date that the utterance was last recorded.</p>
    pub fn get_last_uttered_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_uttered_date
    }
    /// Consumes the builder and constructs a [`UtteranceData`](crate::types::UtteranceData).
    pub fn build(self) -> crate::types::UtteranceData {
        crate::types::UtteranceData {
            utterance_string: self.utterance_string,
            count: self.count,
            distinct_users: self.distinct_users,
            first_uttered_date: self.first_uttered_date,
            last_uttered_date: self.last_uttered_date,
        }
    }
}
