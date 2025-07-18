// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListEntityRecognizerSummariesInput {
    /// <p>Identifies the next page of results to return.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results to return on each page. The default is 100.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl ListEntityRecognizerSummariesInput {
    /// <p>Identifies the next page of results to return.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of results to return on each page. The default is 100.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl ListEntityRecognizerSummariesInput {
    /// Creates a new builder-style object to manufacture [`ListEntityRecognizerSummariesInput`](crate::operation::list_entity_recognizer_summaries::ListEntityRecognizerSummariesInput).
    pub fn builder() -> crate::operation::list_entity_recognizer_summaries::builders::ListEntityRecognizerSummariesInputBuilder {
        crate::operation::list_entity_recognizer_summaries::builders::ListEntityRecognizerSummariesInputBuilder::default()
    }
}

/// A builder for [`ListEntityRecognizerSummariesInput`](crate::operation::list_entity_recognizer_summaries::ListEntityRecognizerSummariesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListEntityRecognizerSummariesInputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl ListEntityRecognizerSummariesInputBuilder {
    /// <p>Identifies the next page of results to return.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Identifies the next page of results to return.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>Identifies the next page of results to return.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of results to return on each page. The default is 100.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to return on each page. The default is 100.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to return on each page. The default is 100.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`ListEntityRecognizerSummariesInput`](crate::operation::list_entity_recognizer_summaries::ListEntityRecognizerSummariesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_entity_recognizer_summaries::ListEntityRecognizerSummariesInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_entity_recognizer_summaries::ListEntityRecognizerSummariesInput {
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
