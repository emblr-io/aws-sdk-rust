// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartCrawlerOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for StartCrawlerOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl StartCrawlerOutput {
    /// Creates a new builder-style object to manufacture [`StartCrawlerOutput`](crate::operation::start_crawler::StartCrawlerOutput).
    pub fn builder() -> crate::operation::start_crawler::builders::StartCrawlerOutputBuilder {
        crate::operation::start_crawler::builders::StartCrawlerOutputBuilder::default()
    }
}

/// A builder for [`StartCrawlerOutput`](crate::operation::start_crawler::StartCrawlerOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartCrawlerOutputBuilder {
    _request_id: Option<String>,
}
impl StartCrawlerOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`StartCrawlerOutput`](crate::operation::start_crawler::StartCrawlerOutput).
    pub fn build(self) -> crate::operation::start_crawler::StartCrawlerOutput {
        crate::operation::start_crawler::StartCrawlerOutput {
            _request_id: self._request_id,
        }
    }
}
