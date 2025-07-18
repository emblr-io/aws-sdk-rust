// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListRecommendersOutput {
    /// <p>A list of the recommenders.</p>
    pub recommenders: ::std::option::Option<::std::vec::Vec<crate::types::RecommenderSummary>>,
    /// <p>A token for getting the next set of recommenders (if they exist).</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListRecommendersOutput {
    /// <p>A list of the recommenders.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.recommenders.is_none()`.
    pub fn recommenders(&self) -> &[crate::types::RecommenderSummary] {
        self.recommenders.as_deref().unwrap_or_default()
    }
    /// <p>A token for getting the next set of recommenders (if they exist).</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListRecommendersOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListRecommendersOutput {
    /// Creates a new builder-style object to manufacture [`ListRecommendersOutput`](crate::operation::list_recommenders::ListRecommendersOutput).
    pub fn builder() -> crate::operation::list_recommenders::builders::ListRecommendersOutputBuilder {
        crate::operation::list_recommenders::builders::ListRecommendersOutputBuilder::default()
    }
}

/// A builder for [`ListRecommendersOutput`](crate::operation::list_recommenders::ListRecommendersOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListRecommendersOutputBuilder {
    pub(crate) recommenders: ::std::option::Option<::std::vec::Vec<crate::types::RecommenderSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListRecommendersOutputBuilder {
    /// Appends an item to `recommenders`.
    ///
    /// To override the contents of this collection use [`set_recommenders`](Self::set_recommenders).
    ///
    /// <p>A list of the recommenders.</p>
    pub fn recommenders(mut self, input: crate::types::RecommenderSummary) -> Self {
        let mut v = self.recommenders.unwrap_or_default();
        v.push(input);
        self.recommenders = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of the recommenders.</p>
    pub fn set_recommenders(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::RecommenderSummary>>) -> Self {
        self.recommenders = input;
        self
    }
    /// <p>A list of the recommenders.</p>
    pub fn get_recommenders(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::RecommenderSummary>> {
        &self.recommenders
    }
    /// <p>A token for getting the next set of recommenders (if they exist).</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token for getting the next set of recommenders (if they exist).</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A token for getting the next set of recommenders (if they exist).</p>
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
    /// Consumes the builder and constructs a [`ListRecommendersOutput`](crate::operation::list_recommenders::ListRecommendersOutput).
    pub fn build(self) -> crate::operation::list_recommenders::ListRecommendersOutput {
        crate::operation::list_recommenders::ListRecommendersOutput {
            recommenders: self.recommenders,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
