// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListAnomaliesForInsightOutput {
    /// <p>An array of <code>ProactiveAnomalySummary</code> objects that represent the requested anomalies</p>
    pub proactive_anomalies: ::std::option::Option<::std::vec::Vec<crate::types::ProactiveAnomalySummary>>,
    /// <p>An array of <code>ReactiveAnomalySummary</code> objects that represent the requested anomalies</p>
    pub reactive_anomalies: ::std::option::Option<::std::vec::Vec<crate::types::ReactiveAnomalySummary>>,
    /// <p>The pagination token to use to retrieve the next page of results for this operation. If there are no more pages, this value is null.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListAnomaliesForInsightOutput {
    /// <p>An array of <code>ProactiveAnomalySummary</code> objects that represent the requested anomalies</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.proactive_anomalies.is_none()`.
    pub fn proactive_anomalies(&self) -> &[crate::types::ProactiveAnomalySummary] {
        self.proactive_anomalies.as_deref().unwrap_or_default()
    }
    /// <p>An array of <code>ReactiveAnomalySummary</code> objects that represent the requested anomalies</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.reactive_anomalies.is_none()`.
    pub fn reactive_anomalies(&self) -> &[crate::types::ReactiveAnomalySummary] {
        self.reactive_anomalies.as_deref().unwrap_or_default()
    }
    /// <p>The pagination token to use to retrieve the next page of results for this operation. If there are no more pages, this value is null.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListAnomaliesForInsightOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListAnomaliesForInsightOutput {
    /// Creates a new builder-style object to manufacture [`ListAnomaliesForInsightOutput`](crate::operation::list_anomalies_for_insight::ListAnomaliesForInsightOutput).
    pub fn builder() -> crate::operation::list_anomalies_for_insight::builders::ListAnomaliesForInsightOutputBuilder {
        crate::operation::list_anomalies_for_insight::builders::ListAnomaliesForInsightOutputBuilder::default()
    }
}

/// A builder for [`ListAnomaliesForInsightOutput`](crate::operation::list_anomalies_for_insight::ListAnomaliesForInsightOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListAnomaliesForInsightOutputBuilder {
    pub(crate) proactive_anomalies: ::std::option::Option<::std::vec::Vec<crate::types::ProactiveAnomalySummary>>,
    pub(crate) reactive_anomalies: ::std::option::Option<::std::vec::Vec<crate::types::ReactiveAnomalySummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListAnomaliesForInsightOutputBuilder {
    /// Appends an item to `proactive_anomalies`.
    ///
    /// To override the contents of this collection use [`set_proactive_anomalies`](Self::set_proactive_anomalies).
    ///
    /// <p>An array of <code>ProactiveAnomalySummary</code> objects that represent the requested anomalies</p>
    pub fn proactive_anomalies(mut self, input: crate::types::ProactiveAnomalySummary) -> Self {
        let mut v = self.proactive_anomalies.unwrap_or_default();
        v.push(input);
        self.proactive_anomalies = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of <code>ProactiveAnomalySummary</code> objects that represent the requested anomalies</p>
    pub fn set_proactive_anomalies(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ProactiveAnomalySummary>>) -> Self {
        self.proactive_anomalies = input;
        self
    }
    /// <p>An array of <code>ProactiveAnomalySummary</code> objects that represent the requested anomalies</p>
    pub fn get_proactive_anomalies(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ProactiveAnomalySummary>> {
        &self.proactive_anomalies
    }
    /// Appends an item to `reactive_anomalies`.
    ///
    /// To override the contents of this collection use [`set_reactive_anomalies`](Self::set_reactive_anomalies).
    ///
    /// <p>An array of <code>ReactiveAnomalySummary</code> objects that represent the requested anomalies</p>
    pub fn reactive_anomalies(mut self, input: crate::types::ReactiveAnomalySummary) -> Self {
        let mut v = self.reactive_anomalies.unwrap_or_default();
        v.push(input);
        self.reactive_anomalies = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of <code>ReactiveAnomalySummary</code> objects that represent the requested anomalies</p>
    pub fn set_reactive_anomalies(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ReactiveAnomalySummary>>) -> Self {
        self.reactive_anomalies = input;
        self
    }
    /// <p>An array of <code>ReactiveAnomalySummary</code> objects that represent the requested anomalies</p>
    pub fn get_reactive_anomalies(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ReactiveAnomalySummary>> {
        &self.reactive_anomalies
    }
    /// <p>The pagination token to use to retrieve the next page of results for this operation. If there are no more pages, this value is null.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The pagination token to use to retrieve the next page of results for this operation. If there are no more pages, this value is null.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The pagination token to use to retrieve the next page of results for this operation. If there are no more pages, this value is null.</p>
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
    /// Consumes the builder and constructs a [`ListAnomaliesForInsightOutput`](crate::operation::list_anomalies_for_insight::ListAnomaliesForInsightOutput).
    pub fn build(self) -> crate::operation::list_anomalies_for_insight::ListAnomaliesForInsightOutput {
        crate::operation::list_anomalies_for_insight::ListAnomaliesForInsightOutput {
            proactive_anomalies: self.proactive_anomalies,
            reactive_anomalies: self.reactive_anomalies,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
