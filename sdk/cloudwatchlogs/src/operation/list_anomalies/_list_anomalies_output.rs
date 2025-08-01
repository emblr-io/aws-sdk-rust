// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListAnomaliesOutput {
    /// <p>An array of structures, where each structure contains information about one anomaly that a log anomaly detector has found.</p>
    pub anomalies: ::std::option::Option<::std::vec::Vec<crate::types::Anomaly>>,
    /// <p>The token for the next set of items to return. The token expires after 24 hours.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListAnomaliesOutput {
    /// <p>An array of structures, where each structure contains information about one anomaly that a log anomaly detector has found.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.anomalies.is_none()`.
    pub fn anomalies(&self) -> &[crate::types::Anomaly] {
        self.anomalies.as_deref().unwrap_or_default()
    }
    /// <p>The token for the next set of items to return. The token expires after 24 hours.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListAnomaliesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListAnomaliesOutput {
    /// Creates a new builder-style object to manufacture [`ListAnomaliesOutput`](crate::operation::list_anomalies::ListAnomaliesOutput).
    pub fn builder() -> crate::operation::list_anomalies::builders::ListAnomaliesOutputBuilder {
        crate::operation::list_anomalies::builders::ListAnomaliesOutputBuilder::default()
    }
}

/// A builder for [`ListAnomaliesOutput`](crate::operation::list_anomalies::ListAnomaliesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListAnomaliesOutputBuilder {
    pub(crate) anomalies: ::std::option::Option<::std::vec::Vec<crate::types::Anomaly>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListAnomaliesOutputBuilder {
    /// Appends an item to `anomalies`.
    ///
    /// To override the contents of this collection use [`set_anomalies`](Self::set_anomalies).
    ///
    /// <p>An array of structures, where each structure contains information about one anomaly that a log anomaly detector has found.</p>
    pub fn anomalies(mut self, input: crate::types::Anomaly) -> Self {
        let mut v = self.anomalies.unwrap_or_default();
        v.push(input);
        self.anomalies = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of structures, where each structure contains information about one anomaly that a log anomaly detector has found.</p>
    pub fn set_anomalies(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Anomaly>>) -> Self {
        self.anomalies = input;
        self
    }
    /// <p>An array of structures, where each structure contains information about one anomaly that a log anomaly detector has found.</p>
    pub fn get_anomalies(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Anomaly>> {
        &self.anomalies
    }
    /// <p>The token for the next set of items to return. The token expires after 24 hours.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token for the next set of items to return. The token expires after 24 hours.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token for the next set of items to return. The token expires after 24 hours.</p>
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
    /// Consumes the builder and constructs a [`ListAnomaliesOutput`](crate::operation::list_anomalies::ListAnomaliesOutput).
    pub fn build(self) -> crate::operation::list_anomalies::ListAnomaliesOutput {
        crate::operation::list_anomalies::ListAnomaliesOutput {
            anomalies: self.anomalies,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
